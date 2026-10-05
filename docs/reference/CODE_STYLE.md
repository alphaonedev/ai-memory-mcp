# ai-memory Code Style Reference

> Moved verbatim from the `## Code Style` section of the tracked `CLAUDE.md`
> (issue #4507). The Rust engineering standard itself is the `rust-1.98` skill.
> Read on demand; do not load this file whole.

- `cargo fmt` required. All code formatted with rustfmt.
- Zero warnings under `clippy::pedantic`.
- Copyright header on all source files: `// Copyright 2026 AlphaOne LLC` + `// SPDX-License-Identifier: Apache-2.0`
- PRs target `develop` branch, not `main`. `main` is production releases only.
- Commit format: `<type>(scope?): <summary>` — `<type>` ∈
  {feat, fix, docs, style, refactor, test, chore, perf, infra, ci, build, coverage, qc}.
  The last five (`infra`, `ci`, `build`, `coverage`, `qc`) are extended types adopted
  during the v0.7.0 cycle: `infra` for Docker / compose / deployment-config changes,
  `ci` for `.github/workflows/*`, `build` for Cargo.toml / build-script changes,
  `coverage` for `coverage/thresholds.toml` and floor adjustments, `qc` for
  QC-review artefacts + remediation. Scope is encouraged but optional.

### Lint gates (issue #1174 PR10 — pm-v3.1 vendor-monoculture + SECS_PER_*)

Twelve numbered script-based lint gates run in CI alongside the four
cargo gates (fmt / clippy / test / audit) and the two test-guard jobs
(`test-stdin-gate` #1989, `test-env-lock-gate` #2146 — whose census now
runs FIVE arms: (a)-(c) police how a `$HOME` mutation is serialized,
(d) #3475 ratchets literal `set_var`/`remove_var` lines per `src/**`
file, and (e) #3523 ratchets the CROSS-FILE-HELPER writes arm (d)
cannot see, because a mutation routed through
`crate::test_support::EnvGuard` spells neither verb and leaves the
calling file's arm (d) count at zero). All are
HARD-BLOCK. Eleven are wired into `.github/workflows/c8-precheck.yml`,
whose THIRTY-THREE jobs are `c8-precheck`, `vendor-literal-gate`,
`l3-boundary-gate`, `hardcoded-literal-gate`, `docs-vs-ssot-drift`,
`doc-symbol-anchor-gate`, `sdk-route-path-gate`, `ci-job-claims-gate`,
`doc-surface-completeness-gate`, `capacity-claim-gate`,
`benchmark-claim-gate`, `cloud-init-ascii-gate`,
`test-keydir-mode-gate` (#3733), `migration-ladder-gate`, `install-checksum-gate`,
`conformance-readers-gate`, `required-contexts-gate`,
`git-dependency-source-gate`, `create-extension-allowlist-gate`,
`commit-signing-posture-gate`, `cert-expiry-gate` (the
enterprise-federation cert §7 expiry trigger, #2915 — an integrity
gate, not one of the twelve numbered lint gates below),
`foreign-text-to-caller-gate` (#3688),
`external-pr-operator-approval-gate` (an outside-team PR author needs
an `@alphaonedev` review), `url-sink-redaction-gate`, `stale-contract-assertions-gate` and
`claude-plugin-gate` (#3967 — three of the FIVE `check-*.sh` gates
that existed and were referenced by NO workflow; the other two,
`check-count-assertion-declared.sh` and `check-shared-namespace-claims.sh`,
carry dated entries in `scripts/qc-allowlists/gates-not-wired.txt`
naming why each cannot run on a PR event yet),
`declaration-hash-gate` (#3557 — the pre-registered §0.2 SLO/RPO/RTO
declaration's SHA-256 pin, `scripts/check-declaration-hash.sh`; an
integrity gate in the same sense), `truthy-grammar-gate` (#3200),
`const-name-literal-gate` (#3121), `sdk-tls-scheme-gate` (#3782),
`mcp-transport-isolation-gate` (#3829), `test-keydir-mode-gate`
(#3733), `foreign-text-to-caller-gate` (#3688 gate 7),
`external-pr-operator-approval-gate`, plus the two test-guard jobs
above. (This job list re-synced at #2915 — sixteen had rotted to
twenty-one since #2636 — and again at #3719, when it said TWENTY-SIX
while the workflow declared thirty-three: the same prose-rot class
rule (f) of gate 7 blocks mechanically, one layer down. Re-measure
with `scripts/check-required-contexts.sh --dump`, gate 7's own
parser, before trusting the count; a mechanical pin for this
paragraph is tracked in #3719.) The twelfth, gate **8** below, lives in
`.github/workflows/ci.yml` because it needs a Rust toolchain that
`c8-precheck.yml`'s deliberately toolchain-free jobs do not carry.

As of #2636, every job in the three GATING workflows (`ci.yml`,
`c8-precheck.yml`, `coverage.yml`) must be declared either in
`scripts/qc-allowlists/required-contexts-release.txt` or in the dated
`scripts/qc-allowlists/required-contexts-not-required.txt` — see rule
(f) of gate 7. A newly-added integrity gate can no longer default to
unenforced, which is why the three CERT-GATE-2 jobs below are declared
REQUIRED in the mirror rather than left to default.

**Gates 9, 10 and 11 are the CERT-GATE-2 published-claims set** (#2629 /
#2492, 2026-08-01). They exist because a 265-claim audit
(`docs/audit/3x7-claims-register-2026-08-01.md`) found **71
FALSE/OVERCLAIMED published claims** while gate 4 was GREEN — and the
register's diagnosis is the one that governs all three: *"the drift
direction is consistently toward MORE CLAIMED ENFORCEMENT THAN EXISTS.
That is not random staleness; it is a systematic bias that a gate must
be built to counter."*

**Two ledger dispositions, and the difference is deliberate.** Gates 4,
10 and 11 carry PENDING-FIX ledgers where a **stale entry is a loud
NOTICE, not a failure** — the `dual-trigger-cancel-allow.txt` precedent
(rule (d) of gate 7): a stale entry can only suppress a failure that no
longer happens, and failing on it would red whichever PR lost the race
to the correction lane that removed the claim. Gate 9 carries a
BURN-DOWN allowlist where a **stale entry FAILS** — the
`required-contexts-joblevel-if-allow.txt` discipline (rule (b2)) —
because nothing is concurrently correcting those anchors, so a stale
entry there is pure rot. In every ledger a MALFORMED entry HARD-FAILS,
so none of them can rot into prose.

**0. Hardcoded-literal duplication ratchet (pm-v3.1)** —
`scripts/check-hardcoded-literals.sh`. The mechanical enforcement of the
operator's standing "no hardcoded literal values; no literals baked into
variable/constant names" directive (in force ~6mo; instructions alone did
not stop the regression). HARD-BLOCKS any double-quoted string literal
≥ 10 chars that appears on ≥ 3 production sites (a magic value that should
be one named `const`) **when its site-count rises above the frozen
baseline** at `scripts/qc-allowlists/hardcoded-literals-baseline.txt`. It
is a ratchet: existing duplications are grandfathered, new duplication
fails, and the baseline may only shrink ("thresholds rise, never fall").
Fix a violation by defining/reusing one named `const` (or an existing
helper) referenced by name at every site — NOT by scattering the literal.
Intentional, irreducible repetition is bumped via `--update-baseline`
(operator-gated, justified in the commit). `--self-test` proves it is
load-bearing. Magic numbers are out of scope here (the SECS_PER_* class is
gated by #2; a general numeric gate is too noisy). Burn the baseline down
over time.

**1. C8 caller-context allowlist** —
`scripts/qc-codegraph-precheck.sh`. Blocks any new
`CallerContext::for_agent("<literal>")` or
`CallerContext::for_admin("<literal>")` site outside
`scripts/qc-codegraph-allowlists/*.txt`. See the §"Enforceable
Orchestrator Safeguards" section above for the full contract.

**2. Vendor-monoculture + SECS_PER_* gate** —
`scripts/check-vendor-literals.sh`. Blocks regressions in two
disciplines the Wave 1+2 #1174 refactor train landed:

- **Vendor identifiers** (`"claude" | "openai" | "xai" |
  "anthropic" | "gemini" | "groq" | "ollama" |
  "grok" | "mistral" | "cohere" | "huggingface"`) are legitimate
  ONLY in the 12 substrate carve-outs:
  - `src/llm.rs` — canonical alias tables, default URLs
  - `src/config.rs` — per-vendor URL/key/model defaults
  - `src/mine.rs` — `Format::Claude` conversation-mining enum
  - `src/validate.rs` — `VALID_SOURCES` back-compat allowlist
  - `src/cli/wrap.rs` — CLI-binary-name → `WrapStrategy` picker
  - `src/llm_cli_wrap.rs` — per-vendor CLI-binary `WrapStrategy` table (split from `src/cli/wrap.rs` per #1183)
  - `src/harness.rs` — harness vendor-variant enum
  - `src/recover/transcript_paths.rs` — per-AI-host transcript directory router; vendor IS the routing key (#1389 L2)
  - `src/cli/commands/recover_previous_session.rs` — per-AI-host CLI dispatcher; vendor IS the routing key (#1389 L2)
  - `src/secret_screen.rs` — vendor-keyed secret-pattern table
  - `tools/t0-orchestrate/src/main.rs` — orchestrator vendor dispatch
  - `src/identity/model_family.rs` — v0.9.0 §25.3 S1 (#1870) conservative model-FAMILY normalizer table (`family_of`); the vendor-family stems ARE the routing key of the normalization, the same `src/mine.rs::Format::Claude` vendor-keyed-enum precedent

  Every other production-code site must read the vendor string
  from `crate::llm::*` / `crate::config::*` (e.g.
  `crate::llm::BACKEND_OLLAMA` instead of the literal `"ollama"`).
  Per pm-v3.1 (ai-memory `global/policies` memory
  `f5334545-c1f5-4f5c-9efb-a0ec3a0c1fcd`): vendor identifiers
  scattered across substrate/wire code violate the heterogeneous-NHI
  design.

- **SECS_PER_* magic numbers** —
  `Duration::from_secs(3600 | 86400 | 604800 | 3_600 | 86_400 |
  604_800 | 7200 | 21600 | 172800)` and the underscore variants are
  HARD-BLOCKed. Use the named constants from `src/lib.rs`:
  `SECS_PER_HOUR` (3_600), `SECS_PER_DAY` (86_400),
  `SECS_PER_WEEK` (604_800).

  Why script-based instead of clippy `disallowed_methods`:
  `Duration::from_secs` is called 90+ times in the codebase with
  legitimate small-int timeouts (5, 10, 30 seconds for HTTP /
  health probes / circuit-breaker cooldowns); clippy can't
  distinguish "literal magic number" from "named const argument",
  so a blanket disallow would block all 90+ sites including the
  legitimate ones.

**Self-test (load-bearing evidence).**
`scripts/check-vendor-literals.sh --self-test` injects a contrived
`"anthropic"` literal at a production site, runs the gate, verifies
the gate exits non-zero with the expected violation message, then
cleans up. The CI workflow runs the self-test step after the main
check so a regression in the gate's detection logic (e.g. an
over-broad allowlist, a broken test-boundary heuristic) trips
immediately. Per pm-v3.2 NO FAIL MISSION closure discipline
(ai-memory `global/policies` memory
`2cb15d34-2399-4611-a020-df6ef91683fe`): the gate itself must be
load-bearing, not decorative.

**Adding a legitimate exception.** If a new vendor-specific
surface genuinely belongs outside the 12-file allowlist (e.g. a
new dedicated subsystem the way `src/mine.rs` carries
`Format::Claude`), edit `scripts/check-vendor-literals.sh` to
extend the `ALLOWED_FILES` array AND document the carve-out in
this section. Operator-approved review before merge.

**Production-vs-test heuristic.** The script skips:
- Files whose basename matches `*test*.rs` or `tests.rs`
- Lines at or below the first `mod tests {` / `pub mod tests {`
  occurrence in each file
- Comment lines (`//`, `///`) and block-comment continuations (`*`)

The heuristic mirrors `scripts/qc-codegraph-precheck.sh` so the
two gates have the same production-vs-test boundary across the
codebase.

**3. L3-boundary perma-ban gate** (§25.3 S5 / RQ-10, #1853) —
`scripts/check-l3-boundary.sh`. HARD-BLOCKS the case-insensitive
pattern `rqgm|epoch_manifest|red.?queen` anywhere in `src/`
(string literal or comment) — these are internal design-doc
identifiers that must never leak into the shipped binary's
symbol/string surface. The ruled PUBLIC identifiers
(`SignableEpochManifest`, `epoch.manifest_applied`,
`EpochAdvance`, `EPOCH_APPLIED`, `epoch_seq`, `prior_epoch_id`)
are gate-clean by construction. `--self-test` plants a violation
in a tmpdir and confirms the gate rejects it.

**4. Docs vs SSOT drift gate** (v0.7.0 operator directive
2026-05-31; **widened by #2492**, 2026-08-01) —
`scripts/check-docs-vs-ssot.sh`. Markdown has no
native variables, so this gate is the minimal-infra answer:
parses the canonical Rust SSOT consts (`CURRENT_SCHEMA_VERSION`,
`EXPECTED_PRODUCTION_ROUTES_COUNT`, `EXPECTED_CLI_SUBCOMMANDS_*`,
`Profile::full().expected_tool_count()`, `Memory::FIELD_COUNT`,
etc.), walks the operator-facing `.md` files for known
narrative-count patterns, and HARD-BLOCKS when any cited value
drifts from the canonical.

**#2492 — the gate greened a page carrying FIVE stale SSOT values.**
README.md is, and always was, in `DOC_FILES`, so the gap was never the
file walk: it was the PATTERN SET. Every original rule is a
hand-written regex pinned to one exact phrasing
(`\*\*N production \`\.route\(\.\.\.\)\` registrations\*\*`), and a
document that says the same thing in the seventh way nobody enumerated
is invisible. README carried 94→92/93 routes, 88→78 schema, 30→28
`Memory` fields, 103→101 tools and 91/89→89/87 CLI subcommands with
this gate green — the #2444 "reports success while doing nothing"
shape. The fix is a **generalised numeric-claim scanner**: for each
SSOT const, a small set of NOUN-PHRASE ANCHORS (`HTTP route
registrations`, `unique URL paths`, `unique paths`, `MCP tools at
--profile full`, `-entry surface`, `CLI subcommands`,
``-field `Memory` ``, `schema **v`) and ANY adjacent integer in bold /
code / plain form. A re-worded sentence is caught by the anchor; only a
genuinely new NOUN gets past, which is far rarer.

**The historical guard is load-bearing and must not be weakened.**
README legitimately carries release-narrative paragraphs
(``**v0.8.0 (…) — prior release.** … At the v0.8.0 release, surface
was: schema **v<then>**, **<N>** MCP tools …, a **<M>-field** `Memory`.``
— with real numbers in place of the placeholders) and ROADMAP §11.3.1
carries a self-correcting frozen v0.7.1 baseline. Those
numbers are TRUE statements about a PAST release; re-pointing them at
the canonical would falsify the record — the same reasoning that keeps
CHANGELOG.md, the RFC files and the three frozen v0.7 migration guides
out of `DOC_FILES` entirely. So a line that opens a release-narrative
paragraph (`^**v<semver>`) attributed to a NON-current release, or that
says `At the v<x> release` / `release, surface was` / `Ship state at
v<x>` / `Frozen v<x> baseline`, is skipped by the numeric rules.

That guard would be a hole on its own, so **rule N1** closes it: a
paragraph labelled `— current release` MUST attribute the Cargo.toml
version. That is what catches a README paragraph whose lead names a
PRIOR version and still calls itself the current release — the single
paragraph carrying four of the register's five shapes. Once it is honestly relabelled, its numbers are either history
(skipped) or current (checked).

**R-203 is mechanical here.** The pre-fix script is frozen VERBATIM at
`scripts/test/fixtures/docs-vs-ssot-prefix-2492.sh` (the
`ci-classify-prefix-2496.sh` / `required-contexts-prefix-2494.txt`
precedent). `--self-test` plants the exact pre-fix README phrasings and
asserts BOTH directions — the FROZEN gate ACCEPTS them (reproducing the
defect) and the LIVE gate REJECTS all 11 planted claims. A self-test
that only proved the new gate works would be tautological, since the
whole finding was that the old gate greened them. Further legs pin the
historical control (a prior-release paragraph, a frozen baseline and
ladder mentions must still PASS), rule N1, and all three ledger
directions. Scratch lives under `.local-runs/`, never `mktemp -d`.

**#2977 — the GitHub-Pages `.html` surface.** #2492 widened the PATTERN
set; the scan SET stayed markdown-plus-one-file, so ~70 hand-authored
Jekyll pages under `docs/` were ungated and the published site drifted
invisibly through the whole v1.0.0 campaign (stale schema versions, a
sitewide `v0.9.0` chrome stamp, a false sub-10ms recall claim, a
bench-as-merge-blocker claim, a kind-count 10-vs-16) with this gate
GREEN. The html scan set is now **enroll-by-default** over
`docs/**/*.html` minus the frozen pages named in
`scripts/qc-allowlists/html-doc-frozen-exempt.txt` — ONE exemption SSOT,
shared with gate 11 so the two cannot disagree about the boundary. That
INVERTS the `.md` argument above deliberately: an enumerated INCLUDE list
cannot close a class whose whole shape is "a new page lands ungated", and
the `.html` tree's frozen surfaces are a small, named, structurally
obvious set (per-release trees, `whats-new-v*`, release narratives, dated
assessments) where a `.md` glob would drag in the whole
reviews/design/audit sprawl. A missing exemption file, or an empty
resolved set outside the fixture, FAILS CLOSED.

The SAME rule table serves both dialects (`<strong>`/`<b>` for `**`,
`<code>` for a backtick, `&nbsp;` for a space) rather than a second html
table that could silently disagree — and without that, adding the pages
would have been a widening that scans them and can see nothing. Two
html-specific HISTORICAL guards keep TRUE history out of the violation
set: the guard runs over a **tag-stripped, whitespace-collapsed** view
(so `schema <strong>vNN</strong> added …` is still recognised as a ladder
statement — spelled with a placeholder here because the dialect-agnostic
anchor reads this file too, and an example carrying a real number would
BE the drift it describes), and the release-card markers (`PRIOR RELEASE`, `What's New in
vX.Y.Z`) run over a **3-line preceding window**, because an html release
card puts its attribution in the divs ABOVE the numbers. `--self-test`
asserts both directions: the same numbers with the card markers REMOVED
are rejected, so the window is a guard and not a blanket exemption.

**New rule in the same gate — sitewide CHROME version stamp.** The footer
stamp (`ai-memory vX.Y.Z`, scoped to text inside `<footer>`) and the
hero/nav release badge (`<span class="badge">vX.Y.Z`) must equal the
`Cargo.toml` version. Chrome is the version an operator reads on EVERY
page and was the one claim nothing checked. Body prose is never read (a
page may narrate v0.7.0 history all day); frozen pages keep their own
stamp; and **published-install / download references are skipped by
name** — the tag-cut is operator-gated, so an install line pinned at the
last PUBLISHED tag is CORRECT, and flagging it would push a doc author to
publish an install command for a tag that does not exist.

**5. Cloud-init ASCII gate** (#1880) — `scripts/check-cloud-init-ascii.sh`.
A stray non-ASCII byte (a U+2014 em-dash) in a DigitalOcean
cloud-init template made cloud-init silently discard the config
and boot a BARE droplet with none of the postgres/AGE/pgvector
substrate — a silent provisioning failure only visible on SSH
triage. HARD-BLOCKS any non-ASCII byte in `infra/do-hive/*.tpl`.
`--self-test` plants the exact #1880 em-dash byte in a tmpdir
template and confirms the gate rejects it.

**6. Migration-ladder-uniqueness gate** (v1.0.0 guardrail-D, 2x5-vote
`b682c76a`) — `scripts/check-migration-ladder.sh`. Structurally
prevents the SILENT migration-ladder-collision class. Migration SQL
is loaded by `include_str!` at explicit paths in
`src/storage/migrations.rs` (sqlite) + `src/store/postgres.rs`
(postgres) with NO uniqueness enforcement: a PR built on an OLD base
can add `migrations/postgres/0041_v82_archived_valid_time.sql` (#2036)
while release already carries `migrations/postgres/0041_v84_embedding_space.sql`
— SAME numeric prefix, DIFFERENT filename ⇒ ZERO git conflict, git
silently keeps BOTH, and a corrupted/ambiguous ladder ships fleet-wide
(probe-guarded ALTERs make the double-apply a silent no-op — not
fail-closed). #2192 renumbered the collider to `0042_v85_*`; this gate
keeps the class from ever re-landing silently. HARD-BLOCKS any of:
(a) two files in `migrations/<backend>/` sharing a 4-digit prefix (the
#2036/#2192 shape); (b) two ladder ARMS declaring the same schema
version (`if version < N {` in migrations.rs, `migrate_vN` /
`if current_version < N {` in postgres.rs); (c) a gap (outside the
documented `KNOWN_PREFIX_GAPS` — currently `sqlite:48`) or a
non-monotonic arm jump; (d) cross-adapter disagreement (the two
`CURRENT_SCHEMA_VERSION` consts, the highest-prefix file's `vNN` tag,
and the postgres `migrate_vN` tip must all agree); (e) an orphan
migration file (on disk, referenced nowhere under `src/`, not on
`LADDER_EXEMPT_FILES`) or an `include_str!` arm referencing a missing
file; **(f)** a BOOTSTRAP-to-LADDER FORWARD REFERENCE (#2424, GA
blocker) — a `CREATE [UNIQUE] INDEX` in either adapter's BOOTSTRAP
schema (`src/store/postgres_schema.sql`; the `const SCHEMA` block in
`src/storage/migrations.rs`) that references a column the ladder adds
via `ALTER TABLE … ADD COLUMN`. Both adapters replay their bootstrap on
EVERY open, ALWAYS before `migrate`, so on a LEGACY database the
pre-existing table makes `CREATE TABLE IF NOT EXISTS` a no-op, the
column is absent, and the index DDL CRASHES the open — the deployment
cannot start (`IF NOT EXISTS` keys on the INDEX NAME, not the column,
so it is no defence). Such an index belongs exclusively in the
`migrate_vN` arm that adds the column; fresh installs still get it
because `migrate_locked` reads `current_version = 0` and runs every
arm. That is the `bootstrap(fresh)` = `ladder(v0 -> tip)` equivalence
rule (f) enforces statically. `--self-test` plants the EXACT #2036/#2192
same-prefix-different-name collision, a same-version-two-arms case, AND
the #2424 shape on both adapters (the postgres v84
`idx_memories_embedding_space` index that bricked two live deployments,
plus the #1861 sqlite `idx_memories_cid` shape) in a throwaway copy
UNDER the repo (never system `/tmp`) and confirms the gate rejects each.
The `cargo test` twin `tests/migration_ladder_integrity.rs` re-asserts
the same invariants (prefix-uniqueness, gap-free sequence, `MIGRATION_LADDER`
monotonicity, cross-adapter tip agreement, and the rule-(f) forward-reference
check) so a collision fails even if the shell gate is bypassed; the
runtime proof against a REAL postgres — a POPULATED v67 / v73 / v83
legacy database replayed to the tip, then compared column-for-column and
`indexdef`-for-`indexdef` against a greenfield install — is
`tests/postgres_ladder_replay.rs`. Data-integrity guardrail (North Star:
degrade — a loud non-zero exit — never corrupt the ladder).

**7. Required-context + classify-base soundness gate** (#2494 /
#2496) — `scripts/check-required-contexts.sh`. The required-status-check
set on `release/v1.0.0` read as 22 gates and functioned as far fewer, in
three independent ways, all confirmed on live check-run data. **The
wedge:** `ci.yml`'s `mobile-cross-compile` was BOTH a `strategy: matrix`
job AND carried a job-level `if:`. GitHub evaluates a job-level `if:`
BEFORE matrix expansion, so on docs-only commit `45ba8741` it emitted ONE
check-run named `Cross-compile (${{ matrix.target }})` and the two
REQUIRED expanded names were never created — pending forever, and
`enforce_admins: true` means no admin merge clears it. The same commit
proves the correct shape: `Check (ubuntu/macos/windows-latest)` all
EXPANDED and reported `success`, because the `check` job carries NO
job-level `if:` and guards every STEP instead. **The fail-open:** eight
required contexts carry a job-level `if:` and report `skipped`, which
branch protection COUNTS AS SATISFIED — tolerable only while the
classifier is right, and it was not (#2496). **The unreportable
context:** a `paths:` filter on the carrying workflow's `pull_request`
trigger wedges the branch identically, with no `if:` in sight. **The
unrequired decider** (#2494 residual): the job that DECIDED the
skipped-vs-ran disposition of the fail-open was not itself required —
`Classify changes` (ci.yml) and `Coverage classify (docs-only
short-circuit)` (coverage.yml) between them governed ELEVEN required
contexts while being required by nothing. Both are now DECLARED in the
mirror (the declared set is `scripts/qc-allowlists/required-contexts-release.txt`; the LIVE set is
pinned at `scripts/qc-allowlists/required-contexts-live-pin.txt` and the two are held equal by the
wired, fail-closed `scripts/check-required-contexts-live.sh` (#3554), so the integers are deliberately
not restated here — restating them drifted twice, #3968. ORDER for an ADDITION since #3554
(#3985): the job lands with a dated entry in the not-required ledger, then live protection,
then `--pin-from-live`, then the name moves from the ledger into the mirror in the SAME commit
as the pin, so declaration == pin == live at every commit; the old mirror-first order
over-claimed enforcement and now fails the live-drift gate).
HARD-BLOCKS all of it statically against the HAND-AUTHORED mirror at
`scripts/qc-allowlists/required-contexts-release.txt`: **(a)** every
mirror context equals a parsed static job `name` or an expanded matrix
name from a workflow whose `pull_request.branches` covers the protected
branch; **(b1) HARD-FAIL, never allowlistable** — matrix AND job-level
`if:` together (the exact wedge); **(b4) HARD-FAIL, never
allowlistable** — the job is a DECIDER (another job in the same workflow
declares `needs:` it) AND carries a job-level `if:`; a skipped decider
skips its whole dependent subtree and every skipped member then counts
as SATISFIED, so ONE allowlist entry would buy the subtree, which is
exactly why (b4) is not ratchetable the way (b2) is; **(b2)** a
job-level `if:` at all fails unless listed in the burn-down ratchet
`required-contexts-joblevel-if-allow.txt`, where a STALE entry also fails
so the ledger cannot rot; **(c)** the carrier's `pull_request` trigger
exists and has no `paths:`/`paths-ignore:` filter; **(b3)** in any
`needs: classify` job with no job-level `if:`, EVERY step carries the
`docs_only` guard (bare `actions/checkout@*` is the single structural
exemption). **(d) HARD-FAIL, applied to EVERY workflow in
`.github/workflows/` and not only to required-context carriers** — the
#2508 CANCELLED DUPLICATE: the workflow triggers on BOTH `push` and
`pull_request`, at least one `push.branches` pattern can match a PR HEAD
branch, and it declares a `concurrency.group` with
`cancel-in-progress: true` whose key is not event-distinct. On a push
there is no `pull_request` context, so the house key's ternary falls
through to `github.ref_name` = the head branch while the same-repo
`pull_request` event resolves to `head.ref` = the identical string —
one group, two runs per SHA, one ALWAYS cancelled, and the cancelled
check-run row is permanent. `cancelled` READS AS PASS in `gh pr checks`
while branch protection does not count it as satisfied, so the branch
wedges the day that context is required and the standard triage command
conceals the cause; the scope is repo-wide precisely because the
artefact must be dead before anyone reaches for that hardening step.
Head-branch overlap is decided by `glob_match`-ing each pattern against
the declared `PR_HEAD_PROBES` corpus (the commit-type vocabulary above,
cross-checked against measured PR head prefixes); `main` / `develop` /
`release/**` are deliberately not probes, and an exact literal like
`feat/v0.7.0-grand-slam` matches nothing because it cannot match a
CLASS of heads. Event-distinctness is a conservative STRUCTURAL test —
a group containing `${{ github.event_name }}` is exempt, everything
else is treated as colliding — since the house key is exactly the shape
that looks event-aware and collides anyway. `cancel-in-progress: false`
(or no concurrency block) is NOT flagged: two SUCCESS runs are
wasteful, not the defect. The carrier that surfaced the class was fixed
in #2509; `c8-precheck.yml`'s own `local/**` overlap in #2523;
`token-budget.yml` is held in the PENDING-FIX ledger
`scripts/qc-allowlists/dual-trigger-cancel-allow.txt` (`<workflow-file>
<push-pattern> #<issue>`, format enforced so the ledger cannot rot,
per-pattern so a newly-acquired overlap is not absolved) while #2506
repairs it — a stale entry there is a loud NOTICE, not a failure,
because it can only suppress a failure that no longer happens and
failing on it would red whichever PR lost the race to the carrier fix.
**(e) HARD-FAIL, never allowlistable, repo-wide** — a job `name:` written
as an UNQUOTED scalar whose raw value contains whitespace-then-`#`. That
is the #2473 shape: YAML truncates the name at the `#`, so the DECLARED
name and the check-run GitHub reports differ, and an operator copying the
reported name into branch protection pins the truncation — which is
literally how the malformed context entered the live set. The remedy is
one character of quoting, so there is no legitimate instance and no
ratchet; a deliberate trailing comment stays expressible by quoting the
scalar first (`name: "Foo"  # note`). Scoped repo-wide by the rule (d)
argument: a truncated name is a declared≠actual lie in every UI today and
becomes a wedge the moment that context is required. The `(#1174 PR10)` /
`(#2146)` / `(#1989)` family is NOT flagged — a `#` preceded by `(` is
not a YAML comment — which is what aims the rule at the defect rather
than the neighbourhood. **The mirror is hand-authored from intent and
must NEVER be regenerated from live API state:** the canonical
demonstration is #2473, where one required context was
`L3-boundary perma-ban gate (§25.3 S5 / RQ-10` because the unquoted
` #1853)` in `c8-precheck.yml` opened a comment. It MATCHED, so the gate
was green on a name nobody wrote; regenerating the mirror would have
laundered the truncation into the declaration and made rule (a) a
tautology that passes forever, which is why the artefact was preserved
rather than "repaired" until the coupled fix. #2473 CLOSED it — the
workflow name is quoted, both mirrors declare the full string, and rule
(e) keeps the class from re-landing. Its landing order is documented in
the mirror: the swap's two halves pull opposite ways (drop the TRUNCATED
context from protection BEFORE the rename merges, add the FULL one
AFTER), because after the rename lands no PR reports the old name and
before it lands no PR reports the new one. The awk parser
implements the real YAML scalar rule (a `#` preceded by whitespace opens
a comment; `(#1174 PR10)` does not) and was cross-checked against PyYAML
on all jobs across all 17 workflows with zero mismatches (re-run at
#2473; the job count is 59 at #2636 — it has drifted both ways since, so
treat it as a measurement, not a pin — and the cross-check is the
standing proof that rule (e)'s premise about YAML is real).
`--self-test` plants the (b1) wedge, an (a) unmatched context, an (e)
unquoted ` #` job name (asserting via `--dump` that the parse really is
truncated at the `#` BEFORE asserting the gate rejects it, so a parser
that stopped truncating could not make the rule fire for the wrong
reason), a (c) path-filtered carrier, a (b3) unguarded step, a (b4)
decider `if:` (rejected EVEN WHEN allowlisted — the property that
separates (b4) from (b2)), both directions of the (b2) ratchet, and —
for (d) — the VERBATIM
pre-#2509 `tool-count-drift.yml` trigger+concurrency block (R-203)
alongside four NEAR MISSES that must each PASS (the #2509-narrowed
triggers, `cancel-in-progress: false`, a push-only workflow, an
`event_name`-keyed group) so the rule fires on the defect and not on its
neighbourhood, in a throwaway copy under `.local-runs/` (never system
`/tmp`, never `mktemp -d`);
`--dump` prints the raw parse stream. The job is wired UNCONDITIONALLY —
no `needs: classify`, no job-level `if:`, no `paths:` — because a gate
policing the docs-only short-circuit must not be subject to it. Its
sibling step runs `scripts/test/test-ci-workflow-invariants.sh`, which
EXTRACTS the `classify` shell verbatim from `ci.yml` and drives it over
throwaway git fixtures, then runs the same fixtures against the pre-fix
block frozen at `scripts/test/fixtures/ci-classify-prefix-2496.sh` — a
code-then-docs PR must classify `docs_only=false` live and `true` frozen,
so a silently-broken extraction cannot make the assertions vacuous. Its
SECTION C (#2494 residual) holds the four live premises that make
requiring a decider safe — name declared in the mirror (re-derived from
the workflow through the gate's own `--dump` parser, never a hand-copied
literal, so an unmirrored rename fails here too), no job-level `if:` and
no matrix, `pull_request` covering `release/**` unfiltered, and a `push:`
branch list that cannot match a PR HEAD branch (the #2508 precondition:
one run per SHA, no `cancelled` twin) — with an R-203 regression leg
against the mirror frozen at
`scripts/test/fixtures/required-contexts-prefix-2494.txt`: under that
pre-fix mirror a planted decider `if:` passes the gate SILENTLY, which is
the blind spot the declaration closes and the proof the leg is not
tautological. **(f) HARD-FAIL, added #2636** — every job in a GATING
workflow (`ci.yml`, `c8-precheck.yml`, `coverage.yml`,
`cert-postgres-age.yml`, `postgres-ignored.yml`, declared as
`COVERED_WORKFLOWS` in the gate) must be declared EITHER in the mirror OR
in the dated ledger
`scripts/qc-allowlists/required-contexts-not-required.txt`
(`<workflow-file> <job-id> <YYYY-MM-DD> #<issue>`). Rules (a)-(e) all
reason mirror -> job, so not one of them can see a job that is simply
ABSENT from the mirror: a newly-added integrity gate lands unrequired, in
silence. It did. FOUR c8-precheck gates ran on every PR required by
nothing — `Installer checksum fail-closed gate (#2449)`, `Non-Rust
conformance-reader proof gate (#2452)`, `Git-dependency-source
supply-chain gate (#2050/#2512)`, and `Required-context + classify-base
soundness gate (#2494/#2496/#2508)`, which is THIS GATE, the sole
mechanical proof that the other required contexts are sound; a PR that
broke the gate proving the gates work could merge. The prose KNOWN GAPS
note meant to record this named only TWO of the four and had gone stale
unnoticed, which is the whole argument for a machine-parsed ledger over a
comment: prose cannot fail CI. PARTIAL matrix coverage fails (an
undeclared expansion can fail and merge while its siblings look green).
Stale entries are FATAL here, unlike the rule (d) pending-fix ledger,
because a stale line pre-absolves whatever job next takes that id in the
workflow where the integrity gates live; both directions fail (a job that
no longer exists, and a job whose context IS in the mirror). The SCOPE is
cross-checked in both directions — a declared covered workflow with no
parsed jobs fails, and a mirror context carried by an UNCOVERED workflow
fails — so it cannot silently narrow. It is deliberately NOT repo-wide
(contrast (d)/(e)): those detect static defects, wrong anywhere, while (f)
encodes a policy judgement that must be authored per workflow, and
sweeping in the ~45 jobs of `release.yml` / `publish-sdks.yml` / `yank.yml`
etc. — none of which fire on `pull_request` — would build a junk drawer
readers skim past. Every ledger entry is a dated decision record, not an
absolution. Data-integrity guardrail (North Star: a control that reports
success while doing nothing is worse than a missing control, because 22
green checks actively imply rigor that is not present). **(g) HARD-FAIL,
added #3967** — rule (f) audits jobs that EXIST; a `scripts/check-*.sh`
with no job is invisible to it, and FIVE of forty gates sat in exactly
that state — including `check-url-sink-redaction.sh`, the credential-leak
gate written AFTER its class recurred four times (#3648 #3649 #3667
#3674) — all passing by hand, none able to fail, because nothing called
them. Every gate script must now be referenced by basename on a
NON-COMMENT line of some workflow under `.github/workflows/` (a
commented-out `run:` is exactly the shape that switches a gate off in
place and still reads as wired), or carry a dated, tracked entry in
`scripts/qc-allowlists/gates-not-wired.txt` (`<check-*.sh> <YYYY-MM-DD>
#<issue>`). Stale entries are FATAL in both directions (a listed script a
workflow does reference; a listed script that no longer exists), a
malformed entry is fatal, and an empty script set fails closed. The
self-test plants the unwired script, the commented-out reference, the
dated entry (PASS), and each hygiene failure. Three of the five were
wired by #3967 (`url-sink-redaction-gate`, `stale-contract-assertions-gate`,
`claude-plugin-gate`, declared in the not-required ledger until the
branch-protection call promotes them); the two that cannot run on a PR
event yet are ledgered with the reason.

**8. Build-script custom-build ledger gate (#2259 / #2635)** —
`scripts/check-build-script-vetting.py`, run by the `Build-script
custom-build ledger gate (#2635)` job in `.github/workflows/ci.yml`. A
cargo build script executes arbitrary code with the BUILDER's authority at
compile time, on every CI runner and every operator machine; this gate is
the mechanical enforcement of the operator's firmest standing rule, "no
external code injection. EVER." (§ above), adopted after an external party
attempted precisely this vector including a cargo-squat trap on a crate
that did not yet exist. Until #2635 the gate iterated ONLY its own ledger
(`for record in ledger["packages"]`), which held TWO packages while
`cargo metadata` resolved 90 with a `custom-build` target out of 547 —
there was NO reverse direction, so a new crate with a hostile `build.rs`
was never examined and the gate printed `PASS (2 records verified)`. It
now walks the resolved graph and HARD-BLOCKS on any custom-build package
ABSENT from `supply-chain/build-script-vetting.json`: the ledger is an
allowlist that must COVER REALITY. Records carry `reviewed` (source read;
requires a dated `docs/security/build-script-vetting.md` anchor and a
pinned build-dependency closure — 2 today) or `inventoried` (pinned and
dated, NOT source-reviewed — 88), because stamping 90 `reviewed` records
on unread source would buy a green check that actively asserts rigor which
is not present; the PASS line always prints both counts and states what it
does not attest. `inventoried_ceiling` is a monotone burn-down ratchet in
the `hardcoded-literals-baseline.txt` shape: admitting an unreviewed build
script requires BOTH a ledger line and raising a number that exists for no
other purpose. Registry packages are pinned by `Cargo.lock` checksum;
`vendor/paste` — the one package with no source, no checksum, in-tree and
editable in any PR — is pinned by `tree_sha256` over its git-tracked tree,
and a registry package may never be pinned that way (else "declare it
vendored" becomes a universal bypass). `--self-test` plants an unvetted
build-script package plus eight sibling defects against synthetic
metadata, requires each rejection to NAME the right violation, spares six
near-miss shapes, and carries an R-203 leg that runs the FROZEN pre-#2635
ledger-only algorithm over the same fixture and requires it to MISS.
`--update-checksums` refreshes EXISTING pins only and is structurally
incapable of admitting a new build script. The job carries NO job-level
`if:`: the gate used to be a STEP inside `Lint (fmt + clippy)`, which
reports `skipped` on a docs-only diff — counted as SATISFIED — so a
supply-chain gate was switchable off by a classifier verdict about
markdown.

**9. Doc symbol/path anchor gate** (#2629, CERT GATE 2) —
`scripts/check-doc-symbol-anchors.sh`. Gate 4 pins VALUES; **nothing
pinned SYMBOLS**. Documents cite `file:line` anchors, `path.rs::symbol`
qualifications and ``[`sym`](../src/path.rs)`` links that rot silently
on every rename and module split. The 3x7 audit sampled SIX anchors and
found **6/6 MISS at HEAD**, including `decorate_memory` — a symbol that
has not existed since the recall decorator was batched into
`decorate_memory_many` (`src/mcp/tools/recall.rs:610`). The register's
ruling: *"Anchors that miss 6/6 are worse than no anchors — they cost
the reviewer trust they cannot get back."* The class is worse than
value drift because a wrong VALUE is falsifiable in one grep, while a
wrong ANCHOR sends the reader to the wrong place and then makes them
doubt everything else. FOUR rules, all keyed on PATH-QUALIFIED grammar:
**PATH** (a cited `src/<p>.rs` must exist — this is what caught the
pre-modularisation `src/handlers.rs` / `src/mcp.rs` / `src/db.rs`
anchors still live in the operator guides), **LINE** (a `src/<p>.rs:<N>`
anchor must name a line the file has), **QUAL** (every identifier in
`src/<p>.rs::<sym>` and `src/<p>.rs::{a, B::c, d}` must be defined IN
THAT FILE — each `::` component is checked, so
`VectorIndex::build_with_capacity` resolves only if both do), and
**MDLINK** (a ``[`sym`](../src/<p>.rs)`` link must resolve, or `sym`
must BE the module's file stem, which is a legitimate module citation).

**What is deliberately NOT a rule:** a bare backticked identifier
sharing a line with a `src/` path. Measured against the tree that
grammar yields **1,827 hits over 879 distinct tokens** — MCP tool
names, DB columns, wire strings, env vars — almost none of them Rust
definitions. A rule with that false-positive rate gets switched off
within a week, and a gate nobody can leave on is worse than no gate.
Two further carve-outs are load-bearing: a line that DELIBERATELY names
a path as absent (CLAUDE.md's own worktree pre-flight asserts
`test ! -f src/handlers.rs`) is exempt, evaluated over a THREE-LINE
window because this repo hard-wraps prose and the disclaimer routinely
lands on the line above the path it disclaims; and frozen doc trees
(`docs/v0.*/`, `docs/internal/`, `docs/audit/`, `docs/rfc/`, `docs/adr*`,
`docs/BASELINE-*.md`, the `perfect-endpoint-assessment` wave artefacts)
are out of scope for the CHANGELOG reason — they describe a tree AS IT
WAS. **NO NEW SSOT** (operator direction): where the migration-ladder
tip is needed the gate EXTRACTS and reuses `read_current_schema_version`
from `scripts/check-migration-ladder.sh` rather than deriving the tip a
third time, and fails loudly if that function is renamed. That rule
immediately caught `docs/postgres-age-guide.md` naming a ten-versions-
stale `migrate_vNN()` as the end of the postgres ladder — the #2629
issue title's own example. Burn-down allowlist
`scripts/qc-allowlists/doc-symbol-anchors-allow.txt`, where a **STALE
entry FAILS**. `--self-test` plants the audit's own `decorate_memory`
rename, a pre-modularisation path, a past-EOF line anchor, a stale
`migrate_vNN` tip claim and a dead markdown symbol link, with
near-miss controls (the correct symbol, a `Type::method` brace list, an
in-range anchor, a module link, the absent-path assertion) that must
each PASS.

**10. SDK-path vs `routes.rs` membership gate** (#2629, CERT GATE 2;
register 3.3.2) — `scripts/check-sdk-route-paths.sh`. **Nothing pinned
the SDK READMEs or SDK client sources against
`src/handlers/routes.rs`**, so two defect classes shipped: **C-19** —
`grant()` / `revoke()` / `cluster()` in BOTH SDKs calling
`/api/v1/memories/{id}/grant`, `…/revoke` and `/api/v1/cluster`, three
paths with ZERO hits in `routes.rs`, i.e. three shipped, typed,
documented methods that **404 at runtime** (the TS source even carries a
comment saying "Some may not be merged server-side yet" — the knowledge
was in the tree and no control acted on it); and **C-20** — TS
`unsubscribe(id)` targeting `DELETE /api/v1/subscriptions/:id` when
`src/lib.rs` registers delete on the COLLECTION path only and the id
rides the query string (`src/handlers/subscriptions.rs`). The register
calls the check "mechanically trivial", and it is; the value is
catching both AT AUTHORING TIME rather than at a customer's first call.
The gate builds the registered set from the `routes.rs` const SSOT,
extracts every `/api/v1/…` literal from `sdk/*/README.md` + the client
sources, and **NORMALISES path PARAMETERS on both sides** — `{id}`,
`:id`, `${encodeURIComponent(id)}`, `{memory_id}`, `<id>` all collapse
to `{}`. That step is what makes it catch C-20: a raw-string membership
test PASSES it (the collection path IS registered) and a
parameter-blind test passes it too; only normalisation makes
`/api/v1/subscriptions/{}` a non-member while
`/api/v1/memories/{}` stays a member.

**A path is a CLAIM only where it is a CALL.** This is the property
that decides whether the gate is usable at all: a rule that greps RAW
FILE TEXT fails on the CORRECTED tree, not the broken one. The
C-19/C-20 fix deletes the three dead methods and repoints
`unsubscribe`, but its BREAKING-CHANGE notes NAME the dead paths in
order to explain them — ``// `cluster()` was REMOVED at v1.0.0. It
posted to `/api/v1/cluster` …`` in the clients, a docstring narrating
the old `unsubscribe` shape, a migration paragraph in each README.
Failing those would force the removal notes to be deleted, and the
migration note is precisely the thing that stops an integrator
re-adding the method. So extraction is scoped by construction, not by
allowlist: `.ts`/`.js` with comments stripped (`//`, `/* */`, JSDoc
`*` continuations), `.py` with `#` comments AND triple-quoted
docstrings stripped, and READMEs restricted to TABLE ROWS and FENCED
CODE (a method-signature cell documents a live call; a prose paragraph
explaining a removal does not). **The acceptance criterion is the
PAIR** — RED on the pre-fix tree, GREEN on the corrected one — and the
self-test's clean-control leg carries the verbatim removal-note shapes
so a regression to raw-text matching fails there immediately. The scan
set is `sdk/**` BY PATTERN, never an enumerated file list:
`sdk/python/ai_memory/async_client.py` carried all four defects and
appears nowhere in the 429-line claims register, so a gate scoped to
the files the register named would have missed it entirely. PENDING-FIX
ledger `scripts/qc-allowlists/sdk-route-paths-pending.txt`. `--self-test`
plants C-19 in the TS client, the python client and BOTH READMEs and
C-20 in the TS client and its README, with near-miss controls that must
PASS: a correctly-templated member path in each SDK dialect, a
collection call with a QUERY STRING (the shape C-20's fix must adopt),
and the bare `/api/v1/` base-URL prefix. An empty sdk scan set fails
CLOSED so the gate cannot no-op to green.

**11. Named-CI-job existence + enforcement-truthfulness gate** (#2629,
CERT GATE 2; register 3.3.3) — `scripts/check-ci-job-claims.sh`. Four
published claims, all the same shape — *"a control was removed and the
prose was not"*: **C-24**, `ci.yml`'s "Code Coverage" job cited as the
live coverage gate in BOTH README and ROADMAP after being REMOVED in
#1993 (README even documents the removal two clauses after asserting
the job enforces a ratchet); **C-23**, `docs/v1.0.0/release-notes.md`
saying the postgres/AGE stack is "gated **nightly** by the
`postgres-age` CI job" when that job was deleted in `da3fb9cc` and
`postgres-parity-nightly.yml` says in its own header the coverage is
"gone rather than repaired"; **C-21**, PERFORMANCE.md citing an AGE
bench gate in `.github/workflows/bench.yml`, which has zero `age` hits;
**C-31**, PERFORMANCE.md saying `bench.yml` "gates every PR and trunk
push" when `bench.yml:18` says of ITSELF "Bench is advisory (not in
required-status-checks)" and `grep -ic bench
scripts/qc-allowlists/required-contexts-release.txt` is 0.

TWO rules, in strength order. **EXISTENCE** (unambiguous): every
workflow file and named CI job cited in `README.md`, `ROADMAP.md`,
`PERFORMANCE.md` or `docs/v1.0.0/*.md` must resolve to a file under
`.github/workflows/` or to a parsed job `name:` / job key / matrix
expansion within one; the parse follows the SAME YAML scalar rule gate 7
established (a `#` preceded by whitespace opens a comment, `(#1174
PR10)` does not), because a job whose DECLARED name differs from the
reported one is exactly how the #2473 truncated context entered the live
required set. Catches C-24 and C-23 outright. **ENFORCEMENT-TRUTHFULNESS**
is the rule that counters the register's stated systematic bias: a doc
that says a named job or workflow *gates* / *blocks merge* / *fails the
PR* / *is required* must resolve to a context actually declared in
`scripts/qc-allowlists/required-contexts-release.txt`. Existence alone
GREENS C-31 — `bench.yml` exists and its job exists, and the claim that
it gates anything is still false. Two calibrations keep it aimed at the
defect rather than its neighbourhood: the enforcement verb must sit
within **90 characters** of the citation (a ROADMAP "Code anchors" line
names five workflows and one gate, and only one of the five is the
gate's subject), and `operator-gated` is excluded because that is a
claim about HUMAN release authority, not a required status check —
demanding that a `workflow_dispatch`-only `release.yml` be a required PR
context would be incoherent, so `workflow_dispatch`-ONLY workflows are
exempt from ENFORCEMENT (never from EXISTENCE; a `schedule:`-only
nightly is NOT exempt, since claiming a nightly gates a PR is exactly
the false-enforcement shape). Shipped as a ratchet with the PENDING-FIX
ledger `scripts/qc-allowlists/ci-job-claims-pending.txt` because five
document-correction lanes are in flight concurrently. `--self-test`
plants all four claims; the C-31 leg asserts the rejection comes from
the ENFORCEMENT rule specifically, and its paired near-miss — the same
workflow described WITHOUT an enforcement verb — must PASS so the rule
does not ban mentioning an advisory workflow at all.

**#2977 — the html corpus.** The DOCS corpus's html half was a THREE-FILE
allowlist AND every citation regex required a MARKDOWN code span, so a
bench / CI-enforcement claim on any of the other ~70 published Jekyll
pages was invisible for TWO independent reasons — campaign finding C6
(`at-a-glance.html`'s bench claim) is exactly that shape. The html half is
now enroll-by-default over `docs/**/*.html` minus
`scripts/qc-allowlists/html-doc-frozen-exempt.txt` (the SAME exemption
SSOT gate 4 reads), and the citation shapes admit `<code>` alongside the
backtick. Fixing only the corpus, or only the regexes, would have been a
widening that scans 53 more pages and reports success while doing nothing
— the #2444 shape, in the gate built to catch it. Two live claims fell
out on first run: an advisory workflow called a "CI guard" and a
`Bench · bench` composite that resolves to no declared job.

**`cargo test` twin for gates 4 / 9 / 10 / 11:**
`tests/doc_claims_integrity.rs` (the
`tests/migration_ladder_integrity.rs` precedent). All four shell gates
live in ONE workflow, so a deleted job, a renamed script or a `paths:`
filter would make every one of them silently stop running while the
branch stayed green. The twin re-asserts the two invariants with a
concrete RUNTIME consequence (SDK path membership; named-CI-job
existence) plus two STRUCTURAL properties — every ledger parses, and
every gate is wired into `c8-precheck.yml` **with its `--self-test`
step**, with no `needs: classify`, no `paths:` filter and no job-level
`if:`. It deliberately does NOT duplicate the full pattern sets: two
definitions that can disagree teach reviewers to ignore both. Run it as
`( umask 022; cargo test --test doc_claims_integrity )` — the bare
`cargo test` umask trap is #2628.
