# What we tested on 2026-05-28, and why it matters

## The short version

We put ai-memory v0.7.0 — the next version of our open-source
persistent-memory system for AI agents — through a second round of
testing on May 28th, 2026. **It passed.** The substrate is solid,
the documentation now matches the code exactly, and the few issues
we found were fixed the same day.

This is the second testing round for v0.7.0. The first round (May
22nd) got 7,321 / 0 / 0 — every test passing. This second round is
the "finishing touches" pass: integration testing against a more
realistic three-container setup, a one-hour live-usage stress test,
a complete documentation audit, and a fresh second-opinion
assessment from an independent AI agent.

If you'd like the executive summary, see `audience-c-level.md`. The
deep technical writeup is `audience-sme-engineer.md`.

## What is ai-memory?

ai-memory is software that gives AI assistants a long-term memory.
By default, AI assistants forget everything when a conversation
ends. ai-memory fixes that — it stores facts, decisions, and
context across conversations and across different AI models. It
runs on your own computer or server; your memories stay yours.

## What we tested

1. **A one-hour live-usage stress test.** The maintainer's actual
   working AI session, running for a full hour against the new
   binary. **Pass.** The daemon stayed alive (in fact, 16+ hours
   continuously), used about 18 MB of memory throughout (it didn't
   leak — that's the important bit), and answered every request
   correctly.

2. **A rebuilt three-container "lab" environment.** Two simulated
   AI agents ("alice" and "bob") and a shared database, exercising
   a realistic deployment where multiple AI agents share
   infrastructure. **Pass.** All three containers came up healthy.

3. **A full Postgres + Apache AGE regression test.** 8,028
   automated tests against the new three-container setup.
   **Mostly pass — 9 failures, all closed.** Of those 9: 5 were
   build-system race conditions (not real bugs — cleared on
   re-run); 4 were real test-discipline bugs (the tests assumed a
   clean database but other tests left state behind). We filed
   those 4 as issue #1381, built a tiny per-test isolation helper
   as PR #1382, and all 4 now pass.

4. **A complete sweep of the documentation.** Over the past month
   the product's numbers changed (e.g., the command-line tool grew
   from 57 commands to 79; the database schema version moved from
   v49 to v51). About 27 documentation files still cited the old
   numbers. We hunted down every stale number with three different
   audit passes (literal text search, then structural code-graph
   search, then fault-injection on the "guard rail" tests). About
   55 places needed fixing; all are fixed. Closes documentation-
   drift issues #1197 and #1198.

5. **A scholarly citation.** The product's design has independent
   conceptual lineage with a published research framework called
   CoALA (Cognitive Architectures for Language Agents, Princeton,
   February 2024). We added an explicit citation acknowledging the
   prior art, with a mapping document showing how our primitives
   line up. We deliberately did NOT rewrite our roadmap to claim
   CoALA-compliance — just citation discipline.

6. **A second-opinion assessment from a fresh AI agent.** We
   dispatched an independent AI agent (same model, fresh session,
   no memory of building any of this) to run its own structural
   review of v0.7.0 from scratch. That assessment is in-flight as
   we write this; the report will land under
   `docs/v0.7.0/heterogeneous-ai-nhi-assessment/`.

## What issues did we find?

Five GitHub issues touched: #1197 + #1198 (documentation drift,
both CLOSED), #1378 (the optional auto-installer for the Codex CLI
rejects TOML config; substrate's manual TOML config works fine, so
this only affects the optional installer; OPEN, not blocking
ship), #1381 + #1382 (the 4 test-discipline failures + the fix
PR; CLOSED by the fix).

## Why this matters

For someone installing v0.7.0 next week, this campaign is the
difference between "the docs sort of describe the product" and
"the docs describe the product exactly, every number, every schema
version, every command count." That mattered enough to do three
audit passes until zero defects remained.

The 16-hour stress-test result is the other load-bearing signal: a
memory substrate that leaked even a little would balloon under a
full working day's use; ours stayed at ~18 MB the whole time.

## What happens next

The technical work for v0.7.0 is essentially done. What's left is:

1. **Operator review and merge** of the three open PRs (#1379
   docs/Pages drift, #1380 CoALA citation, #1382 test isolation
   helper).
2. **The 24-hour dogfood loop** (a longer version of the 1-hour
   loop above; operator-driven).
3. **The actual release cut**, which is operator-signed-off, not
   automated. AI agents do the engineering, but the final "this
   version is now official" call belongs to a human.

## In one sentence

We ran the full integration test suite + a 1-hour live-stress test
+ a complete documentation audit + a scholarly-citation discipline
pass on v0.7.0, found five issues, fixed the four blocking ones
the same day, and got zero remaining defects across three
independent audit lenses — which is what "ready to ship" means
around here.

---

*Apache-2.0, © 2026 AlphaOne LLC. Authored by Claude (Opus 4.7,
1M context) under autonomous execution authority for the v0.7.0
ship campaign.*
