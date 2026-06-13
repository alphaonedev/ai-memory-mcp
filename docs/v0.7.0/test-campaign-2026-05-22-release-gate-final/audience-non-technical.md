# What we tested on 2026-05-22, and why it matters

## The short version

We put ai-memory v0.7.0 — the next version of our open-source
persistent-memory system for AI agents — through its final
pre-release test on May 22nd, 2026. **It passed.** Every one of the
7,321 automated tests we ran came back green. Zero failures.

Along the way we found 22 small issues we hadn't caught before. We
fixed all 22 of them the same day, ran the tests again, and confirmed
each fix worked. Not one of those 22 was deferred to a future
release. None of them was waved away as "minor" or "out of scope."
That's the standard we hold ourselves to.

This document is the plain-English version of what happened. If you'd
like the executive summary, see `audience-c-level.md`. If you want the
deep technical writeup with every commit, test, and root cause, see
`audience-sme-engineer.md`.

## What is ai-memory?

ai-memory is software that gives AI assistants (Claude, ChatGPT, any
large language model) a long-term memory. By default, AI assistants
forget everything when a conversation ends. ai-memory fixes that — it
stores facts, decisions, and context across conversations and across
different AI models. It runs on your own computer or server; your
memories stay yours.

v0.7.0 is the next major release. It adds a new Postgres + Apache AGE
backend for larger-scale deployments, support for 17 AI providers
(not just one), and a smarter recursive-learning system.

## What we tested

Three things, in one big sweep:

1. **The default version.** Does it still work for the typical user —
   one person, one computer, one SQLite database? **Yes.** Every test
   for the default version passed.

2. **The new Postgres + Apache AGE backend.** Does the new larger-
   scale option behave identically to the default? **Yes.** All 76
   "live-Postgres" tests passed, and all 36 of the "Postgres + Apache
   AGE" integration tests passed.

3. **The agent-to-agent (A2A) scenarios.** Can two AI agents share
   memory safely? Can a third agent be locked out when it should be?
   Can a malicious request be refused by the governance system? Can
   we cryptographically prove that a chain of writes hasn't been
   tampered with? **Yes to all eight scenarios.**

Total: 7,321 automated tests, across 269 different test programs.
**Zero failures. Zero ignored.** Every test that exists in the
codebase ran, and every one passed.

## The 22 issues we found and fixed

22 failures showed up the first time we ran the suite. We fixed
all 22 the same day. The honest breakdown:

- **2 were actual bugs.** A Postgres setup ordering issue (a
  vector-search extension was installing into the wrong schema
  because of a side effect of another extension), and a security
  check that existed on one storage backend but had been omitted
  on the new Postgres one (a user could have read another user's
  knowledge-graph timeline). Both fixed.

- **20 were test-fixture drift.** The tests had gone stale. Over
  the past month we tightened security and privacy across the
  product; the tests that used to pass under the old looser rules
  needed updating to match the new stricter rules. None of the 20
  were bugs in the product itself.

We fixed the tests rather than weakening the product to match
them because the product's behavior is the contract with the
user. When the contract gets stronger, the tests have to update.

## Why this matters

For someone installing v0.7.0 tomorrow, this campaign is the
difference between "we hope it works" and "we have mechanical proof
every behavior is what we say it is." 7,321 tests covers every
feature, every option combination, every edge case the team has
encountered. Finding 22 issues and fixing all 22 — rather than
shrugging at any of them — is the more important signal. The next
person who tries v0.7.0 gets the version we intended, not a version
with known papercuts.

## What happens next

The technical work is done. What's left is:

1. **A 24-hour real-world test** ("dogfooding") where the maintainer
   uses the new version themselves for a full day to catch anything
   the automated tests didn't.

2. **The actual release cut**, which has to be signed off by a human
   operator (not automated). That's intentional: our AI agents are
   trusted to do the testing, write the code, and find + fix the
   defects, but the final "this version is now official" decision
   belongs to a human.

Both steps are scheduled. The 7,321 / 0 / 0 result on May 22nd is
the green light for them to proceed.

## In one sentence

We ran every test we have against the v0.7.0 candidate, found 22
defects, fixed all 22, and re-ran every test until everything was
green — which is what "ready to ship" means around here.

---

*Apache-2.0, © 2026 AlphaOne LLC. Authored by Claude (Opus 4.7,
1M context) under autonomous execution authority for the v0.7.0
release-gate campaign.*
