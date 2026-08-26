---
layout: doc
title: Learn ai-memory
---
# Learn ai-memory

ai-memory is a persistent, attested memory substrate for AI agents: a single
local-first binary that any MCP-speaking assistant (Claude, ChatGPT, Grok,
Gemini, Cursor, Codex, OpenClaw, …) can plug into, so what an AI learns is
kept, ranked, shared and audited instead of forgotten at the end of a chat.

This section teaches ai-memory **by audience**. Each track is self-contained,
starts from zero, and links out to the deeper reference pages only where you
need them. Pick the one that matches you — or read all three in order; they
build on each other.

| Track | You are … | What you will be able to do afterwards | Time |
|---|---|---|---|
| **[1 · End users](end-users.md)** | A person using one AI assistant (or a small handful of agents) on a laptop, phone or home server — no engineering background required | Install ai-memory in minutes, understand what it remembers and why, keep your data private, tidy or forget memories, back them up, and fix the common hiccups | ~25 min |
| **[2 · Decision makers](decision-makers.md)** | A C-level executive, director or budget owner deciding whether and how your organisation adopts AI memory | Explain what ai-memory is and is not, judge the value and the risks, understand the security and governance controls, know the certified operating scope, ask the right questions and set the right guardrails | ~30 min |
| **[3 · Engineers, architects & scientists](engineers.md)** | A software engineer, architect, SRE, security engineer, data scientist or researcher who will build on, deploy, harden or study ai-memory | Understand the architecture end-to-end (storage, recall, identity, governance, federation, coordination), operate it in production, extend it through the API/SDKs, and reason about its data-integrity guarantees | ~90 min |

> **How the tracks relate.** Track 1 is the *experience*, track 2 is the
> *decision*, track 3 is the *mechanism*. Every claim in tracks 1 and 2 has a
> mechanism in track 3, and every mechanism in track 3 has a test or a gate
> behind it in the repository.

## Other ways in

- [At a glance](../at-a-glance.html) — every facet on one page (the atlas).
- [For everyone](../for-everyone.html) — the value proposition by organisation size.
- [Audience pages](../audience/decision-maker.html): [decision maker](../audience/decision-maker.html) · [developer](../audience/developer.html) · [operator](../audience/operator.html).
- [Feature matrix](../feature-matrix.html) — every tool, endpoint and command.
- [Contributing & security controls](../contributing-external.md) · [Managed / non-superuser Postgres](../managed-postgres.md)
