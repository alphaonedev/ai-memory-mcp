---
layout: doc
title: Learn ai-memory — for end users
---
# Learn ai-memory · Track 1 — for end users

*For people using one AI assistant, or a small set of agents, on their own
machine. No programming knowledge assumed. If a step uses a terminal, the
exact command is given.*

## 1. What problem it solves

Every AI assistant forgets. You explain your project, your preferences, the
name of your dog, the bug you fixed last Tuesday — and the next conversation
starts blank. ai-memory gives your assistant a **memory that survives
conversations, restarts and even switching assistants**: what you tell Claude
today, your ChatGPT or Grok session can recall tomorrow, because they all read
and write the *same* memory store on your machine.

## 2. What it is, in plain words

- A small program that runs on your computer (or phone / home server).
- Your AI talks to it through a standard called **MCP** ("Model Context
  Protocol") — the same way it would use any other tool.
- It keeps memories in a single database file on your disk. **It never sends
  your memories anywhere** unless you deliberately turn on a feature that
  does (for example, connecting two of your own machines).
- It decides what is worth keeping, ranks memories by relevance when the AI
  asks, and promotes important ones to permanent storage.

Things it is **not**: it is not a chat app, not a cloud service, not a
subscription, and not a place where anyone else can see your data.

## 3. Install (five minutes)

Follow [the install quickstart](../install-quickstart.md) — "Path A" is you.
The short version on macOS/Linux is one command in a terminal, then wiring
your assistant to it with the snippet the guide gives you. If you use a
phone or tablet, see the mobile section on the [home page](../index.html#mobile).

**Check it worked:** ask your assistant *"remember that my favourite editor is
Zed"*, start a brand-new conversation, and ask *"what's my favourite editor?"*.

## 4. How your assistant uses it (the five tools)

Your assistant sees a handful of tools. You never call them yourself, but it
helps to know what they do:

| Tool | What it means for you |
|---|---|
| `memory_store` | "Remember this." The assistant saves a fact, decision or preference. |
| `memory_recall` | "What do I know about …?" The assistant asks for the most relevant memories before answering you. |
| `memory_list` / `memory_search` | Browse or keyword-search what is stored. |
| `memory_update` / `memory_delete` | Correct or remove something. |

There are many more tools for advanced setups, hidden by default so your
assistant is not overwhelmed. See the [feature matrix](../feature-matrix.html)
when you are curious.

## 5. The ideas worth knowing

- **Namespaces** are folders for memories — `work`, `home`, `novel-draft`. Ask
  your assistant to store things "in the work namespace" and recall from it.
- **Tiers** are how long a memory lives: *short* (a task in progress), *mid*
  (this week's context), *long* (permanent). Important memories are promoted
  automatically; you can also say "make that permanent".
- **Confidence** is how sure the memory is. Corrections you make raise it;
  old, unused facts fade. See [memory tiers](../memory-tiers.html) and
  [TTL controls](../ttl-controls.html).
- **Kinds** — an *observation* ("the build is slow"), a *decision* ("we chose
  Postgres"), an *instruction* ("always answer in French"). Kinds let the
  assistant treat a standing instruction differently from a passing note.
- **Contradictions** — if you say "the meeting is Tuesday" and later
  "the meeting is Thursday", ai-memory can flag the conflict rather than
  silently keeping both. See [memory rules](../memory-rules.html).

## 6. Privacy and safety, honestly

- Everything is stored locally, by default in one file. No account, no
  telemetry, no "phone home".
- If you enable a hosted AI provider *for embeddings or summaries*, text is
  sent to **that** provider, under its terms — ai-memory tells you which
  provider is active and can be pinned to local-only.
- You can encrypt the memory file at rest (see [encryption](../encryption.html)).
- Every write is attributed to the assistant that made it, and can be signed,
  so you can always tell *which* AI said *what* and when.

## 7. Everyday care

- **Back up**: copy the database file (the quickstart shows where it lives) or
  use the built-in export. See [archival](../archival.html).
- **Tidy**: "forget everything about project X", "what have you stored this
  week?", "consolidate my notes about the trip" — the assistant can run these
  through the delete / list / consolidate tools.
- **Move machines**: copy the file; the new machine's assistants pick up
  where the old ones left off.

## 8. If something goes wrong

1. Run `ai-memory doctor` in a terminal — it checks the install, the database
   and the AI wiring and prints what to fix.
2. Restart your assistant app; MCP tools are picked up at start.
3. The [install quickstart](../install-quickstart.md) has a troubleshooting
   section for the common cases (tool not showing up, permission errors,
   wrong database path).
4. Ask on the [project issue tracker](https://github.com/alphaonedev/ai-memory-mcp/issues)
   — reports from users are welcome and are reviewed.

## 9. When to graduate to the next track

If you start running several agents that need to share memory across
machines, want to give different people different access, or need audit
trails — read [Track 2](decision-makers.md) for the *why* and
[Track 3](engineers.md) for the *how*.
