# ai-memory v0.7.0 — `same NHI tomorrow`

> Persistent, governed, attested memory for **any** AI. Self-hosted. MCP-native. The release where a substrate-native memory system learns to **reflect on what it knows**, **survive a crash between turns**, and **prove who wrote what** — across SQLite *and* PostgreSQL+AGE, on the desktop *and* on-device.

---

## Why v0.7.0 matters (read this first)

v0.6.x made ai-memory a fast, token-lean memory server. **v0.7.0 makes it a substrate.** Three things change the category:

1. **It reasons over its own memory.** Recursive learning lets the system reflect on stored memories to produce higher-order insight, consolidate near-duplicates with provenance, and traverse a knowledge graph of entities and relations — with a hard, stoppable depth cap.
2. **It never loses context to a crash.** The #1389 **L1–L4 layered auto-capture** architecture guarantees that a `SIGKILL` between conversation turns no longer loses — or duplicates — what was learned.
3. **It can prove its provenance.** Every write can be attested; the audit chain is a tamper-evident, cross-row hash chain that **fails closed**; federation requires signatures + replay-proof nonces by secure default.

All of it runs on a single storage-abstraction layer (SAL) with **two production backends** — embedded SQLite and PostgreSQL + Apache AGE — behind one identical API.

---

## TL;DR by audience

### 👤 If you just want your AI to remember things
Nothing to relearn. `brew upgrade ai-memory` (or `cargo install ai-memory --force`) and your existing setup keeps working. Your AI can now *recover its own context* after a crash and *build on what it learned* instead of just looking it up.
```bash
brew upgrade ai-memory && ai-memory doctor
```

### 🛠️ If you build agents / NHI on top of ai-memory
- **74 MCP tools** at `--profile full` (7-tool `core` default + always-on `memory_capabilities` bootstrap); three-surface parity across MCP / HTTP / CLI.
- New primitives: `memory_reflect`, `memory_consolidate`, `memory_entity_register` / `memory_entity_get_by_alias`, `memory_kg_query` / `memory_find_paths` / `memory_kg_timeline` / `memory_kg_invalidate`, `memory_capture_turn` (idempotent L4), `memory_offload` / `memory_deref`, `memory_persona`, `memory_calibrate_confidence`.
- Provider-agnostic: point the LLM **and** the embedder at any of 15 vendor aliases (or self-hosted OpenAI-compatible / Ollama). Tier no longer dictates vendor.

### 🏢 If you operate it in production
- **PostgreSQL + Apache AGE** backend at full parity with SQLite via the SAL trait (`--store-url postgres://…`).
- Secure-by-default posture: governance fails **closed**, SSRF guard fails **closed**, keyless-bind refusal, signed federation with per-message nonces, agent-attestation enforcement.
- Config schema v2 (sectioned `[llm]` / `[embeddings]` / `[reranker]` / `[storage]` / `[limits]`) with `ai-memory config migrate`; `ai-memory doctor` reachability probes for LLM + embeddings.

---

## What's new

### 🧠 Substrate-native recursive learning
- `memory_reflect` produces reflections over source memories with a **stoppable depth cap** (`REFLECTION_DEPTH_EXCEEDED` at the namespace `max_reflection_depth`, default 3), `reflects_on` edges, and `reflection_origin` lineage.
- `memory_consolidate` merges near-duplicates, preserving `derived_from` + `consolidated_from_agents` provenance.

### 🕸️ Knowledge graph
- Recursive-CTE traversal (`find_paths`, `kg_query`, `kg_timeline`) with temporal validity (`valid_from` / `valid_until`) and `kg_invalidate`; Apache AGE Cypher on the PostgreSQL backend.
- First-class entities with alias resolution (`entity_register` → `entity_get_by_alias`), union-idempotent re-registration.

### 🛟 L1–L4 layered auto-capture (#1389) — never lose context to a crash
- **L1** store-first discipline + capture-lag watcher · **L2** `recover-previous-session` (transcript rehydration after `SIGKILL`) · **L3** filesystem watcher · **L4** `memory_capture_turn` — host-volunteered, **idempotent by `(host_session_id, host_turn_index)`**, backed by schema v52 `transcript_line_dedup`.

### 🔐 Attestation, governance & a fail-closed audit chain
- V-4 cross-row hash-chained `signed_events`; Ed25519-signed daemon `serverInfo` at the MCP `initialize` handshake.
- Operator-signed governance rules (R001–R004), namespace standards, K9 permission gate — **all fail closed** on error.
- L4 host-signature verification against an operator allowlist (`attest_level = "signed_by_peer"`); federation requires signatures + nonces by secure default.

### 🔌 Provider-agnostic LLM **and** embeddings
- One client over 15 vendor aliases + generic OpenAI-compatible + Ollama, for both chat and embeddings (#1067, #1598). Switch embedding models with `ai-memory reembed`.

### 📱 On-device build pipeline
- iOS `xcframework` (device + both simulators) and Android `jniLibs` (4 ABIs) artifacts; cross-compile + runtime CI (#1068).

### ⚡ Performance
- Async double-buffered HNSW rebuild (search p95 held under budget during rebuild), sargable list / federation-catchup queries, PostgreSQL stored-generated `tsvector` + GIN, `mmap` reads, and a tuned cross-encoder rerank sequence cap.

### Schema
- Current schema **v57** — automatic migrations on first open; archive→restore lossless for the full v0.7.0 `Memory` shape on both backends.

> Full detail in [`CHANGELOG.md`](https://github.com/alphaonedev/ai-memory-mcp/blob/main/CHANGELOG.md).

---

## Upgrade & compatibility
- **Default MCP surface** remains the lean `core` profile (since v0.6.4). Opt back to everything with `ai-memory mcp --profile full`, `AI_MEMORY_PROFILE=full`, or `[mcp] profile = "full"`.
- **Config**: the sectioned v2 schema is canonical. Legacy v0.6.x flat fields still parse (removed in v0.8) — run `ai-memory config migrate` to convert. Verify wiring with `ai-memory doctor`.
- Migrations apply automatically; existing databases upgrade in place to schema v57.

---

## Distribution channels

| Channel | Install |
|---|---|
| **GitHub Release** | this page — binary tarballs for 5 targets + `.deb`/`.rpm` + iOS/Android artifacts |
| **crates.io** | `cargo install ai-memory --version 0.7.0` |
| **Homebrew tap** | `brew install alphaonedev/tap/ai-memory` |
| **ghcr.io** | `docker pull ghcr.io/alphaonedev/ai-memory:0.7.0` |
| **Fedora COPR** | `sudo dnf copr enable alpha-one-ai/ai-memory && sudo dnf install ai-memory` |

Targets: `x86_64`/`aarch64` Linux, `x86_64`/`aarch64` macOS, `x86_64` Windows.

## Verification
- **Source provenance:** this release is cut from commit [`a2b448f1`](https://github.com/alphaonedev/ai-memory-mcp/commit/a2b448f19a514f8a4b73d30fd49338ae3afe23f8) on `release/v0.7.0`; the `v0.7.0` tag is Ed25519-signed.
- **Binary integrity:** verify downloaded tarballs against the `SHA256SUMS` published on this release page.

## Quality gate
8/8 CI workflows green · per-module coverage 170/170 (global 93.52%) · 3-region PostgreSQL+AGE fleet dogfood green · singleton NHI dogfood clean across all nine substrate surfaces (store · recall/search · reflect · consolidate · entity · KG · governance · capture/offload · capabilities).

---

*Persistent memory so your AI can be the same NHI tomorrow as it is today. Self-hosted, governed, attested.*
