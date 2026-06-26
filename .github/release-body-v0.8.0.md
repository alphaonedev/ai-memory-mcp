# ai-memory v0.8.0 — `distributed-coordination`

> Persistent, governed, attested memory for **any** AI — now with the primitives for **many** AIs to work together safely. Self-hosted. MCP-native. The release where a memory substrate becomes a **coordination substrate**: agents don't just remember, they take turns, hand off work, sign what they say to each other, and operate under guardrails an operator controls and can prove.

---

## Why v0.8.0 matters (read this first)

v0.6.x made ai-memory a fast, token-lean memory server. v0.7.0 made it a **substrate** that reflects on what it knows and proves who wrote it. **v0.8.0 makes that substrate _multi-agent_.**

The thing that changes the category: a single AI with memory is useful; a *fleet* of AIs sharing memory is dangerous — unless something coordinates them and governs what they're allowed to do. v0.8.0 adds exactly that, at the substrate layer, where it can be enforced and audited rather than hoped for:

1. **Agents coordinate, not collide.** A typed action DAG, single-holder leases, signed inter-agent signals, and cryptographically-attested checkpoints turn "several agents" into "one coordinated organism that doesn't have to trust its members" — because the trust is in the Ed25519 signatures, not in good behavior.
2. **The substrate can say _no_.** The governance gate now actually **blocks** a refused action (e.g. `rm -rf /`, writes to protected paths) under operator-signed rules an agent cannot forge — fail-closed, on the desktop and over MCP.
3. **It remembers across time _and_ across processes.** Cross-session continuity plus the coordination primitives mean a goal can outlive any single agent, process, or crash — and still be governed end to end.

All of it runs on one storage-abstraction layer with **two production backends** — embedded SQLite and PostgreSQL + Apache AGE — behind one identical API, across desktop, server, and on-device (iOS + Android).

---

## TL;DR by audience

### 👤 A. If you just want your AI to remember things (non-technical)
Nothing to relearn. Install once and your AI keeps a durable, private, *self-hosted* memory that survives restarts — and now it can safely work alongside other AI assistants without stepping on each other. Your data stays on your machine; nothing is sent to a cloud you don't control.
```bash
brew install alphaonedev/tap/ai-memory && ai-memory doctor
```
**Why care:** your assistant stops being a goldfish. It remembers context across sessions, can pick up where it left off after a crash, and you stay in control of what it's allowed to do.

### 🏢 B. If you decide whether to adopt it (C-level / decision-maker)
v0.8.0 is the release that makes **autonomous AI safe to actually run autonomously** — and provable to an auditor.
- **Governed & stoppable.** Every agent action can be gated by operator-signed rules; refusals are enforced and fail closed. You own the kill-switch, cryptographically.
- **Attested & auditable.** Every write and inter-agent message can be Ed25519-signed; the audit trail is a tamper-evident hash chain. That's the difference between "the AI says it did X" and "here is signed, replayable proof of what happened" — the foundation of a defensible compliance story.
- **No lock-in, no data exfiltration.** Self-hosted, single binary or container, on SQLite or your existing PostgreSQL. Provider-agnostic — local models or 15+ cloud LLM/embedding vendors, swappable by config. Your memory corpus is yours.
- **Real, not vapor.** Validated by an end-to-end multi-agent validation, an external-model adversarial security review (all findings fixed), and a live agent-to-agent campaign across heterogeneous models.

**Why care:** it converts "we're nervous about giving an AI agency" into "we can give it bounded agency we can audit and revoke." That's the gate between a pilot and production.

### 🛠️ C. If you build or operate it (software engineer / architect — SME)
v0.8.0 ships the **distributed-coordination substrate** ([#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709)):
- **Pillar-1 coordination:** a typed action DAG (`requires`/`unlocks`/`blocks`/`gated_by`/`sibling`) with a real state machine, TTL-bounded single-holder **leases** (CAS conflict semantics), Ed25519-**signed signals** (typed, threaded, ack'd), Ed25519-**attested checkpoints** (conditional gates with signed resolution), and replayable **routines**. Driven from MCP, HTTP, or CLI.
- **Pillar-2 typed cognition:** `Goal`/`Plan`/`Step` memory kinds, a `lifecycle_state` machine, and three new typed link relations (`decomposes_into`/`depends_on`/`advances`).
- **Federation hardening, secure by default:** peer-enrollment required ([#1789](https://github.com/alphaonedev/ai-memory-mcp/issues/1789)), per-transition signatures ([#1718](https://github.com/alphaonedev/ai-memory-mcp/issues/1718)), per-write content attestation ([#1464](https://github.com/alphaonedev/ai-memory-mcp/issues/1464)), transition-replay nonces ([#1805](https://github.com/alphaonedev/ai-memory-mcp/issues/1805)), and outbound peer-cert pinning ([#1678](https://github.com/alphaonedev/ai-memory-mcp/issues/1678)).
- **Operational controls:** HTTP admission control ([#1733](https://github.com/alphaonedev/ai-memory-mcp/issues/1733)), deferred AGE graph projection ([#1735](https://github.com/alphaonedev/ai-memory-mcp/issues/1735)), curator compaction, and mandatory-hook-presence enforcement ([#1734](https://github.com/alphaonedev/ai-memory-mcp/issues/1734)).
- **Surface:** schema **v70** · **100** MCP tools at `--profile full` (99 callable + bootstrap) / 7 core · **91** HTTP route registrations (77 unique paths) · **83/85** CLI subcommands · **9** typed link relations · 27-field `Memory`. SQLite **and** PostgreSQL+AGE, identical API.

**Why care:** the hard parts of a governed multi-agent system — coordination, attestation, fail-closed policy, federation auth — are in the substrate, tested and portable, instead of re-invented (badly) in every app.

---

## What's new in v0.8.0

### 🧩 Distributed coordination substrate (#1709)
Actions (DAG + state machine), leases (single-holder CAS), signals (Ed25519-signed, typed, threaded), checkpoints (attested conditional gates), and routines (frozen, replayable plans). The shared nervous system for a heterogeneous agent fleet. See [`docs/coordination.md`](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v0.8.0/docs/coordination.md).

### 🧠 Typed cognition (Pillar-2)
`Goal`/`Plan`/`Step` kinds, a `lifecycle_state` machine, and Goal→Plan→Step typed links — the substrate now models *structured* work, not just flat notes.

### 🛡️ Governance that actually blocks
The Claude Code **PreToolUse governance hook** now *enforces*: a substrate `Refuse` blocks the tool. (It's a `type:command` wrapper — an MCP-tool hook structurally cannot block.) Plus hooks-presence enforcement (#1734) and an `escalate` verdict for human-in-the-loop.

### 🔐 Federation hardened, secure by default
Peer enrollment on by default, per-transition signatures, per-write content attestation, replay-proof nonces, and outbound server-cert pinning. Heterogeneous fleets that don't have to trust each other.

### 🔌 Provider-agnostic LLM **and** embeddings
Local models or 15+ cloud vendors (xAI, OpenAI, Anthropic, Gemini, DeepSeek, Mistral, Groq, …) for chat **and** embeddings — swappable by config, no GPU required.

### 📱 Desktop, server, on-device
SQLite or PostgreSQL+AGE; macOS / Linux / Windows binaries; iOS `.xcframework` + Android `jniLibs` cross-compiled and runtime-tested in CI.

### Schema
v57 → **v70**. Additive coordination/typed-cognition/encryption-prep/archive-edge migrations (v58–v70). Auto-migrates on first open; archive → restore round-trips losslessly.

---

## Distribution channels

| Channel | Install |
|---|---|
| **GitHub Release** | this page — binary tarballs for 5 targets + `.deb`/`.rpm` + iOS/Android artifacts + `SHA256SUMS` |
| **crates.io** (Rust) | `cargo install ai-memory --version 0.8.0` |
| **Homebrew tap** (macOS/Linux) | `brew install alphaonedev/tap/ai-memory` |
| **Fedora COPR** (RHEL/Fedora) | `sudo dnf copr enable alpha-one-ai/ai-memory && sudo dnf install ai-memory` |
| **ghcr.io** (Docker) | `docker pull ghcr.io/alphaonedev/ai-memory:0.8.0` |
| **npm** (TypeScript SDK) | `npm install @alphaone/ai-memory` |
| **PyPI** (Python SDK) | `pip install ai-memory-mcp` |

**Platforms & artifacts**

| Platform | Artifact |
|---|---|
| **macOS** | `x86_64-apple-darwin` + `aarch64-apple-darwin` (Apple Silicon) tarballs; Homebrew |
| **Linux** | `x86_64-unknown-linux-gnu` + `aarch64-unknown-linux-gnu` tarballs; `.deb` + `.rpm`; COPR; Docker |
| **Windows** | `x86_64-pc-windows-msvc` tarball |
| **iOS** | `ai-memory-ios.xcframework.tar.gz` — device (`aarch64-apple-ios`) + Simulator (arm64 + x86_64) slices |
| **Android** | `ai-memory-android.tar.gz` — `jniLibs/` with 4 ABIs |

---

## Upgrade & compatibility

- **Drop-in for v0.7.x.** `brew upgrade ai-memory` / `cargo install ai-memory --force`; the live DB auto-migrates v57 → v70 on first open (archive → restore is lossless).
- **Governance-hook migration (one command).** The PreToolUse governance hook changed to the enforcing `type:command` form. If you installed it before, re-run:
  ```bash
  ai-memory install claude-code --hook pretool --apply --force
  ```
- **Secure-default flips (review before upgrading).** Federation peer-enrollment is now ON by default and several federation paths fail closed. See [`SECURITY.md`](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v0.8.0/SECURITY.md) §"v0.8.0 secure-default changes" and the v0.8.0 [CHANGELOG](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v0.8.0/CHANGELOG.md) "Breaking / secure-default changes".
- **SDKs** (`@alphaone/ai-memory`, `ai-memory-mcp`) are published at `0.8.0`.

---

## Verification

- **Source provenance:** cut from `release/v0.8.0`; the `v0.8.0` tag is signed.
- **Binary integrity:** verify downloaded tarballs against the `SHA256SUMS` on this release page; Docker images carry build provenance; npm publishes with `--provenance`.
- **Substrate provenance:** the audit chain is a tamper-evident cross-row hash chain; reflections, signed-events, and forensic bundles are independently verifiable (`ai-memory verify-reflection-chain` / `verify-signed-events-chain` / `export-forensic-bundle`).

## Quality gate

Full CI matrix green on the release commit — Linux/macOS/Windows test legs, the SQLite **and** PostgreSQL+AGE feature gates, `clippy -D pedantic` + `fmt`, per-module coverage, iOS/Android cross-compile, MSRV (Rust 1.96), and Docker build · `cargo audit` clean. Validated end-to-end by a P0–P11 multi-agent validation, a 5-agent (2-round) external-model security review with every finding fixed, and a live agent-to-agent campaign across heterogeneous models — zero defects.

---

*From "an AI that remembers" to "AIs that coordinate — governed, attested, and stoppable." Self-hosted, provider-agnostic, yours.*
