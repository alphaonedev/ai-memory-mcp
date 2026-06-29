# ai-memory v0.8.1 — `hardened-patch`

> The v0.8.0 coordination substrate, **review-hardened**. A defect-closure patch that takes "shipped" to "shipped, adversarially reviewed, and proven on a second backend": every v0.8.0 development gap closed, a full multi-lane security review with **every confirmed finding fixed**, and the PostgreSQL + Apache AGE + pgvector path verified live. Self-hosted. MCP-native. Drop-in for v0.8.0.

---

## Why v0.8.1 matters (read this first)

v0.8.0 made the substrate multi-agent. **v0.8.1 makes it _trustworthy to run_** — by closing the gaps a careful operator (or auditor) would find first.

This patch is the result of pointing the substrate's own adversarial-review discipline at itself and fixing everything that came back:

1. **Secrets don't leak in, forgotten data doesn't leak out.** A credential pasted into a memory is screened on the write path (refuse/redact, configurable); a `forget` now performs a real erasure fan-out — DLQ cleartext, the transcript-dedup oracle, the vector index, and a **signed tombstone** so a federation peer can't resurrect it — while an *operator's* authorized un-forget still round-trips.
2. **The substrate tells the truth about durability.** A durable-but-under-replicated write returns `202 Accepted` + the replication state, not a misleading `503`.
3. **A real security review, all findings fixed.** A 7-lane × find→adversarial-verify→triage review surfaced **9** confirmed issues across federation auth, secret-handling, injection/DoS, governance/erasure, and CI supply-chain — **all 9 fixed, tested, and closed**, each contested call decided by a deterministic 5-agent vote.
4. **Proven on PostgreSQL + Apache AGE + pgvector.** The postgres+AGE backend was stood up live and put through 3 green rounds + an AI-NHI dogfood — store, pgvector semantic recall, AGE graph projection, forget/erasure, and the secret-screen, all on real infra.

Same identical API across embedded SQLite and PostgreSQL + Apache AGE, across desktop, server, and on-device.

---

## TL;DR by audience

### 👤 A. If you just want your AI to remember things (non-technical)
A maintenance release — nothing to relearn. Upgrade and your AI's memory gets safer by default: it won't quietly store a password you paste, and "forget this" now really means gone. Your data still stays on your machine.
```bash
brew upgrade ai-memory && ai-memory doctor
```
**Why care:** the boring-but-critical safety stuff is now handled for you, without changing how you use it.

### 🏢 B. If you decide whether to adopt it (C-level / decision-maker)
v0.8.1 is the **"we reviewed it and fixed what we found"** release — the evidence layer under a production decision.
- **Independently hardened.** A multi-lane adversarial security review found 9 issues; **100% are fixed and closed**, with the audit trail (issue → fix commit → regression test) public.
- **Right-to-be-forgotten, for real.** `forget` is a genuine erasure across every derived store, with a signed tombstone that blocks peer-driven resurrection — and an operator can still restore intentionally. That's a defensible data-deletion story.
- **Credential hygiene by default.** Pasted secrets are screened at the write boundary before they're ever stored, indexed, federated, or exported.
- **Two backends, proven.** Validated live on PostgreSQL + Apache AGE + pgvector as well as SQLite — no single-backend lock-in.

**Why care:** it turns "looks promising" into "reviewed, fixed, and proven on our database."

### 🛠️ C. If you build or operate it (software engineer / architect — SME)
v0.8.1 is a **defect-closure + security-hardening patch** ([#1821](https://github.com/alphaonedev/ai-memory-mcp/issues/1821)):
- **Gap closure (v0.8.0 dev gaps):** G29 write-path **secret screen** (`AI_MEMORY_SECRET_SCREEN_MODE` refuse/redact/off — content, title, tags, and metadata-values with a crypto-field carve-out so signatures/JWTs aren't mangled); G30 **erasure fan-out** + signed `forget_tombstones` (schema **v71**); G12 durability now `202 + replication body`.
- **Closed audits:** MCP governance now fail-closed on the egress sinks ([#1685](https://github.com/alphaonedev/ai-memory-mcp/issues/1685)); postgres L2 transcript rehydration parity ([#1693](https://github.com/alphaonedev/ai-memory-mcp/issues/1693)).
- **Security review — 9 fixed:** federated-signal authorship binding ([#1843](https://github.com/alphaonedev/ai-memory-mcp/issues/1843)), field-complete secret screen ([#1844](https://github.com/alphaonedev/ai-memory-mcp/issues/1844)), forensic-transcript redaction ([#1845](https://github.com/alphaonedev/ai-memory-mcp/issues/1845)), FTS OR-tree DoS cap ([#1846](https://github.com/alphaonedev/ai-memory-mcp/issues/1846)), CGNAT SSRF ([#1847](https://github.com/alphaonedev/ai-memory-mcp/issues/1847)), archive-restore tombstone gate ([#1848](https://github.com/alphaonedev/ai-memory-mcp/issues/1848)), namespace-less forget governance ([#1849](https://github.com/alphaonedev/ai-memory-mcp/issues/1849)), audit tail-truncation anchor ([#1850](https://github.com/alphaonedev/ai-memory-mcp/issues/1850)), CI workflow_dispatch injection ([#1851](https://github.com/alphaonedev/ai-memory-mcp/issues/1851)).
- **Surface (unchanged from v0.8.0 except schema):** schema **v71** · **100** MCP tools at `--profile full` / 7 core · **91** HTTP routes (77 unique paths) · **83/85** CLI subcommands · **9** typed link relations · 27-field `Memory`. SQLite **and** PostgreSQL+AGE, identical API.

**Why care:** the gaps you'd file on day one of an audit are already filed, fixed, tested, and closed.

---

## What's new in v0.8.1

### 🔑 Write-path secret screen (G29)
`AI_MEMORY_SECRET_SCREEN_MODE` (`refuse` default / `redact` / `off`) screens caller writes — content, title, tags, and metadata string-values — for credential material (PEM/`AKIA`/`ghp_`/`sk-`/`xai-`/`Bearer`/JWT), with a crypto-field carve-out (Ed25519 signatures, pubkeys, attestation JWTs) so legitimate signed writes pass unmangled. Federation/recovery paths redact (never refuse) to preserve convergence.

### 🧹 Erasure that actually erases (G30)
`forget` fans out across the non-cascaded derived stores (federation DLQ cleartext, transcript-dedup hash oracle, HNSW vector) and writes a **signed tombstone** that blocks peer-driven resurrection — while an operator's authorized restore still round-trips (the tombstone gates the *federation* restore path, not first-party un-forget).

### 🤝 Honest durability (G12)
A locally-durable write that misses quorum returns `202 Accepted` with `{quorum_met, acks, needed, durability}` — the replication state, not a misleading `503`.

### 🛡️ Security review — 9 findings, all fixed
A 7-lane adversarial review (authn/identity, federation, secrets, injection/DoS, governance/erasure, memory-safety, supply-chain) → 9 confirmed → all fixed, tested, closed (#1843–#1851). Contested calls (signal-auth shape, metadata-screen scope, forget governance, truncation anchor, restore/erasure reconciliation) each resolved by a deterministic 5-agent vote.

### 🐘 PostgreSQL + Apache AGE + pgvector — verified live
Stood up on real infra and run through **3 green rounds + an AI-NHI dogfood**: store, pgvector semantic recall, AGE graph projection (`memory_graph`), tsvector search, forget/erasure, and the secret-screen — all on PostgreSQL 16 + Apache AGE 1.6 + pgvector 0.6. The do-hive provisioning was fixed to install pgvector + build AGE ([#1842](https://github.com/alphaonedev/ai-memory-mcp/issues/1842)).

### Schema
v70 → **v71**. One additive migration — the signed `forget_tombstones` table (G30). Auto-migrates on first open; archive → restore round-trips losslessly.

---

## Distribution channels

| Channel | Install |
|---|---|
| **GitHub Release** | this page — binary tarballs for 5 targets + `.deb`/`.rpm` + iOS/Android artifacts + `SHA256SUMS` |
| **crates.io** (Rust) | `cargo install ai-memory --version 0.8.1` |
| **Homebrew tap** (macOS/Linux) | `brew install alphaonedev/tap/ai-memory` |
| **Fedora COPR** (RHEL/Fedora) | `sudo dnf copr enable alpha-one-ai/ai-memory && sudo dnf install ai-memory` |
| **ghcr.io** (Docker) | `docker pull ghcr.io/alphaonedev/ai-memory:0.8.1` |
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

- **Drop-in for v0.8.0.** `brew upgrade ai-memory` / `cargo install ai-memory --force`; the live DB auto-migrates v70 → v71 on first open (archive → restore is lossless).
- **New secure default.** `AI_MEMORY_SECRET_SCREEN_MODE` defaults to `refuse` — a caller write carrying credential material is rejected. Set `redact` to store a masked copy, or `off` to disable. See the v0.8.1 [CHANGELOG](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v0.8.1/CHANGELOG.md).
- **Durability status change.** A quorum-miss on a durable write now returns `202` (was `503`). Clients keying off the status code should treat `202` as accepted-and-locally-durable.
- **SDKs** (`@alphaone/ai-memory`, `ai-memory-mcp`) are published at `0.8.1`.

---

## Verification

- **Source provenance:** cut from `release/v0.8.1`; the `v0.8.1` tag is signed.
- **Binary integrity:** verify downloaded tarballs against the `SHA256SUMS` on this release page; Docker images carry build provenance; npm publishes with `--provenance`.
- **Substrate provenance:** the audit chain is a tamper-evident cross-row hash chain — now with an on-host watermark that detects tail-truncation (#1850); reflections, signed-events, and forensic bundles are independently verifiable.

## Quality gate

Full CI matrix green on the release commit — Linux/macOS/Windows test legs, the SQLite **and** PostgreSQL+AGE feature gates, `clippy -D pedantic` + `fmt`, per-module coverage, iOS/Android cross-compile, MSRV (Rust 1.96), and Docker build · `cargo audit` clean · the 3 script gates (no-hardcoded-literals, vendor-neutrality, codegraph) green. Validated by a 7-lane adversarial security review with **every one of 9 findings fixed and closed**, and a live PostgreSQL + Apache AGE + pgvector deployment passing 3 rounds + an AI-NHI dogfood.

---

*From "AIs that coordinate" to "AIs that coordinate — reviewed, hardened, and proven on a second backend." Self-hosted, provider-agnostic, yours.*
