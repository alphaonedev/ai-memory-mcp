---
layout: doc
---

# ai-memory v1.0.1 (Patch 1) — Proposed Development Roadmap

> **Document classification:** Proposed patch-release roadmap. Candidate input for the ROADMAP.md v1.0.1 revision. **Not** a §2 property amendment, **not** a ship-gate, **not** a release authorization. Derived from the code-anchored findings in [`FABLE-5-TO-GROK-4-5-9-CLAIM-3x7-ADJUDICATION.md`](FABLE-5-TO-GROK-4-5-9-CLAIM-3x7-ADJUDICATION.html).
>
> **Date:** 2026-07-18
> **Author:** Fable 5 (Anthropic family) acting as AI NHI, synthesizing a 21-agent (3×7) + 4-supporting-lens CodeGraph-armed adversarial audit.
> **Substrate baseline:** `release/v1.0.0` @ `924965c1` — crate `0.10.0`, **schema v84**.
> **Cross-family basis:** every item below traces to a finding confirmed independently by the Fable 5 (Anthropic) panel and, where noted, agreed by the Grok 4.5 (xAI) package — the two-family [#1171] bar.
>
> **Scope discipline:** v1.0.1 is a **Patch-1 hardening + claims-discipline release**, not a feature release. It closes the **default-safety** and **honesty** gaps the v1.0.0 audit surfaced — the difference between "the machinery exists" and "the machinery is on / true for every running instance." It does **not** open new perfect-endpoint constitution work (that is the separate v1.x program tracked in [`PERFECT-ENDPOINT-MEMORY-V1.0.0-ASSESSMENT-FABLE.md`](PERFECT-ENDPOINT-MEMORY-V1.0.0-ASSESSMENT-FABLE.html) §4). Any item that changes a persisted/signed/wire shape is flagged **[T4]** and requires the 5-agent crossroads vote (`4d3ea1c5`) before implementation.

---

## 0. Why a Patch-1 at all

v1.0.0 is strong: the network surface moved to secure-by-default (four federation sig defaults flipped ON, admission control default-on, capabilities default-on), per-agent-key IDOR closure landed, embedding-space provenance closed the silent cross-space corruption class, and the L3 substrate watcher shipped. The independent two-family audit found **7/7 present in kind, zero missing, zero clean falsifiers**.

But the audit also found a consistent pattern: **the strongest new controls are default-off, advisory, or dormant-until-enrollment**, and **the loudest public surfaces (README badges, landing-page hero copy) still carry over-claims the project's own honesty discipline bans.** v1.0.1 exists to convert "one knob from max" into "safe by default or loud when not," and to make the public claim surface match the code.

**The v1.0.1 thesis in one line:** *defaults should stop being exploitable-or-silent, and public copy should stop out-running the code.*

---

## 1. Priority lanes

| Lane | Theme | Items | Blocking for v1.0.1? |
|------|-------|-------|----------------------|
| **P0 — Default-safety** | Fixes where the shipped default is exploitable or silently lossy | SEC-1, SEC-2, DI-2, CONT-1 | **Yes — all four** |
| **P1 — Hardening completeness** | Close no-disable / max-path gaps so a hardened deploy is genuinely hardened | SEC-3, SEC-4, FED-1, DI-1 | Yes (SEC-3, SEC-4); DI-1/FED-1 recommended |
| **P2 — Claims discipline** | Make public copy match code; add a claims CI gate so it stays matched | CLAIM-1, CLAIM-2 | **Yes** (CLAIM-1 loud items; CLAIM-2 gate) |
| **P3 — Honesty of scaffolds** | Label opt-in scaffolds as scaffolds; close the multi-vendor continuity gap | DECOR-1, CONT-2 | Recommended, not blocking |

---

## 2. P0 — Default-safety (all blocking)

### SEC-1 — Multi-tenant identity binding must be default-safe or fail-loud *(top priority)*
**Finding (Fable §3.2, cross-family with Grok B4).** The shipped default (shared api-key + `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=advisory` + zero enrolled per-agent keys) is **fully cross-tenant IDOR-open** for read, mutate, and admin-spoof: `enforce_for_request` short-circuits to `None` on an empty enrolled map (`src/handlers/identity_binding.rs:153`), so the entire v83/#2044 apparatus is inert. **Worse:** setting `enforce` *alone* without enrolling keys is **silently still exploitable** — no default or startup check compels enrollment or warns that enforce-without-keys is inert.
**Proposed fix.**
1. **Boot guard:** when `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=enforce` is set AND the enrolled per-agent-key map is empty, **refuse to start** (or emit a hard `ERROR` + refuse the multi-tenant surface), naming `ai-memory agents bind-api-key` as the remedy. Mirror the `#1720 B3` owner-lockout-guard shape.
2. **Doctor surface:** `ai-memory doctor` reports the multi-tenant posture explicitly ("HTTP identity: advisory, 0 per-agent keys enrolled → `X-Agent-Id` is NOT a tenant boundary").
3. **Hot-reload (stretch):** allow `agents bind-api-key` to take effect without a `serve` restart (today the map is boot-loaded once, `src/daemon_runtime.rs:5478`).
**Est.** 4 sessions. **[T3 security-posture vote required]** for the boot-refusal disposition.
**Acceptance:** a shared-key-only deployment either enrolls keys or is loudly told it has no tenant boundary; enforce-without-keys never boots silently.

### SEC-2 — Wire the IDOR gate onto the coordination write routes
**Finding (Fable §3.4).** `POST /api/v1/actions/{id}/transition` and `POST /api/v1/signals` do **not** consume `enforce_idor_identity` (`src/handlers/coordination.rs`) — they trust a self-asserted `X-Agent-Id`. Under enrolled per-agent keys + enforce, a shared-key caller can still claim/complete another agent's actions and author signals as a named principal — the exact "handoff with proof" artifacts claim 5 markets.
**Proposed fix.** Route `transition_action` and `send_signal` through the same `enforce_idor_identity` / `enforce_sensitive_identity` gate as `/memories/{id}`, so a `Claimed` caller cannot act as a named coordination principal under enforce.
**Est.** 3 sessions.
**Acceptance:** coordination handoffs under enforce are refused for a merely-`Claimed` caller acting as another named agent; existing enrolled-key + self-relay path unaffected.

### DI-2 — Advertise the `NORMAL` power-loss posture at boot
**Finding (Fable §3.4, answers Grok's R7 question).** `DB_SYNCHRONOUS` default `NORMAL` can silently lose the acked-write tail on a real power cut. Honestly documented in `PERFORMANCE.md`, but **no boot WARN advertises it**, and the public `docs/architectures-t1.html:485` "never lose committed writes" line (kill-list K4) contradicts it.
**Proposed fix.** One-shot boot `INFO`/`WARN` (`sqlite`, standard posture only): "`PRAGMA synchronous=NORMAL` — a power cut can lose acked commits since the last checkpoint; set `AI_MEMORY_DB_SYNCHRONOUS=FULL` for per-commit durability." Silent under `asi-hard` (already pins `FULL`).
**Est.** 1 session.
**Acceptance:** an operator running the default is told the durability trade-off once at boot; K4 doc line fixed in CLAIM-1.

### CONT-1 — Make L3 continuity discoverable (installer + doctor)
**Finding (Fable §3.1).** The #1978 L3 watcher landed but is opt-in with **no installer/service wiring**; a default install loses mid-session turns until the next SessionStart, and nothing tells the operator to start `ai-memory watch --daemon`.
**Proposed fix.** (a) `ai-memory install` writes an *optional, commented* systemd-user / launchd unit for `watch --daemon` and prints the enable command; (b) `ai-memory doctor` reports "L3 continuous capture: not running — start `ai-memory watch --daemon` for unattended mid-session continuity." No default-on daemon (respects the sole-authority / opt-in posture).
**Est.** 3 sessions.
**Acceptance:** the operator is told, at install and at doctor, exactly how to get unattended continuity; nothing is silently enabled.

---

## 3. P1 — Hardening completeness

### SEC-3 — Complete the `asi-hard` no-disable contract *(blocking)*
**Finding (Fable §3.4, vs Grok B3 `7/7_YES`).** The `asi-hard` pin set (`src/security_profile.rs::KNOBS`) is 14 knobs; a nominally-asi-hard node can be silently weakened because the posture does not refuse loosening of: `AI_MEMORY_FED_REQUIRE_SIG` / `FED_REQUIRE_NONCE` / `FED_ALLOW_UNENROLLED_PEERS` (outer federation envelope), `AI_MEMORY_ADMIN_HEADER_TRUST=1`, `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1`, `AI_MEMORY_PERMISSIONS_MODE=off`, `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY` (left at advisory), `AI_MEMORY_REQUIRE_TLS`, `AI_MEMORY_FED_CERT_PEER_BINDING` (left at warn).
**Proposed fix.** Extend `KNOBS` to pin (with boot-refusal on loosening): outer-envelope fed sigs ON, `ADMIN_HEADER_TRUST=0`, `GOVERNANCE_FAIL_OPEN_ON_ERROR=0`, `PERMISSIONS_MODE=enforce`, `HTTP_REQUIRE_ATTESTED_IDENTITY=enforce` (paired with SEC-1 so it is satisfiable), `FED_CERT_PEER_BINDING=enforce`. Consider `REQUIRE_TLS=1` (see the plaintext-bind residual, #2032 M2 defers REFUSE to v1.1.0 — decide whether asi-hard pulls it forward). Update `docs/deploy/asi-hard.env` + `config.asi-hard.toml` in lockstep.
**Est.** 5 sessions. **[T3 vote required]** (posture tightening).
**Acceptance:** a single env override outside the intended set can no longer silently weaken an asi-hard node without a boot refusal; fleet-scale posture attestation is meaningful.

### SEC-4 — Ship an MCP-surface signing story (resolve the #1981 resurfacing at max) *(blocking for asi-hard usability)*
**Finding (Fable §3.4).** `asi-hard` pins `REQUIRE_AGENT_ATTESTATION=1` on every surface, but **no MCP host can construct the `SignableWrite` envelope**, so the max path either bricks the primary agent write surface or drives operators to quietly loosen it.
**Proposed fix (choose via [T4] vote — this touches the signed-write envelope):** either (a) an MCP-side helper that constructs + signs `SignableWrite` from an enrolled agent key (`ai-memory store --sign` parity for the MCP path via a `memory_store` signing param), OR (b) a documented `asi-hard` carve-out that keeps MCP at `attest_level=claimed` (operator-as-actor) by design and does **not** pin `REQUIRE_AGENT_ATTESTATION=1` on the MCP surface. Option (b) is smaller and honest; option (a) is stronger.
**Est.** 4 sessions (b) / 8 sessions (a). **[T4 vote required].**
**Acceptance:** an asi-hard deployment can run MCP writes without either bricking or silently loosening; the chosen posture is documented at the pin site.

### FED-1 — TOFU key distribution for multi-hop relay (or an honest "manual-enroll" doctor path)
**Finding (Fable §3.4).** The v1.0.0 strict write-sig default is operationally self-reverting for multi-hop meshes because TOFU key distribution is deferred — real fleets will set `=0`. 
**Proposed fix (v1.0.1 minimal).** Not full TOFU (that is v1.x, T4). Instead: (a) `ai-memory doctor --federation` enumerates the origin author keys a receiving node is missing (from DLQ cause `unenrolled_author_strict`), turning "set =0" into "enroll these N keys"; (b) a bulk `ai-memory agents enroll-authors <file>` to make manual enrollment fleet-manageable.
**Est.** 4 sessions.
**Acceptance:** an operator running strict write-sig can see exactly which author keys to enroll and enroll them in bulk, instead of reverting to permissive.

### DI-1 — Close the boot-adoption false-stamp residual under strict-off
**Finding (Fable §3.3).** The one surviving silent-cross-space path: §5 boot-adoption on a pre-v84 corpus with a latent same-dim swap and zero recorded provenance can false-stamp old-space vectors as active (WARN-logged, reembed-healable).
**Proposed fix.** Consider making `AI_MEMORY_REQUIRE_EMBED_MODEL_MATCH` (strict, disables auto-adoption) the **default** at v1.0.1, OR add a stronger boot heuristic (e.g. sample-and-compare vector norms/clustering before stamping) so a latently-swapped corpus is refused-and-flagged rather than adopted. Pair with a `doctor` census readout.
**Est.** 3 sessions. **[T3 vote]** if flipping the strict default.
**Acceptance:** a pre-v84 latently-swapped corpus is flagged for reembed, not silently adopted into the active space.

---

## 4. P2 — Claims discipline (blocking for the loud items + the gate)

### CLAIM-1 — Remediate the kill-list public surfaces *(blocking)*
**Finding (Fable §5; three lenses converged with identical anchors).** Nine over-claim surfaces, headlined by **K3 `FedRAMP-certified deployments`** (`docs/at-a-glance.html:1573` — an outright present-tense certification falsehood), **K4 "never lose committed writes"** (`docs/architectures-t1.html:485` — provably false against `PERFORMANCE.md`), **K2 stale NSA badge** (`README.md:19` — links to a v0.7.0-pinned mapping, no non-endorsement text), and **K1 "forever"** (`README.md:26`).
**Proposed fix.** Apply the replacement language in the §5 kill-list table verbatim. Re-pin `docs/compliance/nsa-csi-mcp-security-mapping.md` to schema v84 (or add a currency banner pointing at the v1.0.0 re-verification page, which already exists — `docs/compliance/v1.0.0-security-assessment.html`, 580 self-authored control tests green). Fix the `v0.9.0 — current release` string (K9).
**Est.** 3 sessions.
**Acceptance:** K1–K9 remediated; no public surface claims a certification that does not exist; no absolute contradicts a first-party doc.

### CLAIM-2 — Add a claims gate to CI *(blocking — prevents regression)*
**Finding (Fable §5).** `scripts/check-docs-vs-ssot.sh` gates numeric counts but **not** claims, so the kill-list items are mechanically ungated and a one-time prose edit will regress.
**Proposed fix.** Extend the gate (or add a sibling `scripts/check-claims-discipline.sh`) to HARD-BLOCK: (a) the absolute-claim wordlist (`forever`, `never lose`, `never wrong`, `certified`, `guaranteed`) outside an allowlisted, hedged context; (b) any `NSA`/`OWASP`/`FedRAMP`/`SOC2`/`ISO` token adjacent to `certified`/`compliant`/`endorsed`; (c) a version-pin freshness check on compliance docs vs `CURRENT_SCHEMA_VERSION`; (d) the "current release" string vs `Cargo.toml`. Include `--self-test` per the existing gate discipline.
**Est.** 4 sessions.
**Acceptance:** a new absolute/cert-shaped claim or a stale compliance pin fails CI; the gate self-tests as load-bearing.

---

## 5. P3 — Honesty of scaffolds (recommended, non-blocking)

### DECOR-1 — Label the decorrelation enforce gate as an evidence-starved scaffold
**Finding (Fable §3.4).** `record_loader_observed` has essentially one production call site (curator boot); `serve`/`mcp` never record, so a non-curator fleet accumulates zero attested rows and the `enforce` quorum gate is perpetually inert.
**Proposed fix.** (a) Wire `record_loader_observed` into the `serve`/`mcp` LLM-client construction sites so attested coverage grows in normal operation; (b) `doctor` reports "decorrelation: enforce is low-yield — N attested rows, M families" so operators do not mistake the scaffold for an active defense; (c) ensure no public copy says "enforced heterogeneity."
**Est.** 3 sessions.
**Acceptance:** attested-family coverage grows on any daemon that constructs an LLM client; the enforce gate's real yield is visible in doctor.

### CONT-2 — Real multi-vendor transcript parsers (codex, gemini)
**Finding (Fable §3.1).** L2/L3 route every host through `ClaudeCodeJsonlParser`; codex/gemini resolvers are stubs, so those operators' L2/L3 recovery silently yields zero turns.
**Proposed fix.** Implement real `codex` and `gemini` transcript parsers behind the existing per-host router (`src/recover/transcript_paths.rs`), or — if the formats are unstable — make the stub path emit a loud "no parser for host X; L4 volunteer capture only" WARN instead of silently parsing to zero.
**Est.** 5 sessions (real parsers) / 1 session (loud-stub interim).
**Acceptance:** codex/gemini operators either get real recovery or are loudly told they are on L4-only; "multi-vendor continuity" stops being mono-vendor-in-practice.

---

## 6. Summary table

| ID | Lane | Title | Est. | Vote | Blocking |
|----|------|-------|------|------|----------|
| **SEC-1** | P0 | Multi-tenant identity: default-safe or fail-loud | 4 | T3 | **Yes** |
| **SEC-2** | P0 | IDOR gate on coordination write routes | 3 | — | **Yes** |
| **DI-2** | P0 | Boot WARN for `NORMAL` power-loss posture | 1 | — | **Yes** |
| **CONT-1** | P0 | L3 continuity: installer + doctor discoverability | 3 | — | **Yes** |
| **SEC-3** | P1 | Complete the `asi-hard` no-disable contract | 5 | T3 | **Yes** |
| **SEC-4** | P1 | MCP-surface signing story (#1981 at max) | 4–8 | T4 | **Yes** |
| **FED-1** | P1 | Multi-hop author-key enrollment tooling | 4 | — | Rec. |
| **DI-1** | P1 | Close boot-adoption false-stamp residual | 3 | T3? | Rec. |
| **CLAIM-1** | P2 | Remediate kill-list surfaces | 3 | — | **Yes** |
| **CLAIM-2** | P2 | Claims CI gate | 4 | — | **Yes** |
| **DECOR-1** | P3 | Decorrelation scaffold honesty | 3 | — | Rec. |
| **CONT-2** | P3 | Real codex/gemini parsers (or loud stub) | 1–5 | — | Rec. |
| | | **Blocking total** | **~30 sessions** | | |
| | | **Full program** | **~40 sessions** | | |

---

## 7. Sequencing & release gate

1. **CLAIM-1 first** (3 sessions) — the `FedRAMP-certified` falsehood (K3) is a live public claim and should be fixed immediately, independent of the rest of the program.
2. **P0 default-safety** (SEC-1, SEC-2, DI-2, CONT-1) — the exploitable/silent-loss defaults.
3. **P1 hardening completeness** (SEC-3, SEC-4) — so a hardened deploy is genuinely hardened; FED-1/DI-1 fold in.
4. **CLAIM-2 gate** — lands once the prose is fixed so the gate has a clean baseline.
5. **P3** — as capacity allows.

**v1.0.1 release gate (recommended):** all P0 + SEC-3 + SEC-4 + CLAIM-1 + CLAIM-2 green; four cargo gates + the six script gates clean on a fresh checkout; the new claims gate self-tests green; 24h dogfood on the patched binary; every item's regression test cited. Tag-cut remains **operator-gated** per the standing release-gate framework. AI NHI is 100% autonomous on the development; the tag is the human's.

**Relationship to the v1.x perfect-endpoint program:** v1.0.1 is orthogonal to the 27-requirement constitution work (R13/A1/R75/R45/R20/R22 etc.). Those remain the separate v1.x program. v1.0.1 is strictly "make v1.0.0's shipped machinery safe-by-default and its public copy honest" — the smallest release that closes the audit's default-safety and claims-discipline findings.

---

## 8. Provenance

Every item traces to a code-anchored finding in [`FABLE-5-TO-GROK-4-5-9-CLAIM-3x7-ADJUDICATION.md`](FABLE-5-TO-GROK-4-5-9-CLAIM-3x7-ADJUDICATION.html), itself derived from a 21-agent (3×7) + 4-supporting-lens CodeGraph-armed adversarial audit of `release/v1.0.0` @ `924965c1` (schema v84), family-decorrelated from the Grok 4.5 package it re-audits. Findings SEC-1 and the kill-list are cross-family (Grok + Fable) confirmed.

| Date | Change |
|------|--------|
| 2026-07-18 | v1: initial v1.0.1 Patch-1 roadmap derived from the Fable 5 nine-claim 3×7 re-audit. |

---

*End of document.*
