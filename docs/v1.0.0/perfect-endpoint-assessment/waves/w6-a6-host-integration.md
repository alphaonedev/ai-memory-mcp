# W6-A6 — Host integration (Claude Code hooks · capture L1–L4 · session start)

**Lane:** Host / agent integration & layered capture completeness  
**Scope:** #487 SessionStart · #1388/#1389 L1–L4 · install surfaces · RFC-0001  
**Date:** 2026-07-08  
**Assessor:** W6-A6 (code + docs evidence; not live multi-host dogfood)

**Sources:** `CLAUDE.md` §L1 hard-rule; `docs/integrations/{README,claude-code}.md`; `docs/rfc/RFC-0001-mcp-turn-capture.md`; `ROADMAP.md` §11.3/§11.4.H; `src/recover/{mod,nag,transcript_paths,parsers/*}.rs`; `src/mcp/tools/{session_start,capture_turn}.rs`; `src/handlers/capture_turn.rs`; `src/cli/{boot,install}.rs`; `src/cli/commands/recover_previous_session.rs`; `clients/host-adapter-shim/**`

---

## VERDICT

**CONDITIONAL PASS for Claude Code cold-start (#487); CAPTURE INCOMPLETE for SIGKILL-class durability under defaults.**

Claude Code is the only **Category-1** host with mechanical SessionStart injection (`ai-memory install claude-code` → `ai-memory boot`). Layered capture ships **L1 + L2 + L4-server**; **L3 (fs-notify watcher) is still not built** (operator-`notify`-gated since v0.7.0). **L4 host adoption is zero** in-tree (RFC Draft; shims reference-only). Production durability still depends on agent volunteer `memory_store` + optional L2 transcript scrape after the fact — the #1388 class is mitigated for Claude Code JSONL on the **same host**, not eliminated fleet-wide.

## CONFIDENCE

**0.84** — architecture + surfaces verified in-tree; L3 absence and L4 non-adoption are grep-provable. Did not re-run live SessionStart against a Claude Code process this wave.

---

## SCORE

| Dimension | Score (0–10) | Notes |
|---|---:|---|
| SessionStart / cold-start (#487) | **8.5** | Cat-1 Claude Code 100% when installed; Cat-2 best-effort; Cat-3 SDK/`wrap` reliable when coded |
| Install surface breadth | **7.5** | 10 install targets (MCP config); SessionStart+PreToolUse **only** `claude-code` |
| L1 agent discipline + nag | **6.5** | HARD-RULE + nag shipped; volunteer + non-blocking by design |
| L2 recover-on-boot | **7.5** | Claude Code parser real; dual CLI/MCP/SAL; Codex/Gemini paths stubby |
| L3 substrate watcher | **0.0** | **Not shipped** — still deferred pending `notify` approval |
| L4 server (tool/HTTP/SAL/RFC) | **8.0** | Idempotent write + optional host sig; three surfaces |
| L4 host adoption | **1.0** | Shims + docs only; no vendor auto-call; RFC still Draft |
| v0.9 attestation × Claude Code | **5.0** | Default require-attest breaks unsigned MCP `memory_store` unless `=0` |
| **Capture completeness (aggregate)** | **5.8** | L1+L2+L4-server hold Claude Code; mid-session crash gap open |

---

## Capture completeness (L1–L4)

| Layer | Surface | Status @ v0.9 | Catches | Gap |
|---|---|---|---|---|
| **L1** | CLAUDE.md HARD-RULE + `CaptureNagWatcher` (`src/recover/nag.rs`) | **SHIPPED** | Agent forgets `memory_store` (common case) | Observability only (stderr WARN + `capture_lag` event); never blocks tools. Defaults N=5 / escalate=20 (`AI_MEMORY_CAPTURE_NAG_*`). |
| **L2** | `recover-previous-session` CLI + MCP + SAL postgres (#1693) | **SHIPPED** | SIGKILL **between** sessions; same-host transcript survives | Couples to host JSONL; only `claude_code_jsonl` full parser; Codex/Gemini = path candidates, thin/stub. Graceful exit-0 for SessionStart. |
| **L3** | In-daemon fs-notify mid-session scrape | **NOT SHIPPED** | Mid-session crash; concurrent multi-session | Still `notify`-gated (ROADMAP §11.3/§11.3.1/§24). Schema comments assume future L3; no watcher module. |
| **L4** | `memory_capture_turn` MCP + `POST /api/v1/capture_turn` + SAL | **SERVER SHIPPED** | Clean protocol capture (no format scrape) | Hosts must call it. RFC-0001 **Draft**. Shims under `clients/host-adapter-shim/{bash,node,python}`. Optional host Ed25519 via `AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST` (#1414). |

**Architecture truth:** substrate is **volunteer-mode** until L4 is host-native. L2 is BACKSTOP (never “the fix”). L3 was the mid-session universal scrape; without it, a kill **before** next SessionStart loses in-flight turns that L1 never stored and L4 never received.

**Dedup spine:** schema v52 `transcript_line_dedup` shared by L2 + L4 (`(sha256)` / composite session+turn where host provides both — #1573). L2 stamps `recovered-from-transcript` + `capture_layer: L2`.

---

## Session start & hooks

### Mechanical boot (Category 1)

- Installer: `ai-memory install claude-code [--apply]` writes managed `hooks.SessionStart` → `ai-memory boot --quiet --limit 10 --budget-tokens 4096` (`src/cli/install.rs`).
- Boot: read-only, fast, always-visible status header (#487); `AI_MEMORY_BOOT_ENABLED=0` / `[boot] redact_titles` privacy knobs.
- Optional: `--hook pretool` installs PreToolUse → policy `memory_check_agent_action` (Bash|Edit|Write matcher, #1667). **claude-code only.**

### Best-effort / programmatic

| Cat | Hosts | Mechanism | Reliability |
|---|---|---|---|
| 2 | Cursor, Cline, Continue, Windsurf, OpenClaw | MCP + rules text → `memory_session_start` | Model compliance |
| 3 | Codex, Agent SDK, wrap, xAI, local | App/`ai-memory wrap` prepends `boot` stdout | 100% if implemented |

`memory_session_start` (`src/mcp/tools/session_start.rs`): list+persona+rules bootstrap; visibility filter (#1420); not a substitute for SessionStart hook when the model skips the call.

### v0.9 attestation friction

Claude Code MCP does **not** sign `memory_store`. Default `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=true` (#1751) → **403** on unsigned writes. Documented opt-out in MCP `env` for single-operator Claude Code (`docs/integrations/claude-code.md`). Capture completeness **collapses to zero on write** if operators ship require-attest without client signing.

---

## GAPS (ordered)

1. **L3 missing** — mid-session crash / multi-session concurrent capture hole remains open years after #1389 design.
2. **L4 host non-adoption** — server+RFC+shims without any host auto-invoking `memory_capture_turn` (Claude Code Stop-hook recipe is manual doc, not installer).
3. **RFC still Draft** — capability advertisement (`capture_layer_4`) not load-bearing in `capabilities.rs` grep path; vendor negotiation weak.
4. **L2 multi-host** — Codex/Gemini resolvers exist; full parsers beyond Claude Code JSONL incomplete; no IDE `HostKind` (Cursor/Cline) (#1391).
5. **Cat-2 cold-start** — text-directive `memory_session_start` is best-effort (#487 residual).
6. **L1 non-enforcing** — nag never refuses tool calls; agent can ignore forever after escalate.
7. **Attest default vs host clients** — single-operator Claude Code must opt out or lose store path.
8. **Decision-detector (#1393)** — opt-in curator reclassify of recovered Observation→Decision; quality gap on L2/L4 atoms.
9. **CLAUDE.md framing** — lists L3 as live backstop; code has no L3 — docs/ops drift risk.

---

## VOTE (5-lens synthesis — T6 host-capture completeness)

| Lens | Verdict | Conf |
|---|---|---:|
| Precedent / #1389 design | L1+L2+L4-server correct; L3 defer was explicit trade, now **overdue** | 0.90 |
| Spec-literalism (ROADMAP) | “L3 in v0.7.x” **missed**; multi-vendor L4 “at vendor pace” honest but hollow | 0.88 |
| Operator DX | Claude Code install+boot excellent; attest opt-out is footgun | 0.82 |
| Capture durability | Without L3 or host-L4, mid-session kill still loses volunteer gap | 0.85 |
| Blast radius | Shipping L3 needs `notify` dep vote; forcing L4 host hooks risks host-format coupling until native | 0.80 |

**Council: KEEP L1 volunteer + L2 backstop; SHIP L3 or land one production L4 host path before claiming capture complete; do NOT market four-layer defense as fully live.**

---

## KILLER

**Claiming “four-layer capture defense” while L3 is unbuilt and L4 has zero host callers** is security theater relative to the #1388 RCA. The durable win (Claude Code SessionStart + L2 JSONL recover) is real — it is **not** the architecture’s end-state.

## TOP_RISK

**Mid-session SIGKILL / host crash on a non-Claude-Code or multi-agent host** drops operator directives that L1 never stored: no L3 scrape, no L4 push, L2 only helps if a parseable transcript survives and recover runs next boot. Compound risk: v0.9 attest-required + unsigned Claude Code MCP → **silent write failure** if opt-out forgotten, so even L1 cannot land.

---

## Perfect-system next moves (non-binding)

1. **Decide L3:** approve `notify` + ship watcher **or** formally CUT and stop listing L3 as backstop.  
2. **Installer L4 path:** optional Stop/SessionEnd managed hook calling host-adapter shim for Claude Code (until Anthropic natively MCP-calls).  
3. **Codex/Gemini L2 parsers** + IDE HostKind.  
4. **Single-operator profile:** install template that sets `REQUIRE_AGENT_ATTESTATION=0` (or signs) by default for Claude Code.  
5. Publish RFC-0001 past Draft; advertise `capture_layer_4` in capabilities envelope.

---

*≤250 lines. Absolute paths above under `/Users/fate/Downloads/ai-memory-mcp/`.*
