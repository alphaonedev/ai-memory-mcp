# W2-A4 — Governance Stoppability (§2.3)

> **Agent:** W2-A4 (Governance Stoppability Assessor)  
> **Property:** ROADMAP / Wave-1 §2.3 — *Stoppable without silent corruption*  
> **Ontology bind (W1-A7):** **CONFIRM + NARROW** — stop of *substrate writes / persistence + durable refusal records*, **not** behavioral veto of ASI world-actions.  
> **Date:** 2026-07-08  
> **Anchors:** PE-1 `#1885`/`#1924`, `RuleEngine` / `Permissions`, `HookDecision`, PreStore gates, secret screen, G10.1 macaroons, Wave-1 `w1-a7-synthesis.md`

---

## VERDICT

**PARTIAL HOLD under the Wave-1 narrowed definition; FAIL under any public “kill-switch / stop the agent in the world” reading.**

The substrate has a real **typed refuse stack** on the main write surfaces (MCP + HTTP + CLI governance gate): Deny/Pending/HookVeto/Escalate fail-closed, PE-1 presence enforcement is **wired** on MCP+HTTP, secret-screen defaults **refuse** on caller-origin writes, and permissions resolution defaults **Enforce**. That is load-bearing **record-stop** machinery.

It is **not** a universal stop: hooks-presence enforce defaults **Off** (empty `required_events` = hard no-op even under enforce), namespace governance is **allow-on-silence** (`write: Any`), several **operator fail-open escapes** remain, CLI does **not** consult PE-1 hook chains, federation inbound **degrades refuse→redact**, and refusals are primarily **error + audit events**, not automatically first-class **refusal memories** the cognition re-loads as content. Stop **outside** the substrate (raw tool use, other hosts, unsigned bypass of the daemon) remains free by design.

---

## CONFIDENCE

**0.86**

| + | − |
|---|---|
| Code+env defaults inspected (hooks, permissions, secret screen, capability) | Live multi-surface e2e matrix not re-run this turn |
| PE-1 install path documented at both MCP and HTTP | “Refusal-is-content” durability is partly audit-not-artifact |
| W1 narrow wording unambiguous | Moonshot prose still inflates “kill-switch” |

---

## SHIPPED (structural evidence)

| Mechanism | Location / default | Record-stop role |
|---|---|---|
| **HookDecision** 4-shape | `src/hooks/decision.rs` — Allow / Modify / Deny{reason,code} / AskUser | Typed halt; not silent drop |
| **PE-1 presence enforce** | `src/hooks/enforce.rs` + `dispatch_pre_event_enforced` (`chain.rs`) | Empty required-hook chain no longer silent-Allow **when** mode=enforce **and** event listed |
| **MCP wire-up #1885** | `consult_pre_event_gate` / `PRE_EVENT_ENFORCE_GATE` in `src/mcp/mod.rs` | Pre-commit consult on MCP mutations |
| **HTTP wire-up #1924** | `http_pre_event_gate` → same consult (`src/handlers/create.rs`); install in `daemon_runtime::serve` | Closes CWE-288 HTTP bypass of PE-1 |
| **Eligible pre-events** | PreStore/Delete/Promote/Link/Consolidate/GovernanceDecision/Reflect/PreSignalSend | Deny-capable surface set |
| **PermissionsMode** | `effective_permissions_mode` → secure default **Enforce** (env > config > Enforce); `Default` impl still Advisory for serde only | Unconfigured write policy blocks when standards demand |
| **Permissions pipeline** | `Permissions::evaluate` deny-first rules then hooks; Ask under Enforce → Deny; mode Off → Allow | Combiner honesty |
| **K3 enforce_governance** | MCP/HTTP/CLI store paths; Deny / Pending / Allow | Namespace + action gate |
| **RuleEngine Escalate** | `Decision::Escalate` **is_blocking** (fail-closed until human) | No silent escalate-as-allow |
| **Governance fail-closed** | `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` default **false** | Rule-load outage → refuse |
| **Secret screen** | Compiled default **Refuse**; seeded at boot | Closed **admission class** (S1) for credentials |
| **ReflectHookDecision::Deny** | → `ReflectError::HookVeto` (distinct from depth) | Typed reflect stop |
| **G10.1 macaroons** | `apply_capability_grant`: only Deny/Ask flippable; attenuation-only; default **enabled=false** | Controlled override, not ambient power |
| **STOPPER role (G9)** | `stopperSig` **forensic/advisory**; runtime deny **before** stopper sign | Separation of powers ≠ world kill-switch |
| **CLI store governance** | `cli/governance::enforce` + attestation stamp on store | Operator CLI not completely ungated |

---

## GAPS

### A. Stop **outside** substrate? (jurisdiction)

| Gap | Severity | Notes |
|---|---|---|
| **Bypass free if write never hits daemon** | Structural | World tools, other MCP servers, local files, model weight side-effects — not interceptable. §2.3 **must not** claim otherwise (W1-A2). |
| **Harness PreToolUse is optional install** | Policy | STOPPER/RuleEngine on Claude PreToolUse only if operator installs hooks; substrate alone ≠ OS policy engine. |
| **CLI has governance but no PE-1 hook chain** | Surface hole | No `consult_pre_event_gate` under `src/cli/`; operator-as-actor path can write without required PreStore hooks. |
| **Capabilities flip Deny→Allow** | Intentional escape | Valid issuer token under Enforce overrides coarse gate; closed allowlist + short expiry, but still a stop *defeat* when minted. |

### B. Silent / soft paths (corruption of “stopped cleanly”)

| Gap | Default | Effect |
|---|---|---|
| `AI_MEMORY_HOOKS_ENFORCE_MODE` | **off** | Presence check inert; empty hooks → Allow |
| `required_events` empty | hard no-op | Even `enforce` does nothing (self-DOS guard) |
| Hook `FailMode` | **Open** | Error/timeout → Allow unless PE-1 forces Closed |
| Malformed hook JSON | degrade **Allow** | Documented “fail open, log loudly” (`decision.rs`) |
| `PermissionsMode::Off` / env `off` | escape | Full pipeline skip |
| `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1` | escape | Rule outage → Allow |
| Secret screen `off` / `redact` | operator | Redact admits masked secrets; Off disables |
| Federation refuse→**redact** | always | Inbound cannot pure-refuse without replica divergence |
| Namespace `CorePolicy` | **write: Any** | No standard ⇒ no write gate (“allow-on-silence”, #1569) |
| Unseeded secret screen | **Off** | Library/pre-boot reads Off (tests safe; misuse risk if embedders skip seed) |

### C. Refusal-is-content incomplete

- Denies surface as **typed wire errors** + (often) **signed_events / forensic / pending_actions** — good anti-phantom-context.
- Moonshot claim that “cognition learns from being refused” is **not** automatic: no mandatory store of `MemoryKind::Decision` / refusal artifact into the recall corpus on every Deny.
- Audit chain itself has opt-in posture elsewhere (unsigned daemon, witness require-modes default off) — that is more §2.5, but weakens “durable refusal record” under default deploy.

### D. Kill-switch language honesty

- Moonshot §2.3 still calls stoppability the “**load-bearing kill-switch property**” while Wave-1 freezes **record-stop only**.
- STOPPER name + `stopperSig` invite over-reading; code is explicit: **forensic only**.

---

## SCORE §2.3

| Dimension | Score (0=absent, 1=held) | Rationale |
|---|---|---|
| Typed refuse on write (MCP/HTTP) | **0.85** | Deny/Pending/Veto wired; PE-1 present when configured |
| Fail-closed defaults (core gates) | **0.70** | Permissions Enforce + gov fail-closed + secret refuse; hooks PE-1 Off undercuts |
| PE-1 presence (no silent empty chain) | **0.55** | Code complete (#1885/#1924); **policy default Off** |
| CLI parity | **0.45** | Governance yes; hooks/PE-1 no |
| Closed hold/refuse classes (S1) | **0.60** | Secrets refuse strong; namespace write open-by-default |
| Refusal as durable cognitive content | **0.40** | Audit/pending yes; corpus learning artifact weak |
| World-action / out-of-band stop | **0.05** | Correctly out of scope; score near zero if claimed in-scope |
| Escape-hatch discipline | **0.55** | Escapes exist and are named; several are easy |

### Aggregate (narrowed §2.3 only)

| Metric | Value |
|---|---|
| **held_0_1** | **0.58** |
| **distance_to_perfect_0_1** | **0.42** |
| **structural vs policy** | ~60% structural machinery / ~40% still policy or opt-in |
| **Letter (narrow)** | **C+** |
| **Letter (if marketing kill-switch)** | **F** |

---

## KILLER_OBJECTION

**If “stoppable” is sold as stopping the agent’s world-actions, the product is a category fraud** — the strongest stop is “this SQLite/HTTP/MCP write did not land,” while every side channel remains open.  
**If “stoppable” means record-stop, the remaining kill is quieter:** default-Off PE-1 + allow-on-silence namespaces + fail-open hook parse/FailMode let operators believe enforcement is live when the chain is empty or broken — **silent no-enforcement is still the #1734 class of corruption**, only partially closed by wiring that is inert until configured.

---

## TOP_RISK

1. **Jurisdiction theater** — procurement language inherits moonshot “kill-switch” while W1 forbids it.  
2. **Default-Off PE-1** — `doctor --hooks` can say “WILL DENY” only after operators set mode+required_events; zero-config still empty-Allow.  
3. **CLI / non-daemon writes** as governance side door for anything not also gated at the storage funnel (secret screen is funneled; PE-1 hooks are not).  
4. **Capability mint + fail-open env** as dual operator footguns under Enforce.

---

## VOTE — honesty of kill-switch language

| Claim surface | Vote |
|---|---|
| Moonshot §2.3 “kill-switch property” | **AMEND / REJECT as public wording** — replace with **record-stop / typed-refusal without silent corruption** |
| ROADMAP/W1 narrow (writes + durable refusals) | **ACCEPT as scoring frame** |
| “STOPPER stops the model” | **REJECT** — forensic sig only |
| “PE-1 makes hooks mandatory out of the box” | **REJECT** — default Off; empty required set no-ops |
| “G10.1 capability is a stop” | **REJECT** — it is a **controlled stop-defeat** under Enforce |
| Overall honesty if public materials keep “kill-switch” unscoped | **FAIL** |

**Council vote (this assessor):** **5/5 against unscoped kill-switch language; 4/5 that narrowed record-stop is partially held (0.58).**

---

## RATIONALE

Wave-1 froze the right object: **stop the *record* cleanly**, not the cosmos. Against that object, v0.9 is past “hooks theater”: `HookDecision`, governance Deny/Pending, HookVeto, Escalate-closed, secret refuse, permissions Enforce, and PE-1’s *wiring* on both MCP and HTTP are real engineering. Against perfection, the same tree shows the classic substrate pattern — **secure defaults on some gates, opt-in on the presence gate that closes empty-chain silent Allow**, namespace write-Any, CLI without PE-1, federation redact-degrade, and refusals that mostly exit as errors rather than durable learnable artifacts.

Distance **0.42** is not shameful; it is the honest gap between “we can refuse a store with a code” and “every contact point that matters cannot silently proceed or silently drop.” Closing that gap is configuration discipline + refusal-as-content product work + ruthless public wording — **not** another macaroon layer.

---

## HANDOFF (compact)

- **claim:** record-stop partial; world-stop absent  
- **anchors:** `hooks/{enforce,chain,decision}.rs`, `mcp::consult_pre_event_gate`, `handlers/create::http_pre_event_gate`, `permissions` / `enforce_governance`, `secret_screen`, `governance/capability.rs`  
- **default_posture:** permissions Enforce; hooks PE-1 Off; secret Refuse; capabilities Off; gov fail-closed  
- **gaps:** out-of-band free; PE-1 opt-in; CLI hooks; allow-on-silence; refusal≠memory by default  
- **top_fix:** kill-switch marketing + empty-chain false security  
- **falsification:** set `enforce` + `required_events=[pre_store]` with zero hooks → MCP/HTTP 503; omit list → still Allow; CLI store without hooks → may still insert  

---

*End W2-A4 — under 350 lines.*
