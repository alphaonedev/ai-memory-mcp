# W6-A3 — MCP / HTTP / CLI three-surface parity & freeze discipline (v1.0)

| | |
|---|---|
| **Lens** | Surface parity vs intentional asymmetry; what freezes at v1.0 |
| **Inputs** | `ROADMAP.md` §11.6 · `w3-a5-timeline.md` · CLAUDE.md Architecture · `src/lib.rs` SSOT consts · `src/profile.rs` · FX-12 / ARCH-3 / SR-4 / #1727 |
| **Date** | 2026-07-08 |
| **Role** | Contract critic: freeze the *right* surfaces, document the rest |

---

## VERDICT

**v1.0 freezes a *versioned surface inventory* plus intentional-asymmetry law — not a naive “every verb on every wire.”**

Parity at v0.9 is **substantially closed** for data-plane memory verbs (store / recall / update / link / promote / forget / consolidate / lineage / expand / share / KG / subscriptions / coordination write paths) after FX-12, ARCH-3 / FX-C3, SR-4 / #1111, and #1859. Counts are machine-pinned:

| Surface | v0.9.0 SSOT | Pin |
|---|---|---|
| MCP full | **100** callable + **1** always-on `memory_capabilities` = **101** advertised | `Profile::full().expected_tool_count()` + registry `tool_names::ALL` |
| HTTP | **92** `.route(` regs / **78** unique paths | `EXPECTED_PRODUCTION_ROUTES_{,UNIQUE_PATHS_}COUNT` + `tests/route_count_invariant.rs` |
| CLI | **87** default / **89** `--features sal` | `EXPECTED_CLI_SUBCOMMANDS_{DEFAULT,SAL}` + `tests/cli_subcommand_count_invariant.rs` |

**Freeze discipline (v1.0 contract release, per W3-A5):**

1. **Breaking wire renames/removes** of MCP tools, HTTP paths, CLI verbs, or public SAL methods require a **major** bump after `v1.0.0`.
2. **Counts + path SSOT are contract**, not narrative — every additive ship bumps const + invariant test + docs-vs-ssot gate in the same commit.
3. **Intentional asymmetries are first-class** (security / operator / transport limits) — they MUST appear in a published inventory with vote/memory citation; they are **not** “gaps to close before freeze.”
4. **Behavioral three-surface DTO parity** (same request shape semantics via `RecallRequest`-class DTOs) freezes separately from raw name equality.

**Do NOT freeze** under a lie that MCP ≡ HTTP ≡ CLI set-equality. That would force remote exposure of CLI-only operator weapons (`undo-edit`) or pretend stdio MCP can host postgres (#1675).

---

## GAPS

### A. Closed / load-bearing (do not re-open as “missing parity”)

| Class | Evidence | Freeze posture |
|---|---|---|
| Data-plane three-surface closeouts | FX-12, FX-C3 batch2, SR-4 share, #1111 HTTP catch-up, #1443 expand, #1859 lineage | **IN inventory** |
| Count / path SSOT | `src/lib.rs`, `profile.rs`, route/CLI invariants, `scripts/check-docs-vs-ssot.sh` | **HARD freeze machinery** |
| CLI-ONLY `undo-edit` | SAL trait + `Command::UndoEdit`; 5-agent vote `ff23ddcd` / `4d3ea1c5` | **Documented asymmetry** |
| sal-gated `Migrate` / `SchemaInit` | feature-gated CLI only | **Build-matrix asymmetry** |
| MCP stdio = sqlite-only | `#1675`; `--store-url` on `serve`/`curator` only | **Transport law** |
| Operator verify / epoch / model-attest CLIs | PE-8, #1878, #1870 — local admin surfaces | **Operator-plane** |

### B. Residual gaps before freeze (must resolve or promote to intentional)

| # | Gap | Risk if frozen wrong |
|---|---|---|
| **G1** | **No single published surface-inventory table** mapping MCP tool ↔ HTTP method/path ↔ CLI verb ↔ SAL method ↔ deliberate NONE | Docs drift; procurement “full parity” lies |
| **G2** | **MCP vs HTTP read-visibility asymmetry** — MCP visibility caller = `AI_MEMORY_AGENT_ID` env-only; HTTP can use per-request principal (#1468 / SEC-8) | Multi-tenant agents see different private sets across surfaces |
| **G3** | **Backend split-brain pockets** — some list/observe paths historically sqlite free-fn vs SAL (reviews flag recall-observations class) | Postgres HTTP ≠ MCP semantics under freeze |
| **G4** | **Capability schema negotiation** (`memory_capabilities` accept= / Accept-Capabilities) not fully treated as frozen sub-schema | Hosts pin schema_version without semver story |
| **G5** | **Profile subsets** (core=7 tools) freeze needs explicit “profile is not full product” language | Integrators treat core as complete API |
| **G6** | **DTO field lag** still possible (e.g. historical #1257 CLI `session_id`) — no mechanical *name-set* parity across three constructors | Silent behavioral fork |
| **G7** | **SAL trait surface** not count-pinned the way routes/CLI are | Postgres gate 501 surprises after freeze |
| **G8** | **Federation / admin / curator** mega-CLIs lack 1:1 MCP twins by design — inventory must say so | “CLI-only = incomplete” false defects |

### C. v1.0 freeze checklist (W6 deliverable, not already shipped)

1. **`docs/contracts/surface-inventory-v1.md`** (or generated from registry) with columns: `mcp | http | cli | sal | status{parity,cli-only,mcp-only,http-only,operator,transport-limit} | vote/issue`.
2. **Asymmetry registry** section: at minimum `undo-edit`, `Migrate`/`SchemaInit`, `epoch-apply`, `model-attest`, `reown`, `reembed`, `verify-audit-trail` posture, MCP-sqlite-only, visibility ladder.
3. **Semver rule** in ENGINEERING_STANDARDS: rename/remove wire name = major; additive = minor; bugfix = patch; count const bump required on add.
4. **Invariant expansion:** optional CI matrix that diffs MCP `tools/list` names vs inventory YAML (HARD-BLOCK unknown drift).
5. **DTO parity smoke** retained for recall / store / update / link / lineage (three-surface golden requests).
6. **Claims ban:** no release note may say “full three-surface parity” without linking the inventory + asymmetry list.

---

## VOTE

| Lens | Stance |
|---|---|
| Precedent | Keep SR-4 / FX-C3 closeout pattern; new data verbs get all three surfaces unless security vote says otherwise |
| Spec / ROADMAP §11.6 | Freeze surfaces at v1.0; interpret as **inventory + semver**, not set-equality |
| Security | Preserve CLI-only lossy/admin weapons; never “parity-close” `undo-edit` onto MCP/HTTP |
| Testability | Counts already pinned; add inventory-generated or YAML-diff gate for *names*, not only integers |
| Blast radius | Freeze wire + SAL public shapes; leave profile tokens, env knobs, and internal free-fns free under minor |

**Tally:** 5/5 — **freeze inventory + intentional asymmetry law; reject naive set-equality parity.**

**Chosen pathway:**

1. Publish surface inventory as **contract artifact** before tag.
2. Promote residual G2/G3 to either **fix before freeze** or **explicit permanent asymmetry** with procurement language.
3. Pin SAL public method set (or postgres-gate allowlist completeness) as freeze peer to route/CLI counts.
4. Keep operator/transport asymmetries forever; document, don’t “close.”

**Ballot:**  
`FREEZE_INVENTORY_NOT_SET_EQUALITY` · fix-or-declare G2/G3 · CLI-only security asymmetries permanent · **confidence 0.84**.

---

## KILLER

**“Three-surface parity means every MCP tool has HTTP + CLI, so freeze = equal counts.”**

Equal counts are **false** and **dangerous**:

- MCP advertises **101** entries; HTTP has **92** registrations; CLI has **87/89** verbs — different grains (method+path, subcommand trees, always-on bootstrap, multi-method paths).
- Forcing equality either **exposes** operator undo/migrate/epoch surfaces to remote agents, or **strips** CLI ops so humans lose break-glass tools.
- Transport law: MCP stdio cannot become postgres without a protocol redesign (#1675); “parity” that ignores that is marketing.

The killer failure mode is freezing a **slogan** (“full parity”) that contradicts the SSOT numbers and the security votes — then every post-v1.0 audit finding becomes an API-stability crisis.

---

## TOP_RISK

**Silent semantic fork under frozen names.**

Counts and path strings stay green while **behavior** diverges (visibility caller, sqlite free-fn vs SAL, DTO field defaults). Integrators pin `memory_recall` / `GET /api/v1/recall` / `ai-memory recall` as “the same” and ship multi-tenant bugs that only appear when agents move across surfaces.

Secondary risks:

- **Inventory never written** → freeze is narrative-only; docs-vs-ssot only checks integers.
- **Parity zeal** re-opens `undo-edit` on MCP → remote mutation surface against security vote.
- **Premature freeze** (W3-A5) over incomplete identity/attestation spine → major-version lock on UUID-era thick-row wire while cid/lineage still dual-truth.

---

## One-line north star

> **v1.0 freezes the map of surfaces and the law of intentional holes — not a fiction that MCP, HTTP, and CLI are the same API.**
