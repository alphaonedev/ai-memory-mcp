# W4-A2 — Identity, NHI, multi-tenant privacy

**Lane:** Identity / NHI / multi-tenant privacy  
**Scope:** agent_id claimed vs attested · visibility · reown · admin header trust · G29 secret screen  
**Date:** 2026-07-08  
**Assessor:** W4-A2 (code-evidence, not live-daemon probe)

---

## VERDICT

**CONDITIONAL PASS (ship-ready for single-tenant + attested-write deployments; multi-tenant HTTP still shared-credential)**

Store-path claimed→attested is fail-closed by default at v0.9 (#1751). Read visibility has a single canonical predicate with private-default + #1921 subtree fix. Admin header trust and G29 refuse-default close prior leak classes. Residual risk is **structural multi-tenant authn**, not missing primitives.

## CONFIDENCE

**0.86** — grounded in production modules + dedicated regression tests (`agent_attestation_*`, `admin_header_trust_1570`, `admin_visibility_bypass_gate_1582`, `agent_id_spoof_*`, `secret_screen_g29`, owner-gate suite). Did not re-run the full cargo fleet in this wave; confidence would rise to ~0.92 after a green `AI_MEMORY_NO_CONFIG=1 cargo test` of the pins above.

## SCORE

| Dimension | Score (0–10) | Notes |
|---|---:|---|
| Claimed vs attested (store) | **8.5** | #1751 required default; forged always reject |
| Claimed vs attested (read / HTTP principal) | **5.5** | X-Agent-Id still self-asserted |
| Visibility / multi-tenant isolation | **7.5** | #910/#1921 solid; trust-all when env unset |
| Reown + lockout | **8.5** | CLI+SAL, dry-run, boot guard |
| Admin header trust | **8.5** | #1570/#1582 fail-closed; shared-key residual |
| G29 secret screen | **8.0** | Refuse default; origin-aware; best-effort detectors |
| **Aggregate** | **7.8** | |

---

## Evidence by surface

### 1. agent_id — claimed vs attested

**Store path (load-bearing).**  
`src/identity/attest.rs` + `src/identity/verify.rs::attest_write`:

- Default `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` = **required** (v0.9 #1751). Explicit `0`/`false` only opt-out; typos fail closed.
- Envelope: `SignableWrite` = `agent_id + namespace + title + kind + created_at + sha256(content)`.
- Signed stores require `created_at` within ±`ATTEST_CREATED_AT_SKEW_SECS` (300s) — replay/post-date bound.
- Decision table: forged signature → always `Err(Forged)`; unsigned → `Claimed` only if require=false, else `AttestationRequired`.
- Wired on HTTP create (`handlers/create.rs` stamp_attestation_*) and parallel MCP/CLI store paths.
- Scope **deliberate**: federation uses `resolve_inbound_attribution` / peer allowlist, not this flag; curator/admin self-writes use `CallerContext::for_admin`.

**Read / HTTP principal (claimed).**  
`resolve_http_agent_id` is header-first (body must match — closes #874/#901/#905–#910 spoof series). There is **no** Ed25519 bind on HTTP/MCP **read** callers. `X-Agent-Id` remains a self-asserted claim; transport binding is shared `api_key` (when set). MCP write identity ladder is richer (param → env → clientInfo → host); MCP **read visibility** uses only `AI_MEMORY_AGENT_ID` (`resolve_read_visibility_caller`) — unset ⇒ **trust-all**.

**NHI stamp durability (#1720 B1).** Default `host:<hostname>` / `ai:<client>@host` are pid-free so private ownership survives restart.

### 2. Visibility

Canonical predicate: `src/visibility.rs::is_visible_to_caller` (#951):

| Scope | Visibility |
|---|---|
| absent / `private` | owner `metadata.agent_id` **or** inbox `target_agent_id` |
| `collective` | all callers |
| `team` / `unit` / `org` | namespace **subtree** only (#1921, CWE-863 close) |
| unknown / legacy (e.g. `shared`) | broadly visible (federation shareable posture — intentional) |

SAL adapters push SQL filters + post-filter with the same predicate (`store/postgres.rs`, sqlite list/search). Admin bypass of private rows must use `is_admin_caller_trusted` (#1582), not bare allowlist match — wired in archive/kg/links/power/governance.

**Multi-tenant posture:** private isolation is **opt-in** for MCP (set `AI_MEMORY_AGENT_ID`). HTTP multi-tenant filtering depends on per-request claimed header + SAL caller context — not cryptographic identity.

### 3. Reown

- CLI `ai-memory reown` (`daemon_runtime::Reown`) + `MemoryStore::reown` (sqlite + postgres).
- Exact-namespace rewrite of `metadata.agent_id` only; dry-run; `--claim-unowned`; `validate_agent_id` on target.
- Boot guard `enforce_owner_lockout_guard`: COUNT private rows hidden from env caller → stderr WARN; `AI_MEMORY_REQUIRE_OWNED_ROWS=1` hard-refuses MCP boot.
- No MCP/HTTP reown surface (correct: operator migration tool).

### 4. Admin header trust (#1570)

`src/handlers/admin_role.rs`:

- `AI_MEMORY_ADMIN_HEADER_TRUST` default **off**.
- Admin admit = allowlisted id **AND** (`api_key` configured **OR** explicit trust flag).
- Empty allowlist ⇒ all admin endpoints 403 (safe default).
- Production forbids `"*"` wildcard (#980, test-only).
- `require_admin` audits allow/deny; generic 403 body (no allowlist probe).
- Visibility bypass sites use `is_admin_caller_trusted` (#1582 pin).

**Residual:** any holder of the shared `api_key` who can guess/set an allowlisted `X-Agent-Id` is admin. That is shared-credential multi-tenancy, not header-only trust (header-only is closed).

### 5. G29 secret screen (#1821)

`src/secret_screen.rs`:

- Default mode **`Refuse`** (v0.8.1); env/config ladder via `resolve_secret_screen_mode`.
- Caller-origin: `validate_content` / title / tags / metadata leaves via `screen_for_caller`.
- Federation / L2 / internal: storage funnel forces **redact** (refuse would diverge replicas — 5-agent vote).
- Detectors: PEM private key, AKIA, ghp_/github_pat_, sk-/xai- (length+entropy), Bearer, JWT — entropy is **tiebreak only**.
- Forensic egress: `forensic/bundle.rs` redacts content.
- Unseeded process reads `Off` (library/unit-test isolation).
- Best-effort by design: novel secret formats can pass; not a DLP product.

---

## GAPS

1. **G-ID-1 — HTTP/MCP read principal is claimed, not attested.** Store can require Ed25519; list/recall/get still trust header/env. Multi-tenant HTTP with one shared API key = all clients are one authn class. *Mitigation path:* per-agent macaroons (G10.1 exists but GA-off) or mTLS client cert → agent map.
2. **G-ID-2 — MCP read filtering trust-all default.** Without `AI_MEMORY_AGENT_ID`, private rows are not filtered. Documented single-operator posture; easy misconfig for multi-agent MCP on one DB.
3. **G-VIS-1 — Unknown scope remains world-readable.** Intentional for federation `shared`; an owner typo `scop=…` / custom string broadens their own row (not other tenants’ private data).
4. **G-ADM-1 — Shared API key = shared admin impersonation among allowlisted names.** #1570 closes keyless spoof; does not give per-agent authn.
5. **G-SEC-1 — Secret screen coverage incomplete by nature.** No generic high-entropy refuse; vendor patterns lag new token formats; historical rows pre-screen may still hold secrets until re-write / forensic mask only on export.
6. **G-REOWN-1 — Reown is namespace-wide claim.** Correct operator tool; misuse rewrites every owned row in a ns to one agent (no per-row ACL). Dry-run exists; no dual-control.
7. **G-TEST-1 — Postgres parity for G29 historically `#[ignore]`-gated** (epic note #1855 nightly). Code paths exist both backends; CI green on sqlite is stronger than automated PG parity cadence (verify nightly if multi-backend is in scope).

None of these reopen the closed classes (#901 spoof, #1570 keyless admin, #1582 visibility bypass, #1751 unsigned store default, #1921 team leak) without operator opt-out flags.

---

## VOTE

| Option | Stance |
|---|---|
| A — Block v0.9 ship on identity/privacy | **REJECT** — closed classes are fail-closed with tests |
| B — Ship; track multi-tenant authn as explicit residual | **ACCEPT (majority)** |
| C — Require G10.1 capabilities ON before any multi-tenant HTTP deploy | **ADVISORY** (ops policy, not code block) |

**Vote: B** — CONDITIONAL PASS. Do not treat “claimed agent_id on every surface” as solved; treat “unsigned store + keyless admin + team world-read” as solved.

## KILLER_OBJECTION

> “If X-Agent-Id is still self-asserted on HTTP, how is multi-tenant privacy real?”

**Answer:** Privacy is real for **private-scope rows when the caller principal is correctly established and filtering is on** (MCP: set `AI_MEMORY_AGENT_ID`; HTTP: SAL caller from header + visibility predicate). It is **not** real against a peer who holds the same `api_key` and asserts another agent’s id — that is shared-transport multi-tenancy. Closing that needs per-agent credentials (capabilities / mTLS / attested session), not another visibility predicate. Claiming full multi-tenant NHI isolation under a single shared key would be security theater.

## TOP_RISK

**Shared `api_key` + allowlisted `X-Agent-Id` impersonation on multi-tenant HTTP** (G-ADM-1 / G-ID-1), especially if operators enable `AI_MEMORY_ADMIN_HEADER_TRUST=1` or run keyless behind a misconfigured reverse proxy. Secondary: operator enables multi-agent MCP without setting distinct `AI_MEMORY_AGENT_ID` (trust-all reads).

---

## Regression pins (do not regress)

| Pin | Path / test |
|---|---|
| Store attestation default + forged reject | `src/identity/attest.rs`, `verify::attest_write`, `tests/agent_attestation_integrity.rs` |
| Header-first HTTP agent_id | `identity::resolve_http_agent_id`, `tests/agent_id_spoof_901_regression.rs` |
| Admin header trust fail-closed | `tests/admin_header_trust_1570.rs` |
| Visibility admin bypass | `tests/admin_visibility_bypass_gate_1582.rs` |
| Owner gates (delete/archive/kg/links) | `*_owner_gate_*.rs` suite |
| G29 refuse + PG parity | `tests/secret_screen_g29.rs`, `secret_screen_postgres_parity_g29.rs` |
| Team/unit/org subtree | `visibility.rs` #1921 semantics |
| Reown / lockout | `storage::reown` unit tests, `ENV_REQUIRE_OWNED_ROWS` |

---

## Bottom line

| | |
|---|---|
| **VERDICT** | CONDITIONAL PASS |
| **CONFIDENCE** | 0.86 |
| **SCORE** | **7.8 / 10** |
| **VOTE** | Ship with residual multi-tenant authn tracked (B) |
| **KILLER_OBJECTION** | Shared-key HTTP ≠ per-agent attested NHI — do not overclaim |
| **TOP_RISK** | Shared API key + claimed `X-Agent-Id` admin/tenant impersonation |
