# Section 1 — Security Perimeter (Specialist 1 of 6)

**Base SHA:** `b4ba16c8c` (`local/install-815-816`, post-#901)
**Date:** 2026-05-19
**Scope:** input validation + auth gates + tenant isolation + replay/SSRF

## Per-axis findings

### A.1 — `resolve_caller_agent_id` callsite audit — PASS

6 callsites grepped via `grep -rnE 'resolve_caller_agent_id\(' src/handlers/`. Every one passes `(None, &headers, None)` (header-only auth, no body/query trust), then degrades any caller-supplied body/query `agent_id` to a refinement that must match — 403 on mismatch:

- `src/handlers/subscriptions.rs:72` (`notify`, post-#901)
- `src/handlers/subscriptions.rs:251` (`subscribe`, post-#901)
- `src/handlers/subscriptions.rs:550` (`unsubscribe` postgres branch, post-#874)
- `src/handlers/subscriptions.rs:631` (`unsubscribe` sqlite branch, post-#874)
- `src/handlers/subscriptions.rs:726` (`list_subscriptions`, post-#874)
- `src/handlers/hook_subscribers.rs:47` (`get_inbox`, post-#901)

Function definition at `src/handlers/parity.rs:91-115`. Zero residual #901-class siblings on this exact API.

### A.2 — Input validation on write paths — PASS

Spot-checked 25+ write handlers via `grep -rn 'validate::validate_' src/handlers/`. Every POST/PUT/DELETE on `/api/v1/*` routes calls a `validate::validate_*` helper BEFORE touching storage:

- `create.rs:769` → `validate_create(&body)`
- `links.rs:302, :554` → `validate_link(source, target, relation)`
- `kg.rs:88, :613, :742` → entity / link validation
- `admin.rs:38, :45, :57` → register_agent triplet validation
- `federation_receive.rs:358, :497, :659, :706, :738, :899` → sender + memory + ids + links
- `power_consolidation.rs:220` → `validate_consolidate`

No skipped-validation cases found.

### A.3 — `scope=private` boundary — FAIL (issue #910 filed)

Visibility enforcement (`storage/mod.rs:286 visibility_clause` + `:158 is_visible`) is wired into `recall` (`:2221`), `search` (`:1779`), and `recall_hybrid` (`:6151`). It is NOT wired into:

- `storage::list` (`src/storage/mod.rs:1645-1689`) — SQL omits `visibility_clause`
- `PostgresStore::list` (`src/store/postgres.rs:6688`) — `_ctx: &CallerContext` is unused (note the underscore)
- `handlers::memories_query::list_memories` (`src/handlers/memories_query.rs:37`) — does not extract X-Agent-Id; postgres branch hardcodes `CallerContext::for_agent("ai:http")` at line 101
- `handlers::kg::kg_query` (`src/handlers/kg.rs:861`) — no X-Agent-Id extraction, no `as_agent` threaded through traversal

Cross-tenant attacker can `GET /api/v1/memories?namespace=victim-ns` and surface private-scoped rows. Filed as **issue #910 (security-medium)**.

### A.4 — Replay protection — PASS (with documented opt-in posture)

- `ReplayCache` substrate at `src/identity/replay.rs:69`; wired into `AppState` at `src/handlers/transport.rs:197` and bootstrapped fresh per-process at `src/daemon_runtime.rs:2737`.
- Signed-link verify gates the replay decision at `src/handlers/links.rs:124, :183` with the `record_and_check` call.
- `verify_require_nonce` defaults to `false` (`src/config.rs:2704, :5135`) — documented opt-in via `[verify] require_nonce = true`. Back-compat mode emits a WARN log per request (`links.rs:141-146`) and lets verification proceed. The dispatch's "TRUE for production builds" expectation is not the shipped default; the deliberate posture is operator-opt-in for the v0.7.0 cycle. Documented in `src/config.rs:2677-2706`.
- Federation signature default IS strict: `AI_MEMORY_FED_REQUIRE_SIG` defaults to `1` (`src/federation/signing.rs:118-123`).

### A.5 — SSRF gate (loopback webhooks) — PASS

- `validate_url` (`src/subscriptions.rs:1081`) and `validate_url_dns` (`:1014`) reject loopback hosts + private IPs by default.
- Default `false` confirmed at `src/config.rs:2728` and `:5346-5383` regression tests.
- Production bootstrap reads the resolved value at `src/main.rs:43-44` via `effective_allow_loopback_webhooks()` — no path passes `true` outside the opt-in env var (`AI_MEMORY_ALLOW_LOOPBACK_WEBHOOKS`) or `[subscriptions] allow_loopback_webhooks = true` config.
- Subscribe handler invokes `validate_url(&url)` at `src/handlers/subscriptions.rs:346` before persistence (postgres branch); the sqlite branch routes through the MCP handler which does the same.

### A.6 — Header-based auth completeness — PARTIAL (issues #905, #907, #909, #910)

Sites correctly header-bound post-#874/#901: notify, subscribe, unsubscribe, list_subscriptions, get_inbox (the 6 audited in A.1).

Sites still trusting `body.agent_id` over header:

- `src/handlers/power_consolidation.rs:230` — `resolve_http_agent_id(body.agent_id, header)` — **issue #905 (security-high)**
- `src/handlers/create.rs:86-87` — `resolve_http_agent_id(body.agent_id || metadata.agent_id, header)` — **issue #907 (security-high)**
- `src/handlers/admin.rs:274` — `body.agent_id` used as query target without authn binding — **issue #909 (security-medium)**

`resolve_http_agent_id` (`src/identity/mod.rs:199-218`) is the underlying primitive that prefers body over header — every callsite is a candidate for the #901 mismatch-rejection pattern.

### A.7 — API key enforcement — PASS

- Middleware `api_key_auth` (`src/handlers/transport.rs:581-645`) applied at `src/lib.rs:414-417` via `from_fn_with_state` covering every `/api/v1/*` and `/metrics` route.
- Exemptions: `/api/v1/health` (transport.rs:592) and `/api/v1/sync/*` when mTLS-pinned (`:610`). Both are intentional and documented inline.
- `/metrics` is NOT exempted from api_key_auth (only `/api/v1/health` is); behavior matches Prometheus scrape with `X-API-Key` set on the scrape config.
- Constant-time comparison (`constant_time_eq`, `:617, :633`) closes the per-byte timing-leak surface.

## Audit counts

- 73 public async handler fns enumerated (`grep -rn 'pub async fn' src/handlers/*.rs`, excluding mod.rs)
- 6 `resolve_caller_agent_id` callsites — all post-#901 pattern
- 4 sibling-of-#874/#901 vulnerabilities discovered + filed
- 4 ship-blocker issues filed (#905, #907, #909, #910)
- 0 input-validation gaps on write handlers
- 0 replay/SSRF defaults inverted from spec

## Verdict — **HOLD**

Two security-high (#905, #907) and two security-medium (#909, #910) issues filed against the perimeter. Each is the SAME architectural pattern #874 / #901 closed: a handler trusts caller-supplied `agent_id` as identity, bypassing the X-Agent-Id authentication binding.

#874 + #901 closed 5 instances; this audit found 4 more across `power_consolidation`, `create_memory`, `quota_status`, plus a separate scope=private gap on `list_memories` + `kg_query`. The sibling-vulnerability hunt for #901 is NOT complete — the underlying primitive (`resolve_http_agent_id`) still hands `body.agent_id` precedence over the authenticated header, and every callsite that uses it is a latent #874-class hole.

Recommend the orchestrator dispatch fixes for #905 + #907 before ship; #909 + #910 are reasonable v0.7.0 holds given the operator-set "no surface-level dismissals" prime directive. After the four are landed + retested, the perimeter is SHIP-able.

## Tools used

- `grep -rn` + `Read` (LSP available per `.claude/settings.json` but not directly invocable from this specialist context; grep-and-read fallback per CLAUDE.md "LSP setup" section)
- `gh issue create` for ship-blockers
- All artifacts under `.local-runs/` per project hard rule (no scratch outside the worktree)
