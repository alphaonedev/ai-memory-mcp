## Ballot W1-A (security)
**Vote:** B — the boundary is the right unit and the tree confirms it does not exist yet, but the assessment's evidence numbers are inflated and its "federation is fail-closed" line is half true; amend, then accept.

**Verified evidence (file:line):**
- No dispatch-level authority resolver exists: `grep resolve_caller_authority|CallerAuthority|struct Authority` over `src/` returns nothing; `TOOL_DISPATCH_TABLE` (`src/mcp/mod.rs:3053`) is a bare `(name, fn)` registry whose wrappers "un-bundle ctx into positional args" (`src/mcp/mod.rs:1400-1425`) with no shared pre-gate; the only cross-cutting gates are the optional hook-driven `consult_pre_event_gate` (`src/mcp/mod.rs:1917`), installed per-deployment, not structural.
- `Permissions::evaluate`: 47 textual hits in 21 files is a raw grep. 15 are tests in `src/governance/mod.rs` (tests module at :986; hits :1072-:1434), 3 are doc-comment references (:249, :312, :494), 3 more are doc refs in `src/storage/mod.rs:8990,8996,9114`, 3 are in `src/config.rs` tests (:6631,:6672,:8940; tests module :5290), 3 in `src/handlers/tests.rs`. Production call sites are ~20 in ~18 files (e.g. `src/mcp/tools/store/mod.rs:529`, `update.rs:409`, `delete.rs:169`, `archive.rs:158,260`, `src/storage/mod.rs:9134`).
- "31 attestation sites" is the sum of two greps (13 `require_agent_attestation_for` calls + 18 `WriteSurface::HttpDirect` literals) that double-count the same statements (`src/handlers/bulk.rs:885-886`, `src/handlers/create.rs:1267-1268`) and include the gate's own impl in `src/identity/attest.rs` (definition :196). Real HTTP-direct gate sites: `create.rs` (2), `bulk.rs` (1), `capture_turn/attestation.rs` (2), plus `cli/store.rs`, `daemon_runtime.rs`, `governance/audit.rs`.
- Surface-scoped default is correct as stated: `HttpDirect` required / `Mcp`,`Cli` permissive when env unset (`src/identity/attest.rs:159-200` table). Stdio caller = `AI_MEMORY_AGENT_ID` via `resolve_agent_id` step 2 (`src/identity/mod.rs:394-417`), so stdio is one trust domain by construction.
- HTTP `x-agent-id` is an unauthenticated self-claim when no API key is configured: `api_key_auth` passes every request through with `auth.key == None` (`src/handlers/transport.rs:983-986`), yet `resolve_http_agent_id` calls the header "authenticated" (`src/identity/mod.rs:869-898`). Compensating control: keyless non-loopback bind is refused (`src/daemon_runtime.rs:5855-5883`).
- Bulk goes through the same attestation gate as single create (`bulk.rs:885-886`, per-row stamp/admit `:1107-1140`) and the same governance pre-event gate (3 calls). Neither `create.rs` nor `bulk.rs` contains a `Permissions::evaluate` call; HTTP create authz runs through `enforce_create_governance` (`create.rs:582`) — a second authz pipeline for the same op as MCP `memory_store` (K9 at `store/mod.rs:529`). Whether they converge internally: not verified.
- Restore: directory restore picks newest by mtime (`src/cli/backup.rs:857-880`); `BackupManifest` (`:383-410`) has `sha256` and no signature field; the whole manifest check sits inside `if !args.skip_verify` (`:899-960`); the code itself says sha256 "proves only that the bytes match the manifest WE wrote" (`:963-965`). Unsigned, confirmed.
- Federation receive never calls `Permissions::evaluate` (absent from the 21 files). It has its own authority path: `require_sig`/`require_nonce` default-on (`src/federation/signing.rs:240-249`), `authorize_remote_transition` fail-closed (`src/federation/receive_auth.rs:66-92`), `resolve_inbound_attribution` (`src/handlers/federation_receive.rs:543-570`). But peer *enrollment* is zero-config by default: "Env unset / empty ... inbound write/delete lanes keep faith-based replication (#2491)" (`src/federation/peer_attestation.rs:143-144`); the enterprise posture gate only runs when `ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` is truthy (`src/enterprise_federation_posture.rs:780-784`).

**Where the assessment is wrong or overstated:**
- "47 sites in 21 files" and "31 sites" are grep totals, not enforcement sites; the honest figures (~20 authz, ~8 attestation) still make the point but should not be cited as they stand.
- "peer enrollment default-on" is false: signatures and nonces are default-on; authorship enrollment is opt-in and unenrolled meshes replicate on faith.
- The kernel gap is understated: there are three independent authority resolvers (K9 `Permissions`, write attestation, federation peer-scope), not one resolver called from many places. #3549 as summarised (MCP + HTTP) would leave federation receive outside the boundary.

**Where the assessment is right:**
- No dispatch-level resolver; every gate is per-handler convention.
- stdio single-trust-domain claim matches the code.
- Restore is unsigned with mtime newest-wins; `--skip-verify` bypasses all integrity checks.
- Bulk and single create share the same gates; no bypass there.
- Extraction during the freeze would re-touch every handler for no new control.

**Required amendments to #3581 before acceptance:**
1. Replace the 47/21 and 31 figures with production-only counts and cite the method.
2. Extend #3549's resolver scope to federation receive (or record why the peer-scope path is a separate, equal boundary with its own structural guard).
3. Correct "peer enrollment default-on"; add a GA item: enrolled-peer authorship required by default under the enterprise/asi-hard posture, not only when the posture env is set.
4. Add to #3199: the signature must cover the snapshot, not the manifest alone, and `--skip-verify` must not disable structural/backend checks.
5. Record the HTTP authz split (governance pipeline vs K9) as a #3124/#3549 sub-item.

**One risk if followed / one risk if ignored:**
Followed: a resolver that only wraps MCP+HTTP is declared "the boundary" while federation and CLI restore stay outside it, giving false assurance.
Ignored: authority keeps being fixed per route; an unsigned backup or an unenrolled peer can rewrite history with a valid checksum or a valid transport signature.
