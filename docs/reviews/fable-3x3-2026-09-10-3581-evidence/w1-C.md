## Ballot W1-C (product/GA)

**Vote:** B — the boundary (#3549 + #3199 + #3124) is the right GA-scope product; a crate split costs no latency or UX but real build, publish and evidence churn, and the freeze rule already sends hygiene to v1.1.0; three corrections are required first.

**Verified evidence (file:line):**
- Single crate, no `[workspace]`: `Cargo.toml:1-3`, `[lib]` at `:652-653`; `sal`/`sal-postgres` features `:309-310` reach 536 `cfg(feature = "sal…")` sites in 77 files.
- `--profile` is MCP-only disclosure: `Profile::loads` (`src/profile.rs:754-759`) is static family membership; the sole call-side check is `src/mcp/mod.rs:3571`. No `.loads(` in `src/handlers/` (387 `.route(` sites); HTTP uses the profile only to list tools (`src/handlers/admin.rs:1696`). `[mcp.allowlist]` runs only on schema expansion (`src/mcp/registry.rs:1044-1049`); `allowlist_decision` is never called from tools/call or any handler.
- 104 tools: `tool_names::ALL` and the `pub const MEMORY_*` set both count 104 in `src/mcp/registry.rs`.
- Authz: `pub struct Permissions` at `src/governance/mod.rs:465` (no `src/permissions/`); 47 `Permissions::evaluate` sites in 21 files; `resolve_caller_authority` absent. `src/coordination_guard.rs:1-40` is input bounds/attribution, not authorization.
- Restore: mtime newest-wins at `src/cli/backup.rs:858-870`; sha256-only `BackupManifest` (`:13-16`, `:384`), no signature check. #3549, #3199, #3124 all OPEN `ga-blocker`/`ga-freeze` (gh, 2026-09-09).
- Freeze: cert standard §6 L278-283 (tag vs `cert` = v1.1.0); 0c N11 resolver + guard is **tag**, M (L289); 15 N12 restore fixes **tag** (L310); 16 soak needs "last binary-changing step precedes it" (L311). No row for a crate extraction. Fable §8 L360-371: hygiene lands in v1.1.0.
- Fable §0 reasons at L33, 37, 45, 49, 51; reason 5 = "#3501 VOID + #2437 relevance harness"; §8 L371: "#2437 stays a GA and cert blocker".
- The five named DDL sites all sit below each file's first `#[cfg(test)]` (735<1293, 3394<3539, 1565<4877, 555<591, 328<378); a plain grep hits 25 files, not 5.

**Where the assessment is wrong or overstated:**
- Falsifier 4 misquotes the five reasons and drops reason 5, which holds a recall-quality GA blocker (#2437). It *is* a blocker, orthogonal to the kernel.
- "`--profile` is a filter" understates: it is absent on HTTP and the allowlist never touches tools/call.
- "Verify the five sites" is stale (test fixtures), and the unstated exclusion rule hides 25 raw hits.
- Falsifier 3 is right on latency and one-binary UX (a workspace member statically links into the same `[[bin]]`) but hides the real cost: crates.io publish becomes an ordered set, the `sal` cut spans 77 files, ~1.1k `crate::storage::` and ~1.6k `crate::identity::` paths move.

**Where the assessment is right:**
- The gap is authorization at dispatch: 47 sites, no resolver, MCP-only profile gate. #3549 (tag, M) is the cheapest transport-neutral control.
- Restore is the one un-gated apply path; #3199 is correctly GA-blocking.
- No extraction inside the freeze matches the operator rule.
- Privileged surface < 104 tools holds only by convention today.

**Required amendments to #3581 before acceptance:**
1. Quote the audit's actual five reasons (L33-51); state #2437 is a GA+cert blocker independent of the kernel question.
2. State that `--profile`/`[mcp.allowlist]` are MCP disclosure controls (registry.rs:1044-1049, mod.rs:3571), absent on 387 HTTP routes; #3549's resolver must be specified for both transports.
3. Replace "verify the five sites" with the classification, define the 5-vs-25 exclusion rule, add a CI guard: no `CREATE/ALTER TABLE` outside the ladder except under `cfg(test)`.
4. Placement rule for the v1.1.0 extraction: it is binary-changing, so it lands before N14 and N16's last binary-changing step, or moves to v1.2. Acceptance: same single `[[bin]]`, guard allowlist byte-identical before/after, workspace publish plan.
5. Record the guard's allowlist-with-reasons as the frozen boundary spec; extraction may not add entries.

**One risk if followed / one risk if ignored:**
Followed: v1.1.0 refactors and certifies the same binary, extraction lands after the soak, and G1–G8 evidence is void — hence amendment 4.
Ignored: each new MCP or HTTP tool is another place to forget `Permissions::evaluate`, found one route at a time as in chain 3.
