## Conductor: 1x3 audit + codegraph audit — ADJUDICATED (Fable 5.1, 2026-09-10)

Three independent hard-coder-tier auditors (A security/authority, B architecture/blast radius, C contracts/tests/operability), read-only, codegraph 1.6.0 before grep, rust-1.98 rule IDs. Reports: `docs/reviews/fable-1x3-2026-09-10-3587-evidence/` (redacted). The body above is amended in place (✎).

### Consensus verdicts
| Unit | A | B | C | Ruling |
|---|---|---|---|---|
| U1 | do-not-ship as specified | ship-with-changes | ship-with-changes | **Re-scoped** (below), own GA-boundary review gate |
| U2 | ship-with-changes | ship-with-changes | do-not-ship (cursor) | **Ship** with dedup-based idempotency, no schema change |
| U3 | ship-with-changes | ship-with-changes | ship-with-changes | **Ship first** (detection needs nothing from U1) |
| U4 | ship-with-changes | ship-with-changes | ship-with-changes | **Ship**, Claude Code only, `--hook capture` |
| U5 | ship | ship-with-changes | ship-with-changes | **Split** U5a (ceilings first) / U5b (docs last) |
| U6 | ship-with-changes | do-not-ship as written | ship-with-changes | **Ship** after U2's Postgres path + a service unit |

### Blockers found (all three agree unless noted) and the ruling
1. **Archive XOR link.** A `supersedes` link to an archived row violates the `memory_links` FK (`storage/mod.rs` update_with_archive_on_supersede, #895). Ruling: archive + `metadata.superseded_id`, no link. U3's predicate keys on metadata/archive state, not links.
2. **The premise was wrong.** `cli/link.rs::cmd_resolve` demotes the loser (priority 1, confidence 0.1), writes an unsigned link, does not archive, has no authority check, refuses Postgres. Ruling: new two-backend primitive `archive_as_superseded`; `update_with_archive_on_supersede` cannot be reused either (it patches the old row and would drop the caller's attestation).
3. **Default `on_conflict = merge` destroys the ruling** (A, C): non-claude-code clients upsert in place on `(title, namespace)`, so store #2 overwrites the old ruling before "superseding" it. Ruling: `ruling_key` forces error/mint-new-id and asserts `actual_id != old_id`.
4. **No hardened principal at the MCP chokepoint** (A): the mutation gate is inert unless `AI_MEMORY_AGENT_ID` is set; clientInfo-derived ids are self-asserted. Ruling: supersede only on a hardened principal (env id, attested signer, HTTP header, or admin); otherwise store and echo `supersede_skipped`. Empty-owner rows refused. Priority removed from the authority set.
5. **`supersede_on_contradiction` reverses G7 (#1824)** (A). Ruling: cut from v1.0.0; no `[autonomy]` section.
6. **Four write funnels, not one** (A, C): MCP, HTTP sqlite, HTTP postgres, CLI. Ruling: one funnel beneath all four + parity test; bulk refuses `ruling_key`; federation-forward decides once.
7. **`HostKind` must not carry a path** (all three; 41 symbols, `Copy`, wire shape). Ruling: `WatchSource` at the watcher layer.
8. **DB byte cursor = undeclared schema v99 and lossy on rotation** (B, C). Ruling: reuse `transcript_line_dedup` content hashes; in-memory `(dev, ino, len, offset)` detector; zero schema change; daemon mode allowed.
9. **Self-asserted authorship from file bytes under an admin-bypass context** (B). Ruling: `agent_id` = watch process principal; actor prefix → `metadata.observed_actor`.
10. **`watch` has no Postgres path and no `refuse_pg_store`** (B). Ruling: both the refusal and the SAL path land in U2; U6 gated on it.
11. **Stop payload has no turn index; a synchronous hook can stall the operator** (B). Ruling: `--host-turn-index auto` derived in-transaction, `"async": true`, `--quiet` never-fail.
12. **Wrong flag shape** (B, C): `--hook capture` on the existing `HookKind` seam, not a bool on the shared `TargetArgs`; Codex leg collides with a pinned refusal → dropped.
13. **U3 digest is a write with quota and can storm** (A): one per sweep at the 60 s floor = 1440 rows/day (the `_curator/reports` incident class). Ruling: stale-set-hash dedup + 86400 s floor + short tier; recipient validated at boot; sender = curator via `handle_notify_as_sender`.
14. **"QUAL ceilings unchanged" was false** (B, C): storage/mod.rs 152 lines headroom, config.rs 92, install.rs 42; CLI subcommand counts move. Ruling: U5a lands the lockstep bumps first.
15. **No daemon lifecycle for U6** (C). Ruling: `ai-memory-watch.service` + launchd plist + runbook.

### Gaps the proposal did not close (C) and the ruling
- Only the Stop hook makes a stopped writer write again, and only for Claude Code: accepted for v1.0.0; Codex/Grok capture arrives through the line-file source (their outbox protocol is their turn log).
- Two truth sets (f2 Conductor DB, f1 hive): documented as a boundary; supersession is per store.

### Effort
Adjudicated 19.5 deputy-days (A 18–22, B 13.5, C 10.5–17). Ordering: U5a → U3 ∥ U2 → U1 → U4 → U5b → U6. U1 and U3 never ship in the same chain (U3 is the observability that would catch U1 misbehaving).

### Codegraph audit (Conductor)
`codegraph impact` on `handle_store` (73 symbols), `HostKind` (41), `WatchConfig` (27), `handle_capture_turn` (27), `is_managed_value` (15), `cmd_resolve`; explore on the resolve/append-and-archive paths. All blast-radius lists and rule (e) pin censuses are in the three reports.

**Deputies released**: Grok U5a → U2 → U4 → U5b; Codex (after #3582) U3 → U1; Conductor U6. Tests named in the reports are the acceptance criteria per unit.
