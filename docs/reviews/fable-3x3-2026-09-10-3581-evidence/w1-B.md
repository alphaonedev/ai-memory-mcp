## Ballot W1-B (data integrity)
**Vote:** B — the data-integrity half of the "kernel" is already a real boundary (schema, import, federation apply); only restore is not fork-safe, and that is #3199, not a crate.

**Verified evidence (file:line):**
- Single ladder: `src/storage/migrations.rs:995` `CURRENT_SCHEMA_VERSION: i64 = 98`; forward-version refusal `:1858`; pre-migration snapshot `:1137,1894`. Gate `scripts/check-migration-ladder.sh` wired in CI (`.github/workflows/c8-precheck.yml:488,494`) checks duplicates, gaps, cross-adapter parity, orphan files, bootstrap→ladder forward refs, metadata rows (script header lines 27-91). It does NOT scan `src/` for stray `CREATE TABLE`.
- Out-of-ladder DDL: my sweep finds 25 files, not five. Every hit is inside a `#[cfg(test)] mod tests` or a comment (e.g. `src/visibility.rs:1293`, `src/signed_events.rs:4045`, `src/revisions.rs:591`, `src/mcp/tools/check_agent_action.rs:378`, `src/daemon_runtime.rs:12897` inside test fn at `:12867`). The single production string, `src/storage/embed_skip.rs:83`, is the v96 migration SQL the ladder itself includes (`src/storage/migrations.rs:4407`). Schema is fully isolated; no ad-hoc side tables.
- Import: `src/portability/import.rs:9-20,369-376,443` one `BEGIN IMMEDIATE` transaction, all-or-nothing; `:335-349` spec/schema-version fail-closed; `:380-401,414-433` staged audit spine, revision chain and lineage re-verified in-tx (forged → rollback); `:712-730` `ConflictMode::Version` default suffixes the incoming title, `Merge` is opt-in, `Error` skips; enum at `src/storage/mod.rs:2462-2474`.
- Federation receive: `src/handlers/federation_receive.rs:2211-2275` cert↔peer binding, TOFU allowlist, then `verify_signature_or_reject`; `src/handlers/federation_signing_check.rs:2459-2534` peer enrollment REQUIRED when env unset (#1789), hatch `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS`; `src/federation/signing.rs:240-248` + `receive_auth.rs:381-385` sig and nonce default-on. Authority-granting transitions fail closed (`receive_auth.rs:7-16`); memory/link rows are "accept-and-flag-unsigned" data.
- Federation apply: `src/storage/mod.rs:17760` `merge_inbound` is atomic read-merge-write, same-id rows field-merge via `merge_memory`, peer attest_level neutralised and `updated_at` capped before the LWW tiebreak; `(title,namespace)` dedup falls to newer-wins `insert_if_newer` (`:17269`).
- Restore: `src/cli/backup.rs:857-884` directory restore picks max-mtime snapshot, manifest is the co-located `<stem>.manifest.json`; `:899-905` `--skip-verify` bypasses the whole manifest block; `BackupManifest` (`:384-407`) has sha256 but no signature; zero `ed25519|sign` hits in the file. Behaviour is pinned by `test_restore_from_directory_picks_newest` (`:1305`). #3136 (staged/verified/atomic swap, `:1108-1116`) merged 2026-08-23 but did not change the pick. #3199 OPEN, ga-blocker.

**Where the assessment is wrong or overstated:**
- "Five files" undercounts the match set (25) and frames it as unresolved; the classification is clean and can be stated as fact now.
- "Migration-ladder gate in CI" is implied to cover stray DDL; it does not — nothing structurally forbids a future runtime `CREATE TABLE` outside the ladder.
- "Fail-closed" federation is accurate only as *default-on with env opt-outs*; per-row memory/link signatures are accept-and-flag, not refuse. Still correct on the substance: peer envelope signed, enrollment required, merge forgery-resistant.

**Where the assessment is right:**
- Restore is the only non-fork-safe apply path; the poisoned-snapshot-with-newer-mtime attack is exactly as described in #3199.
- Import and federation apply are adequate; no crate boundary would add a control they lack.
- Schema/durable commit is isolated; #3124 (sqlite allows unstamped rows, postgres refuses) is the remaining commit-truth split.

**Required amendments to #3581 before acceptance:**
1. Replace the "five files to classify" row with the verified result: 25 files, all test fixtures/comments, one ladder-sourced const; schema isolation is proven, not pending.
2. Add a gate clause (or a `tests/` pin) that fails on any non-test `CREATE|ALTER TABLE` outside `migrations.rs`/`storage/mod.rs`/`store/postgres`/`embed_skip.rs`, so the isolation is enforced, not observed.
3. Reword the federation cell to "default-on, env opt-out (`REQUIRE_SIG`, `REQUIRE_PEER_ENROLLMENT`, `ALLOW_UNENROLLED_PEERS`); asi-hard floor via `security_profile.rs:66,270`"; note memory rows are flagged, not refused.
4. Scope #3199 explicitly to also cover `--skip-verify` and the manifest-less pre-migration snapshot path (`backup.rs:989-1000`), or those remain unsigned back doors after signing lands.

**One risk if followed / one risk if ignored:**
If followed: the v1.1.0 "core" extraction re-homes `merge_inbound`/`import_full_envelope` and resets the gate evidence that currently proves them, for no new control.
If ignored: restore stays an unsigned newest-wins apply, so anyone with backup-dir write access forks the ledger through routine DR while federation, the path everyone watches, is already gated.
