# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-07-21

### Security

- **All postgres content-write funnels now route through at-rest content sealing — closing a multi-funnel confidentiality bypass of `AI_MEMORY_ENCRYPT_AT_REST`** ([#2292](https://github.com/alphaonedev/ai-memory-mcp/issues/2292), sibling of [#2288](https://github.com/alphaonedev/ai-memory-mcp/issues/2288); v1.0.0 pre-ship, `security` class). After #2288 sealed `store_batch`, only `store()` / `store_batch()` / the in-place `update()` routed `content` through `crate::encryption::seal_content` before their INSERT. Every OTHER postgres content-write funnel bound **plaintext** into the `content` column and never populated `encrypted_envelope` (schema v68), so under an enabled `AI_MEMORY_ENCRYPT_AT_REST` gate these paths persisted PLAINTEXT while the operator believed at-rest encryption was on — the same silent bypass as #2288, on a WRONG at-rest posture (not "reduced function"). A verification sweep confirmed **nine** bypassing funnels (the issue's audit listed seven; the sweep additionally found `merge_inbound` — a same-id full-row UPDATE that would overwrite an already-sealed row's `content` with plaintext AND leave a stale ciphertext envelope (desync + leak) — and the DEFAULT non-If-Match trait `update()`, the worst of the class (SILENT DATA LOSS; see below)): `store_with_embedding` (the PRIMARY semantic-recall hot path), `capture_turn_idempotent` (L4), `recover_turn_idempotent` (L2), `apply_remote_memory` (federation inbound), `consolidate`, `reflect_with_hooks`, `update_with_archive_on_supersede` (the append-and-archive twin), `merge_inbound`, and the trait `update()`. **Fix (precedent-copy of the #228/#2288 `store()` seal — NO new persisted representation, NO trait/wire/route/schema change):** a shared private `seal_content_for_insert(&Memory) -> (content_to_store, encrypted_envelope)` helper extracts the `store()` seal into ONE site (gate ON → empty placeholder + sealed `0x03` envelope bytes; gate OFF → verbatim content + NULL envelope, byte-identical; fail-closed on a missing `metadata.agent_id`, mirroring `store()`), and every funnel binds its output into the `content` + `encrypted_envelope` columns. On the two upsert funnels with a NEWER-WINS content arm (`apply_remote_memory`, and `merge_inbound`'s resolved-merge write), the envelope moves in **lockstep** with `content` under the IDENTICAL predicate so a merge that keeps local content keeps the local envelope (an unconditional `EXCLUDED.encrypted_envelope` would desync the two). **The trait `update()` (9th funnel — SILENT DATA LOSS, not merely a leak):** its live `UPDATE` bound `patch.content` PLAINTEXT via `content = COALESCE($3, content)` with NO `encrypted_envelope` in the SET, so a content patch on a sealed row wrote V2 plaintext while the row kept the stale cipher(V1) envelope — `get()` (which decrypts on envelope-PRESENCE) then returned the OLD V1, silently discarding the V2 write, leaking V2 in the clear, and bricking the row on key rotation. It now seals the effective new content (the same Rust computation as the If-Match twin `update_with_expected_version_once`) and moves the envelope in lockstep via `encrypted_envelope = CASE WHEN $3 IS NULL THEN encrypted_envelope ELSE $13 END` so a metadata-only patch (`$3 IS NULL`) leaves the sealed envelope UNTOUCHED while a content patch replaces both. **The same sweep closed a latent sibling bug in the If-Match twin:** its unconditional `encrypted_envelope = $13` nulled the sealed envelope on a metadata-only update under an enabled gate (the placeholder-content re-seal returns None, so NULL was bound) — the same silent-data-loss shape; the twin now uses the IDENTICAL CASE guard so the two update paths behave identically. Data-integrity / at-rest-confidentiality (North Star: fail-closed, never silently store plaintext the operator asked to be protected, never silently lose the durable text). **sqlite parity:** the sqlite chokepoint `storage::insert` (+ `insert_if_newer` / `merge` / `update` / archive-restore) already seal the corresponding paths; the ONLY sqlite gap found is `consolidate` (`storage::mod.rs` INSERT omits `encrypted_envelope` + never calls `seal_content`) — a separate-file fix, now FIXED in [#2301](https://github.com/alphaonedev/ai-memory-mcp/issues/2301) (see the sibling bullet below). Regression coverage: `tests/store_parity_gaps.rs::postgres_side::pg_{store_with_embedding,apply_remote_memory,capture_turn,recover_turn,reflect,consolidate,supersede,merge_inbound,update}_seals_content_2292` (live-PG, `#[ignore]`, teardown-before-assert per #2287; each asserts the stored `content` column holds the empty placeholder with NO plaintext + `encrypted_envelope` present + `get` transparently decrypts, plus gate-OFF byte-identical pins on the unconditional + newer-wins conflict shapes, and the `update` test additionally pins the no-data-loss property — `get` returns the NEW V2, not the stale V1 — and the metadata-only-preserves-envelope CASE guard). No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.
- **SQLite `storage::consolidate` now seals the consolidated summary through the at-rest encryption chokepoint (closes an at-rest-encryption BYPASS on the consolidate funnel)** ([#2301](https://github.com/alphaonedev/ai-memory-mcp/issues/2301), v1.0.0 pre-ship; SQLite sibling of the Postgres [#2292](https://github.com/alphaonedev/ai-memory-mcp/issues/2292) / [#2288](https://github.com/alphaonedev/ai-memory-mcp/issues/2288) class). `db::consolidate` mints the consolidated summary via its OWN raw `INSERT INTO memories (...)` that bypasses the `db::insert` chokepoint (where the SQLite seal normally lands, `src/storage/mod.rs:1181`). Pre-#2301 that INSERT bound the plaintext `summary` into the `content` column and never called `seal_content`, so a curator consolidation under `AI_MEMORY_ENCRYPT_AT_REST=1` (sqlcipher build) persisted the summary as PLAINTEXT at rest while the operator believed at-rest encryption was on (a silent confidentiality bypass; North Star: DATA INTEGRITY / never silently store what the operator asked to be protected). `consolidate` now mirrors `db::insert` EXACTLY: it seals the plaintext `summary` to the consolidator's per-agent key (`crate::encryption::seal_content(summary, consolidator_agent_id)`), binds the empty placeholder into `content`, and adds `encrypted_envelope` to the INSERT column list + bound value. The content-id (`cid`) is still minted from the PLAINTEXT summary BEFORE the seal swap (unchanged hashing). With encryption OFF (default) `seal_content` returns `None` and the path is byte-identical to before. Regression coverage: `tests/encryption_at_rest.rs::{issue_2301_consolidate_on_path_seals_summary_and_get_decrypts, issue_2301_consolidate_off_path_is_byte_identical}` (the on-path test is a mutation check — it fails on pre-fix code). The other SQLite content-write funnels (`insert`, `insert_with_conflict`, `insert_if_newer` + merge arm, `update`) already seal; `restore_archived*` carry the already-sealed envelope via their INSERT-SELECT — consolidate was the sole remaining SQLite gap.

### Fixed

- **Federation catch-up `/sync/since` puller now signs its outbound GET, so an enrolled peer's catch-up pull works under the default `AI_MEMORY_FED_REQUIRE_SIG=1` posture** ([#2290](https://github.com/alphaonedev/ai-memory-mcp/issues/2290), found live on the DO GA certification 2-droplet mTLS mesh). The inbound `/sync/since` receiver (`verify_get_signature_or_reject`, `src/handlers/federation_signing_check.rs`) enforces the #1031 signed-GET contract — an ENROLLED peer that omits `X-Memory-Sig` is refused `401 x_memory_sig_missing`. But the OUTBOUND catch-up clients never signed the GET: the serve-daemon catch-up loop (`catchup_once_with_store` + the non-`sal` `catchup_once_legacy` arm, `src/federation/receive.rs`) and the `sync-daemon` CLI pull (`daemon_runtime::sync_cycle_once`) attached only `X-Agent-Id`/`X-Peer-Id`/`x-api-key`. So on the MOST-secure (fully enrolled, default-strict) mesh the catch-up/pull lane was structurally `401`'d on every tick, while it silently worked in the unenrolled/permissive postures — a functional break of federation catch-up under the shipping secure default (DEGRADE, not corrupt: fewer results, never wrong ones). **Fix (a straight precedent-copy of the `/sync/push` client signing — no new posture, no new wire representation):** the outbound GET is now signed with the daemon signing key exactly as the push lane signs its body — `X-Memory-Sig: ed25519=<b64(sign(canonical_get_bytes(method,path,query) || 0x00 || nonce))>` + a fresh `X-Memory-Nonce`. The canonical GET bytes are hoisted to ONE SSOT (`crate::federation::signing::canonical_get_bytes`) that BOTH the receiver verifier (which now delegates to it) and the new client signers (`sign_get_request` / `sign_get_url`) share, so the two ends can never drift (any divergence fails CLOSED at the receiver, never silently accepts). The URL is parsed exactly as `reqwest` sends it, so the signed path+query match the receiver's `OriginalUri` byte-for-byte. When no daemon signing key is on disk the GET stays unsigned (byte-identical to the pre-#2290 wire), preserving the permissive/unenrolled `AI_MEMORY_FED_REQUIRE_SIG=0` posture. Regression: `tests/federation_sync_since_catchup_sig_2290.rs` — a mock `/sync/since` receiver that enforces the SAME signature contract accepts the signed catch-up GET (`200`) and refuses the pre-fix unsigned GET (`401`, the exact #2290 break, mutation-pinned). No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.

- **Federation catch-up `/sync/push` PUSH lane of `daemon_runtime::sync_cycle_once` now signs its outbound POST body, so an enrolled peer's `sync-daemon` push works under the default `AI_MEMORY_FED_REQUIRE_SIG=1` posture** ([#2297](https://github.com/alphaonedev/ai-memory-mcp/issues/2297), the PUSH sibling of #2290, found by the #2296 adjacent-finding audit). The inbound `/sync/push` receiver (`verify_signature_or_reject`, `src/handlers/federation_signing_check.rs`) enforces the #791/#922 body-signature contract — an ENROLLED peer whose POST omits `X-Memory-Sig` is refused `401 x_memory_sig_missing`. But `daemon_runtime::sync_cycle_once`'s PUSH direction attached only `X-Agent-Id`/`X-Peer-Id`/`x-api-key` — no `X-Memory-Sig` (the #2290/#2296 fix signed only the PULL/`/sync/since` GET of the same function). So on the MOST-secure (fully enrolled, default-strict) mesh the CLI `sync-daemon` push lane was structurally `401`'d on every tick, while it silently worked in the unenrolled/permissive postures — a functional break of federation push under the shipping secure default (DEGRADE, not corrupt: the push never converged, but no wrong data was written; the memory TEXT stayed the durable source of truth). **Fix (a straight precedent-copy of the working `/sync/push` client signing in `src/federation/sync.rs` — no new posture, no new wire representation):** the push body is serialised ONCE to bytes and sent via `.body(bytes)` (not `.json()`, which would re-serialise and perturb the signed bytes), then signed with the daemon signing key (`crate::governance::audit::load_daemon_signing_key(local_agent_id)`) as `X-Memory-Sig: ed25519=<b64(sign(body_bytes || 0x00 || nonce))>` + a fresh `X-Memory-Nonce` per the #922 nonce binding. When no daemon signing key is on disk the push stays unsigned (byte-identical to the pre-#2297 wire), preserving the permissive/unenrolled `AI_MEMORY_FED_REQUIRE_SIG=0` posture. Regression: `tests/federation_sync_push_catchup_sig_2297.rs` — the REAL `sync_cycle_once` client drives against a mock `/sync/push` receiver that enforces the SAME body-signature contract, with the daemon key enrolled on disk under `AI_MEMORY_KEY_DIR`; it accepts the signed push (`200`, `sync_cycle_once` returns `Ok`) and refuses the pre-fix unsigned push (`401`, `sync_cycle_once` returns `Err` — the exact #2297 break, mutation-pinned). No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.

- **`tests/form_1_synthesis.rs` test-isolation flake on the synthesis prompt-size telemetry counter** ([#2285](https://github.com/alphaonedev/ai-memory-mcp/issues/2285), observed on [#2283](https://github.com/alphaonedev/ai-memory-mcp/pull/2283) CI run 29852909319). `run_synthesis_pass` (`src/mcp/tools/store/synthesis.rs`) calls `build_prompt_with_cap` — which records the process-global `SYNTHESIS_PROMPT_MAX_CHARS` running-max telemetry counter — unconditionally whenever a store engages synthesis, BEFORE any K9 recheck / delete-cap / failure-mode disposition. Only the two dedicated PERF tests that assert an exact count on that counter held the pre-existing `prompt_max_chars_lock()` guard; every other synthesis-engaging test in the file (14 of them) wrote the same global counter without holding it, so under cargo's default parallel test runner one of those writer tests could land a larger max between an asserting test's prompt build and its `assert_eq!`, producing an intermittent failure. Test-only fix: every test whose `run_store`/`run_store_with_embedder` call reaches `run_synthesis_pass` now takes the same shared `prompt_max_chars_lock()` guard for the duration of the test. No production code changed.

### CI

- **Build-script vetting claims are now mechanically pinned** ([#2259](https://github.com/alphaonedev/ai-memory-mcp/issues/2259); pre-ship 3x7 Wave-B). The formal supply-chain record now covers the actual `reed-solomon-simd` 3.1.0 `build.rs` and its `readme-rustdocifier` 0.1.1 build dependency (including that helper's own build script and full source): both are documentation-only `README.md` → `OUT_DIR` transforms with no network/process/unsafe/native-probe behavior. `scripts/check-build-script-vetting.py`, run in CI, fails on checksum, custom-build-target, or exact build-dependency-closure drift so a future "no build scripts"-style claim cannot rest on an unchecked assumption.

- **Run the SDK-shim test suites in CI + gate the publish on them** ([#1390](https://github.com/alphaonedev/ai-memory-mcp/issues/1390) / [#2212](https://github.com/alphaonedev/ai-memory-mcp/pull/2212); pre-ship 3x7 battery). The four Direct-API SDK shim packages under `clients/` (`anthropic-shim-py`, `openai-shim-py`, `anthropic-shim-ts`, `openai-shim-ts`) ship genuine pytest / `node:test` suites that NO CI job executed, while `publish-sdk-shims.yml` published to PyPI/npm after BUILD-ONLY steps — a broken shim could publish green at the GA release moment. New `.github/workflows/clients-ci.yml` (path-filtered to `clients/**`) runs pytest for the two Python packages (Python 3.12) and `npm test` for the two TypeScript packages on every PR/push touching `clients/**`; the SAME suites are now wired into `publish-sdk-shims.yml` BEFORE each publish step so nothing ships without its tests passing. The TS `test` script needs Node >= 22.6 (`--experimental-strip-types`), so both the new CI leg and the two npm publish jobs run Node 22 (the publish jobs were pinned to Node 20, which cannot run the test script); the published `dist/` still targets the `engines` node >= 18 consumers.

### Fixed

- **Postgres `store_batch` now persists caller-supplied `kind_provenance`** ([#2289](https://github.com/alphaonedev/ai-memory-mcp/issues/2289), v1.0.0 pre-ship). `store_batch`'s INSERT never listed the `kind_provenance` column (#1945, schema v79 — HOW the `memory_kind` was assigned), so a batch-stored memory silently lost caller-supplied epistemic-typing provenance on postgres while `store()` and the sqlite trait-default loop both persist it. The bulk INSERT now lists `kind_provenance` in its column list + per-row `push_bind` (derived from `metadata.kind_provenance` via `crate::storage::extract_kind_provenance`, matching `store()`) + a `COALESCE(EXCLUDED.kind_provenance, memories.kind_provenance)` conflict arm mirroring `store()`. Regression coverage: `tests/store_parity_gaps.rs::postgres_side::pg_store_batch_persists_kind_provenance_2289` (live-PG, `#[ignore]`).

- **`content_patch` unique-match gate now counts OVERLAPPING occurrences so a self-overlapping needle fails closed** ([#2111](https://github.com/alphaonedev/ai-memory-mcp/issues/2111), v1.0.0 Gate-3 correctness review). `ContentPatch::apply`'s `content_replace_from` uniqueness check used `str::matches().count()`, which counts NON-overlapping occurrences: a self-overlapping needle (`replace_from="aa"` on `"aaa"` — occurrences at overlapping index 0 and 1) counted as 1, bypassing the ambiguity gate and silently first-match-replacing the durable memory TEXT to `"Xa"`, violating the documented "occurs EXACTLY once … never a silent first-match replace" safety property (#1974). A new overlap-aware `count_overlapping` helper (a sliding `haystack[i..].find(needle)` walk advancing one UTF-8 char per hit) drives the gate, so the ambiguous case reports `>1` → `PatchError::ReplaceMultiple` (rejected, no bytes change). Genuinely-unique needles (including multibyte) and non-overlapping multi-occurrence needles are unaffected. Data-integrity fix (North Star: never silently corrupt durable memory text). Regression coverage: `content_patch::tests::{replace_self_overlapping_needle_rejected_as_ambiguous, replace_non_self_overlapping_unique_still_ok, replace_non_overlapping_multi_occurrence_still_rejected}`.

- **Import hardening: reserve the SQLite writer up front and strip v1 identity-key claims by default** ([#2250](https://github.com/alphaonedev/ai-memory-mcp/issues/2250), [#2264](https://github.com/alphaonedev/ai-memory-mcp/issues/2264), v1.0.0 pre-ship Wave-B). The all-or-nothing v2 importer now opens `BEGIN IMMEDIATE`, preventing a concurrent writer from invalidating its read snapshot and causing an un-retried `SQLITE_BUSY_SNAPSHOT` during the later write upgrade. The default untrusted v1 importer now removes wire `metadata.agent_pubkey` and `write_signature` claims and downgrades any carried attestation to `claimed` after caller restamping, so a crafted `_agents` row cannot plant a key used to attest future writes. Explicit `--trust-source` backup restores retain their documented verbatim posture.

- **Deferred-audit panic recovery now retains the queue receiver and retries the in-flight event** ([#2271](https://github.com/alphaonedev/ai-memory-mcp/issues/2271), v1.0.0 pre-ship flake). The supervisor owns the receiver, catches sink panics at the synchronous append boundary, rebuilds the sink, and retries the same occurrence within a bounded, scheduler-friendly restart budget. Every submission receives a stable occurrence ID reused as `signed_events.id`; retry/recovery accepts existing chain or DLQ residence only when every matching payload hash agrees. New journal records publish owner-private files with atomic no-clobber links from fsynced staging files into an owner-private spool: Unix creates exact `0600` files / `0700` directories and accepts only root- or daemon-owned lexical/resolved ancestors; any group/world-writable ancestor is rejected unless root/daemon ownership plus the sticky bit provides rename containment, and macOS rejects nontrivial extended ACLs on every ancestor and artifact handle. Windows atomically supplies a protected current-token-owner-only DACL, validates owner/DACL/type/reparse status on retained handles, rejects lexical ancestor reparses, and retains every root-to-parent ancestor plus the spool without delete sharing. Each Windows ancestor must be owned by the daemon, SYSTEM, Administrators, or TrustedInstaller and may grant delete-child/delete/security-control authority only to those principals. These live and durable ancestor invariants prevent a writable-parent or junction rename/swap during admission or after a crash. Startup rejects pre-existing wrong-owner or non-private spool, journal, lock, staging, event, probe, and overflow artifacts rather than repairing or deleting and trusting possibly planted evidence. Because this intentionally rejects inherited-DACL artifacts from earlier Windows builds, the security guide includes a stop/preserve/inspect/recover-with-the-prior-signed-binary/move-aside/restart runbook; v1.0.0 never ACL-repairs and trusts exposed evidence in place. Records are acknowledged after durable chain/DLQ residence and enforce 4,096-entry/32-MiB fail-closed admission bounds under a cross-process OS lock with authoritative rescans. Boot holds that stable lock across the complete snapshot → residence/cardinality check → chain/DLQ append → acknowledgement → legacy-truncation lifecycle, preventing concurrent recovery from duplicating legacy frames or creating dual chain/DLQ residence; `BEGIN IMMEDIATE` transactions recheck both chain and DLQ residence before either insertion, making a matching peer-process append idempotent and preventing dual residence. Boot reconciles complete trusted staging frames and safely removes torn trusted staging while exclusively locked. Up to 256 durable overflow evidence records preserve timestamp/occurrence/payload identity before a saturation marker; startup surfaces their presence. Directory metadata uses write-through flushing on Windows and fsync on Unix, and startup validates filesystem publication support. Recovery/journal-open failure returns a closed audit queue instead of silently downgrading to volatile delivery, while typed audit-admission failures bypass consultation-only fail-open overrides and keep the action blocked. Corrupt complete legacy frames fail closed and legacy aggregate replay is likewise capped. SQLite retry classification is restricted to the chain sequence index.

- **Direct-API SDK shims preserve vendor promise APIs and keep capture work off async event loops** ([#2253](https://github.com/alphaonedev/ai-memory-mcp/issues/2253), [#2254](https://github.com/alphaonedev/ai-memory-mcp/issues/2254), [#2255](https://github.com/alphaonedev/ai-memory-mcp/issues/2255); pre-ship 3x7 Wave-B). The TypeScript wrappers now return the original Anthropic/OpenAI `APIPromise` unchanged (retaining `.withResponse()` / `.asResponse()`) and attach non-consuming response observers; their default MCP capture transport uses ordered asynchronous child processes with timeout/output bounds instead of `spawnSync`. Python async wrappers offload both capture calls through `asyncio.to_thread`. All four READMEs now state accurately that cross-process re-run deduplication requires an explicitly stable session id; the default per-wrap UUID deduplicates only within that wrapped client.

- **Erasure cold-tier recovery and gc hardening** ([#2243](https://github.com/alphaonedev/ai-memory-mcp/issues/2243), [#2246](https://github.com/alphaonedev/ai-memory-mcp/issues/2246), [#2247](https://github.com/alphaonedev/ai-memory-mcp/issues/2247), [#2248](https://github.com/alphaonedev/ai-memory-mcp/issues/2248); pre-ship 3x7 Wave-B). Hostile manifest shard counts are validated before allocation/iteration; a durable purge-intent marker now blocks cross-process sweep re-minting until both the row and bundle are gone; sweep frontiers and per-store reconcile cursors persist across one-shot CLI gc processes; and ordinary reconcile ticks use a slow-refresh committed-bundle inventory, folding stale-temp cleanup into the refresh walk instead of performing two unbounded root scans. Recovery remains fail-closed and derived cache/state failures degrade to re-probing, never unverified payload bytes.

- **Erasure cold-tier sweep no longer runs under the shared HTTP request lock** (pre-ship 3x7 code battery, HIGH availability finding on [#2064](https://github.com/alphaonedev/ai-memory-mcp/issues/2064)). The daemon gc loop ran the #2064 erasure cold-tier sweep (`archive_sync::gc_tick` — up to `SWEEP_LIMIT_PER_TICK`=256 Reed-Solomon encodes + per-shard fsyncs, plus the reconcile/scrub pass) while holding the ONE global `Db = Arc<Mutex<(Connection, …)>>` every HTTP handler serializes on, so with `AI_MEMORY_ERASURE_COLD_TIER` enabled a draining backlog stalled the ENTIRE API for seconds-to-tens-of-seconds every gc tick. The sweep now runs on a **dedicated connection** opened from the daemon's stored DB path, inside `tokio::task::spawn_blocking`, AFTER the in-lock gc section drops the handler mutex (`archive_sync::gc_tick_detached`; the join is awaited so two sweeps of one store can never overlap — the keyset frontier + rotating reconcile cursor are single-sweeper state). Sound because the sweep is DB-READ-ONLY (bundle files are its only writes) and cross-connection concurrency with the purge/restore funnels is the already-supported regime (a CLI purge runs on its own connection against a live daemon); the #2213 invariants — purge-intent journal BEFORE `DELETE`, quarantine-not-destroy for un-journaled rowless bundles, the #2225 poison skip-set — are untouched (only WHERE the sweep's connection comes from changes; the process-static sweep state is keyed by store directory, which resolves identically). FAIL-CLOSED fallback: non-file-backed databases (`:memory:` / `mode=memory`, where a fresh connection would open a DIFFERENT empty database and the detached reconciler would mis-classify every live bundle as rowless) stay on the legacy under-lock tick via `archive_sync::is_in_memory_db_path`. Regression coverage: `tests/erasure_cold_tier_2064.rs::{detached_sweep_completes_while_handler_mutex_is_held, detached_sweep_refuses_non_file_backed_paths, gc_loop_runs_detached_erasure_arm_for_file_backed_db}`. No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.

- **SDK shims: a top-level JSON-RPC `error` capture response is no longer swallowed as success** ([#1390](https://github.com/alphaonedev/ai-memory-mcp/issues/1390) shim hardening; pre-ship 3x7 MEDIUM). The four shims' `capture_turn` transport classified a substrate response purely on the tool-level `result.isError` flag, so a top-level JSON-RPC `error` member (unknown-method / invalid-params / etc.) — which carries no `result` — slipped past the check and was mis-counted as a captured turn (a silent capture loss, masked because the shim is deliberately non-wedging). All four capture paths (`clients/*/…/_capture.py`, `clients/*-shim-ts/src/index.ts`) now screen `resp.error` before the `isError` branch and return `False`/`false` with a WARN. Regression coverage: hermetic offline tests (`test_capture_error.py` monkeypatching `subprocess.run`; `capture.test.ts` spawning a throwaway POSIX fake-substrate) assert JSON-RPC-error → failure, `isError` → failure, ok-result → success. No Rust surface — no SSOT-count move.

- **Claim-bitemporal VALID-time: canonicalize `valid_from`/`valid_until`/`valid_at` to ONE fixed UTC rendering so lexicographic comparison is exactly instant comparison (schema v86)** ([#1834](https://github.com/alphaonedev/ai-memory-mcp/issues/1834), pre-ship 3x7 battery HIGH; data-correctness). Every #1834 predicate — sqlite `build_list_query` (?), keyword `recall` (?13), hybrid FTS (?13) + semantic linear-scan (?11) SQL, the HNSW Rust re-filter, and the postgres `list` ($8) / `recall_hybrid` FTS ($10) / semantic ($11) `::text` binds — compared the RFC3339 TEXT columns BYTE-WISE against the caller's `valid_at`. RFC3339 admits many renderings of the SAME instant (`Z` vs `+00:00`, variable fractional digits, non-UTC offsets) and the substrate itself emits both `Z` and `+00:00` forms, so equal instants ordered WRONGLY as bytes: a `Z`-rendered `valid_until` at the boundary instant was wrongly INCLUDED against a `+00:00`-rendered `valid_at` (silently violating the documented start-inclusive/end-exclusive contract), and a `+05:00`-offset bound mis-filtered by HOURS. Default config, both backends. **Fix = canonicalize-at-boundary (T6-adjudicated over instant-typed predicates — it heals the on-disk data, keeps the SQL shape, and makes byte comparison exact):** the new `validate::canonicalize_valid_time` SSOT re-renders any parseable RFC3339 instant to the fixed-width UTC form `YYYY-MM-DDTHH:MM:SS.ffffffZ` (`SecondsFormat::Micros` = postgres `timestamptz` resolution; lexicographic order ≡ chronological order among canonical strings). Applied at EVERY trust boundary: the sqlite write funnels (`insert`, `insert_with_conflict`, `insert_if_newer`, `overwrite_full_row_by_id`, the `update*` `valid_until` patch), the postgres funnels (`store`, `store_batch`, `apply_remote_memory`, `merge_inbound`, both update funnels) — covering MCP/HTTP/CLI stores, federation receive, import, and CRDT merge structurally — plus every `valid_at` query bind on both backends. **Schema v86** (in-code Rust arm `normalize_valid_time_rows` sqlite / `migrate_v86` postgres; doc twins `migrations/sqlite/0070_v86_valid_time_canonicalize.sql` + `migrations/postgres/0043_v86_valid_time_canonicalize.sql`) normalizes pre-fix rows on `memories` + `archived_memories` once — INSTANT-PRESERVING (only the rendering changes; these columns are UNSIGNED metadata, outside the SignableWrite v2 envelope and the cid genesis pre-image, so no signature breaks), idempotent, and fail-safe (an unparseable value keeps its exact bytes — degrade, never destroy). Regression: `tests/claim_validtime_canonical_1834.rs` (equal-instant `Z`-vs-`+00:00` at the `valid_until` boundary excluded on keyword/hybrid/list; `+05:00`-offset `valid_from` window filters by INSTANT not bytes; the HNSW Rust re-filter twin via precomputed hits; the v86 arm normalizes legacy mixed renderings; the update patch canonicalizes the close instant) + the pg twin additions in `tests/claim_bitemporal_1834_pg.rs` (`#[ignore]` + `sal-postgres`). The #2030 conformance export golden (`conformance/vectors/export/round_trip_l3.json`) was REGENERATED under the new rendering (`db_schema_version` 85→86 + the two valid-time fields to canonical micros+`Z`; `cid` unchanged — valid-time is outside the cid pre-image), and the PORTABILITY-V2 §L1 valid-time clause now states the preserve-the-INSTANT / canonical-rendering contract. No new MCP tool / HTTP route / CLI subcommand; DB migration v85→v86 (SSOT pins + docs bumped in lockstep: settled v85 ladder arm literalized per the #2218 convention with `EXPECTED_CONST_ARMS_SQLITE` staying 8, corpus manifest, CLAUDE.md/DEVELOPER_GUIDE/integrations).
- **v75 lineage-DAG master flag now SEEDED at every production boot funnel — the feature is no longer silently inert in serve / mcp / CLI** ([#2233](https://github.com/alphaonedev/ai-memory-mcp/issues/2233); defaults-lie / data-provenance, surfaced by the #2229/#2215 pre-merge audit). `AppConfig::resolve_storage()` resolved `lineage_dag` (compiled default `true`) + `consolidate_tombstone_sources`, but `daemon_runtime::run` (the common serve / mcp / CLI config-resolution point) DISCARDED the resolved values (`let _ = (…)`) instead of seeding the process-wide atomics, so `crate::config::lineage_dag_enabled()` read the unseeded `false` default in EVERY production process. Consequence: native link writes never populated the schema-v75 `memory_links.source_cid`/`target_cid` content-id mirror, the P-wide acyclicity guard never ran, and the #2215/#2229 Portability-v2 import repopulation stayed inert (it correctly copied the native gate) — the whole v75 mirror feature shipped OFF despite the documented `true` default. No data was ever corrupted or lost (the mirror is derived/advisory; lineage queries `LEFT JOIN` live endpoints), but shipped behavior did not match the documented default. **Fix:** `daemon_runtime::run` now calls `crate::config::set_lineage_dag(resolved_storage.lineage_dag)` + `set_consolidate_tombstone_sources(…)` alongside the existing `set_db_mmap_size` / `set_age_projection_mode` / `set_screen_mode` boot seeds, so `lineage_dag_enabled()` reflects the resolved config (`true` by default, `false` when configured off) in every production process on both backends. The seed is `#[cfg(not(test))]`-gated for TEST ISOLATION ONLY (the lib's own `cargo test --lib` build skips it — a behavior-changing process-wide `AtomicBool` seeded by a `run()` dispatch test would flip it ON for a concurrent storage/consolidate unit test and make the suite order-dependent); the production binary AND every `tests/` integration test link the lib WITHOUT `cfg(test)` and exercise the real seed. Raw-library callers that never run the boot path keep the unseeded `false` default (the `append_only` test-isolation precedent). Regression: `tests/lineage_boot_seed_2233.rs` pins that a production-shaped `daemon_runtime::run` boot leaves `lineage_dag_enabled()` reflecting the config (`true` default; `false` when `[storage].lineage_dag=false`) AND that the v75 `source_cid`/`target_cid` mirror actually populates on a link write after that boot (the feature is no longer inert). **Operator-visible behavior flips (both documented-intended #1859 design, now actually live by default):** (1) `consolidate` now TOMBSTONES its source memories by default instead of hard-deleting them — the sources are retained (`lifecycle_state='tombstoned'`, id + cid preserved, navigable `derived_from` edges written) and excluded from every read/egress lane, so the visible corpus still collapses N→1 but physical storage grows; GDPR/erasure deployments that need hard-delete opt out with `AI_MEMORY_CONSOLIDATE_TOMBSTONE_SOURCES=0` (or `AI_MEMORY_LINEAGE_DAG=0`). (2) A `derived_from`/`reflects_on`/`derives_from` link that would introduce a BACKWARD chronology (a child older than its parent) is now REFUSED by the acyclicity guard with the documented `LINK_CYCLE_ERR_PREFIX` error envelope instead of being silently written. `tests/integration.rs::test_consolidation` was updated to assert the visible population via `list` (tombstone-excluded) rather than the raw `stats.total` COUNT(*), which now counts tombstoned rows (follow-up [#2237](https://github.com/alphaonedev/ai-memory-mcp/issues/2237) proposes a `stats` lifecycle breakdown; [#2238](https://github.com/alphaonedev/ai-memory-mcp/issues/2238) tracks a sqlite/postgres consolidate edge-gate parity gap). No new MCP tool / HTTP route / CLI subcommand / migration.
- **Erasure cold-tier sweep: a poison archived row no longer STARVES bundling of newer rows (R3 residual)** ([#2225](https://github.com/alphaonedev/ai-memory-mcp/issues/2225); tracked from the #2213 durability re-verify). The #2064 sweep's keyset frontier only advances over the CONTIGUOUS current/bundled prefix, so a permanently-failing (poison) archived row — a non-UTF-8 TEXT column, or the F4 non-finite REAL that bails loud — PINS the frontier: every tick re-starts before the poison row. The #2213 `SWEEP_PROBE_BUDGET_PER_TICK` (=4096) bounds the per-tick re-probe COST, but not the pin's DURATION: a poison row plus more than the probe budget of successors fills the budget on the already-current prefix before the tail is reached, so newer archived rows are never bundled until the poison row is fixed (bounded + loud — the archived DB rows are intact, a redundancy gap, never corruption). Fix: a bounded, process-static poison-id skip-set (`src/erasure/archive_sync.rs`). After `POISON_FAILURE_THRESHOLD` (=3) consecutive failures a row enters the skip-set with a WARN naming the id + reason; the sweep then PASSES it (not re-attempted, not charged against the probe budget) and lets the keyset frontier ADVANCE past it, so the starved tail drains. The set is bounded (`POISON_SKIP_SET_CAP` =4096, FIFO-evict-oldest past the cap → degrade to the pre-fix retry-and-repin for that one id, never OOM) and process-static: `reset_process_static_sweep_state_for_dir` (and a daemon restart) clears it so a repaired row is retried — self-healing, consistent with the keyset frontier's own restart-reset semantics. Follows the issue's prescribed design (TRUTH+PRESERVATION class, no 5-agent vote — DEGRADE not CORRUPT per decision memory `b682c76a`). Regression: `poison_row_does_not_starve_successor_bundling_2225` (successors bundle despite the poison predecessor; a settled tick re-probes NOTHING — `failed == 0`, the frontier has passed the poison row) + `poison_skip_set_clears_on_restart_2225` (a restart clears the skip-set and the poison row is retried) in `tests/erasure_cold_tier_2064.rs`. No new MCP tool / HTTP route / CLI subcommand / migration.
- **Backend archive-parity: the postgres SUPERSEDE-archive site is now LAST-WINS, matching sqlite — no more mistyped `NotFound` on re-supersede** ([#2221](https://github.com/alphaonedev/ai-memory-mcp/issues/2221); data-integrity, surfaced by the #2216 Fable pre-merge audit, finding F2 — pre-existing, NOT a #2216 regression). The fifth archive-conflict site, in the same #2195 backend-divergence class the #2216 sweep closed for the eviction/manual paths (both backends MUST behave identically — North Star: DEGRADE, never diverge into WRONG results). The postgres append-and-archive supersede funnel (`PostgresStore::update_with_archive_on_supersede`, `src/store/postgres.rs`) archived the OLD row via `INSERT INTO archived_memories … SELECT … FROM memories WHERE id = $1 ON CONFLICT (id) DO NOTHING` + a `rows_affected == 0` → `StoreError::NotFound` rollback. When an `archived_memories` row for the OLD id ALREADY existed (e.g. an `in_place_edit` snapshot on the same id from a prior content edit — live row still present), the conflict took `DO NOTHING`, `rows_affected` was 0, and the funnel ROLLED BACK with a mistyped `NotFound` for a memory that EXISTS — while sqlite's supersede (which funnels through `storage::archive_memory_no_tx`'s `INSERT OR REPLACE`, LAST-wins) SUCCEEDED. Postgres now uses the shared `SQL_ARCHIVE_ON_CONFLICT_LAST_WINS` clause (introduced by #2216) — overwriting every payload column from `EXCLUDED` — so the supersede succeeds and the archived payload is byte-identical to sqlite, on both the success case AND the error-path disposition. The OLD live row is pinned by the pre-read `SELECT … FOR UPDATE`, so the retained `rows_affected == 0` guard is now defensive-only (it can no longer false-fire on a pre-existing archive row). Canonical semantics chosen = sqlite last-wins per the #2216 precedent (copies the adjudicated disposition, so no new 5-agent vote; TRUTH+PRESERVATION class per decision memory `b682c76a`). Regression: cross-backend supersede-re-archive round-trip pins `sqlite_parity_gap_2221_supersede_rearchive_lastwins` (unconditional) + `postgres_side::pg_parity_gap_2221_supersede_rearchive_lastwins` (live-PG, self-skips when `AI_MEMORY_TEST_POSTGRES_URL` unset) in `tests/store_parity_gaps.rs` — each seeds an `in_place_edit` snapshot on the OLD id, supersedes, and asserts the supersede SUCCEEDS with a last-wins (`archive_reason='superseded'`, OLD-live-payload) archived row; each FAILS on the pre-fix postgres behavior. No new MCP tool / HTTP route / CLI subcommand / migration.
- **Erasure cold-tier: shard/manifest `fsync` no longer panics on Windows (`Access is denied`, os error 5)** ([#2230](https://github.com/alphaonedev/ai-memory-mcp/issues/2230), windows-only durability plumbing surfaced by the #2064 erasure store; 5 `erasure::store::tests` failed on the `Check (windows-latest)` job while passing on ubuntu/macOS). `src/erasure/store.rs::fsync_file` opened each freshly-written shard + manifest READ-ONLY (`File::open`) before `sync_all()`. On unix `fsync(2)` accepts any valid descriptor, so this passed; on Windows `sync_all()` maps to `FlushFileBuffers`, which REQUIRES a handle with write access (`GENERIC_WRITE`) — a read-only handle returns `ERROR_ACCESS_DENIED (os error 5)`, panicking every `put`-driven test. **Fix (`#[cfg(windows)]`-gated, unix path byte-identical):** on Windows the fsync handle is now opened with `OpenOptions::new().write(true)` (no truncation — the bytes are preserved), so `FlushFileBuffers` is permitted and the **per-file durability barrier holds byte-for-byte on BOTH platforms** — the F3 crash-safety claim stays honest on each. The DIRECTORY-fsync step (`fsync_dir`) was ALREADY a documented `#[cfg(not(unix))]` no-op (Windows has no portable `fsync(dir)` equivalent; bundle-publish durability there rests on the per-file fsyncs plus atomic `MoveFileEx` rename semantics) — the per-platform crash-safety claim in the module + fn docs is updated to state this explicitly. Erasure bundles are DERIVED, REGENERABLE redundancy (the archived DB row stays the durable source of truth), so this never risked the durable truth — but a panic on every archive write is a hard defect. Regression: the new `src/erasure/store.rs::tests::fsync_file_succeeds_on_freshly_written_file` pins the barrier directly on every platform (read-only path on unix, write-handle path on Windows) and asserts the bytes survive the write-open; the 5 pre-existing `erasure::store::tests` are the windows-CI verifier. No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.
- **Backend archive-parity: postgres re-archive is now LAST-WINS + carries `lifecycle_state` through the archive→restore round-trip** ([#2195](https://github.com/alphaonedev/ai-memory-mcp/issues/2195), [#2196](https://github.com/alphaonedev/ai-memory-mcp/issues/2196); data-integrity, surfaced by the #2192 Fable audit). Two backend-archive divergences (both backends MUST behave identically — North Star: DEGRADE, never diverge into WRONG results). **(#2196)** Three postgres archive `INSERT ... SELECT` sites — `forget` (`archive_reason='forget'`), `run_gc` (`'ttl_expired'`), and `archive_by_ids` (manual) — OMITTED `lifecycle_state` from the `archived_memories` column list, so `archive_restore` COALESCEd the NULL to `'open'`: a memory archived in a non-open lifecycle_state (e.g. `blocked`, `active`) silently restored as `open` on postgres, a lifecycle data-loss + sqlite/postgres divergence (sqlite always threaded it). The three sites now carry `lifecycle_state` (the `size_gc` + in-place-edit/supersede sites already did); `archive_restore` already read `COALESCE(lifecycle_state,'open')` so the archive-side write completes the round-trip. **(#2195)** The postgres eviction/manual archive paths (`forget`/`run_gc`/`size_gc`/`archive_by_ids`) used `ON CONFLICT (id) DO UPDATE SET archived_at = EXCLUDED.archived_at, archive_reason = EXCLUDED.archive_reason` — refreshing only those two columns (FIRST-payload-wins), while sqlite archives via `INSERT OR REPLACE` (LAST-wins). Re-archiving a memory whose content changed between archivings yielded DIVERGENT archived payloads across backends. Postgres now overwrites every payload column from `EXCLUDED` via the shared `SQL_ARCHIVE_ON_CONFLICT_LAST_WINS` clause, matching the sqlite last-wins contract. The issue's second #2195 defect (pg archive_restore RETAINING the archive copy) was ALREADY resolved at HEAD by #1799 — `archive_restore` deletes the copy via `SQL_DELETE_ARCHIVED_MEMORY_BY_ID` (both backends now delete on restore); the parity tests pin it against regression. Canonical semantics chosen = sqlite (last-wins + delete-on-restore) per the issue's recommendation (copies the sqlite precedent, so no new 5-agent vote; TRUTH+PRESERVATION class per decision memory `b682c76a`). Regression: cross-backend archive→re-archive→restore round-trip pins `archive_lifecycle_state_survives_restore_parity_2196` + `archive_rearchive_is_last_wins_parity_2195` in both `src/store/sqlite.rs::tests` (unconditional) and `src/store/postgres.rs::tests` (live-PG, self-skips when `AI_MEMORY_TEST_POSTGRES_URL` unset) — each FAILS on the pre-fix postgres behavior. No new MCP tool / HTTP route / CLI subcommand / migration.
- **Archive→restore no longer DROPS the #1834 claim-bitemporal VALID-time — `archived_memories` gains `valid_from`/`valid_until` (schema v85)** ([#2035](https://github.com/alphaonedev/ai-memory-mcp/issues/2035)). The v79/#1834 columns `memories.valid_from` / `memories.valid_until` (RFC3339 TEXT; the half-open `[valid_from, valid_until)` interval a claim is asserted to hold) were never mirrored onto `archived_memories`, so a memory archived via GC eviction (`archive_on_gc`), explicit `forget`, or the `in_place_edit` supersede snapshot — and later restored — came back with both columns NULL, silently DROPPING the claim's validity interval. This is the exact data-loss class #1025 (schema v49) closed for the other 14 v0.7.0 columns and #228/#1728 (v68) closed for `encrypted_envelope`: the memory TEXT + all its fields are the durable source of truth, so archive→restore MUST be lossless (North Star). **Fix (additive, both backends):** schema v85 (`CURRENT_SCHEMA_VERSION` 84→85) adds the two nullable columns to `archived_memories` on BOTH backends (sqlite `migrations/sqlite/0069_v85_archived_valid_time.sql` — probe-guarded `ALTER ADD COLUMN`, SQLite has no `ADD COLUMN IF NOT EXISTS`; postgres `migrate_v85` / `migrations/postgres/0042_v85_archived_valid_time.sql` — idempotent `ADD COLUMN IF NOT EXISTS` + the `postgres_schema.sql` bootstrap block), threads the two fields through every archive `INSERT ... SELECT` (memories → archived_memories, all 8 sqlite + 7 postgres funnels) and both `restore_archived*` re-inserts (archived_memories → memories, sqlite + the `PostgresStore::archive_restore` twin). Additive `ALTER ADD COLUMN`, no full-table rebuild → no trigger-drop hazard (the v63/v65 lesson does not arise); mirrors the v49/#1025 archive-column-parity precedent (5-agent vote `4d3ea1c5`, design memory `591608d4`). Regression: `tests/archived_valid_time_roundtrip_2035.rs` proves archive→restore round-trips both columns losslessly on sqlite (unconditional) + the `#[ignore]`+`sal-postgres` twin, plus the co-located `src/storage/mod.rs::tests::archive_restore_roundtrips_valid_time_2035` unit pin. No new MCP tool / HTTP route / CLI subcommand.
- **`curator --daemon` now honors SIGTERM for graceful shutdown (matching its doc)** ([#2119](https://github.com/alphaonedev/ai-memory-mcp/issues/2119)). The `curator --daemon` doc claimed "SIGINT / SIGTERM trigger a clean shutdown between cycles" but both daemon shutdown-notify sites wired only `tokio::signal::ctrl_c()` (SIGINT). Under a process manager whose default stop signal is SIGTERM (`systemctl stop` / `docker stop` / `kill`), the between-cycles clean shutdown never fired — the process was hard-killed. Both curator daemon arms (`src/cli/curator.rs` `run` + `run_store_backed_sweep`) now `select!` over `tokio::signal::ctrl_c()` AND (unix) `SignalKind::terminate()` via a shared `await_shutdown_signal` helper — the exact pattern PR #2100 already landed on the `watch --daemon` arm — with a `pending()` park when the SIGTERM handler cannot install; non-unix falls back to SIGINT-only. The doc claim is now true (option (a), the preferred fix). Regression: `src/cli/curator.rs::tests::curator_daemon_mode_returns_on_sigterm` (unix) self-fires SIGTERM and asserts the daemon returns cleanly, the twin of the existing SIGINT test.

- **Portability-v2 round-trip now preserves the schema-v75 lineage-DAG cid mirror — imported edges keep their tombstone-resilient node identity** ([#2215](https://github.com/alphaonedev/ai-memory-mcp/issues/2215); a #2006 residual fidelity gap surfaced by the #2205 re-audit). The v2 importer's raw `INSERT INTO memory_links` (PR #2205) carried nine columns but NOT the `source_cid`/`target_cid` mirror (#1859 G13-mem, schema v75), AND the wire model `MemoryLink` did not carry them either — so EVERY imported edge landed with NULL mirrors, silently dropping the tombstone-resilience a natively-written edge keeps (after a source is tombstoned at the destination, an imported edge could no longer resolve stable cid identity). **Fix — BOTH sides, lossless:** (1) the EXPORTER twin — `MemoryLink` gains `source_cid`/`target_cid` (`#[serde(default, skip_serializing_if = "Option::is_none")]`, byte-identical wire for the common NULL-mirror row; advisory-resolution only per COND 2, NOT in the Ed25519 `SignableLink` preimage, so byte-compat with every shipped signature + federated peer) and `storage::export_links` now projects the two columns, so the v2 envelope carries them; (2) the IMPORTER — the links loop resolves the mirror as PREFER the bundle's cid → else BACKFILL from the just-staged endpoint's re-derived `memories.cid` (the #1825 deterministic re-derivation) → else leave NULL (the pre-v75 legacy state; DEGRADE, do not INVENT), gated on `lineage_dag_enabled()` for byte-parity with the native `create_link_signed` write path (when the DAG is OFF the mirror binds NULL). The write lands on the sqlite `Connection` (v2 import is sqlite-only, like MCP); the other SAL/read link projections stay selective (`None`, consistent with the existing `signature`/`attest_level` selective-projection posture). Regression: `tests/portability_lineage_cid_2215.rs` — `round_trip_carries_lineage_cids` (export a linked pair carrying cids → import into a fresh dest → the imported edge carries the same source_cid/target_cid; FAILS pre-fix on BOTH the parsed-envelope AND the imported-row assertions), `legacy_bundle_backfills_from_endpoint_cids` (an older bundle with the cids stripped backfills from the staged endpoints), and `legacy_bundle_without_dag_leaves_null` (absent-cid bundle + DAG-off binds NULL, not garbage). No new MCP tool / HTTP route / CLI subcommand / migration (the schema-v75 columns already exist).
- **`recover_from_transcript_store` (SAL/pg twin) now honors `RecoverOpts.bypass_fast_path` — latent #2126 tail-loss closed on the postgres path** ([#2130](https://github.com/alphaonedev/ai-memory-mcp/issues/2130)). Ports the [#2126](https://github.com/alphaonedev/ai-memory-mcp/issues/2126) fix (PR [#2100](https://github.com/alphaonedev/ai-memory-mcp/pull/2100)) from the sqlite twin `recover_from_transcript` to its SAL twin `recover_from_transcript_store` for cross-backend parity. The sqlite path gates the step-2 watermark fast-path (`mtime <= MAX(created_at)` file-skip) behind `if !opts.bypass_fast_path` so the L3 poll watcher — which owns change-detection via its own `(mtime, len)` diff and sets `bypass_fast_path = true` — never fast-path-skips an un-drained `pending_drain` tail after a same-agent wall-clock L1 write pushes the watermark past the static file's mtime. The SAL/pg twin was missing that guard (`src/recover/mod.rs:546`), so a bypassing `RecoverOpts` routed through the store path would silently still fast-path-skip — re-opening the exact #2126 tail-loss on the postgres backend. Latent-not-live at HEAD (the shipped L3 watcher, the only setter of `bypass_fast_path`, is structurally sqlite-only via `recover_from_transcript`), but the gap becomes live the moment any postgres-backed watcher work lands. The fix mirrors the sqlite guard verbatim; the fast-path logic is single-source in the backend-blind `recover_from_transcript_store`, so both backends now honor `bypass_fast_path` identically. Regression coverage: `recover::tests::store_path_honors_bypass_fast_path_2130` (`src/recover/mod.rs`, `--features sal`) drives the store twin via `SqliteStore` (the exact fixed code path the postgres adapter also runs) — the control run fast-path-skips, the `bypass_fast_path = true` run captures the tail instead of dropping it; the live-`PostgresStore` path is covered by the CI postgres feature gate.

### Security

- **Postgres `store_batch` now routes each row through the at-rest encryption seal (closes an at-rest-encryption BYPASS on the bulk write path)** ([#2288](https://github.com/alphaonedev/ai-memory-mcp/issues/2288), v1.0.0 pre-ship). `PostgresStore::store()` seals content into the `encrypted_envelope` BYTEA column (#228/#1728, schema v68) under the `AI_MEMORY_ENCRYPT_AT_REST` gate, but `store_batch()` — the funnel behind `POST /api/v1/memories/bulk` — had ZERO encryption handling, so a bulk write persisted PLAINTEXT into the `content` column while the operator believed at-rest encryption was on (a silent confidentiality bypass; North Star: DATA INTEGRITY / never silently store what the operator asked to be protected). `store_batch` now seals each row through the SAME `crate::encryption::seal_content` contract `store()` uses (content column holds the empty placeholder, ciphertext lands in `encrypted_envelope`), adds `encrypted_envelope` to the INSERT column list + per-row `push_bind` sequence + the `ON CONFLICT … DO UPDATE SET` arm (`encrypted_envelope = EXCLUDED.encrypted_envelope`, so a re-store replaces both placeholder and ciphertext and an encryption-off write clears any stale envelope to NULL). With encryption OFF (default) behavior is byte-identical to before. Regression coverage: `tests/store_parity_gaps.rs::postgres_side::pg_store_batch_seals_content_2288` (live-PG, `#[ignore]` per the `AI_MEMORY_TEST_POSTGRES_URL` convention). Sibling pg content-write funnels (`store_with_embedding`, `reflect_with_hooks`, `capture_turn_idempotent`, `recover_turn_idempotent`, `apply_remote_memory`, `consolidate`, `update_with_archive_on_supersede`) share the same class and are tracked separately.

- **Portability-v2 trust-anchor exports now honor role custody files** ([#2245](https://github.com/alphaonedev/ai-memory-mcp/issues/2245), v1.0.0 pre-ship Wave-B). Recorder, judge, and stopper anchors now use the substrate's canonical enrolled-key loaders, preserving env precedence while also exporting custody-directory `<label>.pub` enrollments; destinations no longer receive a silently weakened anchor set when operators use file custody.

- **Valid-time parity: compare signed KG-link timestamps as instants and preserve claim bounds on Postgres embedded writes** ([#2266](https://github.com/alphaonedev/ai-memory-mcp/issues/2266), [#2267](https://github.com/alphaonedev/ai-memory-mcp/issues/2267), v1.0.0 pre-ship Wave-B). SQLite KG timeline/query/path predicates now parse RFC3339 link bounds at comparison time, so equivalent `Z`/offset renderings cannot silently mis-filter or mis-order edges; stored H2-signed bytes remain untouched and malformed bounds fail closed. Postgres `store_with_embedding` now persists canonical `valid_from`/`valid_until` with the same immutable-genesis/closeable-upper-bound upsert semantics as plain `store()`, closing a hot-path interval data-loss gap.

- **Valid-time parity: Postgres `store_batch` upsert honors the #1834 claim-bitemporal contract** ([#2280](https://github.com/alphaonedev/ai-memory-mcp/issues/2280), v1.0.0 pre-ship Wave-B). `PostgresStore::store_batch`'s `ON CONFLICT (title, namespace) DO UPDATE SET` block was the ONE write funnel missing the explicit `valid_from`/`valid_until` arms that `store()` / `store_with_embedding` already carry, so a batch re-store of an existing `(title, namespace)` silently DROPPED a caller's fresh `valid_until` close — the claim was never closed. (An unlisted column in `DO UPDATE SET` already keeps the existing row value, so `valid_from` was in fact always immutable across the batch upsert; the real data-loss was solely the dropped `valid_until` close.) The upsert arm now sets `valid_from = memories.valid_from` (kept explicit to PIN the immutable-genesis intent and match `store()`'s precedent) and `valid_until = COALESCE(EXCLUDED.valid_until, memories.valid_until)` (a supplied upper bound closes the claim; an omitted one keeps the stored bound), matching both sibling funnels exactly. (`kind_provenance` is intentionally NOT added: like `store_with_embedding`, the `store_batch` INSERT never lists that column, so there is no `EXCLUDED.kind_provenance` to reference — only `store()` both inserts and conflict-merges it; precedent-copy, no invention.) Data-integrity fix (North Star: never silently drop a durable claim-close on a cross-backend write funnel). Regression coverage: `store::postgres::tests::live_store_batch_conflict_preserves_valid_time_2280` (live-PG, `#[ignore]`-convention via the CI Postgres gate).

- **Portability-v2 import: verify attestation against DESTINATION-enrolled keys + run the L1-parity input-validation gate before persist** (pre-ship 3x7 battery, two HIGHs at the [#2006](https://github.com/alphaonedev/ai-memory-mcp/issues/2006) v2 import site, `src/portability/import.rs`). Bundles are UNAUTHENTICATED input per the importer's own threat model (the lane already ships the #2208/#2211 defenses), yet the v2 memories loop (a) persisted the wire-supplied `metadata.attest_level` / `write_signature` / `agent_pubkey` VERBATIM — a crafted bundle minted `attest_level=agent_attested` rows this node's trust surfaces (`row_is_agent_attested`, quarantine routing, ClaimView, forensics) then believed, and the SECURE default `trust_source=false` made it worse by restamping `agent_id` while keeping the stale attestation — and (b) ran ZERO input validation (an L1 parity gap vs `src/cli/io.rs`), landing rows that violate every write invariant (`MAX_CONTENT_SIZE`, priority/confidence ranges, RFC3339 timestamps, refuse-mode secret screen).
  - **HIGH-1 fix (attestation is re-derived, never copied).** Before `insert_imported`, each staged row's attestation is re-derived through the SAME `identity::attest::stamp_attestation` gate the federation receive path (`apply_inbound_write_attestation`, #1464) uses: any presented `metadata.write_signature` is verified against the attributed author's DESTINATION-enrolled Ed25519 key — snapshotted BEFORE the import transaction so a crafted `_agents` registration row staged earlier in the SAME bundle can never self-enroll the key a later row "verifies" against. Valid → `agent_attested`; absent signature / unenrolled author / restamp re-attribution → `claimed` (counted `attestation_downgraded`, WARN); presented-but-FORGED → the row is SKIPPED per-row (counted `forged_signature_skipped`, WARN — the #1464 invariant that a deliberately bad signature never launders in). Under the default restamp posture the wire `metadata.agent_pubkey` identity-key claim is STRIPPED so unauthenticated input cannot seed the `db::agent_pubkey` enrolled-key surface. A row that neither asserts an `attest_level` nor presents a signature crosses byte-identically (round-trip preserved).
  - **HIGH-2 fix (L1-parity validation).** Every staged memory now passes `validate::validate_memory` (extended with the #1834 `valid_from`/`valid_until` RFC3339 format checks, previously unvalidated on the full-Memory import shape) and every link passes `validate::validate_link`, with the import's per-row skip + WARN + counted disposition (`invalid_skipped` / `invalid_links_skipped`) — never a silent accept, never a batch drop. The one-transaction ALL-OR-NOTHING property and the #2208–#2211/N1/N2 defenses are unchanged.
  - **F1 (Fable audit finding on the link lane).** `memory_links` carries `REFERENCES memories(id)` FKs and `db::open` sets `PRAGMA foreign_keys=ON`; SQLite's `OR IGNORE` does NOT apply to FK constraints (the pre-existing #2215-era comment claimed it silently skipped absent-endpoint edges — false), so one bundle link whose endpoint memory was skipped (tombstoned/archived/invalid/forged/conflict-refused — a set the HIGH-1/HIGH-2 gates widen) FK-errored the WHOLE all-or-nothing transaction: zero rows landed and the per-row report/WARNs never surfaced. The link lane now probes both endpoints against the staged transaction state (`memory_row_exists`) and skips + WARNs + counts (`links_skipped_missing_endpoint`) any dangling edge before the INSERT — the per-row disposition holds end-to-end. A one-shot WARN on the `--trust-source` path also names the accepted-risk of verbatim identity-key claims under explicit operator trust (the v1 wire-form sibling is tracked as #2264).
  - The committed conformance golden (`conformance/vectors/export/round_trip_l3.json`) regenerated: its seed memory used `source: "test"`, a value outside `validate::VALID_SOURCES` that was only importable because the v2 route ran zero validation; the fixture now seeds `source: "system"`.
  - Regression coverage (each ★ fails on the pre-fix code): `portability::import::tests::{forged_wire_attest_level_lands_claimed_preship_3x7, forged_write_signature_is_skipped_preship_3x7, valid_write_signature_verifies_agent_attested_preship_3x7, wire_agent_pubkey_is_stripped_by_default_preship_3x7, invalid_rows_are_refused_not_persisted_preship_3x7, link_to_skipped_memory_does_not_fk_abort_the_import_preship_3x7_f1}`. No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.
- **Re-anchor ceremony verifies the chain BEFORE countersigning it** ([#2242](https://github.com/alphaonedev/ai-memory-mcp/issues/2242), v1.0.0 3x7 pre-ship battery, MEDIUM). `emit_reanchor_ceremony` (`src/signed_events.rs`, the #2004 crypto-agility ceremony) read the current `signed_events` chain head via `read_chain_head` and immediately countersigned it — WITHOUT first verifying the chain. A ceremony run on an already-tampered chain (broken `prev_hash` link, sequence gap, anchored tail truncation, witness/head-hash anchor mismatch) therefore produced a fresh signed `ReAnchor` checkpoint blessing the corrupt history — converting recoverable tamper-EVIDENCE into a signed false statement, at exactly the moment an attacker wants a countersignature. **Fix (fail-closed):** the ceremony now runs the FULL `verify_audit_trail` pass (which already reconciles the #1850 forensic watermark, the #1822 witness dual-head anchor, and the #1873 head-hash anchor) BEFORE `build_signed_reanchor_checkpoint`; ANY verdict `AuditTrailReport::is_clean()` treats as dirty REFUSES the ceremony with the new typed `ReAnchorOutcome::RefusedChainDirty(detail)` (reason tag `chain_verification_failed`, detail naming the dirty verdict classes) and persists NOTHING. Withheld `Unknown` verdicts (no anchor enrolled) keep the pre-#2242 clean semantics, so an un-anchored deployment's clean-chain ceremony is byte-identical. The CLI `ai-memory audit re-anchor` surfaces the refusal as a distinct non-zero-exit failure (the #2214 F4 discipline — never a skip), pointing at `verify-audit-trail` for triage. Keeps the #2214 honest sqlite-only scoping (the pg twin remains #2217). Regression coverage: `tests/reanchor_ceremony_2004.rs::{reanchor_refuses_on_sequence_gap,reanchor_refuses_on_inplace_edit}` (tamper → typed refusal + zero persisted checkpoints; clean-chain emission re-pinned by the existing round-trip test). No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.

- **guardrail-D arm-lane hardening: the migration-ladder gate now sees const-phrased (`if version < CURRENT_SCHEMA_VERSION`) arms** ([#2198](https://github.com/alphaonedev/ai-memory-mcp/issues/2198), Fable audit of [#2197](https://github.com/alphaonedev/ai-memory-mcp/issues/2197)). The guardrail-D migration-ladder gate's rule (b) ("two ladder ARMS declaring the same schema version") only saw **literal-number** arms (`if version < N {` / `if current_version < N {`), but the CURRENT house convention phrases the TAIL arms against the const — `src/storage/migrations.rs` carries 8 `if version < CURRENT_SCHEMA_VERSION {` arms and `src/store/postgres.rs` 1 — which were INVISIBLE to the scan. The Fable pre-merge audit of #2197 demonstrated **three** arm-lane escapes that all exited 0 (defense-in-depth gap in one advertised sub-rule, not a hole in the guardrail's protective purpose — rules (a)/(d) still blocked any realistic silent merge-train collision): **D1a** a 2nd `if version < CURRENT_SCHEMA_VERSION {` arm; **D1b** a literal `if version < 85 {` arm that duplicates the const-phrased v85 tip (the monotonic scan reads `85 > 84` as "increasing"); **D2** a postgres `fn migrate_v85_extra(` name-variant (precedent: `migrate_v29_stamp`) that escapes the exact-name `fn migrate_vN(` dup regex. **Fix (`scripts/check-migration-ladder.sh` + `tests/migration_ladder_integrity.rs`, both lanes, no schema change):** rule (b) now (b1) NORMALIZES symbolic arms — a literal or resolved-arithmetic (`CURRENT_SCHEMA_VERSION ± K`) arm AT OR ABOVE the const tip is flagged as a duplicate of the const-phrased tip cohort (catches D1b); (b2) PINS the exact count of bare const-phrased arms per adapter (`EXPECTED_CONST_ARMS_SQLITE=8`, `EXPECTED_CONST_ARMS_POSTGRES=1`; a silent add moves the count and fails — bump the pin in lockstep with a dated comment, module-size-ceiling discipline; catches D1a); (b3) flags a DUPLICATE `migrate_v<N>` VERSION even under a name-variant the exact-name regex misses (catches D2). The `--self-test` reproduces all three escapes (cases c/d/e) so the new detection is load-bearing, and the runtime twin re-asserts the same invariants fail-closed so bypassing the shell gate still fails; the twin also fail-closes on a `.sql` migration file that does not match the `NNNN_*` convention (the shell gate flagged it, but `ladder_files` silently dropped it). DATA-INTEGRITY guardrail (North Star: degrade — a loud non-zero exit — never corrupt the ladder). No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.

- **Federation inbound: reject foreign-embedding-model shipped vectors at the receive gate** ([#2168](https://github.com/alphaonedev/ai-memory-mcp/issues/2168)). The #1566 / #1579 B1 embed-ship receive path stored a peer-shipped embedding vector VERBATIM once it passed the DIMENSION + finiteness/L2-norm (#1584) gates — but it never compared the shipped `model` against the receiver's own embedder identity, even though `ShippedEmbedding.model` already carries it on the wire. A same-dimension vector produced by a DIFFERENT embedding model (or the same model under a different prefix scheme — the #1520 nomic asymmetric scheme) lives in a different coordinate space: cosine against the local query embedder returns a numerically-valid but semantically-MEANINGLESS score, so recall silently returns wrong matches (no error, no WARN, no counter). Post-#1598 every node resolves its embedder independently, so a heterogeneous fleet (peer A on nomic-768, peer B on granite-768) is one env var of drift away from silently poisoning the receiver's vector space — and it fired identically on BOTH backends.
  - **Fix (migration-free, both funnels).** A new canonical vector-space fingerprint `<canonical_model_id>#<prefix_scheme>` (`embeddings::embedding_space_fingerprint` + `Embedder::space_fingerprint`) generalises the existing dim-equality gate into a vector-space IDENTITY check. The DIMENSION is deliberately excluded from the fingerprint — it stays on the separate dim gate so there is one SSOT per axis (M-DOCUMENTED-MAGIC); the prefix scheme is derived from the model id EXACTLY as the local embed path derives it (`Embedder::model_requires_nomic_prefix`, the #1520 predicate). On inbound (`federation_receive::sync_push` sqlite + `federation_signing_check::sync_push_via_store` postgres), the receiver compares the shipped fingerprint (canonicalised from `se.model`, prose-tolerant + wire-back-compat — NO wire change) against its OWN configured embedder fingerprint. MATCH → the vector is stored verbatim exactly as before (no #1566 perf regression). MISMATCH → the foreign vector is NOT stored; the row falls through to the EXISTING deferred-local-re-embed fallback so it still lands (CRDT convergence preserved — the memory is not dropped, only its foreign vector is refused) and is re-embedded under the LOCAL model, plus a structured WARN (`M-LOG-STRUCTURED`, `federation::attestation` target) naming both fingerprints + the peer. **CORE INVARIANT:** a foreign-fingerprint vector NEVER enters the local space (nor the live HNSW index) — worst case the row is re-embed-pending, never poisoned. Distinct model ids never collide, so the gate can produce a false MISMATCH (a safe local re-embed) but never a false MATCH (corruption): degrade, never corrupt. `M-STRONG-TYPES-GUARD`.
  - Regression coverage: `tests/federation_2168_embed_fingerprint.rs` (foreign-model → deferred re-embed with the foreign vector never stored; matching-model → stored verbatim; bare-id prose-tolerant match; #1584 finiteness/norm still applies under a matching fingerprint) + `src/embeddings.rs::space_fingerprint_2168_tests` (fingerprint identity/prefix-scheme unit coverage). No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.

- **Audit-trail: detect a same-length whole-suffix rewrite on an unsigned daemon (CWE-354 tail gap)** ([#1873](https://github.com/alphaonedev/ai-memory-mcp/issues/1873), residual-1 of #1850). The `signed_events` tamper-evidence anchors compared the head **sequence only**, so an attacker with DB write access on an UNSIGNED daemon (no enrolled key → `verify_chain`'s verifier is `None`) could rewrite the whole suffix with a recomputed `prev_hash` at the SAME row count and BOTH the chain-walk and the seq-only `TruncationCheck` / `WitnessCheck` read clean — even though the #1850 forensic watermark and the #1822 dual-chain witness already RECORD the head canonical hash. The fix adds the verifier-side recompute-and-compare that finally uses it.
  - **New independent `HeadHashCheck {Unknown|NotDetected|Mismatch{chain,detail}}` verdict** + pure `compute_head_hash_verdict` (key-free — verifier-independence is self-evident) + pure `fold_head_hash_verdicts` (ANY `Mismatch` wins → dirty; else `NotDetected` if any lane verified a match; else `Unknown` withhold). It composes with the in-tree G5b witness (#1822) + G9 role-separation (#1826) verdicts as a SIXTH independent per-check verdict on `AuditTrailReport` (the `RollbackCheck` #1946 shape), leaving the shipped seq-only enums' closed wire vocabularies untouched; the three-state `Unknown` withhold cleanly models the #1930 encoding-skew false-positive an overloaded `Detected` could not express.
  - **Both anchors, both chains, both backends (K3 parity):** each `verify_audit_trail` recomputes the canonical hash of the surviving row **AT THE ANCHORED SEQUENCE** (`SHA-256(canonical_chain_bytes(row))`) and compares it whenever `anchored_seq <= db_head` — against the #1850 forensic watermark (`signed_events`) and the #1822 dual-chain witness (`signed_events` **and** `memory_revisions`). The sqlite path and the postgres twin recompute identically. New `AuditTrailReport.head_hash` field + `is_clean()` clause (`Mismatch` is dirty, like `TruncationCheck::Detected`) + CLI render line.
  - **#2202 — compare AT the anchored sequence, not only when it is still the head (Fable pre-merge finding F1).** The first cut gated the comparison on `head_sequence == anchored_seq`, but the watermark is interval-throttled with no shutdown flush, so in the steady state (~63/64 of the time) the daemon has appended past the anchor and the equal-sequence gate NEVER consulted it — the passive same-length whole-suffix rewrite went clean, and one attacker INSERT (`head = W+1`) evaded even the at-head case. The fix fetches the surviving row **by `sequence = anchored_seq`** (`recompute_signed_row_hash_at` / `revisions::recompute_revision_row_hash_at` + pg twins) and convicts on mismatch whenever `anchored_seq <= db_head`. Sound + false-positive-free: `canonical_chain_bytes` excludes `prev_hash` and rows are append-immutable, so the anchored row's hash is stable under later appends; a missing row at the anchored sequence (a gap already surfaced by the scan) withholds `Unknown`; `anchored_seq > db_head` stays owned by the truncation/witness lanes.
  - **#2203 — postgres false-positive on a CLEAN chain (Fable pre-merge finding F2, K3 parity).** `pg_append_signed_event_with_chain_in_tx` hashed the in-memory `Utc::now()` nanosecond timestamp into the watermark/witness head anchor, while the verifier recomputes from the `TIMESTAMPTZ` (microsecond) readback → structurally unequal on nearly every row → a false `HeadHashCheck::Mismatch` (exit-1) on a completely clean pg chain. The pg append chokepoint now `truncate_to_microseconds` the timestamp BEFORE hashing, so the anchor and the readback-recompute agree by construction (the `link_internal` G3 precedent). Historical pre-fix pg anchors heal at the next watermark under the fixed emitter (a one-interval #1930-style transient).
  - **F3 (hardening) — witness head-hash lane through the pin+signature gate.** The witness dual head is now consumed via `verified_witness_dual_head`, which enforces the SAME K1 pubkey pin + Ed25519 signature check `compute_witness_verdict` uses, so a forged in-DB checkpoint cannot mint a false `Mismatch` or an unearned `NotDetected` (the forensic-watermark lane is off-table and unaffected).
  - **Honest scoping (residual-2, documented in `CLAUDE.md`):** `canonical_chain_bytes` deliberately excludes `prev_hash`, so a single head-row hash does NOT transitively bind interior rows — an interior/mid-suffix rewrite BELOW the anchored head, the ≤`WATERMARK_INTERVAL`−1 un-anchored tail window, and the #1930 encoding-skew transient remain out of scope for the in-DB verdicts (the off-host `AI_MEMORY_LOG_SINK=syslog` tier or a future rolling/accumulator hash is the residual-closing control).
  - Regression coverage: 5 pure-fn unit tests (`src/signed_events.rs`) + `tests/audit_truncation_anchor_1850.rs` (forensic lane — the at-head rewrite plus the #2202 **passive** (rewrite below the head after appends) and **active** (rewrite-then-append-one-linked-row) constructions the audit named, each `Mismatch` + `is_clean()==false` while truncation reads `NotDetected` and the chain stays intact; no-anchor withhold) + `tests/audit_witness_truncation_1822.rs` (witness lane — same-length rewrite of the `signed_events` AND `memory_revisions` heads at head AND below-the-head-after-appends, plus append-one-to-evade, via a real-head-binding checkpoint; **plus a live-pg (`sal-postgres`) head-hash test** driving the real pg append chokepoint that asserts a clean pg chain reads `NotDetected` and a real rewrite reads `Mismatch` — the #2203 gap that had NO pg head-hash coverage). No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.

Five-agent adversarial security review of the HTTP/MCP surface (auth & access control, injection/deserialization, SSRF/outbound, transport/deployment exposure, federation-crypto/DoS), OWASP-aligned, motivated by the `7WaySecurity/ai_osint` exposure-recon threat model. Cryptographic core verified sound (macaroon verify, `verify_strict` everywhere, fail-closed federation defaults, comprehensive webhook SSRF guard, parameterized SQL, no command injection, no request-decompression bomb, 2 MiB body cap, constant-time key compare) — no SQLi / command-injection / high-critical SSRF. 13 findings recorded with `file:line` evidence + remediation (1 High + 3 Medium, all bounded to specific deployment postures; the two highest share one root cause: unattested `X-Agent-Id` on the HTTP read/mutate/admin paths). **NSA CSI MCP compliance re-verified GREEN** at the v1.0.0 dev tip — every named test in the control→test matrix (19 controls: NSA concerns a–j + recommendations a–g + 2 meta) re-run: **580 tests, 0 failed**. New public evidence page `docs/compliance/v1.0.0-security-assessment.html`.

- **HTTP-surface per-agent-key principal binding — closes H1 (cross-tenant IDOR/BOLA) + M1 (admin spoof)** ([#2044](https://github.com/alphaonedev/ai-memory-mcp/issues/2044) / #2032-A, 5-agent vote `4d3ea1c5`). The two highest #2032 findings share ONE root cause: on the HTTP surface `X-Agent-Id` is a SELF-ASSERTED principal while the `api_key` is only a SHARED transport credential, so any api-key-bearing caller could set `X-Agent-Id: <victim>` to read/mutate another agent's `scope=private` rows (H1) or `X-Agent-Id: <admin>` to pass the `require_admin` allowlist (M1). The fix binds an asserted identity to proven possession of that agent's per-agent api-key.
  - **New schema v83 `agent_api_keys` table** (both backends; `sha256(token) → agent_id`, additive `CREATE TABLE IF NOT EXISTS` + index — the RAW token is never stored, only its digest) + SAL accessors `bind_agent_api_key` / `agent_id_for_api_key` / `list_agent_api_keys` and the sqlite `db::` twins.
  - **`api_key_auth` middleware** now accepts an enrolled per-agent key for transport (additive, non-breaking beside the shared key) and, per the `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY` posture, BINDS `X-Agent-Id` to the key-derived principal — a mismatching self-asserted header is corrected (`advisory`) or refused with `403 identity_binding_mismatch` (`enforce`) — and injects an `AuthenticatedPrincipal { agent_id, AuthLevel }` into the request extensions. The enrolled map is boot-seeded into memory so the hot path does a pure map lookup, NOT a per-request DB hit (respects the M3 inflight-cap / L2 auth-backoff expensive-verify-DoS layering).
  - **IDOR + admin gates consume the level.** The single-row object routes (`GET/PUT/DELETE/promote /memories/{id}`), the BULK read surfaces (`GET /api/v1/memories` list, `GET /api/v1/memories/search`, `GET/POST /api/v1/recall`) — which apply the SAME self-asserted-`X-Agent-Id` → `is_visible_to_caller` scope=private filter — and `require_admin` (every admin route) re-derive the caller's `AuthLevel` self-containedly from the enrolled map + presented `X-API-Key`; under `enforce` a merely-`Claimed` (shared-key) caller acting as a NAMED principal is refused (`403 attested_identity_required`) BEFORE the ownership/visibility check. **Out of the box (`advisory` default + zero per-agent keys enrolled) H1/M1 behave EXACTLY as pre-#2044** — the gate is fully inert until an operator enrolls per-agent keys AND sets `enforce`; this is the correct secure-migration posture (`enforce`-by-default with zero keys would brick every existing shared-key deployment, the #1985 trap).
  - **`AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY = off | advisory | enforce`** (row 135), **v1.0.0 default `advisory`** — inert + zero-WARN for a single-operator deployment that enrolled no per-agent keys; `enforce` (and its escalation to more surfaces) is the follow-on posture. Per the #1950 read-path freeze this reuses the presented per-agent key and adds NO new signed read/mutate request envelope.
  - **Enrollment + revocation.** New CLI sub-verbs `ai-memory agents bind-api-key --agent-id <a> --token <t>` (stores `sha256(token)`) and `ai-memory agents revoke-api-key --agent-id <a>` (invalidates a leaked key — the PK is the token digest, so revocation is by agent binding). Both route through the CONFIGURED backend (`build_store_handle` → sqlite or postgres via the #1927 non-argv store-url channel), so enrollment works on a postgres-backed daemon (#2095). The daemon boot-loads the enrolled set, so restart `serve` after enrolling/revoking.
  - **`is_admin_caller_trusted` closed (#2093).** The SECOND admin-admission predicate (guarding the read + destructive admin branches — `purge_archive`, kg/power/governance/links admin flags) now consumes the SAME per-agent-key attestation gate as `require_admin`, so under `enforce` a shared-key caller can no longer bypass it with a forged admin `X-Agent-Id` (including the destructive cross-tenant archive purge).
  - **SSE approval-stream closed — LAST member of the H1 class ([#2154](https://github.com/alphaonedev/ai-memory-mcp/issues/2154)).** `GET /api/v1/approvals/stream` (`handlers::approvals_sse`) filters a live broadcast of `ApprovalEvent` governance-workflow metadata by the self-asserted `X-Agent-Id` (`subscriber_agent`) via `sse_event_visible_to`, with only `api_key_auth` in front — the SSE cousin of the gated `get_inbox` / `list_pending` reads. Under `enforce` a shared-global-key caller (`is_global` → skips the #2044 middleware binding) forging `X-Agent-Id: <victim>` would stream the victim's approval events. The `enforce_idor_identity` gate is now applied at STREAM OPEN (before the broadcast subscription is filtered), refusing a merely-`Claimed` named principal with `403 attested_identity_required` — matching the sibling routes; the identity decision is made once (the connection is long-lived) and the `subscriber_agent` fed to `sse_event_visible_to` is the middleware-bound principal, never a still-honored forged header. Fully inert under zero-enrollment / `advisory` / `off` (no behavior change for legitimate subscribers). H1 is fully closed only once BOTH #2129 and #2154 merge.
  - **Full identity-sensitive route-closure sweep** (exhaustive route-enumeration audit of the #2044 gate, [#2125](https://github.com/alphaonedev/ai-memory-mcp/issues/2125)/[#2096](https://github.com/alphaonedev/ai-memory-mcp/issues/2096) + #2131/#2132/#2133 + #2135/#2137/#2138/#2140). The `enforce_idor_identity` gate is applied at EVERY remaining identity-sensitive read/write funnel that resolves a self-asserted `X-Agent-Id` into a `scope=private` visibility/ownership principal — the destructive-write routes (create/delete link, `kg/invalidate`, archive-by-ids/restore/purge, consolidate, namespace-standard set/clear), the identity-sensitive reads (`get_links`/`get_lineage`/`entity_get_by_alias`/`detect_contradictions`/`check_duplicate`/`get_inbox`/`kg_query`/`kg_find_paths`/`kg_timeline`/`list_pending`/`list_subscriptions`), plus `session/start` (#2135), `memory_load_family` + `memory_smart_load` (#2137), and the per-agent `quota/status` path (#2138). **`memory_reflect` (#2140)** additionally trusted a self-asserted BODY `agent_id` (reading the victim's private sources AND writing a reflection authored as the victim); it is now bound HEADER-AUTHORITATIVELY (the body `agent_id` must match the key-attested caller or the write is refused `400 agent_id_body_header_mismatch`, the #874/#1555 posture), closing the body-field IDOR sibling the header gate alone did not cover. Per [#2156](https://github.com/alphaonedev/ai-memory-mcp/issues/2156) the body binding is gated on the SAME per-agent-key enrollment condition as the header gate: with zero keys enrolled it is INERT, so the shipped header-optional #1317 body-`agent_id` reflect contract stays byte-identical in a zero-config deployment. `session_start` moved from the sqlite-only `State<Db>` extractor to `State<AppState>` so it can reach the enrolled-keys map. **Inert out of the box** — like the #2044 gate, every route stays byte-identical to pre-fix until an operator enrolls a per-agent key AND sets `enforce`.
**Tranche 3 — deprecation-clock completion + hard WARNs** (following tranche 1 [#2043](https://github.com/alphaonedev/ai-memory-mcp/issues/2043) LM1/LM2/L3 and tranche 2 M3/L4/L2/LM3-partition/M2-envs):

- **L1 — `?api_key=` query-string credential REMOVED** (OWASP A07/A09). The HTTP `api_key_auth` middleware no longer honors an API key presented in the URL query string — URL-embedded credentials leak into access / proxy / Referer logs. Authentication is now **header-only** (`x-api-key`). The deprecation WARN soaked since v0.7.0 ([#1574](https://github.com/alphaonedev/ai-memory-mcp/issues/1574)); v1.0.0 completes the deprecation. A stale caller that still rides the query string gets a `401` plus a once-per-process diagnostic WARN naming the header alternative. The `percent_decode_lossy` helper (which existed solely to decode the query value) is removed with it.
- **M2 — cleartext off-host bind: hard boot-WARN** (OWASP A02/A05). A keyed non-loopback bind that serves the api-key + memory content in cleartext (no in-process TLS, discoverable + sniffable by `ai_osint`-class exposure recon) now emits a HARD boot WARN via the new `tls_bind_guard`, naming the two tranche-2 escape hatches: `AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK=1` (acknowledge upstream TLS termination → silence the WARN) and `AI_MEMORY_REQUIRE_TLS=1` (fail-closed-now → refuse a plaintext bind on any host). Loopback binds are exempt (same-host reverse-proxy default). Binding is **not** refused by default this release — the REFUSE flip for unacknowledged plaintext non-loopback binds lands v1.1.0 (secure-by-default without breaking the reverse-proxy shape; #1985 surface-scoping lesson).
- **LM3 — link-verify `require_nonce` WARN-carrier** (OWASP A08). `POST /api/v1/links/verify` replay protection is only enforced when the caller presents a `verification_nonce`; with `[verify] require_nonce = false` (today's default) a caller may omit it and skip the guard. A once-per-process boot WARN now announces the v1.1.0 flip of that default to `true` (fail-closed) so operators can enroll nonces on every verify caller before the flip. (The per-caller partition of the replay cache landed in tranche 2.) Nothing is flipped this release.

- **Postgres trait `update` (the DEFAULT no-If-Match funnel) now consults the substrate `GOVERNANCE_PRE_WRITE` gate** ([#2141](https://github.com/alphaonedev/ai-memory-mcp/issues/2141), HIGH — [#1451](https://github.com/alphaonedev/ai-memory-mcp/issues/1451) parity). `PostgresStore::update` (`PUT /api/v1/memories/{id}` WITHOUT `If-Match`, plus the pg promote handler path) was the LAST un-gated postgres update surface: the If-Match path (`update_with_expected_version_once`, #1451 block), the supersede twin (`update_with_archive_on_supersede`, FX-C5), and the sqlite twin (`storage::update_with_expected_version`, which BOTH sqlite update surfaces route through) all consult the hook on the post-merge row — so on a postgres daemon a refuse rule could be evaded by storing benign content then PUT-ing it (simply omitting the `If-Match` header) into the refused namespace / tier / title. The funnel now builds the post-merge `governed` candidate exactly the way the If-Match path does (patch-or-current namespace/title/metadata, tier-downgrade-protected effective tier mirroring the SQL `tier_rank` CASE, current `memory_kind`) and consults `consult_governance_pre_write_pg` AFTER the #2060/#2103 authorship gate (the #2106 item-3 ordering) and BEFORE any SQL mutation, inside the tx so a refusal rolls back with no row mutated. Live-PG enforce-mode regression: `pg_update_no_if_match_refuses_governance_refused_shape_2141` in `tests/issue_2059_2060_covenant_pg.rs` (store-benign → update-into-refused-title REFUSED + row untouched; a governance-clean update on the same path still lands).
- **#2123 regression pins for the merge/supersede covenant parity** ([#2123](https://github.com/alphaonedev/ai-memory-mcp/issues/2123); the code fixes shipped inside #2101). (1) The sqlite `merge_inbound` same-`id` field-merge branch — whose `overwrite_full_row_by_id` writer deliberately bypasses the `insert`/`insert_if_newer` chokepoints — is pinned to CONSULT the gates cluster: `merge_inbound_same_id_consults_governance_pre_write_2123` (a governance-refused merged shape is rejected + the tx rolls back) and `merge_inbound_same_id_never_refuses_missing_why_trace_under_enforce_2123` (the inbound why_trace gate stays never-refuse — CRDT convergence) in `tests/issue_2059_2060_covenant_write_gates.rs`. (2) The pg supersede why_trace semantics — `why_trace` is deliberately NOT in `IMMUTABLE_PROVENANCE_KEYS`, so inheritance is WHOLE-OBJECT-only — are pinned by `pg_supersede_omitted_why_trace_not_laundered_via_inheritance_2123` (a patch that SUPPLIES a metadata object but omits `why_trace` is REFUSED under enforce; the old rationale is not silently laundered onto a rewrite) + `pg_supersede_whole_object_omission_inherits_why_trace_2123` (omitting metadata entirely inherits the existing metadata verbatim and is allowed) in `tests/issue_2059_2060_covenant_pg.rs`, closing the untested "existing had why_trace, patch omits it" case the #2113 supersede test never exercised.
- **#2167 embedding-space cosine-gating residuals (defense-in-depth) from the #2187 Fable pre-merge audit** ([#2188](https://github.com/alphaonedev/ai-memory-mcp/issues/2188), [#2189](https://github.com/alphaonedev/ai-memory-mcp/issues/2189), [#2190](https://github.com/alphaonedev/ai-memory-mcp/issues/2190)). (1) **#2188** — `storage::proactive_conflict_check_candidates` (the ANN-routed candidate verdict pool) now carries the same row-side `AND (?N IS NULL OR embedding_space = ?N)` gate on `embeddings::active_embedding_space()` that the #2181 scan fallback got, so the LAST remaining row-side cosine consumer can never score a cross-space vector — closing the false-409-advisory window a concurrent out-of-process `ai-memory reembed`'s stale-active fingerprint opens (sqlite-only: proactive-conflict has no postgres twin — it runs on the rusqlite `Connection` in `handlers/create.rs`). Poison-pin `embedding_space_2188_candidates_path_excludes_foreign_space_row` in `tests/proactive_conflict.rs` (a foreign-space candidate id is never scored; the same row re-stamped into the active space DOES still 409). (2) **#2189** (test-hygiene) — the `STRICT_FLAG_GUARD` in `tests/embedding_space_provenance_2167.rs` is now an `RwLock<()>`: strict-flag flippers hold the EXCLUSIVE `write` lock for their whole window via the panic-safe RAII `StrictFlagSession` (restores the flag to `None` on drop), and every non-flipping reader holds a SHARED `read` lock, so a concurrent reader can never observe a half-flipped process-global flag (an intermittent test is a real bug, per the #1724 lesson). Regression pin `strict_flag_session_restores_flag_on_drop_even_on_panic_2189`. (3) **#2190** (test-gap) — live-pg twins `pg_heal_foreign_space_knob_widens_scan_2183` (the #2183(b) opt-in `AI_MEMORY_PG_HEAL_FOREIGN_SPACE` widened `list_unembedded` arm: knob OFF/unseeded never widens; knob ON + seeded fingerprint sweeps the foreign row but not the active row; NULL-space + NULL-embedding always swept; a `set_embeddings_batch` re-stamp makes the healed row leave the scan — monotone) + `pg_get_embedding_with_space_returns_real_space_2181` (the pg override returns the real per-row space, and `None` for a NULL-embedding row) in `tests/embedding_space_provenance_2167_pg.rs`, both exercised under the CI Postgres feature gate.

### Added

- **`valid_from` / `valid_until` claim-bitemporal bounds are now reachable on every write surface** ([#2258](https://github.com/alphaonedev/ai-memory-mcp/issues/2258)). The [#1834](https://github.com/alphaonedev/ai-memory-mcp/issues/1834) VALID-time interval `[valid_from, valid_until)` had a durable persist + immutable-on-upsert layer (schema v79, both backends) and a `valid_at` recall filter, but was UNREACHABLE from every advertised write surface — MCP `memory_store`, HTTP `POST /api/v1/memories`, and CLI `ai-memory store` all hardcoded `valid_from: None` / `valid_until: None`, so an agent following the bitemporal-backfill docs silently got store-time semantics (durable, WRONG bitemporal data with no error). This adds the optional `valid_from` + `valid_until` params to the store request DTO on all FOUR write funnels — MCP `memory_store` tool params, HTTP `POST /api/v1/memories` body fields, HTTP `POST /api/v1/memories/bulk` (both the sqlite and postgres build branches), and CLI `ai-memory store` `--valid-from` / `--valid-until` flags — each validated as RFC3339 via the existing `validate::validate_valid_at` (a malformed bound is a loud typed error, never a silently-stored value that would mis-filter `valid_at` recall). `valid_from` is stamped at create and preserved IMMUTABLY on a later upsert (the persist layer's ON CONFLICT keeps the stored value on both backends — the MCP `on_conflict=merge` content-dedup detour likewise never rewrites it); `valid_until` stays updatable via `memory_update`. An INVERTED interval (`valid_from > valid_until`) is deliberately ACCEPTED, not rejected — it is a well-defined EMPTY half-open interval that matches no `valid_at` instant, so it DEGRADES to fewer results, never wrong results (North Star), consistent with the `memory_update` `valid_until`-patch precedent; `validate_valid_at`'s doc records this explicitly. No new MCP tool / HTTP route / CLI subcommand — the counts are unchanged (only optional params were added; the trimmed full-profile `tools/list` grew 6692 → 6712 cl100k tokens, within the existing 6750 ceiling). Regression coverage: `tests/valid_from_write_surface_2258.rs` (MCP + HTTP single-create + HTTP bulk + CLI round-trip, RFC3339 rejection on each surface, `valid_from` immutable-on-merge, inverted-interval-is-empty, `valid_at` recall participation).
- **OPT-IN `notify`-backed L3 watch path (`fs-notify` feature, OFF by default)** ([#1978](https://github.com/alphaonedev/ai-memory-mcp/issues/1978)). Adds an inotify/FSEvents/ReadDirectoryChangesW event-driven watch loop ALONGSIDE the existing std-only `std::fs::metadata` poll fallback, behind a new `fs-notify` cargo feature (`dep:notify`, optional) that is OFF by default — the poll watcher stays the portable default and the build is byte-identical when the feature is off. The `notify` crate (notify-rs org, v8.2.0, CC0-1.0; `cargo audit` clean) subscribes to the configured hosts' transcript PARENT directories (`transcript_paths::watch_dirs`, reusing the same vendor-keyed path builders the resolver walks so the watch set and the poll resolver can never drift). On a filesystem event it triggers the SAME `poll_once` recovery funnel (debounced/coalesced) — the capture logic is never forked, so the L2-identical `(mtime, len)` change detection + `transcript_line_dedup` idempotency are unchanged. FAIL-SAFE / North Star (DEGRADE, never corrupt): a periodic BACKSTOP poll at `--interval-secs` still runs even under a silent event stream (a dropped inotify event under load degrades to the poll cadence, never lost capture), and on ANY init failure (unsupported platform, watch-limit exhaustion, no watchable directory) or a mid-run watcher fault the daemon FALLS BACK to the pure poll loop rather than silently stopping. Respects the same `Arc<AtomicBool>` shutdown contract. Enable with `--features fs-notify`.
- **`ai-memory update` content-patch flags (`--content-append` / `--content-replace-from` / `--content-replace-to`)** ([#2079](https://github.com/alphaonedev/ai-memory-mcp/issues/2079) — CLI half of the #1974 content-patch three-surface parity). Brings the [#1974](https://github.com/alphaonedev/ai-memory-mcp/issues/1974) content-patch primitive (already live on the MCP `memory_update` surface via PR [#2078](https://github.com/alphaonedev/ai-memory-mcp/pull/2078)) to the CLI `update` subcommand, reusing the same backend-agnostic pure helper `crate::content_patch::ContentPatch` (`src/content_patch.rs`, on release via [#2200](https://github.com/alphaonedev/ai-memory-mcp/pull/2200)) — no re-implementation. `--content-append` concatenates raw text onto the current content (verbatim, no separator); `--content-replace-from` / `--content-replace-to` perform a UNIQUE-match substring replacement (0 or >1 matches → typed error naming the count, never a silent first-match; the replacement may be empty). All three are mutually exclusive with `--content` and with each other. The flags are added to the EXISTING `update` subcommand — the top-level CLI subcommand count is UNCHANGED (still 89 default / 91 sal; pinned by `tests/cli_subcommand_count_invariant.rs`) — following the #1727 CLI-only precedent (freeze-safe: no wire-format change). Data-integrity posture (North Star): the patch is a pre-step that assembles the FULL replacement content and threads it through the SAME `validate_content` (empty-reject + secret-screen of the RESULT) and version-gated CAS a full `--content` replacement takes; the read pins the observed `version` and threads it as `expected_version` (TOCTOU fail-close — a concurrent write between read and CAS surfaces as VERSION_CONFLICT), and a caller-supplied `--expected-version` must agree with the observed version. Fail-closed on a zero/non-unique replace match or an empty assembled result — no bytes change. Tests (`src/cli/update.rs::tests`): append, unique-match replace, ambiguous-match refusal (no write), not-found refusal (no write), content+patch mutual-exclusion, empty-result rejection, version-pinned append. The HTTP `PUT /api/v1/memories/{id}` half of #2079 is a frozen-wire-surface expansion DEFERRED to v1.x (per the `b682c76a` ruling framework); #2079 stays open + milestoned v1.x for the HTTP remainder.
- **TRACT L1 honesty-slice anchors — the 8-gap port to `release/v1.0.0`** ([#1829](https://github.com/alphaonedev/ai-memory-mcp/issues/1829), [#1832](https://github.com/alphaonedev/ai-memory-mcp/issues/1832), [#1833](https://github.com/alphaonedev/ai-memory-mcp/issues/1833), [#1836](https://github.com/alphaonedev/ai-memory-mcp/issues/1836), [#1839](https://github.com/alphaonedev/ai-memory-mcp/issues/1839), [#1862](https://github.com/alphaonedev/ai-memory-mcp/issues/1862), [#1863](https://github.com/alphaonedev/ai-memory-mcp/issues/1863), [#1864](https://github.com/alphaonedev/ai-memory-mcp/issues/1864); campaign ruling `b682c76a` — honesty slices ship, mechanisms stay v1.x). Ports the main-based TRACT anchor chain (PRs #2053–#2077, now superseded) onto the release tree, reconciled with the landed #2064/#2213 `DurabilityModel` seam. Per piece:
  - **#1836 (G22)** `src/claim/` — `ClaimView`, a NON-AUTHORITATIVE, read-only, lossy projection of the 30-field `Memory` row through the frozen 9-field TRACT Claim shape, with `KNOWN_DIVERGENCES` + `CLOSED_ALGEBRA_ENFORCED_BY_DEFAULT = false` as machine-checked honesty pins; the kernel INVERSION stays ruled-v1.x (#2052). Canonical contract doc: `docs/spec/TRACT-L1-CLAIM-CONTRACT.md`.
  - **#1833 (G19)** `src/claim/relation.rs` — PROVISIONAL compile-time drift-gate mapping the closed 9-variant `MemoryLinkRelation` onto the TRACT relation kernel (wildcard-free exhaustive `classify`; a 10th variant breaks the build until classified); `OPEN_PREDICATES_SUPPORTED = false`; the open-predicate model stays ruled-v1.x (#2054).
  - **#1862 (G10.2)** `src/claim/refusal.rs` — `RefusalClaim`, the read-only Claim-shape a governance refusal WOULD persist as; `GovernanceRefusal::Display` now renders THROUGH the projection byte-identically (wired, not floating); `REFUSAL_PERSISTED_AS_CLAIM = false`; the persist mechanism stays ruled-v1.x (#2070).
  - **#1829 (G15)** `src/retention.rs` — `RetentionModel` anchor (`DiscreteTtlTiers`, no `CostOfAccessGradient` variant); `Tier::default_ttl_secs` reroutes through it BYTE-IDENTICALLY (the raw values live in the new `Tier::discrete_ttl_secs`), pinned by a per-tier equality test; the cost-gradient stays ruled-v1.x (#2066).
  - **#1830 (G16 residual disclosure)** — `resolve_durability_model` gains its FIRST production consumer (the #2213 audit's F6 note): `serve` boot now discloses `durability model: <label> (multi-node: <bool>)` from the REAL resolved config (synchronous level, quorum wiring, erasure cold-tier flag).
  - **#1832 (G18 clause 4)** — the signed forget-receipt SURFACED to the requester: `db::{ForgetReceipt, get_forget_tombstone, verify_forget_receipt}` (read-only projection of the v71 tombstone row; recomputes the signable bytes from the receipt's own fields, `verify_strict`, verdict `Valid|Invalid|Unsigned` — an unsigned receipt is NEVER `Valid`) + CLI `forget --show-receipt <id>` / `--verify-receipt <id>` query-only sub-modes (no new top-level command / MCP tool / HTTP route — the #1727 CLI-only precedent). Clauses 1+2 shipped opt-in via #2101; clause 3 stays ruled-v1.x (#2061).
  - **#1839 (G31)** — honesty fixes, NOT a governor: the registered-but-NEVER-observed `ai_memory_recall_latency_seconds` histogram is now actually observed on the HTTP recall path (both backends), and the recall `mode` vocabulary is const-ified (`RECALL_MODE_HYBRID`/`RECALL_MODE_KEYWORD` beside `RECALL_MODE_HYBRID_RERANK`, byte-identical). The latency governor stays ruled-v1.x (#2068).
  - **#1863 (G10.3)** / **#1864 (G10.4)** — characterization machine-checks (`storage::tests::g10_3_*` / `g10_4_*`) pinning the honest state: `long` tier is reachable via three lanes of which only caller-promote is court-gated, and namespace is a FILTER (exact-match, span-all on `None`), not an enforced trust boundary. The adjudicated-permanence posture (#2072) and the read-side bridge-capability (#2074) stay ruled-v1.x.
  - No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move (the `forget` receipt flags are sub-modes of the existing command). `src/storage/mod.rs` ceiling bumped 26_250 → 26_750 in lockstep.
- **Portability-v2 §V2-6 envelope L1/L2/L3 round-trip conformance fixture** ([#2030](https://github.com/alphaonedev/ai-memory-mcp/issues/2030)). Closes the last CC0 conformance-corpus residue tracked in `conformance/README.md`. The former blocker — "the #1944 v1.x v2-envelope producer" — was STALE: the integrity-complete exporter + fail-closed importer shipped at v1.0.0 (#2006, `src/portability/`), so the fixture is now generable from a PINNED PRODUCTION encoder under the same drift-gated discipline as its hex-vector siblings. The new golden `conformance/vectors/export/round_trip_l3.json` is an encoder-generated, fully DETERMINISTIC (fixed ids + timestamps; no `Date::now`/`Utc::now`/uuid nondeterminism) single-document v2 envelope carrying a row in every §V2-2 signed class — `signed_events` (a real hash-linked V-4 chain), `memory_revisions`, `forget_tombstones`, `model_attestations` — plus the L1 source-of-truth memory (with #1834 claim-bitemporal bounds + #1825 cid), the L3 `governance_rules`, and the operator PUBLIC trust anchor (a fixed CC0 TEST key enrolled at generation → the exporter's COMPUTED `conformance_level` reaches L3 deterministically; the private seed never crosses the envelope). `tests/conformance_export_roundtrip_2030.rs` (a) DRIFT-GATES the golden against a fresh regeneration (`AI_MEMORY_REGEN_GOLDEN=1 cargo test --test conformance_export_roundtrip_2030` rewrites it — the `conformance_corpus` regen precedent) and (b) round-trips the COMMITTED golden through the production importer (`import::import_full_envelope`), asserting per-class BYTE-EXACT preservation of the signed spine + `reverify_chain_ok`/`reverify_revisions_ok` (L2), the source-of-truth memory TEXT + cid re-derivation (L1), and the governance rule + advisory trust anchor (L3), per spec §V2-1. The envelope fixture is NOT part of `manifest.json`/`corpus_digest` (which cover the signed-byte hex family the non-Rust readers verify) — it exercises the Rust production importer end-to-end. The stale "blocked on #1944" claim is corrected in `conformance/README.md` + `docs/spec/PORTABILITY-V2.md` §V2-6. No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.

- **Erasure-coded archive cold tier (opt-in) + `DurabilityModel::ErasureCodedColdTier`** ([#2064](https://github.com/alphaonedev/ai-memory-mcp/issues/2064), closing the [#1830](https://github.com/alphaonedev/ai-memory-mcp/issues/1830) TRACT-gap G16 subsystem tracker). The finite-field codec is the **operator-authorized** (2026-07-18, sole-authority dependency rule) `reed-solomon-simd` crate (Leopard-RS GF(2^16), O(n log n), SIMD on x86-64 + AArch64; MIT AND BSD-3-Clause; zero RustSec advisories) — the #1830 2×5 adversarial vote (`4d3ea1c5`) UNANIMOUSLY rejected hand-rolling a codec, so `src/erasure/` contains **zero** finite-field math of its own and the shard on-disk format is the vetted crate's codec format (resolving the vote's T4 freeze-hostile concern).
  - **Shape.** When `AI_MEMORY_ERASURE_COLD_TIER` is truthy, a paced, idempotent, resumable SWEEP (the embedding-backfill pattern; `SWEEP_LIMIT_PER_TICK = 256` oldest-first per gc tick, wired into the daemon gc loop + `ai-memory gc`) encodes each committed `archived_memories` row into `k` data + `m` parity shards (`AI_MEMORY_ERASURE_DATA_SHARDS`/`AI_MEMORY_ERASURE_PARITY_SHARDS`, defaults 4 + 2) under `AI_MEMORY_ERASURE_DIR` (default: a `<db>.erasure` sibling). Bundles are self-describing (manifest pins codec id, geometry, per-shard SHA-256, whole-payload SHA-256, row schema version) and are DERIVED, REGENERABLE redundancy — the archived DB row stays the durable source of truth. The sweep reads only COMMITTED rows, so a rolled-back archive can never leave a resurrectable phantom bundle.
  - **Reconstruct-on-read.** `memory_archive_restore` (all surfaces — the existing verb, no new SSOT counts) re-materializes an archived id whose DB row is GONE from its verified shards inside the restore transaction, then runs the UNCHANGED normal restore path (governance pre-write hook, collision check, cid re-mint). The owner-scoped twin verifies the bundle's own ownership metadata first, so an un-owned bundle is never materialized (no existence oracle). A degraded-but-within-budget bundle self-heals (re-encoded to full loss budget) on read.
  - **Degrade, never corrupt.** RS *erasure* decoding must know which shards are bad, so every shard is hash-verified and corruption is DEMOTED TO AN ERASURE (never fed to the decoder as good); `>= k` verifiable shards are required BEFORE decoding, and the reassembled payload must pass the whole-payload SHA-256 gate on EVERY path. The acceptance invariant holds: **any k of n = k + m shards reconstruct the original bytes exactly**; loss/corruption beyond the `m`-shard budget FAILS LOUD (typed `ErasureError::InsufficientShards` / `PayloadHashMismatch`, transaction rolled back, zero partial state) — never partial, never wrong.
  - **Destruction intent flows through — SAFELY (pre-merge durability-audit fixes F1/R1).** The purge funnels (`purge_archive`, `purge_archive_for_caller`, gc auto-purge) record intent in a durable, fsync'd **write-ahead purge-intent journal** (`.purge-intent/` markers) BEFORE the `DELETE`, then remove the bundles — keyed on the bundle DIRECTORY existing, not the enable flag. A bundle that survives a crash between the `DELETE` and the removal is reconciled by the gc-tick pass (`reconcile_and_scrub`), which discriminates the two byte-identical rowless states the auditor flagged: a **journaled** rowless bundle is HARD-reaped (confirmed destruction; `archive restore` also refuses a journaled id and the restore path drops the now-stale bundle in-flow), while an **un-journaled** rowless bundle — byte-indistinguishable from partial DB LOSS where the bundle is the last surviving copy — is **QUARANTINED** (`.quarantine/`, preserved + invisible to serving, NEVER auto-destroyed) with a loud WARN, recoverable via `AI_MEMORY_ERASURE_RECOVER_QUARANTINE=1`. This upholds the prime directive: "never cause unintentional data loss" outranks "purged content must not resurrect". The false "caught by the next purge" self-healing claim was corrected.
  - **Bundle write durability + paced reconciliation + scrub (audit F2/F3/R2/R3).** The sweep bounds its per-tick pacing on ATTEMPTS (not just successes) AND on a probe budget (so a single permanently-failing "poison" row can no longer pin the keyset resume frontier and reopen an O(N)-per-tick re-probe, R3), and the frontier skips an already-bundled prefix so a steady-state tick does zero filesystem work. The reconciliation scan walks a ROTATING window over the full bundle listing so a store larger than one tick's scan limit is still eventually covered (R2). The bundle temp-dir publish now `fsync`s each shard + the manifest + the temp dir + the parent directory around the rename (a torn shard behind a surviving manifest can no longer be silently trusted after a power loss, F3); a bounded scrub lane hash-verifies current bundles and re-mints any torn one from the durable archived row before a reconstruct needs it. Crashed `.tmp-*` assembly dirs are reaped. A non-finite (`NaN`/`±Inf`) REAL column now fails LOUD on encode instead of silently becoming JSON `null` (F4).
  - **Honest durability disclosure (flips the #1830 anchor).** `DurabilityModel` (PR #2065's `#[non_exhaustive]` seam, vendored onto this base) gains the `ErasureCodedColdTier` variant through its wildcard-free exhaustive matches; `resolve_durability_model` now takes the erasure flag (precedence: quorum > erasure > power-loss-safe > local). `is_multi_node()` stays HONESTLY `false` for the erasure tier: v1.0.0 shard placement is single-node (one local directory) — it hardens the cold tier against partial disk corruption / lost shard files, NOT whole-node loss. The G16 no-primary multi-node placement + postgres archive-funnel parity are the tracked residuals.
  - Coverage: `tests/erasure_cold_tier_2064.rs` (sweep + reconstruct-on-read after row loss; shard loss + in-place corruption up to the parity budget; beyond-budget fails loud with zero partial state; purge removes bundles; owner-scoped refusal; pacing; default-OFF byte-identical; **the two inverted R1 pins — journaled-purge orphan reaped vs un-journaled DB-loss bundle quarantined-not-destroyed + DR-recoverable — plus the R5 aborted-purge stale-marker-cleared pin**) + `src/erasure/codec.rs` unit suite (exhaustive any-k-of-n subset reconstruction, tampered-manifest refusal, foreign-codec refusal) + `src/erasure/store.rs` unit suite (self-heal, hostile-id refusal) + the updated `src/durability.rs` pins. No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.
- **Integrity-complete Portability-v2 exporter + importer — `ai-memory export --full`** ([#2006](https://github.com/alphaonedev/ai-memory-mcp/issues/2006), rebuilt fresh on schema v85, vote `34bbf781`). Closes the #1944 residue: the DEFAULT JSON `export` is a memories+links convenience view that DROPS the signed audit/governance spine (a durability data-loss on a pipe-to-file "backup"). `export --full` now emits the complete Portability-v2 envelope (spec `docs/spec/PORTABILITY-V2.md`) — `spec_version="2"`, `db_schema_version`, and every §V2-2 signed record class (`signed_events`, `memory_revisions`, `forget_tombstones`, `agent_lineage`, `model_attestations`, `governance_rules`, role `trust_anchors`) byte-preserved (a shared provably-inverse hex codec keeps every `Vec<u8>` signature/hash byte-exact instead of serde's default number-array), with a **computed** `conformance_level` (L1/L2/L3) marker derived from an in-export re-verify pass (a broken source chain honestly downgrades to L1). No new top-level CLI command (`Export` → `Export(ExportArgs)` with `--full`), MCP tool, HTTP route, or DB migration — no SSOT-count move; the default `export` is byte-unchanged.
  - **★ Symmetric importer — LOSSLESS + FAIL-CLOSED.** `import` detects a v2 envelope by `spec_version` and routes to `src/portability/import.rs::import_full_envelope`, the highest-data-integrity path (a BULK WRITE into source-of-truth memory TEXT). It is **ALL-OR-NOTHING**: every class is staged inside ONE transaction and the imported signed spine is re-verified (`verify_audit_trail`) BEFORE commit — a malformed / tampered / truncated bundle (a broken `prev_hash` link, a sequence gap, or detected tail-truncation) is REJECTED with the transaction rolled back, so a rejected bundle applies **ZERO rows** (never a partial apply). Signed classes are RAW-inserted byte-preserved (the importer NEVER re-signs; `agent_lineage` `record_bytes` is recomputed byte-identically via the record's own canonical-CBOR encoder and its witnesses ride the `signed_events` array, so lineage is never re-witnessed / double-anchored). Idempotent (id-keyed memories + `INSERT OR IGNORE` signed classes); tombstones-before-admit; governance rules verify-or-drop; trust anchors advisory-only (never adopted as a trust root). v85 composition: memories cross the screened `Memory` path so their durable TEXT is lossless; the #1825 `cid` re-derives deterministically on import, `kind_provenance` re-denormalises from metadata, and #2167 `embedding_space` correctly re-stamps on the destination re-embed (carrying a source tag without the regenerable vector would falsely label a non-existent vector — a fail-closed violation).
  - **★ Import-hole hardening (Fable pre-merge audit [#2208](https://github.com/alphaonedev/ai-memory-mcp/issues/2208)/[#2209](https://github.com/alphaonedev/ai-memory-mcp/issues/2209)/[#2210](https://github.com/alphaonedev/ai-memory-mcp/issues/2210)/[#2211](https://github.com/alphaonedev/ai-memory-mcp/issues/2211)).** Four holes in the first-cut v2 importer, all closed before merge. **#2208 (BLOCKING, forget covenant):** the memories loop consulted only the BUNDLE's tombstones — the DESTINATION's `forget_tombstones` were never probed, so re-importing a bundle after the dest ran `memory_forget` RESURRECTED the erased content alongside its own tombstone; the loop now probes `db::memory_is_tombstoned` (dest + bundle uniformly, bundle tombstones stage first) AND the new `db::memory_is_archived` (a dest-archived id is not re-admitted live — no `memories`/`archived_memories` dual residency), counting `tombstoned_skipped`/`archived_skipped`. **#2209 (BLOCKING, spine gate covered `signed_events` only):** the pre-commit re-verify now ALSO (a) replays the WHOLE staged `memory_revisions` chain from the stored columns (`verify_staged_revision_chain` — unique contiguous `1..=N` sequences + `prev_hash == SHA-256(canonical_revision_chain_bytes(predecessor))`, the revisions-chain verifier the codebase lacked), (b) rejects when `verify_audit_trail`'s `LineageCheck` verdict is `Forged` (tampered/forked `agent_lineage`), and (c) enforces IDENTICAL-OR-REFUSE on every signed-class `INSERT OR IGNORE` (an ignore is legitimate ONLY when the surviving row is byte-identical — an ignore from the UNIQUE `sequence` index / `(agent_id, epoch)` PK with a DIFFERENT surviving row is a chain fork/equivocation that would otherwise be SILENTLY dropped while the report claimed success). **#2210 (HIGH, fail-open envelope parse):** `spec_version` is now validated by VALUE (`!= "2"` refuses loudly at the route AND the funnel — a v3 bundle can never fall through to the L1 path or parse with its new classes dropped), `ExportEnvelope` gained `#[serde(deny_unknown_fields)]` (an unknown top-level record class refuses at parse — a wire envelope, NOT an MCP tool-request struct, so the #1052 permissive rule does not apply), and `db_schema_version > dest applied schema` refuses. **#2211 (HIGH, L1-restamp bypass):** the v2 route now honours `ImportArgs` — `metadata.agent_id` is RESTAMPED with the caller's id by default (original preserved under `imported_from_agent_id`; verbatim identity requires the explicit `--trust-source`, deliberately NOT earned by an intact-but-unsigned spine, which is trivially forgeable), `--on-conflict` governs `(title, namespace)` collisions (default `version` suffixes the INCOMING title so `storage::insert`'s upsert can never clobber a dest row's durable text; `error` skips + counts), and memories land via the new `db::insert_imported` (same funnel as `insert` minus the local vector-clock stamp — remote-admission semantics mirroring `insert_if_newer`, so the dest never misattributes clock authorship of rows it did not author).
  - **★ Re-audit round 2 (N1/N2, same review thread).** **N1 (HIGH, downgrade bypass of the #2208 gate):** the v1 wire-form path (`import` without `spec_version`) never consulted tombstones — stripping `spec_version` from a bundle carrying a dest-forgotten memory resurrected it under its original id through `insert_with_conflict`; the L1 memories loop now runs the SAME `db::memory_is_tombstoned` + `db::memory_is_archived` probes as the v2 route (skip + per-row reported error), so the forget covenant holds on BOTH wire forms. **N2 (MEDIUM, unauthenticated tombstone suppression):** bundle `forget_tombstones` raw-inserted without cross-checking live dest rows — a bundle tombstone for a LIVE dest id planted the contradictory live-row+tombstone state and permanently suppressed that id's future federation/import admission; the staging loop now SKIPS (+ WARN + `tombstones_skipped_live` count) any bundle tombstone whose id is currently live at the destination — only the destination's own `memory_forget` funnel may erase a live dest row, while erasure-receipt transfer for not-live ids is unchanged.
  - Regression coverage: `tests/portability_roundtrip_2006.rs` (end-to-end byte-exact round-trip of every signed class + the memory source-of-truth fields + deterministic cid re-derivation through a real JSON serialize→import; a source interior-delete downgrades `conformance_level` to L1) + `src/portability/import.rs` (TAMPERED + TRUNCATED bundles rejected with zero rows applied; idempotent re-import; dest-forgotten NOT resurrected + dest-archived not re-admitted #2208; tampered revision chain + diverging dest chain + forged lineage rejected with zero rows #2209; newer spec/schema + unknown record class refused #2210; spine-less bundle restamped + no local clock bump + collision never clobbers #2211) + `src/cli/io.rs` (v2 route refuses spec_version "3" / unknown class; restamps by default #2210/#2211) + `src/portability/{hex_bytes,dto,emit,read}.rs` unit coverage. `docs/spec/PORTABILITY-V2.md` §V2-7 flipped from "deferred to v1.x" to SHIPPED (the NDJSON streaming framing #2040 + embedder-tag round-trip #2041 remain the only v1.x follow-ups).
- **Opt-in vectorlite ANN backend scaffolding (feature `vectorlite`, OFF by default)** ([#1860](https://github.com/alphaonedev/ai-memory-mcp/issues/1860)). A [vectorlite](https://github.com/1yefuwang1/vectorlite)-backed implementation of the #1005 `VectorSearchIndex` seam (`src/vectorlite.rs`), operator-authorized 2026-07-18. Vetting: upstream is an Apache-2.0 C++ SQLite **loadable extension** (hnswlib + Google Highway SIMD); **no Rust crate exists** (the crates.io `vectorlite` name is an unrelated project) and upstream prebuilts ship only inside `vectorlite_py` wheels (linux-x86_64, macos-x86_64/arm64, win-amd64 — no linux-arm64). Because a build-time native-lib acquisition step would break the 3-OS CI matrix, the 5 release channels, and reproducible builds (the exact #1860 blockers), the feature performs **zero build-time acquisition**: it only enables rusqlite's `load_extension` API (bundled SQLite unchanged) and loads an **operator-acquired** binary at runtime from `AI_MEMORY_VECTORLITE_EXTENSION` (acquisition helper with pinned upstream SHA256s: `scripts/fetch-vectorlite.sh`). Default builds are unchanged (`cfg`-gated module, no new dependency, `cargo audit` clean); the flag is deliberately in **no CI job or release channel** — cross-matrix native-lib availability remains an operator/release-infra decision.
  - **Fail-closed / degrade-never-corrupt contract.** The ANN index stays a **derived, disposable artifact** (in-memory, rebuilt from the durable memory text/embeddings at every boot; the on-disk persistence + 2PC-coherence substrate re-platforming stays deferred per the #1860 review). Load/smoke failure at boot → the new backend-resolving funnels (`hnsw::boxed_configured_index` for the daemon, `hnsw::arc_configured_index` for MCP stdio — both sharing `vectorlite::from_env`) log an ERROR and fall back to the default pure-Rust HNSW backend. A hard mid-life failure degrades **in place** to a default backend re-seeded from the retained entry mirror (eviction sink re-wired, removed ids stay removed). Construction smoke-verifies the full virtual-table contract (create/insert/`knn_search`/delete/re-insert) before the backend is eligible. Strict-dim boundary is structural (#1005 G4 superset); capacity honors the #1005 G2 evict-oldest / `hard-fail-at-cap` semantics with the same `max_entries_reached` eviction-sink events.
  - Coverage: `tests/vectorlite_1860.rs` (fail-closed construction + funnel fallback, plus `#[ignore]`d live seam-parity + capacity/eviction suites against an operator-acquired extension — verified locally against the pinned linux-x86_64 v0.2.0 binary) and `src/vectorlite.rs` unit tests (hard-failure degrade paths, no native lib required). No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.
- **Claim-bitemporal VALID-time read/write surface** ([#1834](https://github.com/alphaonedev/ai-memory-mcp/issues/1834), residual of PR #2036 re-landed on the v85 tree). The schema-v79 `memories.valid_from` / `valid_until` columns (RFC3339 TEXT; the half-open `[valid_from, valid_until)` END-EXCLUSIVE interval a claim is asserted to HOLD, distinct from the `created_at` transaction-time axis) are now threaded through the full read/write surface on BOTH backends. `Memory` gains the two optional fields (`FIELD_COUNT` 28→30; `skip_serializing_if` so legacy wire shapes are byte-identical when unset); `db::insert` / `insert_if_newer` / the pg `store`/`store_batch`/`apply_remote_memory` persist them with the LWW discipline `valid_from` IMMUTABLE (stored/genesis value always wins on upsert + federation merge, like `cid`) and `valid_until` caller-closable (`COALESCE` on upsert; newer-wins under federation LWW so a peer that CLOSED a claim replicates that close). The same-`id` federation merge lane also carries the close: `crdt_merge::merge_memory` resolves `valid_until` newer-wins (LWW, `valid_from` local-immutable) and BOTH full-row-overwrite writers (`overwrite_full_row_by_id` sqlite, pg `merge_inbound`) persist the two columns, so a peer that CLOSED a claim replicates that close by id and replicas CONVERGE on VALID-time ([#2207](https://github.com/alphaonedev/ai-memory-mcp/issues/2207)). `memory_update` (HTTP `PUT /memories/{id}`, MCP `memory_update`, SAL `UpdatePatch.valid_until`, sqlite `update`/`update_with_expected_version` + pg `update_with_expected_version_once`) accepts an opt-in `valid_until` patch — `valid_from` is structurally absent from every UPDATE SET list, so the genesis assertion instant can never be rewritten. Recall + list gain an opt-in RFC3339 `valid_at` AS-OF instant (validated 400/typed-error at every entry surface via the new `validate::validate_valid_at`): the keyword `recall` (?13), the hybrid FTS (?13) / semantic linear-scan (?11) SQL predicates + the HNSW Rust re-filter, the pg FTS ($10) / semantic ($11) pools, and `build_list_query` / pg `list` ($8) all apply the same NULL-guarded half-open window — `None` is byte-identical to pre-#1834. Threaded through `RecallRequest.valid_at` (all three surface constructors), `ListQuery`/`RecallQuery`/`RecallBody`, the MCP `memory_recall`/`memory_list`/`memory_update` tools, and the SAL `Filter.valid_at`. Archive→restore carries the interval losslessly via the schema-v85 `archived_memories` mirror (#2035). Regression coverage: `tests/claim_bitemporal_recall_1834.rs` (store→recall/list AS-OF windowing on keyword + hybrid + list; start-inclusive/end-exclusive boundary; `valid_until` close via update with `valid_from` immutability; archive→restore round-trip; RFC3339 validation) + `tests/claim_bitemporal_federation_convergence_2207.rs` (same-`id` `merge_inbound` of a remote-newer close closes the receiver's row so a post-close `valid_at` recall excludes it; a stale remote leaves a fresher local close intact) + the postgres twin `tests/claim_bitemporal_1834_pg.rs` (`#[ignore]` + sal-postgres: SAL `Filter.valid_at` recall/list windowing + `UpdatePatch.valid_until` close with `valid_from` preserved).
- **Direct-API SDK shims — Anthropic + OpenAI, Python + TypeScript** ([#1390](https://github.com/alphaonedev/ai-memory-mcp/issues/1390)). Four thin (~100 LOC) standalone wrapper packages under `clients/` that proxy a vendor LLM SDK client and record each turn to ai-memory via the `memory_capture_turn` MCP tool (RFC-0001) BEFORE returning the response verbatim. Closes the #1389 layered-capture gap for Direct-API users — callers who hit `anthropic.messages.create` / `openai.chat.completions.create` in their own scripts WITHOUT a host harness (Claude Code, IDE plugins) that writes a recoverable transcript. Packages: `clients/anthropic-shim-py` (PyPI `ai-memory-anthropic-shim`), `clients/openai-shim-py` (PyPI `ai-memory-openai-shim`), `clients/anthropic-shim-ts` (npm `@alphaone/ai-memory-anthropic-shim`), `clients/openai-shim-ts` (npm `@alphaone/ai-memory-openai-shim`). Each ships a README + offline (fakes + recorded cassettes) test suite + a live-MCP-server integration test (auto-skips when no server). **Design invariants:** (1) **transparent pass-through** — `wrap(client)` returns a proxy that delegates every attribute to the wrapped client verbatim, intercepting ONLY `messages.create` / `chat.completions.create`; args + response are forwarded unchanged, so the shim never couples to the vendor SDK's evolving internals (it is model-agnostic — no model id is inspected). (2) **non-wedging** — a capture failure (missing `ai-memory` binary, substrate error, unexpected response shape) NEVER propagates into the caller's LLM call; it emits a stderr WARN and returns the response untouched. (3) **idempotent** — turns dedup on `host_session_id` + monotonic `host_turn_index` so a re-run does not duplicate memories. (4) **streaming** — a `stream=True` call records the request turn only and passes the stream through untouched (consuming it to record the reply would break passthrough). The vendor SDKs (`anthropic`/`openai` for Python, `@anthropic-ai/sdk`/`openai` for TypeScript) are optional/peer dependencies — the caller brings their own client instance. A manual-only `workflow_dispatch` publish workflow (`.github/workflows/publish-sdk-shims.yml`) builds + tests each package and gates the literal registry publish (PyPI Trusted Publishing / npm token) behind protected GitHub Environments — there is DELIBERATELY no push/tag auto-trigger. Standalone client packages: NO Rust surface, NO MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.
- **`memory_update` content-patch primitive — append / unique-match replace** ([#1974](https://github.com/alphaonedev/ai-memory-mcp/issues/1974)). Opt-in flat params on the EXISTING `memory_update` tool (deliberately NOT a new tool → MCP tool-count SSOT unchanged): `content_append` (raw suffix concat onto the current content; empty rejected) and the `content_replace_from` + `content_replace_to` pair (**UNIQUE-match** substring replace; `to=""` = deletion). **★ Data integrity (North Star): the durable memory TEXT is mutated FAIL-CLOSED.** The unique-match replace refuses on a ZERO-match (`ReplaceNotFound`) OR a non-unique match (`ReplaceMultiple(n)`, count named) with NO bytes changed — never a silent first-match, never a wrong/multiple-span rewrite; append can only concatenate (it can never truncate); an empty ASSEMBLED result is refused by the same `validate_content` empty-reject. Implemented as a PURE backend-agnostic read-modify-write pre-step (`src/content_patch.rs`) that assembles the FULL replacement content and threads it through the **SAME** version-gated CAS a full-content update takes — so it inherits, byte-identically to a full `content` replacement: the v45 optimistic-concurrency `version` CAS + bump, the #1727 `archive_reason='in_place_edit'` prior-content snapshot (undo-recoverable — prior TEXT never lost), the re-embed on content change, and the genesis-immutable #1825 `cid` (an in-place update does not re-stamp the genesis content-address, and `cid_genesis` stays consistent — no corruption). **Mutual exclusion** (`content` + any patch param, or append + replace, → validation error) and **TOCTOU fail-close** (the current-content read pins the observed `version` and threads it as `expected_version`; a concurrent write between the read and the CAS surfaces as `VersionConflict`, and a caller-supplied `expected_version` that disagrees with the observed version is refused before any write) are enforced at the handler. Adds 3 param-name SSOT consts (census 128→131). 26 tests (12 pure-helper `content_patch::tests` + 14 handler `mcp::update::tests`): append-preserves-prior, unique-replace, non-unique/zero-match fail-closed-no-write, empty-result rejected, mutual-exclusion, version fail-close + matching-version-ok, all-non-content-fields-preserved, genesis-cid-consistent, in_place_edit-snapshot-for-undo. HTTP `PUT /memories/{id}` + CLI `update` surface parity is a mechanical 1:1 follow-up (the assembly is the shared pure `crate::content_patch` helper).
- **v1.0.0 honesty/disclosure slice — docs/char-test/infra bundle** ([#1868](https://github.com/alphaonedev/ai-memory-mcp/issues/1868), [#1875](https://github.com/alphaonedev/ai-memory-mcp/issues/1875), [#1980](https://github.com/alphaonedev/ai-memory-mcp/issues/1980), [#1987](https://github.com/alphaonedev/ai-memory-mcp/issues/1987), [#1979](https://github.com/alphaonedev/ai-memory-mcp/issues/1979), [#1707](https://github.com/alphaonedev/ai-memory-mcp/issues/1707)). Six independent, no-schema disclosure/docs/char-test/infra slices folded into one branch. **#1868** — B7-STREAM disposition: MCP tool responses are single-terminal (the stdio loop dispatches inline, one response per request); streaming is feasible but deliberately deferred, pinned by `initialize_advertises_no_streaming_capability_1868` (`src/mcp/mod.rs`). **#1875** — discloses the SQLite-vs-Postgres curator behavioral difference (`docs/cli-design-rationale.md`). **#1980** — a signed-rule-pack refuse-by-default template + workflow docs (`docs/governance/signed-rule-pack.md` + `docs/governance/refuse-by-default-rules.template.json`). **#1987** — wires `bench --baseline` regression guard into CI + the baseline-capture recipe (`PERFORMANCE.md`, `.github/workflows/bench.yml`). **#1979** — the Claude Code plugin marketplace manifest (`.claude-plugin/marketplace.json` + `plugins/ai-memory/`). **#1707** — shadow consume-vs-access divergence evidence in the confidence-calibration report (`src/confidence/calibrate.rs::ConsumeAccessDivergence`) — SHADOW MODE, logged/reported only, never consulted by `recall()`, no ranking change. **This bundle ships the v1.0.0 honesty/disclosure slice only; the freeze-hostile TRACT mechanisms (G16 durability, G15 retention, G31 latency, G10.2 refusal-persist, G10.3 promotion-court, G10.4 bridge-capability) are tracked v1.x per standing ruling** — their disclosure-anchor PRs (#2065/#2067/#2069/#2071/#2073/#2075) depend on the still-unmerged TRACT-L1-CLAIM-CONTRACT.md foundation (#1836/#1833/#1832) and were deliberately excluded from this bundle rather than force-fit.
- **Fail-closed migration-ladder-uniqueness CI gate + runtime assertion (guardrail-D)** (2x5-vote decision memory `b682c76a`). Structurally prevents the SILENT migration-ladder-collision class that made the upcoming schema-PR merge train unsafe. Migration SQL is loaded by `include_str!` at explicit paths in `src/storage/migrations.rs` (sqlite) + `src/store/postgres.rs` (postgres) with NO uniqueness enforcement anywhere: a PR built on an OLD base can add `migrations/postgres/0041_v82_archived_valid_time.sql` ([#2036](https://github.com/alphaonedev/ai-memory-mcp/issues/2036)) while release already carries `migrations/postgres/0041_v84_embedding_space.sql` — SAME numeric prefix, DIFFERENT filename ⇒ ZERO git conflict, git silently keeps BOTH, the build succeeds, and a CORRUPTED / ambiguous ladder ships fleet-wide (probe-guarded ALTERs make the double-apply a silent no-op — non-fail-closed). [#2192](https://github.com/alphaonedev/ai-memory-mcp/issues/2192) renumbered the collider to `0042_v85_*`; this guardrail keeps the whole class from ever re-landing silently. Two layers: (1) **CI gate `scripts/check-migration-ladder.sh`** (HARD-BLOCK, `--self-test`, wired into `.github/workflows/c8-precheck.yml` as `migration-ladder-gate`) fails non-zero on (a) two files in `migrations/<backend>/` sharing a 4-digit prefix (the #2036/#2192 shape), (b) two ladder ARMS declaring the same schema version, (c) a prefix gap (outside documented `KNOWN_PREFIX_GAPS`) or a non-monotonic arm jump, (d) cross-adapter disagreement (the two `CURRENT_SCHEMA_VERSION` consts + the highest-prefix file's `vNN` tag + the postgres `migrate_vN` tip must all agree), (e) an orphan migration file or an `include_str!` arm referencing a missing file — the `--self-test` plants the EXACT same-prefix-different-name collision AND a same-version-two-arms case in a throwaway copy under the repo and confirms rejection of both plus a clean control; (2) **runtime twin `tests/migration_ladder_integrity.rs`** re-asserts prefix-uniqueness, gap-free sequence, `MIGRATION_LADDER` monotonicity, and cross-adapter tip agreement in `cargo test` so a collision fails even if the shell gate is bypassed. Documented as lint gate #6 in CLAUDE.md. DATA-INTEGRITY guardrail (North Star: degrade — a loud non-zero exit — never corrupt the ladder). No new MCP tool / HTTP route / CLI subcommand / DB migration — no SSOT-count move.
- **Crypto-agility re-anchor ceremony wired into a signed checkpoint** ([#2004](https://github.com/alphaonedev/ai-memory-mcp/issues/2004), R75; milestone-override from `[v1.x]`/8-0-defer into v1.0.0 per the operator 100%-fix + the 2×5 vote `4d3ea1c5`). The FROZEN `re-anchor/v1` primitive (`src/identity/re_anchor.rs`) shipped at the crypto-core close-out with ZERO non-test callers — bytes frozen but unwired. This wires it into the SAME off-daemon-custody, K1-pinnable `checkpoints`-row persistence the #1822 audit-head witness uses, so an operator can actually RUN the ceremony and the anchor is loadable + verifiable on both backends. Per-record PQ signatures are forbidden (spec §2.4 — incompatible with endpoint budgets), so post-quantum strength binds at CHECKPOINT granularity: the new-suite key countersigns "seen prior chain head H @ sequence N", so enabling a stronger / PQ suite on a live corpus later causes ZERO write failures and ZERO record rewrites and every pre-break record stays attributable.
  - `governance::audit::build_signed_reanchor_checkpoint` (mirrors `build_signed_witness_checkpoint`) countersigns the prior head under `SuiteId::Ed25519Sha256` with the audit-witness custody key, rides the canonical `re-anchor/v1` CBOR + its detached signature (base64) in a signed `ConditionType::ReAnchor` resolution, envelope-signed via `checkpoints::sign_resolution_into`.
  - `governance::audit::verify_reanchor_checkpoint` + `ReAnchorCheckpointError` — fail-closed read-back: type guard → **K1 pin** (`resolver_pubkey == enrolled witness key`) → envelope-sig → `decode_re_anchor_v1` the PERSISTED bytes (never a re-derived projection) → `verify_re_anchor` (+ the §2.4 suite cross-check). Returns the decoded `ReAnchorRecord`.
  - `signed_events::emit_reanchor_ceremony` — operator entry point (reads the head, loads the witness key, builds + inserts). NOT throttled / NOT fire-and-forget — an explicit ceremony whose disposition is returned; `Ok(None)` when no witness key is enrolled or the chain is empty (opt-in no-op).
  - `ai-memory audit re-anchor [--json]` — a SUB-VERB under the existing `audit` command (no new top-level subcommand → no CLI-count bump). RELOADS the persisted anchor row from the database (`checkpoints::get`) and self-verifies THAT row (K1) — the true persisted round-trip, not the in-memory struct (PR #2214 audit F3). The read-back is fail-closed: enrolment drift (`AI_MEMORY_WITNESS_PUBKEY` ≠ the custody signing key) or a reload miss (`row_missing`) surfaces a visible FAILED line + a NON-ZERO exit (never a silent "ok"); "no pubkey enrolled" is a distinct exit-0 `no_enrolled_pubkey` state (defensive-unreachable in the shared-custody layout; kept fail-safe against future custody divergence). Every disposition prints WHICH db + chain was anchored (`db <path>`, `chain sqlite:signed_events` — PR #2214 audit F2 honesty: the verb operates on the LOCAL sqlite chain only; the postgres chain has no re-anchor twin yet, tracked #2217). Custody dispositions are three-way typed (`signed_events::ReAnchorOutcome`, PR #2214 audit F4): genuinely ABSENT custody / an empty chain are explicit exit-0 `{"status":"skipped","reason":"witness_custody_absent"|"empty_chain"}` JSON (never an empty stdout an automation would have to guess about); an enrolled-but-UNLOADABLE key (corrupt / half-enrolled / public-only) is a ceremony FAILURE — exit 1, `{"status":"error","reason":"witness_key_unloadable"}` — never a silent skip with false "enrol a key" guidance. Nothing persists on any non-Anchored disposition (pinned by tests). Per audit F1 the R75 "crypto-agile" public claim stays LOCKED (this PR ships the ceremony slice only; universal `suite_tag` + a second enrolable suite remain v1.x).
  - `ConditionType::ReAnchor` (free-text, no schema migration — the SAL enforces the closed set). No new hard-to-reverse signed-bytes layout is introduced: the frozen bytes remain the golden-pinned `re-anchor/v1` CBOR, and the `ReAnchorResolutionWire` JSON is versioned (`v:1`) + rides verbatim inside the already-signed checkpoint envelope (the #1822 witness `resolution` precedent), so an on-disk anchor keeps verifying forever regardless of future serializer behavior. The universal per-signed-class `suite_tag` + a separate PQ-capable enrolment key stay v1.x-deferred (today the only enrolled suite is Ed25519-SHA256).
  - Regression coverage: `tests/reanchor_ceremony_2004.rs` (7 sqlite + 1 live-pg parity: emit→reload→verify round-trip binds the real head sequence + the Ed25519 suite tag; every tamper class fail-closes — broken envelope → `EnvelopeInvalid`, re-signed-envelope tampered countersig → `CountersignatureInvalid`, wrong enrolled key → `PubkeyNotEnrolled`, non-re-anchor → `NotReAnchor`; opt-in no-op on no-key / empty chain) + `src/cli/audit.rs::reanchor_ceremony_2004_cli_tests` (the three-state read-back: PASS exits 0, enrolment-drift fails closed exit 1, no-pin is exit-0 `no_enrolled_pubkey`).

- **Embedding vector-space provenance (schema v84)** ([#2167](https://github.com/alphaonedev/ai-memory-mcp/issues/2167), COMPLETE — S1–S9 landed, both backends). A per-row `embedding_space TEXT` column (`<canonical_model_id>#<prefix_scheme>`, NULL = legacy/unverified) on `memories` + `archived_memories` (both backends, additive `ALTER ADD COLUMN` + ladder-owned partial index, no rebuild; `CURRENT_SCHEMA_VERSION` 83→84) so recall can never score a stored vector from a different embedding space (a same-dim model swap) — worst case is DEGRADED recall (excluded until `reembed` regenerates from the durable text), never WRONG. The canonical fingerprint (`embedding_space_fingerprint`, the single SSOT shared with the #2168 federation gate: prose-strip + daemon-native family-fold + `:latest`-strip + `nomic-task-v1` prefix) is stamped in the SAME statement as every embedding write (`set_embedding` / `set_embeddings_batch` / `_reembed`, SAL `update_embedding` / `set_embeddings_batch`, boot backfill, HTTP/MCP create·update·consolidate·reflect, reembed CLI). Federation ACCEPT stamps the sender's CLAIMED space (`mint(se.model)`).
  - **S4 ★ recall-core gate (landed).** `CosineComparison` gains `SpaceMismatch{stored_space}` + `UnverifiedSpace`; the new `Embedder::cosine_similarity_space_checked` gates in the load-bearing order space→dim→score. All four sqlite recall sites enforce it: the FTS branch keeps the keyword score + forces cosine `0.0` + counts (degraded-not-invisible — a foreign/NULL row stays keyword-recallable), while the semantic linear-scan + the #1692 HNSW-hit recompute skip + count; the #1692 `None`-arm stale-`hit.distance` fallback is DELETED (an ANN hit whose row-side vector cannot be re-verified is excluded + counted, never trusted). HNSW defense-in-depth: `db::get_all_embeddings` filters the boot seed set to `AND embedding_space = <active>` (a foreign vector never enters the graph) and the row-side post-filter makes any missed boundary harmless-not-wrong. Postgres: every recall `<=>` cosine consumer gains `AND embedding_space = $fp` (SQL `NULL != $fp` excludes unverified rows for free — matching the sqlite comparator exactly). The active fingerprint threads through the recall free-fn family + `semantic_phase` + the SAL `Filter.active_embedding_space` so every production surface (HTTP/MCP/CLI, sqlite + postgres adapters) gates. `RecallTelemetry` gains `embedding_space_mismatch` + `embedding_unverified_space` + an aggregated per-recall WARN naming the active fingerprint + the heal commands.
  - **S5 boot adoption + S6 census (landed).** `db::adopt_legacy_embedding_space` stamps NULL→active-fp for dim-matching embedded rows, guarded by [G1] `AI_MEMORY_REQUIRE_EMBED_MODEL_MATCH` strict OFF AND [G2] no differently-stamped row exists (the exact §5 rule; safety proof preserved in the module doc). `db::distinct_embedding_spaces` + `db::embedding_space_boot_maintenance` run in the load-bearing order embedder→adopt→census at serve + MCP boot BEFORE the index seed; a heterogeneous corpus emits a loud WARN naming per-space counts + the heal commands + the reembed-pending total. New env `AI_MEMORY_REQUIRE_EMBED_MODEL_MATCH` (direct-read strict flag, cached atomic + `set_for_test`, the `strict_dim` precedent).
  - **S8 restore/migrate HEAL (landed).** Every archive `INSERT ... SELECT` (all 8 sqlite + 7 postgres funnels: archive/GC/in-place-edit/supersede/forget) now carries `embedding_space` so an archive→restore round trip inside ONE space is lossless. On restore (`storage::restore_archived` / `restore_archived_for_caller` / `PostgresStore::archive_restore`) the vector is classified against the process-wide active-space fingerprint (`embeddings::active_embedding_space`, seeded at serve + MCP boot alongside the §5 adoption): a row whose space == active restores INTACT (no needless re-embed on a homogeneous corpus), while a foreign- or NULL-space vector has its WHOLE trio (`embedding`/`embedding_dim`/`embedding_space`) NULLed in the same statement so the existing `embedding IS NULL` backfill re-embeds it from the durable text under the LIVE space — SELF-HEAL, closing the pre-fix gap where a restored `embedding-NOT-NULL, embedding_space-NULL` row was excluded from semantic recall AND never re-embedded (excluded forever). A process with no active embedder (keyword-only / CLI) keeps any STAMPED vector verbatim but still NULLs an unverifiable NULL-space vector (never re-introduce an unverifiable vector as valid). Degrade, never corrupt.
  - Acceptance coverage: `tests/embedding_space_provenance_2167.rs` — **T-INV-1** (mixed active/foreign/NULL + cross-dim corpus → semantic results NEVER contain a foreign/NULL row; the three counters reconcile exactly), degraded-not-invisible (a foreign row stays keyword-recallable), None-active legacy dim-only, T-funnel (`set_embedding` stamps vector+space together), adoption a/d/e (the [G1]/[G2] rule), and **T-restore** (active-space round-trips intact + not a backfill target; foreign-space → NULLed → backfill re-heals → recallable; NULL-space legacy → NULLed → backfill target; None-active keeps stamped, drops unverified). No new MCP tool / HTTP route / CLI subcommand.
  - **S7 reembed knobs (landed).** `ai-memory reembed` gains the #2169 fleet-repair primitives: `--stamp-only` (the strict-mode / [G2]-blocked operator's explicit unattested→attested path — stamps embedded NULL-space rows with the active fingerprint WITHOUT re-embedding, but fail-closed REFUSES with exit 4 unless the FULL dim census of embedded NULL-space rows matches the active dim, via `db::stamp_embedding_space_attested`), `--skip-current-space` (only re-embed rows NOT already at the target space — the resumable / incremental heal, `embedding_space IS DISTINCT FROM <target>`), `--sleep-ms` (inter-batch pacing / thundering-herd guard) and `--max-rows` (chunked-run row budget). `get_memory_texts_batch` threads the optional `exclude_space` predicate; `run_reembed_live` threads a `ReembedPacing` carrier. No new subcommand (flags on the existing `reembed` verb).
  - **S9 dup-check space gate + pg `<=>` pin + fed HNSW insert-gate (landed).** A dup-check must NEVER match across embedding spaces (a cross-space cosine could produce a FALSE duplicate verdict → silent merge/skip of a distinct memory = corruption): both the postgres `check_duplicate_with_text` `<=>` cosine arms AND the sqlite `check_duplicate` candidate scan now gate on the process-wide active space (`embeddings::active_embedding_space`) via a nullable `IS NULL OR =` predicate (legacy dim-only behavior preserved when unseeded; the content-hash exact-match short-circuit stays space-agnostic — identical content is a dup regardless of space). A static **pg `<=>` site-count pin** (`pg_cosine_query_sites_all_carry_the_space_gate_2167`) asserts every postgres cosine query carries the gate so a future ungated `<=>` cannot land silently. **Federation §3.3 layer 2:** `hnsw_updates` carries the shipped vector's claimed space and the ANN-index insert loops skip any row whose claimed space differs from the known active space (defense-in-depth — a foreign vector is stored + keyword-recallable but NEVER indexed). Postgres **T-INV twin** (`tests/embedding_space_provenance_2167_pg.rs`, `#[ignore]` + `--include-ignored`, sal-postgres) proves the runtime `<=>` exclusion in CI's Postgres gate.
  - **S6 `doctor` census (landed).** `ai-memory doctor` gains an "Embedding Space Census (#2167)" section (#2169 fleet-manageability primitive): the per-space `GROUP BY embedding_space` breakdown of the embedded corpus, the active space + strict-mode flag, and the `distinct_non_null_spaces` / `unverified_rows` / `reembed_pending` counts — a heterogeneous corpus (>1 distinct space OR any NULL-provenance row) is a loud WARN naming the `ai-memory reembed` / `reembed --stamp-only` heal commands.
  - **Residual hardening — the three non-blocking #2167 Fable-audit follow-ups (both backends)** ([#2181](https://github.com/alphaonedev/ai-memory-mcp/issues/2181), [#2182](https://github.com/alphaonedev/ai-memory-mcp/issues/2182), [#2183](https://github.com/alphaonedev/ai-memory-mcp/issues/2183)):
    - **#2181 — residual ungated cosine sites gated.** The remaining stored-vs-stored / advisory cosine consumers now carry the same space discipline as the S4/S9 recall + dup-check gates so a cross-space pair is never clustered/merged or flagged as a near-duplicate. (1) The `proactive_conflict_check` bounded recency-scan pool (`src/storage/mod.rs`) gains `AND (?N IS NULL OR embedding_space = ?N)` on `embeddings::active_embedding_space()` (the ANN-routed `_candidates` path is already gated because the index only holds active-space vectors); a cross-space cosine could otherwise surface a FALSE 409 conflict advisory on a legitimate write (degrade/availability, not corruption, but posture-inconsistent with S9). (2) Both consolidation clusterers — the live autonomy `find_consolidation_clusters` (sqlite) and the curator `ConsolidationPass` / `ConsolidationClustering::cluster_memories` (SAL, both backends) — now fetch each candidate's `embedding_space` alongside its vector (new `db::get_embedding_with_space` + SAL `MemoryStore::get_embedding_with_space`, sqlite + postgres overrides) and count the pairwise cosine ONLY when both stored vectors carry the SAME non-NULL space. This extends the #1774 missing-embedding-blocks-merge precedent to mismatched-space-blocks-merge: a mixed-space corpus (same-dim model swap, or NULL-provenance legacy rows) can never feed a meaningless cross-space cosine into a destructive MERGE decision (degrade-never-corrupt applies to merge/advisory decisions too).
    - **#2182 — spec §10 test-gap closures** in `tests/embedding_space_provenance_2167.rs` (all NON-VACUOUS — each fails on pre-#2167 code): **T-INV via a POISONED HNSW index** (a foreign-space vector + a vanished-vector row force-inserted into the graph are NEVER scored on `hit.distance` — the §3.3 layer-3 row-side post-filter + the deleted #1692 None-arm exclude + count them), **T-hnsw-boot** (`db::get_all_embeddings` seeds ONLY active-space rows), **T-INV-3** (a reembed killed at an arbitrary batch boundary leaves no vector-without-space and no scoreable cross-space row — the per-row single-statement re-stamp invariant), and **T-strict** (`AI_MEMORY_REQUIRE_EMBED_MODEL_MATCH` [G1] disables boot adoption end-to-end through recall — a legacy NULL-space row stays excluded under strict, becomes recallable when strict is off).
    - **#2183 — postgres FOREIGN-stamped heal.** The pg census / adoption WARN + strict INFO no longer misleadingly name the sqlite-only `ai-memory reembed` for a postgres corpus (honest guidance: NULL-space rows self-heal via the serve-boot backfill; FOREIGN-stamped rows via the new opt-in knob). New **direct-read opt-in knob `AI_MEMORY_PG_HEAL_FOREIGN_SPACE`** (default OFF, byte-identical): when truthy AND a live active fingerprint is seeded, the pg `list_unembedded` boot-backfill scan additionally returns rows stamped with a non-active `embedding_space` (`embedding_space <> $active`) so the existing paced sweep (batched by `AI_MEMORY_EMBED_BACKFILL_BATCH`) re-derives them from the durable text and re-stamps the active space — the postgres-native heal for the post-same-dim-model-swap state, monotone (each row heals in one pass) and paced (no thundering-herd). Closes the North-Star gap where a pg model swap previously had no sanctioned recovery.
  - **Postgres write-side + boot-heal parity (landed — Fable pre-merge audit blockers [#2178](https://github.com/alphaonedev/ai-memory-mcp/issues/2178)/[#2179](https://github.com/alphaonedev/ai-memory-mcp/issues/2179)/[#2180](https://github.com/alphaonedev/ai-memory-mcp/issues/2180)).** The postgres backend now matches the proven sqlite guarantee end-to-end. (1) `PostgresStore::store_with_embedding` (the primary pg create anchor) stamps `embedding_space` in the SAME statement as the vector on BOTH the fresh INSERT and the `ON CONFLICT DO UPDATE` upsert-merge arm (`embedding_space = CASE WHEN EXCLUDED.embedding IS NOT NULL THEN EXCLUDED.embedding_space ELSE memories.embedding_space END`), so a same-dim model swap-back can never leave a stamp attesting a foreign vector (the cross-space score path #2167 forbids); the space threads through a compile-enforced `store_with_embedding(…, space: Option<&str>)` signature (mirroring `update_embedding`/`set_embeddings_batch`), and the dim-migration NULL path clears the stamp WITH the vector so no orphan stamp survives to falsely trip [G2]. (2) The §5/§6 boot machinery gains postgres twins (`PostgresStore::{adopt_legacy_embedding_space,distinct_embedding_spaces,embedding_space_boot_maintenance}`) run against the actual pg corpus at pg `serve` boot (adopt→census, [G1]/[G2]-guarded identically to sqlite; the dim gate uses `vector_dims(embedding)` since a legacy row may carry a NULL `embedding_dim` scalar) — closing the silent, unhealable fleet-wide recall outage where a v84 upgrade permanently excluded the entire legacy pg corpus from semantic recall with zero operator signal. The pg backfill predicate also targets `embedding IS NOT NULL AND embedding_space IS NULL`, so the serve-boot sweep re-embeds any [G1]/[G2]-blocked NULL-space rows from durable text (the pg reembed/heal). New pg T-INV twins (`tests/embedding_space_provenance_2167_pg.rs`, `#[ignore]` + sal-postgres) pin the stamp + adoption + [G2]-refusal. (3) The S1 `CORPUS_SCHEMA_VERSION` 83→84 bump regenerated `conformance/manifest.json` (schema_version-only; `corpus_digest` byte-identical) so the per-module coverage sweep evaluates the new LOC.
  - Remaining (S6 residual): §6 strict keyword-degrade WITHHOLD of the recall-side embedder on a heterogeneous census under `AI_MEMORY_REQUIRE_EMBED_MODEL_MATCH`; the health/capabilities `embedding_space: {active, census, reembed_pending, strict}` scrapeable fields + the two telemetry counters surfaced in the `RecallMeta` wire meta; `[embeddings].auto_reembed` + `reembed_sleep_ms` config + the daemon background sweep.
- **Hot-swappable `[llm]` config — reload the LLM model/provider without restarting the serve process** ([#2166](https://github.com/alphaonedev/ai-memory-mcp/issues/2166), **`[llm]` ONLY**). The long-lived serve processes now pick up a `config.toml` `[llm]` model/provider change WITHOUT a full restart — closing the gap the 2026-07-17 `google/gemma-4-31b-it` → `x-ai/grok-4.5` swap surfaced (the curator daemons re-run `AppConfig::load()` per sweep and were already hot; the MCP-invoked + HTTP-daemon LLM paths captured the boot client for the process lifetime).
  - **Scope is `[llm]` ONLY.** `[embeddings]` stays restart-only (hot-swapping the embedding model mid-corpus corrupts the shared vector space; the sanctioned change-path stays `ai-memory reembed`) and `[reranker]` is out of scope. The LLM is stateless (prompt→response; nothing persisted is bound to the specific model), so a live client swap is safe by construction.
  - **`crate::reload::SwappableLlm`** — a concurrency-safe holder over the current `[llm]` client that implements `AutonomyLlm` by resolving the CURRENT handle per call (capture-inversion: a consumer armed with it ONCE at boot always observes the live client, no re-arming). Reads clone a cheap `Arc` under a read lock and drop the guard before any `.await` (no lock guard across a suspension point). `AppState.llm` is now `Arc<SwappableLlm>` and `AppState.resolved_models` is `Arc<Swappable<ResolvedModels>>` so `memory_capabilities.models.llm` never lies about the active model post-swap. Every HTTP read site resolves the current client via `app.llm.current()`.
  - **Reload triggers.** HTTP daemon: **`SIGHUP`** on the `serve` loop re-resolves + rebuilds the `[llm]` client and atomically hot-swaps it (plus the capability model surface). **⚠️ Behavior change:** `SIGHUP`'s default disposition TERMINATES a process; installing this handler DELIBERATELY converts kill→reload (the conventional daemon-reload pattern). MCP stdio: a **lazy `config.toml` mtime check between requests** (NOT `SIGHUP` — avoids HUP/orphan semantics on a stdio child) rebuilds only when the mtime changed; the single-threaded stdio dispatch makes the between-request swap race-free by construction.
  - **Validate-before-swap.** New Result-returning `AppConfig::try_load` / `try_load_from` PROPAGATE a parse/secret-validation error instead of swallowing it to `AppConfig::default()` the way `load_from` does. On failure the reload KEEPS the current working client and logs a loud WARN — a broken/typo'd config can never swap in the compiled-default model. The rebuild reuses `daemon_runtime::build_llm_client` (HTTP, async) / the shared `reload::resolve_and_build_mcp_llm` (MCP, sync), so the #1963 inference-egress gate is RE-EVALUATED on every reload — a reload can legitimately DISABLE the client (egress `deny`/`loopback-only`).
  - **No SSOT pins move** — `SIGHUP` + the MCP mtime check add no MCP tool, HTTP route, CLI subcommand, or schema version (an admin reload verb was deliberately deferred to v1.x). No new dependency: the swap holder is a zero-dep `RwLock<Arc<T>>` (the operator-named `ArcSwap` alternative deferred to avoid an unauthorized `Cargo.toml` add). Regression coverage: `tests/hot_swap_llm_2166.rs` (swap-succeeds, validate-before-swap-keeps-old-client, egress-deny-disables-client, concurrent-swap-and-reads-no-panic).
  - **Pre-merge audit fixes** ([#2172](https://github.com/alphaonedev/ai-memory-mcp/issues/2172) BLOCKING, [#2173](https://github.com/alphaonedev/ai-memory-mcp/issues/2173), [#2174](https://github.com/alphaonedev/ai-memory-mcp/issues/2174), Fable audit of PR #2170). (#2172) The MCP `memory_atomise` (`LlmCurator`) + `memory_ingest_multistep` (`OllamaDispatch`) handlers were built ONCE at boot from `llm_client.clone()` and the mtime-reload block reassigned only `llm` + `resolved_models`, so post-swap those two tools silently kept driving the OLD model/provider (the exact bug class this PR closes), a disabling reload left them egressing memory content to the OLD vendor (bypassing the #1963 egress re-eval), and the signed `atomisation_complete` `curator_model` misattested the live model. Both handlers are now `mut` and REBUILT inside the reload block from the freshly-resolved client via the shared `build_atomise_handler` / `build_ingest_multistep_handler` helpers — at the same race-free single-threaded swap point as `llm` — so EVERY per-op LLM consumer resolves the current client after a swap. Regression: `tests/hot_swap_llm_2166.rs::atomise_driven_after_swap_uses_new_model_2172` (rebuild-from-swapped-client re-points the signed `curator_model` model-a→model-b + drives `memory_atomise` end-to-end through the rebuilt handler) + `src/mcp/mod.rs::tests::atomise_ingest_handlers_rebuild_from_swapped_client_2172` (pins the private helpers). (#2173) The MCP mtime-reload lane now re-stats `(mtime, len)` AFTER `try_load_from` and DEFERS the swap to the next request if the file changed mid-read — a torn read of a truncate-then-write config (valid-but-incomplete TOML that parses `Ok`) can no longer transiently downgrade the model; self-heals, degrade never corrupt. (#2174) Per-sibling assessment of the boot-captured `[llm]`-adjacent knobs a reload does not refresh (documented restart-only in `src/reload.rs`; worst case a stale sibling until restart, no data corruption): `auto_tag_model` (`[llm.auto_tag].model`) is `[llm]`-family but its `Swappable` public-field migration across ~140 `AppState` construction sites is a focused follow-up; `llm_call_timeout` is a separate top-level knob (not part of `[llm]`); `tier` also gates the deliberately-not-hot-swapped embedder + reranker, so refreshing it in an `[llm]`-only reload would half-apply a tier change.
- **`ai-memory watch` — L3 substrate poll-based filesystem-watcher capture daemon** ([#1978](https://github.com/alphaonedev/ai-memory-mcp/issues/1978)). Implements the L3 layer of the #1389 layered-capture architecture (policy memory `f62cb182`) WITHOUT the `notify` crate the canonical design named — adding `notify` is a new external dependency, operator-gated under the sole-authority no-external-injection rule, so this ships a **std-only bounded poll loop** instead: `crate::recover::watcher::run_watch_daemon` ticks every `--interval-secs` (default 5s, clamped `[1, 3600]`), diffs `std::fs::metadata` mtime/size per watched host transcript (`claude-code` / `codex` / `gemini`, tracked independently rather than the `Auto` most-recent-wins union), and on a detected change feeds the change into the EXISTING shared L2 parser pipeline (`recover_from_transcript`) — same `transcript_line_dedup` idempotency, same per-host graceful degradation, zero new parsing code. `ai-memory watch --once [--json]` runs a single tick and reports; `ai-memory watch --daemon [--host <h>]... [--namespace <ns>] [--limit <n>] [--dry-run]` loops until SIGINT (mirrors the `curator --daemon` `Notify`→`AtomicBool`→`spawn_blocking` bridge). Opt-in — never runs unless explicitly invoked; no implicit activation from `serve`/`mcp`. Adds the `Watch` `Command` variant (`EXPECTED_CLI_SUBCOMMANDS_DEFAULT` 88→89, `_SAL` 90→91, pinned by `tests/cli_subcommand_count_invariant.rs`).
  - **Pre-merge audit fixes** ([#2134](https://github.com/alphaonedev/ai-memory-mcp/issues/2134), [#2136](https://github.com/alphaonedev/ai-memory-mcp/issues/2136), Fable audit of PR #2100). (#2134) `poll_once` now advances its per-host `(path, mtime, len)` watermark ONLY after a successful `recover_from_transcript` — a change whose capture fails (a transient DB-open error while a live MCP session shares the DB) leaves the watermark UNADVANCED and `pending_drain` UNTOUCHED, so the next tick re-detects the same delta (or the still-armed drain) and retries even on a now-static transcript instead of stranding the un-captured lines (the same loss class as #2117/#2126, via the Err path; convergent, dedup-idempotent, bounded to one attempt per `--interval-secs`). (#2136) `WatchReport.absorb_tick` + the `watch --once` human report now surface errors EMBEDDED in an otherwise-successful `RecoverReport` (a transcript parse failure returns `Ok(report)` with `report.errors` set per the never-wedge contract; per-turn write failures land there too) — a parse-failed tick previously reported `errors_total: 0` with no indication anything failed. Regression coverage: `poll_once_retries_after_transient_recovery_failure_on_static_file_2134`, `absorb_tick_surfaces_embedded_recover_errors_2136` (`src/recover/watcher.rs`), `print_watch_report_surfaces_embedded_recover_errors_2136` (`src/cli/watch.rs`).
  - **Bounded retry of the `Ok`-with-embedded-errors capture-loss lane** ([#2150](https://github.com/alphaonedev/ai-memory-mcp/issues/2150), Fable audit of PR #2100). Closes the residual lane the #2134 fix left open: a `watch` tick where ONE turn's write fails *transiently* (`SQLITE_BUSY` on the per-turn `BEGIN IMMEDIATE` while a live MCP session holds the write lock) returns `Ok(report)` with `report.errors` set (NOT `Err`, per the never-wedge contract) and rolls the turn back atomically (no dedup row). The #2134 fix only retries the `Err` arm, so this `Ok`-with-embedded-errors case advanced the watermark and, once the transcript went static, was never retried — a permanent capture loss (the L2 boot backstop is fast-path-gated, `src/recover/mod.rs:373-385`). `HostPollState` gains a bounded `retry_attempts` budget: a non-dry-run tick with embedded errors ARMS the retry (`retry_attempts > 0` forces `decide_poll` to `Recover` the same static delta next tick, exactly like `pending_drain`) up to `WATCH_RECOVERY_MAX_RETRIES` (3), re-parsing the failed turn idempotently until the transient error clears. **Convergence invariant (#2126):** a *permanently*-erroring turn (validation reject, quota — errors that never clear) is re-parsed at most the initial parse + N retries per delta, then the watermark advances, the counter resets, an exhaustion WARN naming the stranded-turn count + remediation (`touch <transcript>` / re-run `recover-previous-session`) is emitted, and re-parsing stops — never the unbounded busy-loop #2126 case (b) forbids. The counter RESETS on a genuine new `(mtime, len)` delta so a flaky-but-progressing transcript never exhausts its budget prematurely. Preserves the #2134 Err-arm retry, #2117 `pending_drain` tail carry, #2126 `bypass_fast_path` drain + dry-run guard, #2136 error visibility. Regression coverage (`src/recover/watcher.rs`): `poll_once_retries_after_transient_embedded_error_on_static_file_2150`, `poll_once_persistent_embedded_error_converges_bounded_2150_2126`, `poll_once_retry_budget_resets_on_fresh_delta_2150`, `exhaustion_warning_names_stranded_count_and_remediation_2150`.

- **Test-infra: IronClaw lan-parity compose peer-key auto-provisioning** ([#1803](https://github.com/alphaonedev/ai-memory-mcp/issues/1803)). A bare `docker compose -f infra/lan-parity-test/docker-compose.yml up -d` now yields a WORKING enrolled 2-daemon mesh out of the box — no manual peer-key step. Closes the gap the 2026-06-24 live IronClaw A2A campaign hit, where alice's signed `/sync/push` to bob `401`'d even after a manual `.pub` copy.
  - **Root cause (source-pinned, not a product defect).** Each daemon's OUTBOUND federation `/sync/push` signing key is loaded by `governance::audit::load_daemon_signing_key(&sender_agent_id)` (`src/federation/peer.rs`), keyed by the RESOLVED federation identity (`AI_MEMORY_FED_IDENTITY` env > `host:<hostname>`; `src/federation/identity/resolver.rs`) — a DIFFERENT on-disk file from the fixed `DAEMON_KEYPAIR_LABEL = "daemon"` link/audit keypair the entrypoint already mints. `ai-memory serve` has NO auto-generate fallback for that identity-labeled key, so federation pushes went out UNSIGNED and any peer enforcing the v1.0.0 secure defaults (`AI_MEMORY_FED_REQUIRE_WRITE_SIG` / `_SIGNAL_SIG`) rejected them. A manually-copied `.pub` had nothing to verify against because the authoring side never held the matching signing key under that name.
  - **Entrypoint keygen** (`entrypoint.plan-c.sh`): on first boot each daemon now also mints a keypair under its resolved federation identity in `ai-memory serve`'s OWN key directory (`identity::keypair::default_key_dir`), idempotent across restarts.
  - **Compose wiring** (`infra/lan-parity-test/docker-compose.yml`): alice/bob pin `AI_MEMORY_FED_IDENTITY` explicitly (`host:ic-parity-alice` / `host:ic-parity-bob`), plus a new one-shot `ic-parity-peer-key-provisioner` service (gated `depends_on: service_healthy`) that runs `infra/lan-parity-test/provision-peer-keys.sh` to cross-copy each side's real `<fed_identity>.pub` into the other's key volume under the exact name `identity::verify::lookup_peer_public_key` (and the `peer_not_enrolled` gate) reads. The provisioner only ever touches `.pub` material — no private key crosses sides. Verified end-to-end against the release binary + a standalone assertion harness (`tests/lan_parity_provision_peer_keys.sh`: happy-path cross-enrollment, timeout fail-closed, missing-env guard).
- **TRACT covenant clauses 1+2 — opt-in why_trace write-gate + authorship-immutability enforcement** ([#2059](https://github.com/alphaonedev/ai-memory-mcp/issues/2059), [#2060](https://github.com/alphaonedev/ai-memory-mcp/issues/2060), deferred from #1832 G18; `docs/spec/TRACT-L1-CLAIM-CONTRACT.md` §8.1). Two additive, env-gated ENFORCEMENT layers at the store write funnel, both defaulting OFF (advisory-WARN posture, byte-identical legacy behavior) — no schema change (the v73 `signed_events.cause_hash` and v76 `agent_lineage` columns already exist).
  - **Clause 1 — `AI_MEMORY_REQUIRE_WHY_TRACE`** (`storage::{REQUIRE_WHY_TRACE_ENV,require_why_trace_enabled,why_trace_present,consult_why_trace_gate}`). Mirrors the truthy grammar + secure-opt-in shape of the existing VERIFY-time `AI_MEMORY_REQUIRE_CAUSE_BINDING`, but gates the WRITE path instead: a memory with no non-empty `metadata.why_trace` caller-authored provenance rationale always emits an advisory WARN (`covenant.why_trace` target); when the env is truthy it additionally REFUSES the write via the shared `GovernanceRefusal` envelope (identical `403 GOVERNANCE_REFUSED` wire shape on both backends). Wired into EVERY caller-origin store funnel on BOTH backends (#2102): sqlite `insert` + `insert_with_conflict(Error)` (the `db::reflect` / `memory_reflect` path), postgres `PostgresStore::{store, store_batch, store_with_embedding}` (`consult_why_trace_gate_pg`). The FEDERATION-RECEIVE + archive-RESTORE funnels (sqlite `insert_if_newer` / `restore_archived`, postgres `apply_remote_memory` / `merge_inbound`) use the never-refuse sibling `consult_why_trace_gate_inbound` — a refused inbound write would diverge replicas (CRDT convergence) and a refused restore would make legacy archived data un-restorable, so those paths WARN + record but always proceed (mirrors the secret-screen refuse→redact degrade on the same funnels). **Internal-writer carve-out keyed on AUTHENTICATED ORIGIN, never the caller-controlled `memory_kind`** ([#2110](https://github.com/alphaonedev/ai-memory-mcp/issues/2110), HIGH — supersedes the initial #2106-item-4 kind-exemption, which any external HTTP/MCP caller defeated by setting `kind:"reflection"`/`"persona"`, zero privilege): the exemption now keys on the write's authenticated SYSTEM principal (`CallerContext::bypass_visibility` — `for_admin`, per env #48; external tenant callers can NEVER set it), applied at the SAL `SqliteStore::store` / `reflect` (stamp) and `PostgresStore::{store,store_batch,store_with_embedding}` methods (stamp — [#2124](https://github.com/alphaonedev/ai-memory-mcp/issues/2124): the three pg store-family funnels originally SKIPPED the gate under `bypass_visibility` WITHOUT stamping, so an internally-authored row landed with no clause-1 rationale on postgres while sqlite recorded `substrate:system-authored` — cross-backend provenance drift, and under enforce a later tenant `memory_share` of a curator-authored row inherited a why_trace on sqlite but not on postgres; they now stamp the SAME substrate marker BEFORE consulting the gate unconditionally as defense-in-depth, mirroring the pg reflect/capture_turn/consolidate funnels; parity pinned by the `*_store_family_stamps_substrate_why_trace_for_system_2124` twins in `tests/issue_2059_2060_covenant_pg.rs`), so curator/autonomy automation stays exempt while a tenant `memory_store`/create with a forged `kind` is REFUSED. Substrate-internal writers that reach the funnel via a direct `db::insert` (atomisation, persona generation, curator rollback/self-report/reverse) stamp a canonical `metadata.why_trace = "substrate:system-authored"` (`storage::stamp_substrate_why_trace`) at construction — a marker external callers cannot forge. **Reflect funnel** ([#2113](https://github.com/alphaonedev/ai-memory-mcp/issues/2113)): the postgres `PostgresStore::reflect_with_hooks` (`POST /api/v1/reflect`) was missing the gate entirely (sqlite's `insert_with_conflict(Error)` reflect path was gated but the postgres twin only consulted governance) — now gated with the same `bypass_visibility` parity (a tenant `memory_reflect` on a postgres daemon is refused without `why_trace`; the curator's internal reflect is exempt via the stamp). **Comprehensive funnel audit:** every `INSERT`/`UPSERT` funnel on BOTH backends now consults the why_trace gate (refuse), the never-refuse `_inbound` variant, or stamps the substrate marker — `store`/`store_batch`/`store_with_embedding`/`insert`/`insert_with_conflict`/`reflect`/`update_with_archive_on_supersede` (refuse; the postgres supersede's inline `INSERT` was the last un-gated create funnel, mirroring the sqlite twin's transitive `insert()` gate), `insert_if_newer`/`apply_remote_memory`/`merge_inbound`/`restore`/`archive_restore` (inbound, never-refuse), and `capture_turn`/`recover_turn` (L2/L4 transcript re-store, env #95 never-lose-a-turn) + `consolidate` (substrate-derived merge over already-gated sources) stamp the substrate marker. The audit enumerated every `consult_governance_pre_write[_pg]` site on both backends and confirmed each has a why_trace/authorship/inbound/stamp sibling in the same function — no missed funnel remains.
  - **Clause 2 — `AI_MEMORY_REQUIRE_IMMUTABLE_AUTHORSHIP`** (`storage::{REQUIRE_IMMUTABLE_AUTHORSHIP_ENV,require_immutable_authorship_enabled,consult_authorship_immutable_gate}`). A defense-in-depth REFUSE posture on top of the existing SILENT preserve helpers (`identity::preserve_agent_id` / `identity::preserve_provenance_keys`). Detects a caller-supplied `metadata.agent_id` that differs from a row's existing stored authorship at the update/merge funnel; always WARNs (`covenant.authorship_immutable` target), and REFUSES via the shared `GovernanceRefusal`/`StoreError::PermissionDenied` envelope when the env is truthy. Wired into EVERY update funnel on BOTH backends (#2103): sqlite `update_with_expected_version` + `update_with_archive_on_supersede`, postgres `update_with_expected_version_once` (If-Match), `MemoryStore::update` (the default no-If-Match PUT path — pre-#2103 a rewrite there was a silent, unlogged, non-refusing no-op), and `update_with_archive_on_supersede` (`consult_authorship_immutable_gate_pg`). Gate ordering is authorship-then-governance on both backends (#2106 item 3). A legitimate identity migration remains the operator `ai-memory reown` tool.
  - **Backend-parity + omission-erasure fix** (#2106 items 1+2): the sqlite `update_with_expected_version` UPDATE now preserves the immutable provenance keys (`agent_id` + `derived_from` / `consolidated_from_agents`) via a `json_patch` overlay mirroring `insert`'s ON-CONFLICT arm and the postgres CASE overlay — so effective protection is IDENTICAL across backends even with the gate OFF, AND a full-object metadata patch that OMITS `agent_id` no longer silently WIPES the stored author (erasure is strictly worse than a rewrite). The mint-new-id supersede path (both backends) preserves provenance onto the superseding row via `identity::preserve_provenance_keys`.
  - **Auditability** (#2104): both gates now emit the WARN UNCONDITIONALLY (before the enforce short-circuit) so an enforce-mode REFUSAL is visible server-side, and append a durable forensic `governance::audit::record_decision` row (`covenant.why_trace` / `covenant.authorship_immutable`) on every advisory-or-refuse disposition so operators can query covenant-compliance drift before flipping to enforce. **DRY** (#2106 item 6): both env resolvers reuse the shared `governance::audit::env_flag_enabled` truthy-grammar helper.
  - Regression coverage: sqlite integration tests in `tests/issue_2059_2060_covenant_write_gates.rs` (truthy-grammar, advisory-vs-enforce, `insert` / `insert_with_conflict` / `insert_if_newer` / `update_with_expected_version` / `update_with_archive_on_supersede` end-to-end, **#2110 external-caller-cannot-forge-exemption-via-kind** for both `reflection` + `persona`, federation-inbound never-refuse, omission-preservation) PLUS `sal`/`sal-postgres` integration tests in `tests/issue_2059_2060_covenant_pg.rs` (#2105 — skip-if-`AI_MEMORY_TEST_POSTGRES_URL`-unset for the live-PG cases) exercising `store` / `store_batch` / `store_with_embedding` / `update` (no-If-Match) / `update_with_archive_on_supersede` / `apply_remote_memory` under the enforce knobs, the **#2110 authenticated-origin exemption end-to-end on both `SqliteStore` + `PostgresStore`** (a `for_admin` system principal is exempt while a `for_agent` tenant forging `kind` is refused), and the **#2113 reflect-funnel gate on both `SqliteStore::reflect` + `PostgresStore::reflect`** (a `for_agent` tenant reflect without `why_trace` is refused under enforce; the `for_admin` system reflect is exempt; a `why_trace`-bearing tenant reflect is allowed), closing the zero-postgres-coverage gap that was the root cause of the shipped bypasses.

- **Reranker offline/bundled model pre-stage** ([#2086](https://github.com/alphaonedev/ai-memory-mcp/issues/2086), unlock condition (i) named by [#1867](https://github.com/alphaonedev/ai-memory-mcp/issues/1867)/[#1969](https://github.com/alphaonedev/ai-memory-mcp/issues/1969) for a future reranker default-on flip reconsideration). The neural cross-encoder (`cross-encoder/ms-marco-MiniLM-L-6-v2`) now has a documented, air-gap-friendly pre-stage path — the reranker's counterpart to the embedder's `FALLBACK_MODEL_SUBDIR` pattern (`src/embeddings.rs`, [#1501](https://github.com/alphaonedev/ai-memory-mcp/issues/1501)).
  - **Pre-stage cache dir** under `$HOME/.cache/huggingface/hub/models--cross-encoder--ms-marco-MiniLM-L-6-v2/` (`src/reranker.rs::CROSS_ENCODER_FALLBACK_MODEL_SUBDIR` names the hand-staged `snapshots/main` leaf). [#2114](https://github.com/alphaonedev/ai-memory-mcp/issues/2114): the offline resolver derives the hf-hub repo cache dir and **scans every `snapshots/*` leaf**, so it resolves BOTH the hand-staged air-gap layout (`snapshots/main/`) AND a cache populated by an earlier online `hf-hub` fetch (`snapshots/<commit-hash>/`, ref-pointed by `refs/main`) — the "ran online once, now offline" path no longer silently degrades to lexical.
  - **`CrossEncoder::resolve_cross_encoder_files()`** (mirroring the embedder's `load_from_fallback`) now gates the neural-reranker file resolution on `AI_MEMORY_EMBED_OFFLINE`/`HF_HUB_OFFLINE` (the same offline knob the embedder honors, now `pub(crate)` on `Embedder::remote_fetch_disabled`): offline mode resolves the three cross-encoder artifacts (`config.json`, `tokenizer.json`, `model.safetensors`) from the pre-stage cache via a plain filesystem check — zero network, zero hf-hub API — and bails LOUD naming both the repo dir and the model id when no complete snapshot leaf is found (`new_neural` then surfaces `reranker_used = "degraded_lexical"`, never a silent network attempt). Online mode is byte-unchanged.
  - This closes the reranker/coverage-CI test dependency on a live HuggingFace download that [#2019](https://github.com/alphaonedev/ai-memory-mcp/issues/2019)'s coverage-CI fix flagged as blocking hermetic neural-reranker test coverage.
- **mTLS `/sync/*`: client-cert ↔ `X-Peer-Id` cross-check** ([#2045](https://github.com/alphaonedev/ai-memory-mcp/issues/2045), #2032 finding **L6**). Closes the federation identity-spoof gap where, under `AI_MEMORY_FED_REQUIRE_SIG=0`, the mTLS `/sync/*` path trusted a verbatim `X-Peer-Id` header — any holder of ANY allowlisted client cert could assert any peer identity and author/attribute as the victim.
  - **Trust model.** mTLS here is fingerprint-pinning of (typically self-signed) peer certs, so a cert's own Subject/SAN is attacker-chosen and MUST NOT be the identity anchor — an enrolled peer could mint a cert whose SAN names a victim. Identity is therefore bound through an **operator-authored `<sha256-hex> <peer-id>` map file** (`AI_MEMORY_FED_CERT_PEER_BINDING_MAP`), the same operator-declares-the-pin model as the outbound peer-fingerprint pinning ([#1678](https://github.com/alphaonedev/ai-memory-mcp/issues/1678)), rather than parsing a self-asserted cert SAN (which would also have required a new X.509-parser dependency).
  - **Plumbing.** A new `tls::PeerBindingAcceptor` wraps `serve_rustls_acceptor` (verifier chain + the [#1581](https://github.com/alphaonedev/ai-memory-mcp/issues/1581) `TCP_NODELAY` fix preserved verbatim); after the handshake it resolves the presenting leaf cert's SHA-256 fingerprint to its operator-bound peer-id and injects a `ClientCertPeerId` request extension (the long-deferred axum peer-cert-in-extensions plumbing). `sync_push` + `sync_since` cross-check it against the asserted `X-Peer-Id` via `enforce_cert_peer_binding` (both backends; runs before the postgres dispatch), refusing a mismatch with `401 peer_id_cert_mismatch`.
  - **Posture** `AI_MEMORY_FED_CERT_PEER_BINDING = off | warn | enforce` (default `warn`, one release then `enforce`), **independent of** `AI_MEMORY_FED_REQUIRE_SIG` — it is the compensating control for the `=0` window. It composes with the [#1056](https://github.com/alphaonedev/ai-memory-mcp/issues/1056) TOFU allowlist (strictly stronger). Legacy certs whose fingerprint has no binding **always degrade to WARN, never brick**; with no map configured the acceptor is not installed and the path is byte-identical to pre-#2045.
- **Operator-authorized skill retire/unretire/purge lifecycle** ([#2024](https://github.com/alphaonedev/ai-memory-mcp/issues/2024), 5-agent vote `4d3ea1c5`). The FULL skill lifecycle: reversible RETIRE/UNRETIRE plus an irreversible, deliberately-explicit hard-delete/PURGE. Schema **v82** adds three additive nullable `skills` columns (`retired_at`, `retired_by`, `retire_reason`; SQLite-only — the postgres twin `migrate_v82` is a version-stamp no-op keeping the lockstep parity green).
  - **New MCP tools `memory_skill_retire` + `memory_skill_delete`** (advertised tool count 101 → 103, callable 100 → 102). `memory_skill_retire` takes an `unretire` bool flag; default target is the whole `(namespace, name)` LINEAGE — every version in the chain is stamped so `memory_skill_get` is truthful for superseded versions too; an optional single-version target by `skill_id` retires just that row. Re-retiring an already-retired target is idempotent (`affected = 0`, never an error). All mutations run inside one `BEGIN IMMEDIATE` transaction.
  - **Hard purge (`memory_skill_delete`)** hard-deletes the WHOLE `(namespace, name)` lineage (every version), so no `superseded_by` pointer is ever left dangling (partial-chain delete is unsupported; a by-`skill_id` request resolves to and purges the whole lineage). **Safety gate:** refused unless the lineage is already retired (`retired_at IS NOT NULL` on every version) OR the request carries `force = true` — the default two-step retire→delete flow makes accidental purge of an active skill impossible. **Audit-safe erasure:** inside one `BEGIN IMMEDIATE` tx a daemon-signed `skill.purged` `signed_events` row (carrying the purged ids + their `digest` hex + namespace/name) is appended BEFORE the `DELETE`, so the tamper-evident audit record survives the content erasure (`signed_events` has no FK to `skills`; `skill_resources` rows cascade via `ON DELETE CASCADE`).
  - **HTTP** `POST /api/v1/skill/{id}/retire` (new) + `DELETE /api/v1/skill/{id}` (purge; reuses the existing `/skill/{id}` path) → production routes 92 → 93, unique paths 78 → 79. Both admin-gated like every skill surface (#949). **CLI** `ai-memory skill retire --id <uuid> | --name <n> [--namespace <ns>] [--unretire] [--reason <r>] [--json]` and `ai-memory skill delete --id <uuid> | --name <n> [--namespace <ns>] [--confirm] [--json]` (`--confirm` maps to `force`).
  - **Discovery hides retired skills** (`memory_skill_list` gains `AND retired_at IS NULL`; `include_retired: true` shows them). **Re-registration is refused** onto a retired lineage from INSIDE `register_core`'s existing `BEGIN IMMEDIATE` tx (TOCTOU-safe: a concurrent retire/register cannot race a silent revive). Retire is discovery-hide + re-register-block; it does NOT hard-block activation-by-id (consistent with superseded-stays-addressable) — `memory_skill_get` / `_export` / `_compositional_context` surface a `retired` flag instead.
  - **Audit.** New `skill.retired` / `skill.unretired` / `skill.purged` daemon-signed `signed_events` rows (the governance-toggle lane) appended in the same tx, plus a forensic `record_decision` row before every mutation.

### Changed

- **Refactor (#1802 R-05, step S1): `storage/mod.rs` doctor/observability probes extracted to `src/storage/doctor.rs`** ([#1802](https://github.com/alphaonedev/ai-memory-mcp/issues/1802), from the [#1798](https://github.com/alphaonedev/ai-memory-mcp/issues/1798) R-05 finding; rebuilt on the v1.0.0 HEAD, superseding PR #2164). First step of the storage-monolith decomposition (proof-of-approach for the remaining steps): the ~678-LOC doctor-probe region (`is_namespace_standard` .. `doctor_reflection_totals_by_namespace`, incl. `sweep_pending_action_timeouts` and the capability-expansion ledger) moved VERBATIM to a new PRIVATE `storage::doctor` submodule with an itemized `pub use` re-export shim, so every public path (`crate::storage::*` / `crate::db::*`) is byte-stable and no caller churns. Zero behavior change. Lockstep: the `qual_10` ceiling for `storage/mod.rs` REDUCED 26_750 → 26_100 (+ a new 800 row for `doctor.rs`), and `scripts/ci-test-impact.sh` widened its foundational entry to `src/storage/*` so the split can never weaken the "storage changes force the full suite" invariant.

- **`ai-memory export` de-silenced: it is a convenience view, not the portability path** ([#1944](https://github.com/alphaonedev/ai-memory-mcp/issues/1944), B_WARN de-silencing, 2×5-agent vote `woaiwndla` / `4d3ea1c5`). The JSON `ai-memory export` command (and its HTTP sibling `GET`-admin export) emits `{memories, links, count, exported_at}` — a **memories + links CONVENIENCE view** that silently omitted the substrate's tamper-evidence + governance spine (governance rules, the append-only revision log, forget tombstones, derivation lineage, per-write attestations, the signed-events audit chain). It now announces that scope instead of dropping it silently:
  - **Stderr WARN (CLI).** `ai-memory export` writes a prominent WARN to **stderr only** (never stdout, so a piped `export > corpus.json` stays valid JSON) naming the omitted signed classes, stating the memories + links convenience scope, and directing to `ai-memory backup` (lossless SQLite `VACUUM INTO`) for integrity-preserving portability and `ai-memory export-forensic-bundle` for the signed crypto spine.
  - **Additive in-band markers (CLI + HTTP).** The export payload gains additive, non-breaking fields — `export_scope="memories+links"`, `portability_complete=false`, `excludes=[governance, revisions, tombstones, lineage, attestations, signed_events]` — so a pipe-to-file consumer that never sees the stderr WARN still learns the scope. The pre-existing `{memories, links, count, exported_at}` shape is **unchanged**; the serialization core (`storage::export_all` / `export_links`) is untouched.
  - **Claims narrowed (DEFAULT `export` only).** The DEFAULT `ai-memory export` does NOT round-trip the integrity spine and is NOT the portability path — it remains the convenience view. The integrity path now ships as the separate `ai-memory export --full` verb (see the #2006 entry under Added); `ai-memory backup` (lossless SQLite `VACUUM INTO`) also remains a portability path.
  - **~~Deferred to v1.x~~ → SHIPPED at v1.0.0 ([#2006](https://github.com/alphaonedev/ai-memory-mcp/issues/2006)):** the full integrity-complete v2-envelope exporter (emitting the §V2-2 signed arrays from one verb) is delivered as `export --full` + the symmetric v2 importer. B (the #1944 stderr WARN) remains the honest de-silencing on the DEFAULT verb.
- **Federation per-write signature: sender EMIT + secure-default flip** ([#1801](https://github.com/alphaonedev/ai-memory-mcp/issues/1801) → [#1954](https://github.com/alphaonedev/ai-memory-mcp/issues/1954), ratified MINIMAL scope, 5-agent vote `w9mr01vi8`). Completes the [#1464](https://github.com/alphaonedev/ai-memory-mcp/issues/1464) per-write content-attestation lane by adding the **author-side EMIT** and flipping the receive default to secure.
  - **EMIT at STORE time.** The authoring node now persists the detached Ed25519 author signature into `metadata.write_signature` (standard base64, over the #626 `SignableWrite` envelope `agent_id + namespace + title + kind + created_at + sha256(content)`) at store time — wired into the CLI `--sign` path, the MCP store, and both HTTP signed-store endpoints (`POST /api/v1/memories` single-create and `/memories/bulk`, on both the sqlite and postgres backends) (`identity::attest::persist_write_signature`). The existing federation broadcast forwards full metadata verbatim, so the origin signature propagates unchanged across every relay hop and re-verifies at `apply_inbound_write_attestation`. A relaying node **never re-signs** a third-party attribution (that would mint a signature that fails against the author's enrolled key — Forged, strictly worse than absent); an already-present signature is preserved verbatim (non-clobbering).
  - **Secret-screen ordering fix.** The credential-redact funnel mutates `content`/`title` at persist time; the write is now redacted to storage form BEFORE it is signed (`identity::attest::redact_before_sign`) so the signed bytes equal the persisted (and propagated) bytes — without this a `redact`-mode secret would make the propagated signature unconditionally Forged at every receiver.
  - **Default flip.** The former single `FED_REQUIRE_SIG_DEFAULT` is split into `FED_REQUIRE_WRITE_SIG_DEFAULT` and `FED_REQUIRE_SIGNAL_SIG_DEFAULT`, and **both flip `false → true`** for v1.0.0 (the v0.10.0 WARN cycle shipped the heads-up; federation inbound is the network surface, ruling `9e9c3cf2` condition 7). `AI_MEMORY_FED_REQUIRE_WRITE_SIG` (row 94) and `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` (row 96) now resolve **STRICT when unset**; an explicit falsy token (`0`/`false`/`no`/`off`) is the staged-rollout opt-out, and the split lets the two lanes revert independently.
  - **Operator signal (manual TOFU substitute).** A honored third-party relay refused under the flip emits a distinguishable WARN — `missing-author-key` (cause `unenrolled_author_strict`, added to the `push_dlq::classify_quarantine_cause` taxonomy) vs `missing-signature` — so an operator gets an actionable "enroll author X's key" signal. Under the flip, multi-hop propagation of third-party content requires the ORIGIN author's Ed25519 key enrolled at EACH receiving node; name `AI_MEMORY_FED_REQUIRE_WRITE_SIG=0` as the staged-rollout bridge.
  - **Deferred to v1.x:** TOFU key distribution and a promoted typed wire field for the signature.

### Removed

- **`AI_MEMORY_RECALL_TOUCH_SYNC` removed** ([#1953](https://github.com/alphaonedev/ai-memory-mcp/issues/1953)). The legacy synchronous recall-time touch opt-back-in — deprecated at birth by the [#1869](https://github.com/alphaonedev/ai-memory-mcp/issues/1869) pure-recall vote, with its one-cycle v0.10.0 deprecation WARN already shipped (see the `[0.10.0]` entry below) — is gone: the env knob, `crate::config::recall_touch_sync_enabled` / `ENV_RECALL_TOUCH_SYNC` / `RECALL_TOUCH_SYNC_DEPRECATION_WARNING` / `warn_recall_touch_sync_deprecation_once`, and every recall-path caller of the explicit touch verbs (the sqlite HTTP + postgres HTTP branches in `src/handlers/recall.rs`, and `db::recall` / `apply_recall_post_ops` in `src/storage/mod.rs`) are removed. Recall is now **unconditionally pure** on every surface (HTTP/MCP/CLI/shell/SAL, both backends) — the periodic fold job (`db::fold_recall_accesses` / `MemoryStore::fold_recall_accesses`) is the sole applier of the access ladders from the `recall_observations` ledger. No migration is needed for operators who were already relying on the pure default (unset is byte-identical); operators who had set `AI_MEMORY_RECALL_TOUCH_SYNC=1` must remove it — the value is now silently ignored rather than restoring the legacy synchronous touch.

### Fixed — test-infra

- **Intermittent full-suite wedge closed for good with a CI regression guard** ([#1989](https://github.com/alphaonedev/ai-memory-mcp/issues/1989)). The two root causes were already fixed on the release branch — the `cli::shell` eof-stdin REPL test that blocking-read the real (never-EOF under CI/agent-harness) process stdin while holding the process-global `std::io::Stdin` lock (commit `c10e55b4`), and the `qual_10` module-size ceiling drift plus the CI watchdog wrapping compile+run of every integration binary in one 1500s timeout (commits `ea1b58a3` / `43c4d410`). A targeted `cargo test --lib -- --test-threads=8` now runs to a clean **6676 passed / 0 failed** with no wedge. To keep the wedge class from silently returning, this release adds the **`scripts/check-test-stdin-reads.sh` lint-gate** (a seventh `c8-precheck.yml` HARD-BLOCK job with a `--self-test`): it rejects any **test-reachable** acquisition of the process-global `io::stdin()` handle outside the single sanctioned `with_stdin_lines` helper in `src/cli/shell.rs`. A test must drive stdin through that helper (it serialises fd-0 mutation under `STDIN_LOCK`, feeds a pipe whose write end is closed before the read for a deterministic first-read EOF, and restores fd 0 panic-safely) or write to a spawned subprocess's `ChildStdin` (the safe, non-gated pattern) — never grab the real process stdin.

- **v86 valid-time normalization migration pins its `archived_memories` arm** ([#2281](https://github.com/alphaonedev/ai-memory-mcp/issues/2281), v1.0.0 pre-ship Wave-B). The schema-v86 in-code canonicalization arm heals mixed RFC3339 renderings on BOTH `memories` and `archived_memories` (the v85 archive-parity migration carries the #1834 valid-time columns into the archive), but only the `memories` arm was regression-covered. A new sibling test plants a mixed rendering on an ARCHIVED row at schema 85, re-opens, and asserts the archived `valid_from`/`valid_until` heal to the canonical fixed-UTC form — mutation-checked against the `has_archive_table` branch in `src/storage/migrations.rs`. Regression coverage: `tests/claim_validtime_canonical_1834.rs::v86_migration_normalizes_archived_memories_rows_2281`.

- **Shared-DB test isolation: pending-action seeders now reap their global `pending_actions` rows** ([#2287](https://github.com/alphaonedev/ai-memory-mcp/issues/2287), v1.0.0 pre-ship). The sal-postgres suite shares ONE `ai_memory_test` database with no per-test schema isolation, and `GET /api/v1/pending` / `list_pending_actions` is a GLOBAL list, so `serve_postgres_extended::pending_list_returns_structured_empty_on_postgres` (asserts `count == 0`) breaks whenever a broad impact set co-schedules any pending-action seeder before it. Full runs stayed green only by accident (`tests/embedding_dim_migration.rs`'s `DROP TABLE … CASCADE` reset the DB first); an impact set that excludes it surfaced the latent leak (deterministic `left: 8`). Seven live seeders now clean up their rows even on assertion failure (cleanup-before-assert): three lib-suite tests in `src/store/postgres.rs` (`live_list_pending_actions_returns_seeded_row`, `fx_c2_batch5_live_decide_pending_action_alias_works`, `fx_c2_batch5_live_approve_with_approver_type_alias_works`) delete by seeded id, and four `tests/cov_ga2_pg_handlers_1.rs` `seed_pending_store` callers delete by namespace via a new `cleanup_pending_ns` helper (mirroring the existing `cleanup_governance_ns` convention). **Durable close (#2291 fold): the assertion no longer depends on every other test's teardown at all** — `pending_list_returns_structured_empty_on_postgres` now establishes its OWN precondition (`DELETE FROM pending_actions` before the `GET`). Safe by construction because the Postgres feature gate runs SERIAL (`cargo test … -- --test-threads=1` on every branch of the ci.yml "Run lib + integration tests" step), so there is never a concurrent test whose in-flight rows a blanket delete could nuke; this ends the seeder whack-a-mole (a future un-cleaned seeder can no longer red this test). Test-only; no production behavior change.

### Documentation

- **Pre-ship v1.0.0 docs reconciliation — tool/CLI counts, ROADMAP §23, PORTABILITY-V2 field contract, env table, release-notes ladder (Gate-0 tag-blocking, pre-ship 3×7 battery).** TEXT-ONLY; every count verified against the Rust SSOT (`Profile::full().expected_tool_count()`=103, `EXPECTED_CLI_SUBCOMMANDS_{DEFAULT,SAL}`=89/91, `Memory::FIELD_COUNT`=30, `CURRENT_SCHEMA_VERSION`=85). (1) `README.md` + `CLAUDE.md` first-read surfaces corrected from the stale 101 advertised / 100 callable / 89-sal-CLI figures to 103 / 102 / 91-sal (89 default); the `Stop` ([#1955](https://github.com/alphaonedev/ai-memory-mcp/issues/1955)) + `Watch` ([#1978](https://github.com/alphaonedev/ai-memory-mcp/issues/1978)) subcommands added to the CLI history. (2) `ROADMAP.md` §23 gained a v1.0.0 status banner recording that [#1860](https://github.com/alphaonedev/ai-memory-mcp/issues/1860) shipped only default-OFF `vectorlite`-only scaffolding (no sqlite-vec, no `--index` factory, fail-closed to builtin HNSW), §11.4.H.1 SDK shims marked SHIPPED (PR #2212), the L3-watcher `notify`-approval sites marked SHIPPED (#1978 + #2220), §11.6 mDNS/MVCC/OTel given an explicit v1.x-deferred disposition ruling, and the §24 parenthetical corrected to schema 85 / 103 tools. (3) **`docs/spec/PORTABILITY-V2.md` field-count contract corrected 28→30** (append `valid_from?`/`valid_until?` with the #1834 claim-validity semantics) — a spec-conforming importer coded to 28 silently dropped the claim-validity interval (data-loss); the stale `src/portability/emit.rs` doc comment was reconciled in lockstep. (4) `CLAUDE.md` env table gained the `AI_MEMORY_VECTORLITE_EXTENSION` row (#1860/#2219) + the default-off `vectorlite` cargo feature note. (5) `docs/v1.0.0/release-notes.md` schema ladder extended v78→v81 → v78→v85 (v82 #2024, v83 #2044, v84 #2167, v85 #2035), CLI/tool/route counts corrected, and the portability bullet rewritten to describe the shipped `export --full` v2 exporter + fail-closed all-or-nothing v2 importer ([#2006](https://github.com/alphaonedev/ai-memory-mcp/issues/2006), PORTABILITY-V2 §V2-7). The `scripts/check-docs-vs-ssot.sh` drift gate was extended to scan `docs/spec/PORTABILITY-V2.md` and police the `Memory::FIELD_COUNT` citation so the field-count contract cannot silently regress. No Rust behavior change — the only source edit is a doc comment.

## [0.10.0] — 2026-07-12 — `warn-carrier` (deprecation-WARN cycle for the v1.0.0 secure-default flips, [#1972](https://github.com/alphaonedev/ai-memory-mcp/issues/1972))

### Deprecated

- **v0.10.0 WARN-carrier release — deprecation WARNs ahead of the v1.0.0 fail-open → fail-closed flips** ([#1972](https://github.com/alphaonedev/ai-memory-mcp/issues/1972)). Every v1.0.0 secure-default flip rides the one-cycle-deprecation pattern: v0.10.0 EMITS the WARN, v1.0.0 flips. This release flips **no** default — it only adds the WARN machinery and the flip-ready code paths behind the existing env knobs.
  - `AI_MEMORY_RECALL_TOUCH_SYNC=1` is deprecated and will be **removed in v1.0.0** ([#1953](https://github.com/alphaonedev/ai-memory-mcp/issues/1953), citing the [#1869](https://github.com/alphaonedev/ai-memory-mcp/issues/1869) pure-recall vote). A one-shot WARN fires at daemon boot and on first recall-path use when the knob is set; migrate by unsetting it and relying on the pure-recall fold ledger. The knob still works this release.
  - `AI_MEMORY_FED_REQUIRE_WRITE_SIG` (env-table row 94, [#1464](https://github.com/alphaonedev/ai-memory-mcp/issues/1464)) and `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` (row 96, [#1843](https://github.com/alphaonedev/ai-memory-mcp/issues/1843)) each emit a one-shot boot WARN when **unset**, announcing the v1.0.0 flip of their shared compiled default to **required-per-surface** — federation inbound is the network surface (ruling `9e9c3cf2` condition 7) ([#1954](https://github.com/alphaonedev/ai-memory-mcp/issues/1954)). The resolution now routes through the single named `FED_REQUIRE_SIG_DEFAULT` const (currently `false`; the v1.0.0 flip is a one-line diff), and the `=0` opt-out keeps working past the flip.
  - `AI_MEMORY_REFLECT_DECORRELATION_MODE` unset/off emits a one-shot advisory on each `curator --reflect` run: v1.0.0 defaults the decorrelation probe to **advisory** (per D3-021), with enforce-as-default tracked for v1.x (D3-021 → D3-031 → D3-060) ([#1952](https://github.com/alphaonedev/ai-memory-mcp/issues/1952)). No behaviour change; the anti-theater refusal rules are unchanged.

### Changed

- **Agent attestation default is now surface-scoped** ([#1985](https://github.com/alphaonedev/ai-memory-mcp/issues/1985), resolving [#1981](https://github.com/alphaonedev/ai-memory-mcp/issues/1981)).
  `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` becomes tri-state with a per-surface
  compiled default: with the env unset, an unsigned direct-store write is
  rejected (`403 ATTESTATION_FAILED`) **only on the HTTP direct-write
  surface** (`POST /api/v1/memories` + `/memories/bulk`); the MCP
  `memory_store` and CLI `store` surfaces are the operator-as-actor path and
  stay permissive (unsigned → `attest_level="claimed"`). `=1` forces strict
  on every surface (the v0.9.0 posture), `=0` forces permissive on every
  surface (the v0.8 posture). Scope is by API surface, never transport/bind.
  A presented-but-forged signature is rejected unconditionally on every
  surface (unchanged). The `AttestationRequired` refusal text now names the
  three remediation paths — sign the write (`ai-memory store --sign` with a
  keypair bound via `ai-memory agents bind-key`), the `=0` opt-out, and that
  HTTP-direct requires attestation by default while MCP/CLI do not ([#1984](https://github.com/alphaonedev/ai-memory-mcp/issues/1984)).

### Errata (v0.9.0)

- The v0.9.0 #1751 compiled default required attestation on **every** store
  surface, but this was **unsatisfiable on MCP surfaces**: no MCP host can
  construct and sign the canonical `SignableWrite` envelope, so an unsigned
  `memory_store` under the default was rejected with no in-band remediation
  (the [#1981](https://github.com/alphaonedev/ai-memory-mcp/issues/1981)
  external break). The reference deployment had validated the `=0` **opt-out
  path**, not the shipped require-everywhere default. Corrected to the
  surface-scoped default above (#1985); the v0.10.0 per-surface flips
  (#94/#96) follow this precedent.

## [0.9.0] — 2026-07-08 — `security-hardening`

**§2-property contribution (release-level declaration, per §17):** v0.9.0
strengthens **§2.1 (persistent, endpoint-resident index)** via the
vector-search minimal opt-in slice (`VectorSearchIndex` seam, the G2/G4
capacity/dimension guards, and the §5.2 namespace-starvation fix — all
operating on the endpoint-resident HNSW index) and the B7-SKILL
executable-artefact minting; **§2.4 (improvable across model
generations)** via the `recall_observations` shadow-feedback sweep
(#1706) and the `parameters_schema`/`version` skill-memory surface;
and **§2.5 (index/governance events land in the signed, append-only
chain)** via the §25.3 P0 spine (signed rule enable/disable, signed
`policy_version` advances, signed `model_attestations`, signed
`reflection.decorrelation_refused`, and the signed one-tx epoch-apply
triple anchor). Not every hardening item below maps onto one of these
three named properties (e.g. the P0-1 recall-purity behavior change and
the P0-3 attestation secure-default flip are write-path/security-posture
changes, not index-property changes) — those are stated on their own
terms rather than force-fit onto §2.1/§2.4/§2.5.

### §11.5 B7-SKILL — skill memories first-class: `parameters_schema` at register, `invocation_record`, version surface ([#1865](https://github.com/alphaonedev/ai-memory-mcp/issues/1865))

Strengthens **§2.1 (executable artefacts are admin-minted, #949)** and
**§2.5 (attested — honest audit trail)**. No schema migration on either
backend: every field rides an EXISTING structure.

- **`parameters_schema` accepted + validated at REGISTER (fail-closed).**
  `memory_skill_register` / `ai-memory skill register --parameters-schema
  <PATH>` / `POST /api/v1/skill/register` now accept the same
  `parameters_schema` JSON-Schema-shaped object the promote path already
  did. Structural validation (`skill_register::validate_parameters_schema`)
  runs BEFORE any DB write — a malformed schema is rejected at MINT time,
  never deferred to activation (`memory_skill_get`), because skill rows
  are admin-minted executable artefacts (#949). The same gate was added
  to the promote path (previously a non-object schema was silently
  dropped instead of rejected). Stored in the existing
  `skills.metadata` JSON column under `parameters_schema` — the same
  column L2-7's `composes_with_reflections` mirror already uses; no new
  column, no migration.
- **`invocation_record` capture.** `memory_skill_get` (documented as
  returning a skill's "activation payload") now appends a best-effort,
  unsigned `signed_events` row (new `event_types::SKILL_INVOKED =
  "skill.invoked"`) on every activation fetch and surfaces
  `{event_id, recorded_at}` under the response's `invocation_record`
  key. Rides the EXISTING append-only `signed_events` table (no new
  `skill_invocations` table) — the same audit-log primitive
  `skill_register` already uses for its own `skill.registered` event.
- **Version surfacing.** The version-chain already existed at register
  (re-registering the same `(namespace, name)` supersedes the prior row
  via `superseded_by`); `skill_register::compute_skill_version` is a
  pure read-side walk of that EXISTING chain, now surfaced as `version`
  on `memory_skill_register`, `memory_skill_promote_from_reflection`,
  and `memory_skill_get` responses (1-indexed; works for the current row
  and for any old, already-superseded row).
- **Both backends.** The `skills` table (and `skill_resources`) has no
  Postgres schema at all — Agent Skills (v0.7.0 L1-5) has always been a
  sqlite-only substrate (no `MemoryStore`/SAL trait methods, no
  `postgres_schema.sql` entry). `signed_events` (which `invocation_record`
  rides) DOES exist on both backends with matching columns, so no
  postgres-twin drift is introduced.

Snapshots re-blessed for the new `memory_skill_register.parameters_schema`
property: `tests/snapshots/tool_definitions_pre_d1_6.json` (hand-patched —
property-membership only, no bless mechanism on that specific test) and
`tests/snapshots/tools_list_full.json` (`AI_MEMORY_BLESS_SNAPSHOTS=1`).

### §11.5 — close the `recall_observations` feedback loop, SHADOW mode ([#1706](https://github.com/alphaonedev/ai-memory-mcp/issues/1706))

Strengthens **§2.4 (improvable across model generations)** — recall now
generates the evidence needed to justify (or kill) a future usage-aware
ranking wire, without touching ranking itself.

- **`recall_outcome` backfill.** `confidence_shadow_observations.recall_outcome`
  (schema v39, always-`NULL` in practice — no live caller has ever stamped
  it) is now populated by a new offline sweep step,
  `confidence::shadow::backfill_recall_outcomes`: for every shadow row
  still `NULL`, it joins the `recall_observations` consumption ledger
  (schema v47, #886; dual-backend + authenticated per #1705) on
  `memory_id` and writes `consumed` / `unconsumed`; rows with no
  correlated ledger entry stay `NULL`. No new schema — the column was
  already provisioned.
- **`consumption_utility` metric.** `PerSourceBaseline` (part of
  `CalibrationReport`) carries a new `consumption_utility: Option<f64>` —
  `COUNT(consumed) / COUNT(judged)` per `(namespace, source)` group.
  **Logged only** (CLI table `UTIL` column, JSON envelope, and a
  `tracing::info!` line) — `crate::storage::recall`'s score formula is
  **completely untouched**; nothing reads this metric back into ranking.
  `None` (never a misleading `0.0`) when no row in the group has ledger
  evidence yet.
- **Cadence.** Rides the existing `calibrate_from_shadow` offline sweep
  (`ai-memory calibrate confidence --from-shadow` /
  `memory_calibrate_confidence`, gated `AI_MEMORY_CONFIDENCE_SHADOW=1`
  for the write side) — zero new hot-path code, recall p95 and the
  sqlite single-writer mutex untouched.
- **Skip-with-WARN.** When the `recall_observations` table is absent
  (pre-#886 schema, or a bare fixture), the sweep logs `"recall_observations
  ledger absent, skipping consumption utility backfill"` and returns
  cleanly instead of erroring.
- **The key honesty guarantee.** A new regression test
  (`recall_output_byte_identical_around_1706_shadow_sweep`, mirroring the
  reranker's `ReflectionBoostConfig::disabled()` byte-equality pin) proves
  `recall()`'s Memory payload + ranking order are byte-identical before
  and after the sweep runs — the sweep writes only into
  `confidence_shadow_observations`, a table `recall()`'s query never
  references.
- **Honest scope note on #1705 gating.** #1705 (ledger backend-parity +
  integrity hardening) is already closed, so the sqlite-backed sweep runs
  against the authenticated dual-backend ledger today. The confidence-
  shadow/calibration subsystem itself (`confidence_shadow_observations`,
  `calibrate_from_shadow`) remains sqlite-only — no postgres variant
  exists for it independent of this issue — so the skip-with-WARN path
  protects the reachable "ledger table absent from this sqlite DB" case
  (pre-#886 schema, bare fixtures) rather than a live postgres connection.
  Separately, `confidence::shadow::observe` has no live caller on the
  recall/store hot path today, so `confidence_shadow_observations` stays
  empty in a stock deployment until that wiring lands — out of scope
  here; the sweep and metric are correct against whatever shadow rows
  exist.
- **Out of scope (unchanged, per the issue's hard cuts):** no live
  ranking change, no bandit/online-reweight/trajectory selection, no
  exploration pool, no per-recall LLM-judge, no schema bump. Item 5
  (rank-delta shadow telemetry) was **not** shipped in this pass — kept
  out to bound scope; #1707 (the live-wire decision) stays conditional on
  this shadow data showing real divergence.

### §11.5 B7-RR-2 — reranker BertModel worker pool sized to physical CPUs (G7-step2, [#1867](https://github.com/alphaonedev/ai-memory-mcp/issues/1867))

- **`BatchedReranker` now runs a worker POOL** sized to the physical CPU
  count instead of a single worker. `resolve_reranker_pool_size()` resolves
  `AI_MEMORY_RERANK_POOL_SIZE` (positive int) > `available_parallelism()`,
  clamped to `1..=RERANK_POOL_MAX` (20). Every worker shares the ONE
  `Arc<BertModel>` (the #1084 no-mutex `forward(&self)` is concurrency-safe),
  so concurrent autonomous-tier recalls no longer serialise on a single
  handle **and** model RAM stays flat in pool size — no per-worker weight
  copy (footprint documented in PERFORMANCE.md). Each worker releases the
  shared job receiver before its forward pass, so sibling forwards run
  concurrently. Shutdown moved from a single one-shot channel to a shared
  `stop` flag so `Drop` terminates every worker within the 100 ms poll
  cadence. The #1597 candidate-pool cap and the auto-select direct path for
  lexical/degraded-lexical encoders are unchanged.
- **Scope note (honest):** the §11.5 "envelope-level degraded signal" was
  found ALREADY shipped since v0.7.0 as `meta.reranker_used`
  (`src/models/memory.rs`; values `neural`/`lexical`/`degraded_lexical`/`none`),
  so no duplicate `meta.reranker_mode` field was added. The global
  reranker default-on flip stays DEFERRED to v1.0 per vote `0b232b00` /
  B7-RR-AMEND-1. This commit ships G7-step2 (pool sizing) only;
  `resolve_reranker` and per-tier `cross_encoder` defaults are untouched.
- Tested (all CI-run): `src/reranker.rs::tests::pool_size_from_env_override_wins_and_clamps`,
  `::pool_size_from_invalid_env_falls_through_to_detected` (sizing/clamp
  logic); `tests/cov_ga2_misc.rs` (pool construction + shared-`Arc<BertModel>`
  concurrency coverage).

### bench-gap — Bench p95 gate now exercises the handler-layer rerank stage ([#1871](https://github.com/alphaonedev/ai-memory-mcp/issues/1871))

- **New `ai-memory bench` operation: `memory_recall` (rerank stage, depth=1).**
  `run_recall_hot` timed `db::recall` directly, but the cross-encoder rerank
  stage lives ABOVE `db::recall` in the MCP/HTTP handler, so the Bench CI
  p95 rule could never fire on a reranker change. The new op reproduces the
  handler's recall→rerank sequence in-process — the SAME `db::recall` call
  followed by the SAME `BatchedReranker::rerank` pass the handler runs — so
  the rerank STAGE COST is now inside the timed path and gated. A lexical
  cross-encoder stands in for the neural model (per #1871 the target is the
  stage cost being visible, not model quality — no HF-Hub download on the
  CI hot path). Budget: 60 ms default / 100 ms at `--scale 10000` (recall
  budget + rerank-stage headroom); the existing 7 operations are unchanged
  and unaffected (the new op runs after them). This is precondition (ii) of
  B7-RR-AMEND-1 for the future v1.0 reranker default-on flip.

### §25.3 P0 spine (S3/S4/S1/S2/S5; 2×5-wave vote `b0c1e157-3419-4d48-aebc-857283a97dfd`)

- **S3 (F-40) — signed rule enable/disable.** `rules_store::set_enabled_signed`
  flips `enabled`, re-signs the post-state canonical bytes, appends an
  operator-signed `governance.rule_{enabled,disabled}` audit row, and
  advances the policy version — all in one transaction, closing the CLI's
  two-statement atomicity gap.
- **S4 (F-41) — `policy_version`.** Monotonic, signed, append-only policy
  surface (whole-ruleset SHA-256 digest over enabled rules; seq = count of
  `governance.policy_version_advanced` events, emitted in the same tx as
  every signed rule mutation). Verdict/enforcement checkpoint wire binds
  `policy_seq`/`policy_digest_hex` (`ROLE_RESOLUTION_VERSION` 1→2, old
  checkpoints verify unchanged). Boot digest reconciliation is ADVISORY in
  v0.9 (doctor + warn); refusal is v1.0.
- **S1 (D3-012, [#1870](https://github.com/alphaonedev/ai-memory-mcp/issues/1870)) — `model_attestations` substrate, schema v78.**
  Claimable: **"attests model family (loader-attested, ~40% hard cap)"** —
  loader attestation is a process-lifetime trusted-substrate self-report,
  NOT per-write cryptographic provenance; only substrate-invoked generation
  is attestable (~40% ceiling, ROADMAP.md:1229). `model-attest list|enroll`
  CLI; forgery-pinned attested-read predicate; `memory_update` fail-safe
  downgrade of a caller-forged stamp.
- **S2 (D3-021, [#1767](https://github.com/alphaonedev/ai-memory-mcp/issues/1767)) — write-time attested-family decorrelation, ENFORCE-CAPABLE + wired.**
  `evaluate_write_quorum` counts DISTINCT ATTESTED families only (CLAIMED
  rows never laundered as diverse, nor weaponized into a refusal). Wired at
  BOTH reflect chokepoints (sqlite + postgres) between validation and
  insert: `off` (compiled default) = byte-identical; `advisory` = WARN +
  CLAIMED-not-ATTESTED caveat; `enforce` = REFUSE only on attested evidence
  (`attested_rows ≥ floor AND distinct < N`) with a signed
  `reflection.decorrelation_refused` row (`ReflectError::DecorrelationRefused`).
  Tested (all CI-run): `tests/decorrelation_enforce_s2.rs` (sqlite) and
  `tests/decorrelation_enforce_s2_pg.rs` (postgres) — the EPIC
  exit-criterion-8 kill-test, both backends.
  **"decorrelation enforced" STAYS BANNED** — the enforce-as-DEFAULT flip is
  v1.0; this ships the enforce-CAPABLE path, default `off`.
- **S5 (RQ-10, [#1878](https://github.com/alphaonedev/ai-memory-mcp/issues/1878)) — verify-only epoch-freeze consumer.**
  `ai-memory epoch-apply <manifest.json>`: parse → content-hash integrity →
  operator signature over canonical CBOR → strict monotonic `epoch_seq` →
  policy binding vs the live `current_policy_version()` (sqlite governance,
  the sole rules store on every backend) → ONE-tx triple anchor (resolved
  `EpochAdvance` checkpoint + `epoch.manifest_applied` audit row, sharing one
  SHA-256). Stale-policy / wrong-key / tampered / non-monotonic manifests are
  refused with zero rows. Tested (all CI-run): `tests/epoch_apply_s5.rs`
  (sqlite), `tests/epoch_apply_s5_pg.rs` (postgres, incl. a pg-backed-node
  non-vacuity test), `tests/epoch_contract_conformance.rs` (git-tracked
  contract conformance at `docs/contracts/`). The L3-boundary perma-ban
  gate (`scripts/check-l3-boundary.sh`) is CI-wired with a dual self-test.
  With the consumer now wired + git-tracked, **"epoch closure shipped" /
  "RQ-01 shipped" becomes claimable** — but the manifest structurally cannot
  assert diversity (no such field; `additionalProperties:false`), so it never
  launders unattested diversity.

### Behavior change — recall is PURE by default (P0-1, [#1869](https://github.com/alphaonedev/ai-memory-mcp/issues/1869); 2×5-wave vote `38d5af91-835d-4053-86eb-60d7cf1391e2`)

- **Pure recall (scoped claim):** recall mutates **zero rows in
  `memories` (and every other table) except the sanctioned append-only
  `recall_observations` audit ledger, which is neither silent nor
  memory state** — on EVERY entry path (HTTP GET/POST on both backends,
  MCP `memory_recall`, CLI `recall`, the shell REPL, and the SAL
  `recall_hybrid` surface). Pre-#1869 every recall path synchronously
  rewrote the returned rows (access_count bump, `last_accessed_at`,
  per-tier TTL floor-extend, mid→long promotion, priority decade
  ladder — including the hidden HTTP phase-2 writer at
  `src/handlers/recall.rs` and the postgres `touch_after_recall`),
  which the v0.9.0 epic kill-test (exit criterion 8) classified as
  silent mutation of memory state.
- **The access signal is decoupled, not deleted:** every recall appends
  to the `recall_observations` ledger (the CLI/shell/SAL-sqlite paths,
  which never wrote it, now do — closing their signal gap), and a
  periodic **FOLD** maintenance job (`db::fold_recall_accesses` /
  `MemoryStore::fold_recall_accesses`) batch-applies the exact legacy
  touch ladders from unfolded rows in bounded, chunked transactions
  (≤1000 memories per tx, zero-work early return; snapshot-consistent
  single-statement CTE on postgres). The fold deliberately touches the
  RETURNED (post-filter) set, fixing the pre-filter-set inconsistency
  vs #757. Scheduling: dedicated loop (default 60 s,
  `AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS`, env row #119; `0` =
  gc-tick-only) **plus** fold-before-gc on every eviction path (sqlite
  gc loop, admin HTTP `run_gc` both backends, CLI `gc`) so a recalled
  row is extended before eviction is evaluated. Bounded staleness
  (≤ fold interval) applies to access-count consumers (ranking frecency
  term, tier promotion, TTL slide, autonomy priority feedback, curator
  reflection clustering, opt-in confidence decay — which moves onto the
  fold on BOTH backends, preserving the #1572 postgres decay parity —
  doctor validation, the `memory_inbox` `access_count==0` unread
  marker, and the recall response's `freshness_state`; the
  `skill_compositional_context` recall_score and the `crdt_merge`
  access_count max-merge are fold-safe/monotonic), and holds only
  while a daemon runs: CLI-only topologies freeze counts between manual
  `ai-memory gc` runs.
- **Legacy opt-back-in:** `AI_MEMORY_RECALL_TOUCH_SYNC=1` (env row
  #118) restores the strict-legacy synchronous touch; recall-path
  ledger rows are then written pre-marked `folded = 1` so the
  always-running fold never double-applies a sync-touched access.
  **Deprecated at birth — removal targeted v1.0.** Mixed-version
  caveat: a pre-v77 binary sharing a v77 postgres DB sync-touches AND
  inserts unfolded rows a v77 daemon then folds (bounded double-count,
  capped by the 7d ledger TTL + the 1M/priority ceilings) — upgrade all
  daemons together.
- **Schema v77** (76→77, both backends in lockstep):
  `recall_observations.folded` + partial unfolded index
  (`migrations/sqlite/0061_v77_recall_observations_folded.sql`,
  `migrations/postgres/0036_v77_recall_observations_folded.sql`,
  greenfield mirror in `src/store/postgres_schema.sql`); the migration
  BACKFILLS `folded = 1` on pre-existing rows (already sync-touched —
  folding them would double-count), probe-guarded on both backends.
  The ledger is now **load-bearing for retention**: both pruners delete
  `folded = 1` rows only, with an age-capped safety valve (unfolded
  rows older than the ledger TTL are pruned with a WARN) so a dead fold
  loop or a third-party no-op SAL fold cannot grow the table forever —
  do not truncate the table by hand.
- Tested (all CI-run): `tests/recall_purity_p01.rs` — dump-compare
  purity across `db::recall` / `db::recall_hybrid` / MCP / HTTP (real
  axum router) / CLI / shell / SAL-sqlite, N=25 iterations with
  result-set stability + exact ledger growth, the decay variant, the
  sync-mode no-double-count companion, fold idempotency + twin-DB
  equivalence vs `touch_many` + promotion/priority/cap edges +
  chunk-boundary + inbox unread flip + fold-before-gc retention + the
  v77 backfill + the `INTERVAL=0` gc-tick fold pin;
  `tests/recall_purity_p01_postgres.rs` (postgres-parity-nightly
  allowlist) — SAL + HTTP purity dump-compare, cross-backend fold
  parity (promotion + decade crossing in one window, decay-enabled
  with timestamp normalization), postgres fold-before-gc retention;
  `tests/recall_purity_caller_guard_p01.rs` — touch-verb caller-census
  regression guard; `src/background/access_fold.rs` + `src/config.rs`
  unit suites. Bench note: the pure default REMOVES the `BEGIN
  IMMEDIATE` + 3K-UPDATE write burst from the recall hot path (a strict
  win); PERFORMANCE.md p95 budgets are intentionally NOT tightened in
  this change.

### Breaking / secure-default changes — store-path agent attestation now REQUIRED by default ([#1751](https://github.com/alphaonedev/ai-memory-mcp/issues/1751); deprecation cycle from [#1464](https://github.com/alphaonedev/ai-memory-mcp/issues/1464)); pre-event hook-enforcement gate now dual MCP+HTTP ([#1885](https://github.com/alphaonedev/ai-memory-mcp/issues/1885) / [#1924](https://github.com/alphaonedev/ai-memory-mcp/issues/1924))

- **`AI_MEMORY_REQUIRE_AGENT_ATTESTATION` compiled default flipped
  `false → true`** (`src/identity/attest.rs::require_agent_attestation_enabled`,
  env-table row #48). An UNSIGNED direct-store write — MCP `memory_store`,
  HTTP `POST /api/v1/memories`, CLI `store` — is now rejected
  (`403 ATTESTATION_FAILED` / CLI error) instead of landing
  `attest_level = "claimed"`. A presented signature is verified against the
  agent's bound key exactly as before (valid → `agent_attested`; forged →
  reject, unconditionally). This is the flip promised by the v0.8.0
  one-cycle deprecation WARN (#1464 5-agent vote, UNANIMOUS Option A); that
  one-shot WARN is now removed, its obligation fulfilled.
- **Migration:** operators with unsigned store workflows must either sign
  writes (`ai-memory store --sign` with a keypair bound via
  `ai-memory agents bind-key`) or set the explicit opt-out
  `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` (or `=false`, case-insensitive)
  to restore the pre-v0.9 permissive posture. Any other value falls
  through to the required default, so a typo fails closed.
- **Scope (per the #1464 vote):** the STORE/direct-write path ONLY. The
  federation receive path attests via the per-peer authorship allowlist
  (`resolve_inbound_attribution`, #1464) — NOT this flag — so this flip
  does not change the network boundary; per-write cryptographic
  verification of federated memories remains tracked under #1719.
  Curator/autonomy self-writes go through the SAL `store()` surface
  (`CallerContext::for_admin`) and never traverse this gate. The
  non-loopback boot posture WARN (R-12) now describes the permissive
  posture as the explicit opt-out rather than the default.
- Tested: `tests/config_precedence.rs::test_require_agent_attestation_env_parsing`
  (unset ⇒ REQUIRED; `0`/`false` ⇒ permissive; `1`/`true` ⇒ required;
  unrecognized ⇒ required) +
  `src/identity/attest.rs::tests::require_flag_parse_core_v09_default_required` +
  the pre-existing strict-posture rejection suites
  (`tests/agent_attestation_integrity.rs`, `tests/agent_attestation_postgres.rs`).
- **[#1885](https://github.com/alphaonedev/ai-memory-mcp/issues/1885) / [#1924](https://github.com/alphaonedev/ai-memory-mcp/issues/1924) — mandatory-hook-presence enforcement gate now fires on BOTH the
  MCP write path and the HTTP write path.** `#1734` (v0.8.0) installed the
  process-global pre-event enforcement gate (`consult_pre_event_gate`,
  `src/mcp/mod.rs`) for the MCP surface only — a required-event hook
  configured but absent/disabled correctly fails closed there, but an HTTP
  write (`POST /api/v1/memories` and siblings) never consulted the gate at
  all, a silent bypass (CWE-288): a caller could skip MCP entirely and land
  a write with zero hook coverage even when a mandatory hook was configured.
  `#1885` re-confirmed and hardened the MCP-side gate; `#1924` wires the
  same installed gate onto the HTTP write path
  (`http_pre_event_gate`, `src/handlers/create.rs`), so both surfaces now
  enforce identically. Inert unless enforce mode is configured — no
  behavior change for deployments that don't use mandatory-hook enforcement.

### Security / code-review hardening — 49 fixes across a 5-lane adversarial review ([#1885](https://github.com/alphaonedev/ai-memory-mcp/issues/1885)–[#1935](https://github.com/alphaonedev/ai-memory-mcp/issues/1935))

Five review lanes (crypto/daemon/federation, security/crypto, handlers/governance,
authz/isolation, mcp) landed 49 confirmed findings, all fixed. The two
write-path-wide items (#1751 attestation-required default, #1885/#1924 dual
hook-enforcement gate) are called out above under "Breaking / secure-default
changes"; the remaining highlights:

- **[#1919](https://github.com/alphaonedev/ai-memory-mcp/issues/1919) — `bulk_create` is now attestation-gated per row** (CWE-288/CWE-345).
  Mirrors the #1751 single-write requirement onto the batch path
  (`src/handlers/memories_query.rs`) — every row in a `bulk_create` request
  must carry a valid agent attestation; a batch cannot bypass the
  required-attestation default just by going through the bulk endpoint.
- **[#1920](https://github.com/alphaonedev/ai-memory-mcp/issues/1920) — federation approval authorship gate** (CWE-862). An inbound
  federated PENDING approval (`src/handlers/federation_receive.rs`) is now
  honored only when it is attributed to the peer's registered approver; an
  enrolled-but-hostile peer can no longer forge an approval for an
  unauthorized requester.
- **[#1921](https://github.com/alphaonedev/ai-memory-mcp/issues/1921) — `team`/`unit`/`org` visibility scope hardening** (CWE-863).
  `src/visibility.rs` now enforces the namespace-ancestor subtree
  correctly for the `team`/`unit`/`org` scopes, closing a cross-tenant
  over-broad-visibility gap where a shared-scope row could project beyond
  its intended subtree.
- **[#1923](https://github.com/alphaonedev/ai-memory-mcp/issues/1923) — `skill_register` `folder_path` import jail** (CWE-22/CWE-59).
  `src/mcp/tools/skill_register.rs` canonicalizes and confines
  `folder_path` under the configured root; a symlink anywhere inside the
  imported tree is refused outright rather than followed.
- **[#1927](https://github.com/alphaonedev/ai-memory-mcp/issues/1927) — non-argv store-url credential channels** (CWE-214). New
  `AI_MEMORY_STORE_URL` (owner-only `/proc/environ`) and
  `AI_MEMORY_STORE_URL_FILE` (a `0600` file) let `ai-memory serve` receive
  the store URL — including any embedded password — without putting it on
  `--store-url` argv, which is exposed via world-readable
  `/proc/<pid>/cmdline` and `ps auxww` to any local UID.
  `resolve_store_url()` (`src/daemon_runtime.rs`) resolution order:
  `AI_MEMORY_STORE_URL_FILE` → `AI_MEMORY_STORE_URL` → `--store-url`.
- The remaining findings across the crypto/daemon/federation, security/crypto,
  handlers/governance, and mcp clusters (#1886–#1918, #1922, #1925, #1926,
  #1928–#1935) are defect closures with no external-facing behavior/API
  change; see `git log` for the per-cluster commits
  (`59508a8c`, `5ffd5748`, `d2ca4d75`, `540465b5`, `212d2e3b`, `3ae00af3`,
  `7d136222`, `3c6a8f39`).

### Added — vector-search minimal opt-in slice ([#1005](https://github.com/alphaonedev/ai-memory-mcp/issues/1005); full substrate deferred to [#1860](https://github.com/alphaonedev/ai-memory-mcp/issues/1860))

Every item below is byte-identical to legacy behavior until its flag /
allowlist is set (the shipped G5b/G9/G10.1 inert-until-enabled idiom).
No schema migration; no new dependencies.

- **`VectorSearchIndex` seam** (`src/hnsw.rs`): the swappable
  vector-search trait (named to avoid colliding with the concrete
  `VectorIndex` struct). The existing HNSW `VectorIndex` implements it
  verbatim as the inert default backend; the shared daemon state and
  the recall/write pipelines now hold
  `Arc<tokio::sync::Mutex<Option<Box<dyn VectorSearchIndex>>>>` /
  `Option<&dyn VectorSearchIndex>` instead of the concrete struct, so
  an alternative backend (the v1.0 #1860 substrate) can slot in
  without touching the pipelines. Signatures preserve `&self` +
  interior mutability and `String` memory-id keys.
- **§5.2 recall fix — namespace starvation (opt-in,
  `AI_MEMORY_VECTOR_NAMESPACE_ALLOWLIST`):** when enabled and the
  recall is namespace-filtered, the ANN phase threads the namespace's
  embedded-row id set into the search and consumes the nearest-first
  iterator LAZILY until `k` in-namespace hits or iterator exhaustion —
  replacing the fixed `k*2`/`ann_limit = max(limit*5, 50)` global
  cutoff that let a large foreign corpus crowd a small namespace's
  rows out of semantic recall entirely. Hierarchical namespaces admit
  ancestor rows (the Task 1.12 contract). `None`/flag-off is
  byte-identical legacy. Tested (CI-run): `tests/recall_ns_allowlist_1005.rs`
  (flag-on in-namespace recall + ancestor admission + flag-off
  byte-identical-legacy regression, both pinned in the same suite).
- **G4 strict embedding-dimension guard (opt-in,
  `AI_MEMORY_REQUIRE_DIM_MATCH`):** the HNSW `cosine_distance`
  zip-truncation residual now (under the flag) collapses a
  mismatched-dimension pair to `f32::MAX` (ranks last; dropped by the
  recall cosine gate) with a typed `EmbeddingDimMismatch` record, and
  the index write boundary rejects mismatched-dimension inserts.
  Default stays tolerant (legacy truncating comparison).
- **G2 capacity knob wired (`[limits].vector_index_capacity` /
  `AI_MEMORY_VECTOR_INDEX_CAPACITY`):** the residency cap the
  v0.7.0 M8 eviction-rate ERROR has told operators to tune is now an
  actual knob (resolved by `AppConfig::resolve_limits`, threaded into
  every index construction site). Plus opt-in hard-fail-at-cap mode
  (`[limits].vector_index_hard_fail_at_cap` /
  `AI_MEMORY_VECTOR_INDEX_HARD_FAIL`): reject inserts at capacity
  (ERROR log, index unchanged; the row stays keyword/FTS-recallable)
  instead of silently evicting the oldest embeddings.

### Added — G13-mem memory-derivation lineage-DAG ([#1859](https://github.com/alphaonedev/ai-memory-mcp/issues/1859))

- **Lineage-DAG query surface** over the provenance link subset
  P = {`derived_from`, `reflects_on`, `derives_from`} (a VIEW over
  `memory_links` — no new table, no new relation): MCP `memory_lineage`
  (tool count 100 → 101, `graph` family), HTTP
  `GET /api/v1/memories/{id}/lineage`, CLI `ai-memory lineage`
  (subcommands 83/85 → 84/86), Python SDK `lineage()`. Both backends
  return the identical `{id, cid, relation, depth}` node shape (SQLite
  recursive CTE; Postgres AGE Cypher with CTE fallback + the
  deferred-projection read-your-own-write reroute).
- **Schema v75** (both ladders): additive nullable
  `memory_links.source_cid` / `target_cid` mirror the endpoints'
  schema-v74 `memories.cid` at link-creation time (advisory
  federation-resolution anchor — the UUID stays authoritative).
- **BEHAVIOR CHANGE (flag-gated):** with `AI_MEMORY_LINEAGE_DAG` +
  `AI_MEMORY_CONSOLIDATE_TOMBSTONE_SOURCES` on, `memory_consolidate` no
  longer erases its sources — it **tombstones** them
  (`lifecycle_state='tombstoned'`, id + cid retained) and writes
  navigable `derived_from` edges, making store → reflect → consolidate
  multi-hop lineage walkable. Erasure-required (GDPR) deployments set
  the sub-flag off to keep the legacy hard-delete.
- **CONSOLIDATE revision-leaf baseline corrected:** pre-#1859 the
  Postgres consolidate already emitted a per-source `CONSOLIDATE`
  `memory_revisions` leaf under `AI_MEMORY_APPEND_ONLY` while SQLite
  emitted none. Both backends now emit EXACTLY ONE leaf per source
  through the single shared predicate
  `revisions::consolidate_leaf_enabled()` (append-only AND/OR the
  tombstone sub-flag; never zero when either is on, never two when both
  are).
- **P-wide acyclicity guard** on lineage-relation link writes (strict
  chrono `>` on `created_at`; equal same-batch instants admitted;
  federation imports bypass — traversal cycle-detection is the
  backstop), surfaced via the existing `LINK_CYCLE_ERR_PREFIX` 409
  envelope on both backends.

### §11.5 B7-FC — function/tool-calling protocol for `/api/chat` + curator wiring ([#1866](https://github.com/alphaonedev/ai-memory-mcp/issues/1866))

Strengthens **§2.4 (improvable across model generations)** — a tool-capable
model can now be driven with schema-constrained calls instead of
JSON-in-text parsing, with no regression for models that ignore tools.

- **`OllamaClient::generate_with_tools` (+ async)** (`src/llm.rs`): new
  `ToolDef`/`ToolCall`/`ChatOutcome` types; when `tools` is non-empty the
  `/api/chat` (Ollama) / `/chat/completions` (OpenAI-shim) body carries a
  JSON-Schema `tools` array and the reply is parsed for a structured
  `tool_calls` array (Ollama object args, OpenAI-shim string args
  re-parsed on ingest; malformed entries skipped). A model that ignores
  tools degrades gracefully to `ChatOutcome::Text` — byte-identical to
  `generate_async` when `tools` is empty. Circuit-breaker, the governance
  `NetworkRequest` gate, and wire shape are unchanged.
- **Curator wiring** (`src/atomisation/curator.rs`): `LlmGenerate` gains a
  defaulted `generate_with_tools` (default = text fallback via
  `generate`, so every existing implementor is unchanged).
  `Curator::decompose` now offers an `emit_atoms` tool matching the
  `CuratorResponse` schema; a tool-capable backend returns a
  schema-constrained call (no `extract_first_json_object` heuristics on
  the happy path), and tool-unsupporting backends fall back to the
  historical text-parse path unchanged.
- Tested (all CI-run, `src/llm.rs::tests` + `src/atomisation/curator.rs::tests`):
  `tool_def_to_wire_uses_openai_function_shape`,
  `parse_tool_calls_object_and_string_arguments`,
  `generate_with_tools_async_dispatches_structured_call`,
  `generate_with_tools_async_falls_back_to_text_when_model_ignores_tools`,
  `generate_with_tools_async_malformed_tool_calls_degrades_to_text`,
  `generate_with_tools_async_openai_string_arguments`,
  `generate_with_tools_async_empty_tools_is_plain_text`,
  `generate_with_tools_async_breaker_open_short_circuits`,
  `emit_atoms_tool_schema_is_well_formed`, `parse_tool_atoms_happy_and_error_arms`,
  `curator_dispatches_emit_atoms_tool_call`,
  `curator_retries_when_tool_args_malformed_then_succeeds`,
  `curator_falls_back_to_text_when_tools_unsupported`.

### G5a/G5b — audit cause-binding + dual-chain witness anchor ([#1822](https://github.com/alphaonedev/ai-memory-mcp/issues/1822); schema v73)

Strengthens **§2.5 (the signed audit trail binds *why* a write happened,
not just *what*)**. Additive and permissive — byte-identical legacy when
the require-flags are unset.

- **Schema v73** (both ladders): additive nullable
  `signed_events.cause_hash` — a 32-byte SHA-256 over a secret-screened,
  identity-only pre-image of the TRIGGERING CAUSE of an audit-bearing
  write. Folded PRESENT-ONLY into the cross-row canonical bytes (legacy
  `NULL`-cause rows hash byte-identically) and into the per-row Ed25519
  signing input, so tampering the cause breaks both the next row's
  `prev_hash` link and the row's own signature. `migrations/sqlite/0057_v73_signed_events_cause.sql`
  + postgres `migrate_v73`; `CURRENT_SCHEMA_VERSION` 72 → 73.
- **G5b dual-chain witness anchor:** `verify_audit_trail` gains an
  independent `audit_head_witness` checkpoint (one anchor per 64
  `signed_events` appends + graceful shutdown) plus per-row cause-binding
  coverage checks, both surfaced as verdicts on both backends.
- **Two new K2 require-flags** (both default `false`/permissive — they
  withhold judgement rather than dirty by default):
  `AI_MEMORY_REQUIRE_WITNESS` (truthy ⇒ a missing/unpinnable/invalid
  witness anchor is `WitnessCheck::Missing`, exit 1) and
  `AI_MEMORY_REQUIRE_CAUSE_BINDING` (truthy ⇒ any `cause_hash IS NULL`
  row is `CauseBinding::Detected`, exit 1). `Detected`/`Forged` tamper
  verdicts stay dirty unconditionally regardless of the flags.

### G6 — append-only spine: every mutation site routed to signed revision leaves ([#1823](https://github.com/alphaonedev/ai-memory-mcp/issues/1823))

Strengthens **§2.5 (index/lifecycle events land in the signed, append-only
chain)**. Additive and flag-gated (`config::append_only_enabled()`,
default OFF — byte-identical legacy until enabled).

- **Every production memory-mutation primitive on both backends** now
  appends ONE identity-only signed leaf to `memory_revisions` IN-TX when
  the flag is on: COW SUPERSEDE (in-place content UPDATE, same id) on
  `update_with_expected_version`/`bind_agent_pubkey`/`revoke_agent_pubkey`/
  `overwrite_full_row_by_id` and their postgres twins; capture-then-compact
  TOMBSTONE/FORGET/EXPIRE/EVICT/ARCHIVE/CONSOLIDATE leaves emitted BEFORE
  the corresponding delete on `delete`/`apply_remote_deletion`/
  `purge_and_tombstone_forget`/`forget`/`gc`/`size_gc`/`archive_memory`/
  `consolidate`. Leaves are identity-only (`memory_id`/`kind`/
  `prior_version`/`namespace`/`agent_id`/`ts`/`sig`) — **never content.**
  The postgres `apply_remote_deletion` fix additionally closes a
  pool-direct hard-delete data-loss gap (now atomic tx + audited leaf).
- Tested (all CI-run): `tests/append_only_spine_guard_g6.rs` (static
  every-mutation-site-is-routed guard, enforced with an empty worklist);
  `tests/append_only_spine_flagon_g6.rs` (flag-ON behavior: exact leaf per
  primitive, Ed25519 signature verification, same-id-supersede +
  federation-convergence non-perturbation, flag-OFF zero-rows
  re-confirmation).
- **"append-only" / "no silent delete" remain BANNED** for a global claim
  — this ships the flag-gated capability; the global default-on flip is
  out of scope here (see §1.5 discipline in the EPIC doc).

### G8 — additive content-addressed BLAKE3 content-id (cid) ([#1825](https://github.com/alphaonedev/ai-memory-mcp/issues/1825); schema v74)

Strengthens **§2.5 (stable, content-addressed genesis identity for
federation resolution)**. Fully additive — the UUID `id` stays the PK,
every FK, and the federation LWW tiebreak.

- **Schema v74** (both ladders): additive nullable `memories.cid`
  (TEXT `b3:<hex>`) + `memories.cid_genesis` (BLOB/BYTEA) columns +
  `idx_memories_cid`. `cid` is a BLAKE3 content-address minted from a
  memory's GENESIS fields (`agent_id + namespace + screen(title) +
  memory_kind + created_at + SHA256(screen(content))`); title/content
  are secret-screened MODE-INDEPENDENTLY so federated nodes on different
  `AI_MEMORY_SECRET_SCREEN_MODE` mint the SAME cid. `cid_genesis` is
  NULLed on erasure (`RecordKind::Forget`) while `cid` is retained so the
  stored digest can't become a confirmation-oracle.
  `migrations/sqlite/0058_v74_memories_cid.sql` + postgres `migrate_v74`;
  `CURRENT_SCHEMA_VERSION` 73 → 74.
- **`AI_MEMORY_CID_ENFORCE`** (default `false` = detect-and-log): when
  truthy, a cid/`cid_genesis` mismatch is logged at `WARN` under the
  `cid.enforce` target. Enforcement is DETECT-AND-LOG ONLY — it never
  refuses a write and never refuses a federated receive (that would break
  CRDT convergence). cid is partial-corruption detection + genesis-identity
  binding, NOT at-rest forgery-evidence.

### G9 — three-key Recorder/Judge/Stopper signing-layer separation ([#1826](https://github.com/alphaonedev/ai-memory-mcp/issues/1826))

Strengthens **§2.5 (governance verdicts/enforcement land in the signed
chain)**. Additive and opt-in — byte-identical legacy when unconfigured.

- **Three governance-role signing keys** (Recorder/Judge/Stopper),
  reusing the existing witness-custody + pin-first-then-verify
  discipline. Every governance verdict is Recorder-signed (daemon-key
  fallback); every enrolled Judge signs a `GovernanceVerdict` checkpoint
  on every verdict; an enrolled Stopper signs a `GovernanceEnforcement`
  checkpoint on every deny (advisory `stopperSig`, produced independent of
  the deny decision itself). `verify_chain` / `verify_audit_trail`
  (postgres twin) both gain per-row Recorder signature verification plus
  a shared `RoleSeparationCheck` (pin-first judge/stopper pubkeys +
  pairwise distinctness), fail-closed under the require flag
  `AI_MEMORY_REQUIRE_ROLE_SEPARATION` (default `false`/permissive; when
  truthy a failed check hard-blocks the verdict).
- Tested (all CI-run): `tests/role_separation_1826.rs` — legacy
  byte-equality, recorder/judge/stopper signature pins, cross-role
  forgery (all four legs), require-flag fail-closed, domain separation,
  live-gated postgres parity.
- **Honest scope:** single-process key custody (no HSM/M-of-N, no
  cross-host key split) — the capability manifest explicitly disclaims
  BFT/HSM/M-of-N/`governance.halt` and intra-process key co-location.
  Global "three-key" / trust-boundary claims stay DEFERRED to v1.0 (§B4
  per-stream deferral).

### G10.1 — macaroon capability tokens wired end-to-end ([#1827](https://github.com/alphaonedev/ai-memory-mcp/issues/1827))

Strengthens **§2.5 (capability grants/rejects land in the signed audit
trail)**. Byte-identical legacy until `[capabilities].enabled` (default
`false`).

- **The stateless macaroon capability-token layer is now reachable on
  every governed surface** (MCP/HTTP/CLI edges), on top of the pre-shipped
  pure core: `[capabilities]` config block with a CLOSED-allowlist loader
  (misconfigured issuers are SKIPPED, never fall through to
  `db::agent_pubkey`); `CallerContext.capability` threaded through
  `db::enforce_governance`, the SAL trait, and the postgres inline gate as
  a signature parameter (compiler-enforced — no caller can be missed); one
  wiring hook (`governance::capability::apply_at_gate`) runs inside both
  backend gates on the final coarse decision, Enforce-arm only: a granted
  Pending flips to Allow (no stray approval row), a reject returns the
  unchanged base refusal plus a capability-reject forensic row, grants
  land capability-grant rows naming issuer/root_id/op_level.
  Agent-caveat identity is pinned to the gate's own `agent_id` argument,
  closing an impersonation seam by construction.
- Tested (all CI-run): `tests/g10_capability_tokens.rs`,
  `tests/capabilities_v2.rs`, `tests/capabilities_v3.rs`,
  `tests/capabilities_v3_l3_5.rs`,
  `tests/capabilities_v3_provenance_layer.rs`.

### G13 (bare) — signed identity-lineage key-succession chain, rotation-survival core ([#1828](https://github.com/alphaonedev/ai-memory-mcp/issues/1828); schema v76)

Strengthens **§2.5 (identity succession lands in a signed, verifiable
chain)**. Opt-in and additive — no lineage enrolled = byte-identical
legacy resolution through the flat `metadata.agent_pubkey`.

- **An agent_id can now name a SEQUENCE of keys** `K0 → K1 → … → Kn`
  linked by predecessor-signed succession records; a verifier walks
  genesis → head and trusts `Kn` via an unbroken Ed25519 chain rooted at
  `K0`. New `src/identity/lineage.rs` (`LineageRecord`, `LineageError`,
  `verify_succession`/`verify_lineage`, `LineageCheck` verdict — mirrors
  `RoleSeparationCheck` for K3 cross-backend parity); `sign.rs` gains a
  domain-tagged `SignableSuccession` (carries `recovery_pubkey` for v1.0
  forward-compat) + `sign_succession`; `keypair::rotate_with_succession`
  signs+persists the handoff with `K_old` before archive/save destroys
  it (legacy `rotate()` untouched); dedicated `agent_lineage` table
  (composite PK `(agent_id, epoch)`) on both backends; CLI
  `identity enroll-lineage` / `succeed` / `register-recovery-key`;
  `verify-audit-trail` surfaces the `LineageCheck` verdict on both
  backends. New require-flag `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE`
  (default `false`/permissive): when truthy, a broken or absent
  succession chain fails closed rather than falling back to the flat
  `metadata.agent_pubkey`.
- Tested (all CI-run): `tests/identity_lineage_succession.rs`.
- **Honest scope (per ROADMAP §26.5 — see EPIC §B5):** this ships
  **rotation-survival continuity only** — a *voluntary* predecessor
  signing its successor. It does **not** solve "key-loss = death": if the
  sole active key is lost there is nothing left to sign a successor.
  True loss-recovery needs M-of-N threshold/social recovery (G17/#1831),
  which is **v1.0**. Do **not** claim "key-loss recovery" for v0.9 — this
  is why `recovery_pubkey` exists on the wire type now but v0.9 does not
  implement a recovery-VERIFY path against it.

## [0.8.1] — 2026-06-29 — `hardened-patch` — defect closure + security review ([#1821](https://github.com/alphaonedev/ai-memory-mcp/issues/1821))

A defect-closure + security-hardening patch that makes shipped v0.8.0 correct
on its own current claims, then puts the result through an adversarial review.
No new v0.9.0 capability. Three streams:

1. **Work items W1–W7** (per `docs/v0.8.1/V0.8.1-PATCH-1-WORK-PROMPT.md`):
   G29 write-path secret screen, G30 erasure fan-out + signed tombstones
   (schema **v71**), G12 honest durability (`202` not `503`), MCP governance
   fail-closed ([#1685](https://github.com/alphaonedev/ai-memory-mcp/issues/1685)),
   postgres L2 rehydration parity ([#1693](https://github.com/alphaonedev/ai-memory-mcp/issues/1693)),
   and documentation/GitHub-Pages drift remediation.
2. **Security review — 9 findings, all fixed.** A 7-lane adversarial review
   (find → verify → triage) surfaced 9 confirmed issues — all fixed and closed,
   7 of the 9 also covered by a dedicated regression test (#1845 forensic-
   transcript redaction and #1851 CI `workflow_dispatch` injection ship verified
   code fixes that are not separately regression-tested), each contested call
   decided by a 5-agent vote (`4d3ea1c5`):
   federated-signal authorship ([#1843](https://github.com/alphaonedev/ai-memory-mcp/issues/1843)),
   field-complete secret screen ([#1844](https://github.com/alphaonedev/ai-memory-mcp/issues/1844)),
   forensic-transcript redaction ([#1845](https://github.com/alphaonedev/ai-memory-mcp/issues/1845)),
   FTS OR-tree DoS cap ([#1846](https://github.com/alphaonedev/ai-memory-mcp/issues/1846)),
   CGNAT SSRF ([#1847](https://github.com/alphaonedev/ai-memory-mcp/issues/1847)),
   archive-restore tombstone gate ([#1848](https://github.com/alphaonedev/ai-memory-mcp/issues/1848)),
   namespace-less forget governance ([#1849](https://github.com/alphaonedev/ai-memory-mcp/issues/1849)),
   audit tail-truncation anchor ([#1850](https://github.com/alphaonedev/ai-memory-mcp/issues/1850)),
   CI workflow_dispatch injection ([#1851](https://github.com/alphaonedev/ai-memory-mcp/issues/1851)).
3. **PostgreSQL + Apache AGE + pgvector verified live.** The postgres+AGE
   backend was deployed on real infra and passed 3 green rounds + an AI-NHI
   dogfood (store / pgvector semantic recall / AGE graph projection / forget /
   secret-screen); the do-hive provisioning was fixed to install pgvector +
   build AGE ([#1842](https://github.com/alphaonedev/ai-memory-mcp/issues/1842)).

### Breaking / API-semantics changes

- **W3 / gap G12 — a durable-but-under-replicated write is now `202 Accepted`,
  not `503`.** On a W-of-N quorum miss the local row is durably committed
  (per `ADR-0001`, never rolled back), so the prior `503 quorum_not_met` +
  `Retry-After: 2` misreported a locally-durable write as a service failure.
  HTTP writes now return **`202 Accepted`** with the replication state in the
  body (`{quorum_met:false, acks, needed, reason, durability:"local"}`); a
  genuine *local* write failure still returns an error status. The shared
  `quorum_not_met_response`/`fanout_or_503` helpers are renamed
  `under_replicated_response`/`fanout_or_pending`. Docs updated
  (`API_REFERENCE.md`, `ADR-0001`). 5-agent crossroads vote (`4d3ea1c5`).

### Security / data-privacy fixes

- **W1 / gap G29 — credential write-path screen (fail-closed).** Caller-origin
  writes (MCP `memory_store`, `POST /api/v1/memories`(+`/bulk`), CLI) are now
  screened for embedded credentials (PEM keys, AWS/GitHub/OpenAI/xAI tokens,
  JWTs, Bearer tokens — anchored patterns with a Shannon-entropy tiebreak so
  benign UUID/hex-SHA/base64 pass). Default `AI_MEMORY_SECRET_SCREEN_MODE=refuse`
  rejects them; `redact` masks; `off` disables. Federation-receive / recovery /
  internal re-store paths degrade to `redact` (a refusal there would diverge
  replicas). Same screen at forensic-bundle egress. Both backends. 5-agent vote
  (`4d3ea1c5`).
- **W2 / gap G30 — erasure fanout / data-remanence on forget.** A hard forget
  (`archive=false`) now erases the derived-store leaks a plain DELETE missed —
  the `federation_push_dlq` cleartext payload + the `transcript_line_dedup`
  content-hash oracle (in-tx, both backends) + the in-RAM HNSW vector (HTTP +
  MCP) — and records a **signed FORGET tombstone** (new schema **v71**
  `forget_tombstones`, both backends) so a peer's LWW re-push of a forgotten
  row is rejected, not resurrected. Cross-mesh tombstone propagation + owner
  authz is the tracked v0.9 federated-erasure layer (#1823). 5-agent vote
  (`4d3ea1c5`).

### Fixed / verified

- **W4 / #1685 — MCP wire-action egress governance gate pinned.**
  `run_mcp_server` already installs `GOVERNANCE_PRE_ACTION` (closed in v0.8.0);
  added `tests/mcp_governance_pre_action_1685.rs` (fresh-`ai-memory mcp`
  subprocess probe) pinning that the `skill_export` egress is refused on the
  MCP surface under a `filesystem_write` rule. #1685 closed with evidence.
- **W5 / #1693 — postgres L2 transcript rehydration parity pinned.**
  `PostgresStore` already overrides `recover_turn_idempotent` and the L2 CLI
  routes `--store-url postgres://` through the SAL path (closed in v0.8.0);
  added `tests/postgres_l2_rehydration_1693.rs` proving sqlite↔postgres
  identical idempotent rehydration against a live instance. #1693 closed with
  evidence.

### Tracking

- **W7 — the 18 UNTRACKED `§26` canonical gaps now have GitHub issues**
  ([#1822](https://github.com/alphaonedev/ai-memory-mcp/issues/1822)–[#1839](https://github.com/alphaonedev/ai-memory-mcp/issues/1839)):
  P1 → milestone `v0.9`, P2 → milestone `v1.0`, all labelled `tract-gap` and
  cross-linked under #1821, so the v0.9.0 epic starts on a clean tracker.

> Remaining in this patch: W6 (subprocess-chain visibility, vote-gated) + the
> §5 operational/dogfood test pass.

## [0.8.0] — 2026-06-25 — `distributed-coordination` (Distributed Coordination Substrate, [#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709))

In progress on `release/v0.8.0`. Schema advances v57 → **v67** (additive: actions /
action_edges / leases at v59, signals at v60, checkpoints at v61, routines /
routine_runs at v62; the `memory_links.relation` closed-taxonomy CHECK extends
6 → 9 relations at v63; the typed-cognition `memories.lifecycle_state` column at
v64; the `memory_links` signature-trigger restore at v65; the
`governance_rules.severity` CHECK extends `refuse`/`warn`/`log` → `+escalate`
for the §22 PE-5 `Decision::Escalate` verdict at v66; the
`memories.target_agent_id_idx` visibility generated column at v67 (#1720 A)). Surface grows to **100 MCP tools** at `--profile full` and
**27 hook lifecycle events** (the tool count is unchanged by the v64 work — the
lifecycle surface adds only permissive optional fields to the existing
`memory_store` / `memory_update` request structs).

### Breaking / secure-default changes

- **[#1794](https://github.com/alphaonedev/ai-memory-mcp/issues/1794) — `ai-memory sync` now CA-validates
  peer server certificates by default (was accept-ANY).** The CLI sync outbound-HTTPS path previously
  used `DangerousAnyServerVerifier` — it accepted ANY peer server certificate, relying solely on the
  peer pinning our mTLS client cert as the compensating control (MITM-able on a hostile network where
  the peer doesn't pin us). It now mirrors the production quorum client (`federation/peer.rs`): the
  **secure default is normal CA validation** against the bundled public webpki roots, with precedence
  `AI_MEMORY_FED_PEER_FINGERPRINTS` pinning (fail-closed for unpinned hosts) > `--insecure-skip-server-verify`
  (the explicit accept-any opt-out, still gated on an mTLS client cert) > a new `--ca-cert <pem>`
  (trust a self-signed / private-CA peer, mirroring `--quorum-ca-cert`) > default CA validation.
  `--insecure-skip-server-verify` and `--ca-cert` are mutually exclusive (clap conflict). **Migration:**
  an existing `ai-memory sync` against a SELF-SIGNED peer over mTLS with no flag will now fail the TLS
  handshake — add `--ca-cert <peer-ca.pem>` (recommended) or `--insecure-skip-server-verify` to restore
  it. Routed through reqwest-native TLS (`use_rustls_tls` + `Identity` + `add_root_certificate`) — zero
  new dependencies. Design resolved by the 5-agent adversarial vote (memory `4d3ea1c5`). Overturns the
  prior #1678 CLI-accept-any posture. Code anchors: `src/tls.rs`, `src/cli/sync.rs`.

- **[#1780](https://github.com/alphaonedev/ai-memory-mcp/issues/1780) — `import` / `mine` no longer
  silently clobber a distinct same-title memory.** Both CLI write paths previously inserted via the
  legacy silent-merge upsert (`ConflictMode::Merge`), so a `(title, namespace)` collision with a
  DISTINCT existing memory silently overwrote it — a data-loss footgun (e.g. two mined conversations
  that truncate to the same 100-char title would clobber each other). **Behavior change:** the new
  `--on-conflict {error|merge|version}` flag governs the collision disposition on both `ai-memory
  import` and `ai-memory mine`, **defaulting to `version`** — a colliding row is auto-suffixed
  (`title (2)`, `title (3)`, …) until a free slot is found, so the import completes losslessly and
  both rows persist (never a clobber). `--on-conflict merge` restores the prior idempotent-upsert
  behavior (re-import a trusted backup without creating suffixed duplicates); `--on-conflict error`
  refuses each colliding row with a typed `CONFLICT` diagnostic, leaves the existing memory untouched,
  and continues the import (the error is collected per-row, never an abort). Root cause also fixed:
  `mine` now populates `source_uri` with `<source-tag>:<conversation-id>` so distinct conversations
  that share a truncated title remain distinguishable by provenance. Wires the existing
  `db::insert_with_conflict(conn, mem, ConflictMode)` primitive. Design fixed by the 5-agent
  adversarial vote (memory `4d3ea1c5`). Code anchor: `src/cli/io.rs`.

- **[#1789](https://github.com/alphaonedev/ai-memory-mcp/issues/1789) — federation now requires peer enrollment by default.**
  `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` flipped its default OFF → **ON** (env-table row #43):
  inbound `/sync/push` and `/sync/since` now refuse an `X-Peer-Id` that has no enrolled Ed25519
  key (and no valid `X-Memory-Sig`) with `401 peer_not_enrolled` — the v0.8 secure default,
  closing the v0.7.0 zero-config unenrolled-peer attribution-spoofing window. **Migration:**
  enroll each peer's Ed25519 key via the operator workflow; OR revert to the v0.7.x permissive
  posture with `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=0` (any falsy value: `0`/`false`/`no`/`off`);
  OR keep accepting unenrolled peers during a rollout window with the now-WIRED escape hatch
  `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1` (env-table row #44 — previously documented but inert,
  wired by this change so the flip is not a hard break with no opt-out). The combined gate is
  `require_peer_enrollment_enabled() && !allow_unenrolled_peers_enabled()` at both
  `/sync/push` and `/sync/since`. Design fixed by the 5-agent adversarial vote (memory `4d3ea1c5`).
  Code anchor: `src/handlers/federation_signing_check.rs`.

- **[#1774](https://github.com/alphaonedev/ai-memory-mcp/issues/1774) — consolidation now requires a
  stored embedding on BOTH sides of a pair.** Consolidation clustering merges a candidate pair only
  when it passes **BOTH** the Jaccard pre-filter **AND** the cosine gate; the cosine gate now requires
  a stored embedding on each side. When either side lacks a stored embedding (keyword-tier /
  never-embedded / oversize-skip rows, no embedder wired, or an embed failure) the pair **no longer
  merges**. This closes a destructive false-positive-merge gap: previously an un-embedded pair could
  merge-and-delete on lexical Jaccard overlap **alone**, bypassing the cosine safety gate — and two
  distinct memories can share high Jaccard (e.g. templated content), so lexical overlap is not a safe
  basis for a destructive op. **Behavior change:** un-embedded / keyword-tier corpora no longer
  auto-consolidate; deployments that want consolidation must run the embedder. This mirrors the
  substrate's skip-on-missing-embedding posture for the other destructive path
  (`proactive_conflict_check` filters `embedding IS NOT NULL`). **No config knob** is added. Affects
  both the autonomy Pass-1 consolidator (`crate::autonomy::find_consolidation_clusters`) and the SAL
  `ConsolidationPass` (`crate::curator::cluster::pair_merges`, `ConsolidationClustering`), kept
  byte-consistent. Design fixed by the 5-agent adversarial vote (memory `4d3ea1c5`). Code anchors:
  `src/curator/cluster.rs`, `src/autonomy.rs`, `src/curator/compaction.rs`.

### Added

- **#1734 (PE-1) — mandatory-hook *presence* enforcement (required-event → fail-closed).**
  Per-hook `FailMode::Open|Closed` already fails closed when a configured hook errors/times out, but an
  **absent or disabled** hook yields an empty `HookChain` whose `fire` returns `Allow` from its terminal
  arm — so an operator relying on a pre-write governance/policy hook got **silently no enforcement** if
  that hook was missing (`FailMode` can never fire on an empty chain). PE-1 closes this presence gap with
  a tri-state mode + an explicit required-event declaration: `AI_MEMORY_HOOKS_ENFORCE_MODE` /
  `[hooks].enforce_mode` (`off`|`advisory`|`enforce`, default `off`, resolver ladder env > config > off,
  mirroring `AI_MEMORY_PERMISSIONS_MODE`) + `[hooks].required_events` (default **empty** — an empty set is
  a hard no-op **even under `enforce`**, the self-DOS guard, since most daemons run zero hooks). The pure,
  unit-tested dispatch-layer helper `hooks::enforce_required_event_presence` (checked **around**, never
  inside, `HookChain::fire`) returns `Deny{code:503}` under `enforce` when a required event has no enabled
  hook (and `effective_fail_mode` forces required-event hooks to `Closed` so a present-but-fail-open hook
  can't defeat enforce); `advisory` WARNs (`hooks.enforce.violation`) + allows. Only pre-* mutation/
  governance events are eligible (`PreStore`/`PreDelete`/`PrePromote`/`PreLink`/`PreConsolidate`/
  `PreGovernanceDecision`/`PreReflect`); an ineligible entry is dropped with a WARN. **Default `off` is
  byte-identical to pre-#1734** (regression-pinned). Discoverability: boot banner (silent when `off`) +
  `ai-memory doctor --hooks` pre-flight ("`PreStore`: REQUIRED but NO enabled hook → WILL DENY"). Design
  resolved by the 5-agent adversarial vote (memory `4d3ea1c5`); explicitly **not** an `EnforceProfile`
  type, a parallel enforce engine, a new `ChainResult` variant, or `RuleEngine` integration. Env-table row
  #83 + `tests/config_precedence.rs` pin. Code anchors: `src/hooks/enforce.rs`, `src/config.rs`
  (`resolve_hooks_enforce_mode`, `resolve_required_events`), `src/cli/doctor.rs`, `src/daemon_runtime.rs`.
- **#1714 (Pillar-1) — MCP `memory_signal_ack` now fires the `PostSignalAck` hook (first MCP hook-event wire-in).**
  The synchronous MCP stdio dispatch held no `HookChain` handle, so no `HookEvent` fired from MCP-driven
  coordination operations. This wires the highest-value POST coordination event — `PostSignalAck` — through
  the existing #1729 `SignalHooks` plumbing to the async hook chain via a best-effort observer
  (`hooks::spawn_post_event_observer`, the runtime-independent sibling of `spawn_eviction_observer`: it owns
  a self-contained current-thread runtime because the MCP loop runs on a `spawn_blocking` thread with no
  entered runtime). **Inert by default:** the bridge sink is installed only when the operator has configured
  a `post_signal_ack` `[[hook]]`; with none configured, dispatch is byte-identical to before (no observer
  thread spawned). **POST-only:** the async observer drains after the op returned, so it cannot carry a
  pre-event's deny/modify — `pre_signal_send` *enforcement* over MCP needs a synchronous in-dispatch chain
  and is tracked as #1752. Coordination observability remains durably available regardless via the
  `signed_events` audit chain (every signal/checkpoint/routine op emits a `coordination.*` row, e.g.
  `coordination_audit::emit(SIGNAL_ACK, …)`, pinned by `send_emits_signed_events_audit_row_1714`); the hook
  bridge adds real-time push to operator-configured subscribers. Decision: 5-agent vote (memory `aa50550b`).
  Code anchors: `src/hooks/chain.rs` (`spawn_post_event_observer`), `src/mcp/mod.rs`
  (`build_mcp_signal_hooks`, `dispatch_memory_signal_ack`, serve-init wiring in `run_mcp_server`).
- **#1464 (P0 security) — agent-attestation v0.8 hardening: deprecation WARN for the permissive store default.**
  Post-#626 Layer-3 follow-up. The federation receive-path forge hole (an enrolled peer claiming
  another agent's authorship → wrong quota/ownership) was **already closed** earlier on this branch
  by the per-memory authorship gate (`resolve_inbound_attribution`, commit `4985ee0e`): an
  unauthorized relayed `metadata.agent_id` claim is rewritten to the sender and stamped
  `attest_level = "claimed"`. This change adds the **store-path secure-default deprecation WARN**:
  when `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` is unset (permissive default) and an unsigned direct
  CLI/MCP/HTTP write lands `claimed`, the substrate warns **once per process** that v0.9 will flip
  the store-path default to require attestation (tracked: #1751), with `store --sign` /
  `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1` as the early opt-in. The WARN is deliberately scoped to
  the **store path** and does not imply it hardens the federation boundary (the receive path attests
  via the peer-authorship allowlist, not this flag). **Honest scoping (5-agent vote, UNANIMOUS
  Option A, memory `45a27602`):** the issue's "thread the synced-write signature through
  `stamp_attestation`" premise was inaccurate — `SyncPushBody.memories` carries no per-memory agent
  signature on the wire, so per-write *cryptographic* attestation of synced memories (upgrade
  `claimed→agent_attested`) needs a federation wire-protocol extension and is tracked under Pillar-3
  CRDT #1719 (item-3: thread attestation into `merge_inbound`); the v0.8.0 default-flip was
  deferred to v0.9 (#1751) because flipping now would `403` every unsigned writer with no migration
  path while curator/autonomy self-writes bypass the gate entirely. Code anchors:
  `src/identity/attest.rs` (`should_warn_permissive_default`, `warn_permissive_attestation_default_once`),
  `docs/SECURITY.md` threat-model item 3.
- **#1750 (Pillar-2.5) — `cosine_threshold` is now live config; size-GC eviction gated on `enabled`.**
  Closes the two `CompactionConfig` knob hazards the #1749 5-agent vote (`1817bc8f`) scoped out.
  (1) **`cosine_threshold` was dead config** — `ConsolidationClustering::new()` hardcoded the 0.75
  default and `CompactionConfig.cosine_threshold` had no consumer (#1691-class). It is now threaded
  into the live clusterer via `ConsolidationPass::with_cosine_threshold` at both production sites
  (`cli/curator.rs` store-backed sweep + `curator/mod.rs::run_consolidation_pass`) and exposed via
  `[curator.compaction].cosine_threshold` + `AppConfig::resolve_compaction_cosine_threshold()`
  (env `AI_MEMORY_COMPACTION_COSINE_THRESHOLD` > config > `0.75`; a parseable `f32` in `(0.0, 1.0]`
  wins, out-of-range/unparseable falls through). (2) **`max_corpus_bytes` size-GC was a decoupled
  hard-delete trigger** — `run_size_gc_pass` gated only on `max_corpus_bytes.is_some() && !dry_run`,
  NOT on `enabled`. It now additionally requires `compaction.enabled` (defensive: `max_corpus_bytes`
  stays out of operator config this slice, so size-GC remains inert in production until explicitly
  exposed). Per the #1750 5-agent vote (`a9b2fe09`, 3-A/2-B), when `max_corpus_bytes` is eventually
  exposed it gets its own dedicated `[curator.size_gc]` switch rather than riding under
  `[curator.compaction]`. Tests: cosine resolver unit + precedence (`tests/config_precedence.rs`) +
  size-GC `cap-without-enabled` no-op test; the 3 existing size-GC tests now set `enabled: true`.
  Env-table rows #81 (updated) / #82. **Deferred to #1488 4.D:** reconciling the `CapabilityCompaction`
  "planned" marker to reflect runtime compaction state needs `AppConfig` threaded through the
  capabilities overlay chain (an envelope change) — tracked there, not in this slice. Code anchors:
  `src/curator/compaction.rs`, `src/curator/mod.rs`, `src/cli/curator.rs`, `src/config.rs`.
- **#1748 (Pillar-2.5 slice-3c2) — store-backed (postgres) `curator --rollback` reversal.**
  `ai-memory curator --rollback <id>` / `--rollback-last N` now reverses consolidations the
  store-backed (postgres) curator wrote (slice-3c1, #1747). Previously the reversal was
  rusqlite-bound (`autonomy::reverse_rollback_entry` over a `Connection`) and the `--rollback`
  arm dispatched **before** the `--store-url` branch, so `--rollback --store-url postgres://…`
  silently no-op'd on the local SQLite file — an irreversible hard-DELETE behind a
  reversible-looking API. Added `autonomy::reverse_rollback_entry_store`, a backend-agnostic
  free async fn over the `MemoryStore` trait (`find_by_title_namespace` collision-guard →
  reinsert originals → delete summary), and a `run_store_backed_rollback` CLI path dispatched on
  `--store-url` (mirroring `run_store_backed_sweep`). Covers all three `RollbackEntry` variants
  (Consolidate / Forget / PriorityAdjust). The slice-3c1 runtime WARN is removed now that
  reversal works on postgres. Guardrails (from the 5-agent vote `4d3ea1c5` → Option B, memory
  `ed85b972`): a `(title,namespace)` collision guard refuses to clobber a different occupant
  (the trait `store` is an UPSERT); originals are reinserted **before** the summary is deleted
  (fail-safe ordering). **Atomicity:** the SAL `begin_transaction` is postgres-internal only
  (SQLite returns `UnsupportedCapability`), so the free fn cannot wrap the multi-write in one
  transaction — the non-atomic window is exact parity with the rusqlite path (also non-atomic),
  minimised by the reinsert-before-delete ordering. Tests: deterministic `SqliteStore` round-trip
  + collision-abort unit tests (`src/autonomy.rs`) and a gated `sal-postgres` round-trip
  (`tests/cov_postgres_core.rs`, the postgres twin of the SQLite
  `reverse_consolidation_restores_originals`). Code anchors: `src/autonomy.rs`
  (`reverse_rollback_entry_store`), `src/cli/curator.rs` (`run_store_backed_rollback`, dispatch in
  `run`, WARN removed from `store_backed_consolidation_sweep`).
- **#1749 (Pillar-2.5 activation) — `[curator.compaction].enabled` is now operator-configurable.**
  The curator's Pillar-2.5 consolidation gate (`CompactionConfig.enabled`) was hardcoded
  `default()` (false) at every production build site, leaving the whole shipped consolidation
  pillar (3b1/3b2a/3b2b/3c1) dormant. It now resolves from operator config via
  `AppConfig::resolve_compaction_enabled()` — ladder `AI_MEMORY_COMPACTION_ENABLED` env >
  `[curator.compaction].enabled` > compiled `false` — threaded into `CuratorConfig.compaction`
  at every site (`cli/curator.rs` `run` + `run_store_backed_sweep`, and
  `daemon_runtime.rs::run_curator_daemon_with_primitives` via a primitive param resolved by its
  caller). Default stays **false (opt-in)**; enabling makes the SAL `ConsolidationPass` the live
  consolidator (hard-DELETE merge of near-duplicates, suppressing autonomy Pass-1). Strengthens
  the Pillar-2.5 §2.4 *improvable* property by making the pipeline reachable. **Reversibility:**
  consolidations are operator-reversible via `curator --rollback` on **sqlite** (#1745) **and
  postgres** (the SAL-port landed in #1748; the earlier runtime WARN is gone). Scoped to
  `enabled` only this slice — the clustering `cosine_threshold`
  (currently unwired into the pass) and the size-GC `max_corpus_bytes` (an independent eviction
  trigger) are intentionally left at defaults and tracked as a follow-up, per the 5-agent crossroads
  vote (memory `4d3ea1c5`). Tests: resolver precedence (`tests/config_precedence.rs`) + config-field
  resolution + build-site coverage. Env-table row #81. Code anchors: `src/config.rs`
  (`resolve_compaction_enabled`, `CuratorCompactionSection`, `ENV_COMPACTION_ENABLED`),
  `src/cli/curator.rs` (`curator_compaction_config`), `src/daemon_runtime.rs`.
- **#1747 (Pillar-2.5 slice-3c1) — consolidation on the store-backed (postgres) curator tick.**
  The SAL `ConsolidationPass` now runs on the postgres / `--store-url` curator path
  (`cli/curator.rs::store_backed_consolidation_sweep`), the backend-agnostic twin of the
  reflection sweep, called from both the `--once` and `--daemon` arms **before** reflection
  (dedup, then reflect over survivors — avoids dangling `reflects_on` edges). It iterates
  non-reserved namespaces via `MemoryStore::list_namespaces`, re-applies the same
  `needs_curation` filter + `max_ops_per_cycle` cap the sqlite path uses, and runs the pass
  real (respecting `dry_run`); a missing LLM folds into the report rather than aborting the
  daemon. Gated on `compaction.enabled` (default false → no-op). Strengthens the Pillar-2.5
  §2.4 *improvable* property to backend parity (consolidation no longer sqlite-only). Tests:
  always-on `SqliteStore` sweep tests (enabled-folds / disabled-noop / no-LLM) + a gated
  `sal-postgres` `consolidate` integration test (closes the cov_postgres_core hole). Gated by
  the 5-agent crossroads vote (memory `4d3ea1c5`). **Caveat (tracked as #1748):** on postgres,
  the operator-reversible rollback rows the pass writes are NOT yet reachable by
  `ai-memory curator --rollback` (that path is rusqlite-bound) — a runtime WARN is emitted and
  the SAL-port is slice-3c2. **Note:** `compaction.enabled` is not yet operator-configurable
  (hardcoded default at all CLI/daemon call sites) — the config wire-up that activates
  Pillar-2.5 consolidation in production is tracked separately. Code anchors:
  `src/cli/curator.rs`, `src/curator/candidates.rs` (`needs_curation` → `pub(crate)`).
- **#1746 (Pillar-2.5 slice-3b2b) — SAL `ConsolidationPass` is the live consolidator (cutover).**
  When `[curator].compaction.enabled` (default `false` → byte-unchanged), `curator::run_once`
  now makes the backend-agnostic SAL `ConsolidationPass` the live memory-consolidator and
  suppresses the legacy `autonomy::run_autonomy_passes` Pass-1 (forget-superseded + priority
  feedback still run). Both are driven from a **single** `compaction.enabled` predicate so they
  can never double-consolidate or zero-consolidate. The SAL pass's counts fold into the cycle's
  `report.autonomy.{clusters_formed,memories_consolidated,rollback_entries_written}` so the
  `_curator/reports` self-report stays accurate, with SAL-specific
  `compaction_pass_{clusters_eligible,rolled_back}` surfaced on `CuratorReport`. Strengthens the
  Pillar-2.5 §2.4 *improvable* property (consolidation routes through the unified, backend-agnostic
  SAL path) while preserving §2.3 *stoppable*/reversible: consolidations remain operator-reversible
  via `curator --rollback` (rollback parity landed in #1745) and the consolidated row's `source`
  label is held byte-stable across the cutover. Gated by the mandatory 5-agent crossroads vote
  (memory `4d3ea1c5`), which re-sequenced the work (#1745 rollback-parity prerequisite first) and
  confirmed clustering membership parity via a new equivalence test. Code anchors:
  `src/curator/mod.rs` (`run_once`, `run_consolidation_pass`),
  `src/autonomy.rs::run_autonomy_passes` (`skip_consolidation`),
  `src/curator/compaction.rs::ConsolidationPass`. Prereqs: #1741 (clustering parity), #1743
  (stored-embedding source parity), #1745 (rollback parity). Postgres-curator consolidation
  parity is tracked as the follow-on slice-3c.
- **#1735 (Pillar-4 4.C) — staggered AGE cold-path for postgres link writes (opt-in).**
  `AI_MEMORY_AGE_PROJECTION_MODE=deferred` (default `sync` = byte-identical) takes the
  ~6 synchronous Apache-AGE Cypher round-trips (`LOAD age`, `create_graph`, node+edge
  `MERGE`) off the link-write hot path. Under `deferred`, `PostgresStore::link_internal`
  enqueues a `kg_projection_outbox` row (schema **v69**) in the **same transaction** as the
  relational `memory_links` INSERT instead of the inline MERGE; a supervised cold drainer
  (`drain_kg_projection_outbox` + `spawn_drainer`, drain-once boot-recovery + interval loop)
  projects pending rows into `memory_graph` out-of-band, with bounded retry → quarantine
  (`MAX_AGE_PROJECTION_ATTEMPTS=100`) mirroring the federation push-DLQ. Postgres `find_paths`
  routes through the always-current relational recursive-CTE under `deferred` so reads stay
  read-your-own-write correct during the projection window (`kg_query`/`kg_timeline` observe a
  bounded staleness window until the drainer catches up). New metrics
  `ai_memory_age_projection_{pending_depth,failed_total,quarantined_total}`. Postgres-only
  (AGE is postgres-only); SQLite stamps v69 as a no-op. Mechanism resolved by the mandatory
  5-agent crossroads vote (memory 4d3ea1c5); the transactional-outbox + supervised-drainer +
  CTE-fallback design composes the existing push-DLQ and deferred-audit precedents.
- **#1733 (Pillar-4 4.A) — HTTP admission control (in-flight-request load-shedding).**
  The axum daemon can now bound concurrent in-flight requests: when
  `AI_MEMORY_MAX_INFLIGHT_REQUESTS` (or `[limits].max_inflight_requests`) is a positive
  `n`, the daemon admits at most `n` concurrent requests and sheds the rest with a typed
  `503` (`{"error":"server_overloaded","code":"OVERLOADED","max_inflight":n}` +
  `Retry-After: 1`) instead of degrading or OOMing under a thundering herd. Implemented as a
  custom `Arc<Semaphore>` + `try_acquire_owned` middleware (mirrors the existing 504-timeout
  layer; no new tower features), applied OUTERMOST so rejection precedes the timeout future /
  body decode / handler work, with the permit RAII-released on every exit path. `/health`,
  `/metrics`, `/api/v1/metrics` are EXEMPT so liveness/readiness probes + Prometheus scrapes
  survive overload (an unexempted cap would let the orchestrator kill an overloaded node,
  amplifying the outage). **Opt-in** — unset / `0` / garbage leaves the layer uncomposed
  (concurrency behaviour byte-identical to before). Shed events increment the
  `ai_memory_admission_shed_total` Prometheus counter + a sampled WARN. Resolver ladder
  `env > [limits] > compiled default 0`; seeded at boot via `crate::set_max_inflight_requests`.
  Mechanism + posture resolved by the mandatory 5-agent crossroads vote (memory 4d3ea1c5).
  Behavioural tests (`src/lib.rs::admission_control_1733_tests`: over-cap shed + typed-503
  wire shape, `/health` exempt, cap=0 disabled) + precedence pin (`tests/config_precedence.rs`).
- **#1720 A — owner-keyed `scope=private` visibility (cross-tenant leak closed, both adapters).**
  The three divergent `scope=private` read predicates (recall / search / list) are collapsed
  onto ONE owner-keyed canonical check: a private row is visible to a caller iff
  `metadata.agent_id == caller` OR `metadata.target_agent_id == caller` (the inbox carve-out),
  NOT namespace-keyed. Closes a confirmed cross-tenant private-memory leak on the recall + search
  paths. sqlite enforces it via `storage::visibility_clause` (`src/storage/mod.rs`) +
  the `scope_idx` / `agent_id_idx` / `target_agent_id_idx` generated columns (schema v67);
  the postgres predicates are owner-keyed to match. The canonical owner check is
  `crate::visibility::is_visible_to_caller` (`src/visibility.rs`). Admin / curator
  `bypass_visibility` trusts-all on recall + search (A7). Leak + bypass regression tests on
  both backends (`tests/visibility_private_leak_1720.rs`,
  `tests/sqlite_admin_bypass_visibility_a7_1720.rs`).
- **#1720 B — durable agent identity + safe enforced-multi-agent opt-in.**
  B1: the `resolve_agent_id` owner-stamp fallbacks (MCP `clientInfo` + host) are now pid-free +
  durable (`ai:<client>@<host>`, `host:<host>`) so ownership survives process restarts (the Op-0
  posture; `process_discriminator()` still backs only the ephemeral `anonymous:` principals).
  B2: the new `ai-memory reown` CLI rewrites `metadata.agent_id` across a namespace
  (`--dry-run` / `--claim-unowned`, both adapters). B3: a boot-time owner-lockout guard
  (`storage::lockout::count_private_rows_hidden_from` + `identity::enforce_owner_lockout_guard`)
  WARNs — or refuses under `AI_MEMORY_REQUIRE_OWNED_ROWS` — when `AI_MEMORY_AGENT_ID` is set but
  pre-existing private rows are owned by a different / pid-suffixed / unowned id, naming
  `ai-memory reown` as the fix.
- **#1720 D — curator reflections stamped explicit `collective` scope.**
  Curator-written reflections (`ReflectionPass::summarize`) now carry an explicit `collective`
  scope instead of the accidental default-private-owned-by-curator (which leaked under trust-all
  and went operator-invisible under enforcement); the owner stays the curator for attribution.
  The read posture (D1) is decided + documented: the curator keeps its `bypass_visibility` read
  for substrate maintenance under the single-operator default.
- **#1720 C — per-namespace `required_scope` (refuse-only) governance knob, both adapters + SDK parity.**
  A new `CorePolicy.required_scope: Option<MemoryScope>` knob (rides in the existing
  `metadata.governance` blob; no schema migration). When a namespace standard pins it, a
  `Store` whose effective scope (`metadata.scope`; absent ⇒ `private`) does not match is
  REFUSED at the CorePolicy governance gate — fail-closed, refuse-only (the gate never
  coerces the write). Enforced on BOTH backends (sqlite `storage::enforce_governance` +
  postgres `PostgresStore::enforce_governance_action`), honoring the existing
  Advisory(warn-only)/Enforce(block) `permissions.mode` handling. Python SDK
  `GovernancePolicy` gains `required_scope: str | None`.
- **§22 Policy-Engine V08-PE-5 — `Decision::Escalate` governance verdict primitive**
  ([#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709),
  epic [#697](https://github.com/alphaonedev/ai-memory-mcp/issues/697)).
  A new severity-based human-escalation verdict, produced by a new `escalate`
  rule severity. The agent-action engine (`src/governance/agent_action.rs`)
  gains `Severity::Escalate` (wire string `"escalate"`) and
  `Decision::Escalate { rule_id, reason }` (serde
  `{"decision":"escalate", rule_id, reason}`); a matched `escalate` rule
  returns it (escalation terminal arm, mirroring refusal-wins). **Fails
  closed:** `Decision::is_allowed()` is restructured to an explicit
  `Allow | Warn` allow-list (NOT `!is_refusal()`) so an unresolved Escalate
  does NOT permit the action; new `is_blocking()` (`Refuse | Escalate`) +
  `is_escalation()` predicates are added, and the two L1-6 governance
  pre-write hook sites (storage pre-write + wire_check) gained an Escalate
  arm that blocks the action (`Err`) and chain-logs it via the deferred
  audit queue (which now gates on `is_blocking`). Schema **v66** extends the
  sqlite `governance_rules.severity` CHECK (`refuse`/`warn`/`log` →
  `+escalate`) via a full-table rebuild that preserves every signed-rule row
  + column + both indexes; postgres ships no `governance_rules` table so its
  v66 arm is a version-stamp no-op (literal 66). **No MCP tool-count change.**
  `// #697 PE-5 follow-on:` the escalation QUEUE persistence + timeout-sweep
  + the PE-5 profile auto-install (PE-1+PE-3+PE-4) are NOT in this primitive —
  they are the next PE-5 unit.
- **§22 Policy-Engine V08-PE-8 — `ai-memory verify-audit-trail` CLI**
  ([#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709),
  epic [#697](https://github.com/alphaonedev/ai-memory-mcp/issues/697)).
  New CLI `ai-memory verify-audit-trail [--since <ts>] [--json]` walks the
  append-only `signed_events` V-4 cross-row hash chain end-to-end (reusing
  `signed_events::verify_chain` — no reimplemented crypto), inventories any
  monotonic-`sequence` gaps, and reports an `AuditTrailReport`
  (`total_events` / `chain_intact` / `first_break_sequence` /
  `sequence_gaps` / `head_sequence`). `--since` is timestamp-scoped and
  boundary-correct (the first in-window row's `prev_hash` is checked
  against its real out-of-window predecessor, never a false break). Exits
  non-zero on any break or gap (CI-scriptable). §2.5 attested / §2.3
  stoppable. CLI subcommand count 80→81 (82→83 sal).
- **Pillar-2.5 compaction — size-GC (corpus byte-cap eviction)**
  ([#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709)). The
  curator now evicts under byte pressure: when a namespace's live corpus
  (`SUM(length(title)+length(content)+length(metadata))` over its
  non-archived rows — the same byte metric the K8 write quota uses) exceeds
  a configured cap, the lowest-value memories are evicted (archived-before-
  deleted, so **restorable**) one at a time until the corpus is back under
  cap. Eviction order is a pure, deterministic SQL ranking — least-durable
  tier first (`short` → `mid` → `long`), then `priority` / `access_count` /
  `last_accessed_at` ascending — so a high-priority, frequently-accessed,
  long-tier row is evicted last, only if still over cap. **No LLM on the
  eviction path.** Surface: the `crate::storage::size_gc` free-fn, the
  `MemoryStore::size_gc` SAL trait method on BOTH the sqlite (delegate) and
  postgres (sqlx-native, per-victim transactional archive+delete mirroring
  `run_gc`'s #1026 atomicity) adapters, the new `CompactionConfig.max_corpus_bytes`
  config knob (`Option<i64>`, default `None` = disabled, opt-in via
  `[curator.compaction]`), and the curator `run_once` wiring (gated on
  `compaction.max_corpus_bytes.is_some()` && `!dry_run`; best-effort
  per-namespace, errors land in `report.errors`) with the new
  `CuratorReport.memories_evicted_size_gc` counter. **No schema change**
  (reuses the existing `memories` / `archived_memories` columns + the
  archive-before-delete path) and **no MCP tool-count change**. Victims
  carry `archive_reason = 'size_gc'`, distinct from TTL-GC's `'ttl_expired'`.
- **Pillar-1 coordination substrate** — typed actions with a state machine +
  typed DAG edges + single-holder heartbeat leases + an hourly lease-sweeper
  (`crate::actions`, `MemoryStore::{action_*,lease_*}`, 8 MCP tools); signed
  signals (`crate::signals`, Ed25519 over canonical content, 5 MCP tools +
  `pre_signal_send`/`post_signal_ack` hook events — now load-bearing, see
  below); attested checkpoints
  (`crate::checkpoints`, Ed25519-attested resolution = separation-of-duties,
  4 MCP tools). All on both the sqlite and postgres SAL adapters.
- **Pillar-1 signal coordination hooks wired** ([#1729](https://github.com/alphaonedev/ai-memory-mcp/issues/1729), the last
  Pillar-1 residual). `HookEvent::PreSignalSend` / `PostSignalAck` shipped at
  v0.8.0-dev declared + classified but had **zero fire sites**, the
  `SignalDelta`/`SignalAck` payloads were undefined, and the signal handlers
  never invoked any hook. Now: `SignalDelta` (writable; `from_agent`/`id`
  provenance-immutable) + `SignalAck` (read-only) are defined
  (`src/hooks/events.rs`); `handle_signal_send_with_hooks` fires `PreSignalSend`
  **before signing** (so a `Modify` rewrite is reflected in the
  Ed25519-signed bytes) honoring `Allow`/`Modify`/`Deny`/`AskUser`
  (`AskUser` is fail-closed on the sync MCP path); `handle_signal_ack_with_hooks`
  fires `PostSignalAck` (notify-only) after the ack stamp commits. Wired via an
  in-substrate sync-callback bundle `SignalHooks` (mirroring the `ReflectHooks`
  precedent — the handlers are synchronous and run on the MCP stdio loop's
  `spawn_blocking` thread with no tokio runtime, so the async wire-level
  `HookChain` cannot be `.await`-ed there; the daemon-side chain bridge is the
  separate [#1714](https://github.com/alphaonedev/ai-memory-mcp/issues/1714) gap). Thin `handle_signal_send`/`handle_signal_ack`
  shims preserve the pre-#1729 signatures (zero caller churn). MCP-only surface
  (no HTTP/CLI signal route). Tests pin Deny-refuses-insert, Modify-rewrites-
  and-persists, AskUser-fail-closed, and post-fires-once (no re-fire on a no-op
  re-ack).
- **Engine-level read-action gating** ([#1730](https://github.com/alphaonedev/ai-memory-mcp/issues/1730),
  PE-2 / §5.5 / #697 Phase-6). Memory reads were never governance-evaluated or
  audited — only writes / wire-actions were, so a confidentiality rule could not
  deny a read. New `AgentAction::Read { surface, namespace?, query? }` variant +
  `read_action` wire kind + a `match_read` matcher (`surface` / `namespace`
  globs + `query_substring`; an explicit `{"all":true}` blanket; an empty matcher
  matches nothing, so an operator typo can't lock out every read). A shared
  `gate_read` / `gate_read_surface` helper is wired into all five MCP read
  surfaces — `recall` / `search` / `list` / `get` / `session_start` — so a
  matched `refuse` / `escalate` rule denies the read with the standard
  governance-refusal wire shape and the decision lands in `signed_events`
  alongside writes. Design via the deterministic **5-agent vote (4d3ea1c5)**
  (tripped T1 new public variant + T3 new gate): (a) **zero-config fast-path** —
  with no enabled `read_action` rules the gate returns immediately (no eval, no
  audit), keeping the recall hot path free (a per-read `signed_events` INSERT
  would turn every read into a serialized WAL write); (b) **best-effort,
  non-fatal audit** — an append failure logs and the read proceeds (read
  availability is never coupled to audit-sink liveness); (c) **fail-CLOSED** on a
  matched `refuse`/`escalate` verdict AND on a rule-load error, honoring
  `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` (the same knob the write pre-hook
  uses). **Scope:** sqlite-MCP-only — `governance_rules` + `check_agent_action`
  are `rusqlite::Connection`-bound (same posture as signals/actions) and the MCP
  stdio path is sqlite-only (#1675); HTTP/postgres reads route through the SAL
  `app.store` (no raw Connection) and are out of scope for this gate. Tests: 8
  `gate_read` unit tests (refuse / escalate-blocks / warn-allows / fast-path /
  surface-narrow / namespace-narrow / empty-matcher-no-blanket / audit-row) + 2
  parity tests (every read surface gated; fast-path passes with no rules).
- **Crash-durable deferred-audit queue** ([#1732](https://github.com/alphaonedev/ai-memory-mcp/issues/1732),
  PE-4 / §5.6 / #697 Phase-6). The deferred-audit queue was an in-memory
  `mpsc`: a SIGKILL before the supervised drainer processed a submitted
  governance refusal LOST it (`signed_events_dlq` only covers an append
  FAILURE after the drainer has the event, not the pre-drain window). Added
  a `DeferredAuditJournal` — an fsync-per-record crash spool
  (`<db>.deferred-audit.journal`, mode 0600; frame =
  `[u32-LE len][canonical_bytes][32-byte sha256]`). `DeferredAuditQueue::submit`
  now durably journals each refusal BEFORE the mpsc send, and
  `recover_deferred_audit` replays un-drained records into `signed_events`
  at boot. New records have stable occurrence IDs and one bounded spool file
  per pending occurrence, acknowledged after durable chain/DLQ residence;
  legacy stream records retain cardinality-aware recovery. Design via the deterministic **5-agent vote
  (4d3ea1c5)** (tripped T4 on-disk format): a journal **file** was chosen
  over a sqlite pending-table because `submit` fires inside `storage::insert`
  holding the substrate's `BEGIN IMMEDIATE` write lock — a second connection
  writing the same DB would self-deadlock; a raw file append touches no
  `Connection`. Replay is **idempotent and content-bound** on occurrence ID so a crash between the
  pre-crash drainer's append and the SIGKILL never double-appends the hash
  chain; a short trailing legacy write is ignored while a complete hash or
  decode failure aborts recovery without deleting evidence. Boot recovery is **replay-all-then-go-live**,
  wired into BOTH the `serve` and `mcp` boot paths (the MCP stdio path has no
  shutdown drain, so durability + boot recovery is its only safety net).
  Tests pin crash-recovery, torn-record-discard, and idempotent-replay.
- **Pillar-2 typed-cognition link relations** — the closed
  `memory_links.relation` CHECK taxonomy extends 6 → 9 with `decomposes_into`
  (parent → child structural: a Goal decomposes_into Plans, a Plan
  decomposes_into Steps), `depends_on` (sibling ordering / prerequisite: a Step
  depends_on another Step), and `advances` (child → ancestor progress: a Step
  advances a Plan/Goal) so the Goal/Plan/Step `MemoryKind` vocabulary can be
  wired into a typed plan graph. Schema v63 on both adapters (sqlite
  full-table-rebuild migration `0053`, postgres `migrate_v63` CHECK-extend);
  `MemoryLinkRelation` + `validate::VALID_RELATIONS` carry the matching set.
- **Pillar-2 promote-as-typed-state-machine** — a first-class
  `memories.lifecycle_state` column (schema v64, additive
  `TEXT NOT NULL DEFAULT 'open'` on both adapters; the `archived_memories`
  mirror keeps archive → restore lossless) that makes the already-shipped
  Goal/Plan/Step `MemoryKind`s load-bearing. The `models::LifecycleState`
  enum (`open` → `active` → `blocked`/`done`/`abandoned`; `done`/`abandoned`
  terminal) provides a proven transition machine
  (`LifecycleState::can_transition_to`, mirroring `ActionState`). The
  `Memory` struct grows to **27 fields** (the 27th is `lifecycle_state`,
  `#[serde(default)]` → `Open` for legacy rows). The column is load-bearing,
  not inert: `memory_store` accepts an optional initial `lifecycle_state`
  (validated), and a `lifecycle_state` transition target is enforced against
  the stored state (`current.can_transition_to(new)`) across **all three
  surfaces** — MCP `memory_update`, HTTP `PUT /api/v1/memories/{id}`, and the
  SAL `MemoryStore::update` path (via `UpdatePatch.lifecycle_state`) — on
  **both backends**. The gate is centralised in the storage primitive
  (#1726): sqlite `storage::set_lifecycle_state` and its postgres twin
  `PostgresStore::apply_lifecycle_patch` SELECT the current state and reject
  an illegal edge (e.g. `open → done`, or any move out of a terminal) with a
  typed `InvalidTransition` → HTTP **409 CONFLICT** (byte-parity error detail
  on both adapters); a legal edge persists and bumps the optimistic-
  concurrency `version`, and a request equal to the stored state is an
  idempotent no-op. No new MCP tool and no tool-count change (the additions
  are permissive optional fields on the existing store / update request
  structs). Schema v64 on both adapters (sqlite probe-then-add ALTER,
  postgres `migrate_v64` stamping the literal 64 for crash-safety).
- **§2.5 attested — read-time attested-provenance surfacing**
  ([#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709), reframed
  from #1715). `memory_recall` now composes provenance at read from already-merged
  signed evidence rather than treating the stored confidence scalar as truth.
  Anchors: `src/mcp/tools/recall.rs::decorate_memory_many` (batched O(1)
  link-attestation prefetch — was O(K) per-row `get_links`),
  `recall.rs::provenance_tier` (composes `confidence_source` + the
  `recall.rs::attest_rank` ladder → `signed_peer` > `curator_derived` >
  `self_signed` > `unsigned_caller`), `recall.rs::insert_confidence_filter_meta`
  (non-silent `confidence_tier` filter → `meta.confidence_filtered_out` +
  `meta.had_filtered_candidates`), `recall.rs::scheduled_validity` (deterministic
  recompute from the `Memory::effective_expires_at` anchor, quantized to a
  `SECS_PER_HOUR` as-of bucket, under `AI_MEMORY_CONFIDENCE_DECAY`), and
  `session_start` routed through `decorate_memory_many` for uniform decoration
  across MCP / HTTP / session_start. All composition is **decoration-only**: the
  stored `m.confidence` ranking term (`src/storage/mod.rs` recall `ORDER BY`) is
  untouched, no read-path DB round-trip is added, no LLM runs on the read path,
  and the recall determinism invariant (`tests/bias_displacement_invariants_2_6.rs`,
  id-ranking byte-equality) holds.
- **§11.4.C — vLLM first-class backend alias**
  ([#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709); reconciles
  doc-drift defect [#1677](https://github.com/alphaonedev/ai-memory-mcp/issues/1677)).
  `AI_MEMORY_LLM_BACKEND=vllm` (and the embeddings sibling
  `AI_MEMORY_EMBED_BACKEND=vllm`) are now a dedicated alias that pre-fills the
  OpenAI-compatible base URL to `http://localhost:8000/v1` (vLLM's default
  `--port 8000` + `/v1` route mount), instead of requiring the generic
  `openai-compatible` backend plus an explicit `AI_MEMORY_LLM_BASE_URL`.
  Keyless by default like `lmstudio` — a Bearer token may still be supplied via
  `AI_MEMORY_LLM_API_KEY` for a secured deployment. Anchors:
  `src/llm.rs::BACKEND_VLLM` (the 16th vendor alias), the
  `src/llm.rs::default_base_url_for_alias` + `src/llm.rs::alias_api_key_env_vars`
  arms, the `doctor` "Valid values:" enumeration, and the embed surface for free
  via `src/config.rs::resolve_embeddings` → `is_api_embed_backend` (everything
  but `ollama`) → the shared `default_base_url_for_alias`. Pins:
  `default_base_url_for_alias_covers_all_16_aliases_1067`,
  `alias_api_key_env_vars_per_alias_pins_1067`,
  `resolve_embeddings_1709_vllm_alias_default_base_url`. The in-process
  candle/mistralrs GPU backend remains v0.8.x-deferred per ROADMAP §11.4.C (the
  `src/inference/mod.rs::GpuBackend` phase labels are corrected here to say so —
  #1677). **No schema change. No MCP tool-count change.**
- **#1722 — coordination-substrate `signed_events` audit observability (full Pillar-1 coverage).**
  Every coordination state-mutation (signal send/ack, action create/transition/add_edge, lease
  acquire/renew/release, checkpoint create/resolve, routine create/freeze/run) appends a
  tamper-evident `coordination.<op>` row to the append-only `signed_events` V-4 chain through one
  shared best-effort writer (`crate::coordination_audit::emit`, 13 event-type slugs SSOT). Emitted
  AFTER the op commits (append failure WARN-logged, never fails the op); payload hash commits to
  the op's identity; daemon-signed when an audit key is installed. Per-handler actor attribution
  (success-arm only). Commits a6f94854, 934989ca.
- **#1670 — `SqliteStore::capabilities()` advertises `ATOMIC_MULTI_WRITE`.** Wire-honesty fix
  (#302 item 6 / #1052 family): the bit is genuinely held — `reflect` / `consolidate` / bulk-insert
  run as a single `BEGIN IMMEDIATE … COMMIT` atom with ROLLBACK on mid-failure. `TRANSACTIONS`
  stays withheld (the SAL adapter exposes no caller-facing `begin_transaction` handle). At parity
  with `PostgresStore` on `ATOMIC_MULTI_WRITE`. Capability-bit↔runtime cross-check test. Commit 14cdd6ce.

### Fixed

- **[#1793](https://github.com/alphaonedev/ai-memory-mcp/issues/1793) — PostgresStore Human-arm approval
  now refuses self-approval + unregistered approvers (HTTP-path parity with #1787).** The
  `ApproverType::Human` arm of `PostgresStore::governance_approve_with_consensus` (the DEFAULT approver
  type) accepted ANY `approver_agent_id` with no requester≠approver check and no registration check, so
  on the HTTP/postgres approval surface the REQUESTER of a Human-gated pending action could self-approve
  it, defeating human-in-the-loop (the Consensus arm was already hardened per #216; the Human arm was
  not). The fix UNCONDITIONALLY (a) refuses `approver == pa.requested_by` (`SELF_APPROVAL_REFUSED`) and
  (b) requires the approver to be a registered agent (mirroring the Consensus arm). Unlike the sqlite
  #1787 fix this is NOT opt-in-keyed: the 5-agent adversarial vote (memory `4d3ea1c5`) established that
  the postgres SAL is reachable only via the inherently multi-tenant HTTP daemon (MCP stdio is
  sqlite-only), where the process-wide `AI_MEMORY_AGENT_ID` the sqlite opt-in keys on is unset (so an
  opt-in gate would never fire) and the per-request `X-Agent-Id` approver is a distinct authenticated
  identity — there is no single-operator self-lock to avoid. No schema change. Code anchor:
  `src/store/postgres.rs`. (Sibling finding: the sqlite-*backed* HTTP daemon has the analogous
  opt-in-off-on-HTTP gap — tracked separately as #1796.)

- **[#1796](https://github.com/alphaonedev/ai-memory-mcp/issues/1796) — the sqlite-backed HTTP daemon
  now refuses Human-arm self-approval + unregistered approvers (sqlite-side sibling of #1793).** On a
  sqlite-backed `ai-memory serve` (the default without `--store-url postgres://`) the `ApproverType::Human`
  self-approval reject + registered-approver gate added by #1787 to `db::approve_with_approver_type` was
  opt-in-keyed on `resolve_read_visibility_caller().is_some()` (the process `AI_MEMORY_AGENT_ID`). The
  multi-tenant HTTP daemon uses per-request `X-Agent-Id` and sets no process `AI_MEMORY_AGENT_ID`, so the
  gate NEVER fired there and a requester could self-approve their own Human-gated pending action — the
  same human-in-the-loop bypass #1793 closed for postgres. The 5-agent adversarial vote (memory
  `4d3ea1c5`, decision memory `7016624d`) resolved the mechanism: a new `pub enum ApproveSurface { Http,
  LocalOperator }` (no `Default`) is threaded into `db::approve_with_approver_type`, keeping enforcement
  canonical in the storage fn. The `Http` surface (both HTTP approve handlers + the SAL trait delegates,
  for parity with the postgres trait impl) enforces UNCONDITIONALLY; the `LocalOperator` surface (MCP/stdio
  + CLI single-operator) keeps the `AI_MEMORY_AGENT_ID` opt-in so the lone operator is never self-locked
  out of approving their own action. No schema change. Code anchors: `src/storage/mod.rs`,
  `src/handlers/{governance,approvals}.rs`, `src/store/sqlite.rs`, `src/mcp/tools/pending.rs`,
  `src/cli/agents.rs`.

- **[#1795](https://github.com/alphaonedev/ai-memory-mcp/issues/1795) — PostgresStore now ENFORCES the
  per-agent daily memory-count quota (it previously only recorded it).** On a postgres-backed daemon
  the per-agent daily write quota (`AI_MEMORY_MAX_MEMORIES_PER_DAY`) was a silent no-op on EVERY tenant
  write path — `store`/`store_batch`/`consolidate` increment the counter but never compared it to the
  cap or rejected, and `create_memory_postgres` never called any quota check (the sqlite path enforces
  at the handler via `quotas::check_and_record`, which the postgres data path doesn't use). So an agent
  could author unlimited memories/day on postgres. This was surfaced by the #1788 5-agent vote as a
  distinct, broader defect than the bulk/consolidate-only #1788. The 5-agent adversarial vote (memory
  `4d3ea1c5`) chose a new tenant-only SAL `check_memory_quota(ctx, namespace, additional_count,
  additional_bytes)` method (day-roll-aware read + compare → `StoreError::QuotaExceeded` → 429), called
  by exactly the 3 postgres tenant handlers (`create_memory_postgres`, the `bulk_create` postgres branch
  with partial-fill, the `consolidate_memories` postgres branch) BEFORE their store write — NOT inside
  `store`/`store_batch` (which are shared with the EXEMPT federation-receive / migrate / CLI / curator
  paths, plus `consolidate` is a separate method `store`-flag enforcement couldn't reach). The day-roll
  reuses the same `date_trunc('day', day_started_at)` idiom as `record_memory_quota_in_tx`. A small
  check-then-record TOCTOU (bounded by pool concurrency) is accepted for a soft daily cap. No schema
  change. Code anchors: `src/store/mod.rs`, `src/store/postgres.rs`, `src/handlers/{create,power_consolidation,memories_query,postgres_gate}.rs`.

- **[#1788](https://github.com/alphaonedev/ai-memory-mcp/issues/1788) — `bulk_create` + `consolidate`
  now charge the per-agent daily write quota (sqlite).** The per-agent daily write quota
  (`AI_MEMORY_MAX_MEMORIES_PER_DAY`) was enforced on the single-write handlers but ABSENT from the
  bulk-create surface (`POST /api/v1/memories/bulk`) and the consolidate surfaces (HTTP
  `POST /api/v1/consolidate` + MCP `memory_consolidate`), so a caller could loop 1000-item bulk POSTs
  to author unlimited memories. The 5-agent adversarial vote (memory `4d3ea1c5`) confirmed the charge
  belongs at the **handler layer**, NOT the SAL `store`/`store_batch` trait — that trait is shared
  with federation-receive (storage-bytes-only per #1544), migration, the CLI (operator-as-actor), and
  the curator/autonomy `ConsolidationPass`, all of which must stay exempt. `bulk_create` now charges
  `check_and_record` per row with **partial-fill** semantics (over-cap rows land in `errors[]` and are
  not persisted, consistent with the handler's existing per-row validation/governance error model;
  refund on insert failure); `consolidate` charges 1 (it mints a net-new attributable memory) on the
  tenant HTTP + MCP surfaces, leaving the curator path exempt. Empty/anonymous principals are skipped,
  mirroring single writes. **Note:** a broader, distinct finding surfaced during this work — PostgresStore
  never *enforces* the daily memory-count cap on any write path (it only *records*) — is tracked as
  [#1795](https://github.com/alphaonedev/ai-memory-mcp/issues/1795). No schema change. Code anchors:
  `src/handlers/memories_query.rs`, `src/handlers/power_consolidation.rs`, `src/mcp/tools/consolidate.rs`.

- **[#1784](https://github.com/alphaonedev/ai-memory-mcp/issues/1784) — consolidation provenance
  (`metadata.derived_from` / `consolidated_from_agents`) is now immutable and survives a metadata
  overwrite.** `consolidate` records the merged source ids on `metadata.derived_from` (and source
  authors on `consolidated_from_agents`) rather than navigable `memory_links` edges — deliberately,
  because a real edge to a source would be FK `ON DELETE CASCADE`-killed the instant `consolidate`
  hard-deletes that source (the sources are never archived, so the pointer is inherently
  non-navigable by design — a genuine impossibility, not a gap). The bug was that only `agent_id`
  was protected across a metadata whole-object overwrite, so a later `memory_update` or a re-store
  /re-consolidation that didn't re-supply these keys **silently dropped the provenance** (and it
  cannot be reconstructed — the sources are gone). Both provenance keys are now preserved
  (existing-wins, exactly like `agent_id`) at every metadata-overwrite site on both backends: the
  caller-layer `crate::identity::preserve_provenance_keys` helper (the generalized
  `preserve_agent_id`, used by the MCP/HTTP/CLI update + store-dedup paths), the postgres in-SQL
  `update` / upsert / federation-merge arms (a `jsonb ||` provenance overlay), and the sqlite in-SQL
  upsert / newer-wins-merge arms (a `json_patch` overlay that — unlike the prior `json_set` —
  preserves the nested array values). The stale `consolidate` doc-comment (which claimed it "creates
  links from new → old") is corrected. No schema change; existing `derived_from` rows keep working
  and now survive updates. Design resolved by the 5-agent adversarial vote (memory `4d3ea1c5`). Code
  anchors: `src/identity/mod.rs`, `src/storage/mod.rs`, `src/store/postgres.rs`.

- **[#1783](https://github.com/alphaonedev/ai-memory-mcp/issues/1783) — AGE knowledge-graph
  projection is now cleaned on hard-delete (no more ghost edges).** `project_link_into_age` was
  MERGE-only — it never issued a Cypher DELETE — so when a memory was hard-deleted (`delete` /
  `forget` / `consolidate` / `run_gc` / `size_gc` / `apply_remote_deletion`, all of which
  cascade-delete `memory_links` relationally via `ON DELETE CASCADE`), the Apache-AGE projection
  `memory_graph` kept the orphaned `(:Memory)` node + its incident edges, so `kg_query` /
  `find_paths` over the AGE backend returned ghost edges to a row that no longer existed (a stale
  SECONDARY index; relational truth + the `find_paths` recursive-CTE fallback were always correct).
  A new `unproject_memory_from_age` helper issues the mirror `MATCH (n:Memory {id}) DETACH DELETE n`
  (best-effort under the same `#1542`/`#1640` SAVEPOINT + AGE-runtime-tolerance posture as the link
  projection; idempotent — a never-projected memory no-ops) at all six hard-delete sites, in the
  surrounding tx where one exists (atomic) and a short own-tx on the two pool-direct paths. The
  cold drainer (`drain_kg_projection_outbox`) gains an existence-guard that SKIPs any pending
  projection whose `memory_links` row was deleted between enqueue and drain — so a deferred-mode
  ADD can never RESURRECT a node the delete removed, **without a schema migration** (the relational
  table is the source of truth). Postgres+AGE only; SQLite/CTE backends have no projection to clean.
  Design resolved by the 5-agent adversarial vote (memory `4d3ea1c5`). Code anchor:
  `src/store/postgres.rs`; tests: `tests/pillar4_4d_age_unprojection_on_delete_1783.rs`.

- **#1781 — `schema-init --embedding-dim` refuses a destructive embedding-dim conversion by
  default.** On a column-dim mismatch the postgres `migrate_embedding_dim` path DROPs the HNSW
  index, NULLs every `memories` / `archived_memories` embedding, and ALTERs the column —
  previously with no emptiness check, so re-running `ai-memory schema-init --embedding-dim` with
  the wrong/default dim against a populated corpus silently NULLed every embedding (semantic
  recall degraded to keyword-only until a full re-embed). The conversion now REFUSES with a typed
  error when stored embeddings exist, printing how many would be NULLed, unless `--force-reembed`
  is passed (the explicit escape hatch; precedent: #1785 DROP-confirm). The #877 daemon
  auto-migrate path is unchanged — it passes `force = true` because enabling auto-migrate is the
  operator's explicit opt-in.
  The path-form handler used the sqlite-only `State<Db>` extractor + a raw rusqlite call, so the
  postgres route-gate 501'd it even though the SAL `get_namespace_standard` was implemented. Now
  delegates to the SAL-backed query-string handler (both backends, same response shape) + added to
  the postgres-gate allowlist. Commit 2a1c39e2.
- **#1713 — flaky MCP-subprocess test deadlock.** ~24 integration tests collected a spawned
  `ai-memory mcp` child with raw unbounded `child.wait_with_output()`; under parallel load a wedged
  child hung the whole integration binary (a 1728s hang). Routed every raw MCP spawn through the
  existing 60s-deadline `drive_mcp_bounded` driver (kill-and-panic-on-expiry) — a silent hang
  becomes a fast, loud failure. Commit 87c30241.
- **#1721 — test scratch DBs moved off `/tmp` → gitignored `.local-runs/`.** Completed the
  `std::env::temp_dir()` → project-local sweep (CLAUDE.md no-`/tmp` hard rule): 73 sites in
  `tests/integration.rs` + ~9 across other test files, behavior-neutral. Commit 522621e8.

### Final pre-tag security review (5-agent, 2-round) + NHI dogfood findings

- **#1804 (HIGH) — `kg_timeline` cross-tenant private-title leak.** Per-target visibility
  filter added on all three read paths (MCP + HTTP sqlite/postgres): `kg_timeline` now drops
  any event whose target memory is not visible to the caller, closing a leak where a
  multi-tenant caller could read a victim's `scope=private` metadata by rooting a link at it.
  Commit d3b87a2d.
- **#1805 — federated action-transition replay.** Per-transition nonce recorded so a replayed
  `/sync/push` action-state transition is refused. Commit c3087e33.
- **#1806 / #1808 / #1809 — lease TTL bound, `verify_strict`, federation E2E docs.** Commit 2abeac68.
- **#1807 — coordination create-path quota + payload-size bound.** `memory_action_create` /
  `memory_signal_send` / `memory_checkpoint_create` now validate metadata size (64 KiB cap) and
  charge the creator's per-namespace storage quota. Commit aa030f1d.
- **#1810 — CI ubuntu `Check` disk-exhaustion.** Free `.ghcup` + docker images before the test
  compile. Commit bcccf1be.
- **#1811 — Claude Code PreToolUse governance hook could not enforce.** The installer wrote a
  `type:mcp_tool` hook that (a) errored `kind is required` (no `input`) and (b) structurally
  cannot block — an mcp_tool hook's `isError`/non-decision response is non-blocking per the
  Claude Code hooks contract. Replaced with a `type:command` wrapper
  (`ai-memory governance check-action --from-pretool-stdin`) that emits
  `hookSpecificOutput.permissionDecision=deny` so a substrate Refuse actually blocks. Operators
  upgrade with `ai-memory install claude-code --hook pretool --apply --force`. 5-agent vote
  `4d3ea1c5`. Commits c7452681 + ef3c17f9.
- **#1812 — `memory_link` silently dropped off-taxonomy relations.** A well-formed but
  non-taxonomy relation (e.g. `frobnicate`) passed the permissive `validate_relation` but was
  silently dropped by the closed-taxonomy `CHECK` under `INSERT OR IGNORE`, while the tool
  falsely returned `linked:true`. Tightened `validate_relation` to the closed 9-relation set
  (aligning it with the `CHECK`, the `MemoryLinkRelation` enum, and the HTTP handler). 5-agent
  vote `4d3ea1c5`. Commit d7d43d55.

## [0.7.1] — 2026-06-15

Hardening patch line over v0.7.0 (`attested-cortex`). A 26-task,
adversarial-audit-driven EPIC ([#1683](https://github.com/alphaonedev/ai-memory-mcp/issues/1683))
closing crash / data-loss, atomicity, knowledge-graph-correctness, governance,
recall-quality, and capability-honesty gaps surfaced by a full-spectrum
codegraph + ai-memory NHI audit, plus the substrate + deployment-harness bugs
caught by a live DigitalOcean **PostgreSQL 18 + Apache AGE + pgvector
agent-to-agent (A2A) federation** validation run. No schema change (stays at
**v57**); the advertised surface is unchanged (74 MCP tools at `--profile full`,
89 production HTTP route registrations / 75 unique paths, 80 CLI subcommands /
82 under `--features sal`). All four gates green on both feature sets
(default 5613 tests / sal-postgres 6034 / 0 failed, `clippy -D pedantic`, fmt,
`cargo audit`).

### Added

- **HTTP recall runs the autonomous-tier cross-encoder reranker**
  ([#1691](https://github.com/alphaonedev/ai-memory-mcp/issues/1691)). The HTTP
  recall surface now applies the same neural cross-encoder rerank stage on the
  hybrid path (sqlite **and** postgres-SAL) that the MCP/CLI paths run, via a
  process-global `RuntimeContext` reranker built at `serve` boot — so a recall
  no longer ranks differently by transport. The envelope reports
  `hybrid+rerank`.
- **Operator-configurable reranker score floor** (`#1691`/n14). A new
  `[reranker].score_floor` config field + `AI_MEMORY_RERANK_SCORE_FLOOR` env
  var (`off` | `absolute:<f>` | `relative:<f>`) wire the previously-dead
  `RerankerScoreFloor` calibration capability through to every reranker build
  site.
- **Per-namespace curator config** (`[curator]` section,
  [#1671](https://github.com/alphaonedev/ai-memory-mcp/issues/1671)/n15).
  `[curator.reflection_namespaces]` makes `curator --reflect --all-namespaces`
  honor a per-namespace `reflection_pass.enabled` gate (previously an inert
  no-op), and `[curator.confidence_decay_half_life_days]` lets the
  confidence-decay sweep apply a per-namespace half-life on both the sqlite
  per-row and postgres bulk paths.

- **`memory_reflect`: top-level `entity_id` convenience param**
  ([#1665](https://github.com/alphaonedev/ai-memory-mcp/issues/1665)). The
  tool now accepts an optional `entity_id` string that desugars into
  `metadata.entity_id` at the MCP boundary, making the entity→auto-persona
  binding discoverable from the tool schema instead of requiring a nested
  metadata key. Precedence is metadata-wins (a differing nested
  `metadata.entity_id` shadows the alias with a warn); a blank value is
  ignored; the `[entity:X]` title marker remains the lower-precedence
  fallback. Applied identically in both reflect parsers (stdio + SAL/HTTP)
  and through the L1-8 pending→execute round-trip. `memory_store` is
  intentionally unaffected (entity binding is reflection-kind only). This is
  **not** a fix for "binding was broken" — `metadata.entity_id` already
  worked; the param closes a discoverability gap.

### Fixed

- **Auto-persona cadence missed whitespace/empty `entity_id`**
  ([#1665](https://github.com/alphaonedev/ai-memory-mcp/issues/1665)). The
  cadence resolver `resolve_entity_id` read `metadata.entity_id` raw while
  the write-time denormaliser `extract_mentioned_entity_id` trimmed and
  empty-filtered it, so a padded/empty value bound a different descriptor on
  the two sides and `count_entity_reflections` silently missed the row. The
  read path now applies the same trim + non-empty filter, and both sites
  route the metadata key through the new `field_names::ENTITY_ID` SSOT const.

- **Managed Claude Code PreToolUse hook fired on every tool, spamming
  `kind is required`**
  ([#1667](https://github.com/alphaonedev/ai-memory-mcp/issues/1667)). The
  installer wrote the PreToolUse guardrail with `matcher: "*"`, so Claude
  Code invoked `memory_check_agent_action` before *every* tool dispatch —
  including MCP / read tools (e.g. `mcp__memory__memory_get`) for which the
  harness builds no `AgentAction` and supplies no `kind`. The tool's
  `required: ["kind"]` input schema then rejected the call, logging
  `PreToolUse:<tool> hook error / kind is required` on every memory MCP call
  (non-fatal, but noisy). The managed matcher is now scoped to
  `Bash|Edit|Write` via a single named `PRETOOL_HOOK_MATCHER` const — the
  agent-external action surface the rule engine actually models
  (`bash` / `filesystem_write`); the regex also substring-covers
  `MultiEdit` / `NotebookEdit`. The `SessionStart` matcher is intentionally
  left as `"*"` (it fires per session, not per tool dispatch). Re-running
  `ai-memory install claude-code --apply` with the new binary cleanly
  replaces a prior `"*"` managed entry.

- **CRITICAL: HNSW non-finite distance crashed recall**
  ([#1684](https://github.com/alphaonedev/ai-memory-mcp/issues/1684)). A `NaN`
  / non-finite cosine distance fed `partial_cmp().unwrap()` in the vector-index
  sort, panicking the MCP/HTTP process mid-recall. Non-finite distances now
  floor to `f32::MAX` and sorts use `total_cmp`; the seed-path is finiteness-checked.
- **Federation catch-up could silently drop a row on a failed apply**
  ([#1687](https://github.com/alphaonedev/ai-memory-mcp/issues/1687)). The
  catch-up watermark now advances only on a successful, non-halted apply across
  all three branches, so a transient apply error no longer skips the row on the
  next pass.
- **Persona generation + online synthesis made atomic**
  ([#1688](https://github.com/alphaonedev/ai-memory-mcp/issues/1688),
  [#1700](https://github.com/alphaonedev/ai-memory-mcp/issues/1700)). Persona
  insert+links+metadata and the `memory_store` synthesis apply (N updates + N
  deletes + insert) are wrapped in transactions so a mid-sequence failure can no
  longer leave a half-written persona / partially-merged cluster.
- **HNSW semantic recall detected dimension mismatch instead of returning garbage**
  ([#1692](https://github.com/alphaonedev/ai-memory-mcp/issues/1692)). The HNSW
  branch recomputes cosine via `cosine_similarity_checked` and skips (counting)
  dimension-mismatched rows rather than scoring across incompatible vector spaces.
- **GC pruners wired + offload TTL reaped on every surface**
  ([#1690](https://github.com/alphaonedev/ai-memory-mcp/issues/1690)). The
  `offloaded_blobs` TTL sweep and `recall_observations` pruner are now spawned in
  the `serve` bootstrap; the MCP `memory_offload` path opportunistically reaps
  expired blobs (pure-MCP deployments run no background sweep); and the
  `federation_nonce_cache` disk mirror is pruned on eviction + bounded on
  hydration, closing an unbounded-growth class.
- **MCP surface installs the `GOVERNANCE_PRE_ACTION` hook**
  ([#1685](https://github.com/alphaonedev/ai-memory-mcp/issues/1685)). The
  agent-action governance gate now installs on the MCP stdio surface, not just
  HTTP `serve`.
- **`rules keygen` warns when it disables enabled unsigned rules**
  ([#1686](https://github.com/alphaonedev/ai-memory-mcp/issues/1686)).
- **`rules` CLI migrates the db on open**
  ([#1690](https://github.com/alphaonedev/ai-memory-mcp/issues/1690)-adjacent;
  surfaced by the DigitalOcean A2A run). `ai-memory rules <verb>` opened the db
  with a raw connection that skipped migrations, so on a fresh db
  `governance_rules` did not exist (`rules_store::list: prepare — no such table`),
  breaking Form-7 governance bootstrap on fresh (especially postgres-backed)
  fleet peers. It now opens via the migrating path like every other command.
- **Knowledge-graph traversals exclude invalidated edges**
  ([#1689](https://github.com/alphaonedev/ai-memory-mcp/issues/1689)). The
  postgres `find_paths` CTE and the Apache-AGE `kg_query` / `find_paths` Cypher
  current-view traversals now filter `valid_until`, matching the sqlite + CTE
  default so a retracted link no longer influences current-view results.
- **Capability honesty**
  ([#1672](https://github.com/alphaonedev/ai-memory-mcp/issues/1672),
  [#1673](https://github.com/alphaonedev/ai-memory-mcp/issues/1673),
  [#1674](https://github.com/alphaonedev/ai-memory-mcp/issues/1674)).
  `curator_mode` reports the SAL feature gate honestly, `callable_now` is honest
  for an unknown caller, and the non-`sal` build reports the live
  `db_schema_version` instead of a hardcoded `0`.
- **do-1461 DigitalOcean A2A harness** (surfaced + fixed during the postgres+AGE
  validation run). The `serve` unit passed both `--db` and `--store-url` (v0.7.1
  rejects the pair) → postgres peers pass only `--store-url`; provisioning ran
  the Batman governance step before the daemon/postgres schema existed →
  reordered so the daemon (schema auto-migrate) comes first and the secure-env
  battery is re-shipped after; VPC CIDR collision avoided.

### Documentation

- **100% schema-version + surface-count drift sweep** across living docs + the
  GitHub Pages site: schema **v57**, **89** route registrations / **75** unique
  paths, **80**/**82** CLI subcommands, **74** MCP tools — reconciled to the code
  SSOT constants; frozen `docs/v0.7.0/**` release/audit artifacts preserved as
  historical record.

## [Unreleased] — v0.7.x doc follow-ups + Wave-2 refactor (post-tag)

### Moonshot-property declaration (ROADMAP §17 quality gate)

> Per ROADMAP §17, every release declares which of the seven §2 moonshot
> properties it strengthens, with code anchors. v0.7.0 is the **first**
> release authored under this discipline. The hardening center-of-gravity
> is **§2.3 stoppable** + **§2.5 attested**; the other five are touched or
> held. Known gaps are named explicitly below rather than elided.

- **§2.3 stoppable — STRENGTHENED (primary).** The substrate refuses
  rather than proceeds on every governance / safety boundary it cannot
  positively clear:
  - Governance consultation fails CLOSED on transient error
    ([#1455](https://github.com/alphaonedev/ai-memory-mcp/issues/1455),
    `src/daemon_runtime.rs` `governance_consultation_unavailable[_inner]`;
    [#1054](https://github.com/alphaonedev/ai-memory-mcp/issues/1054)),
    opt-out only via `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` (default
    `false`).
  - Optimistic `memory_update` now routes through `GOVERNANCE_PRE_WRITE`
    on both backends so the versioned write path can't bypass policy
    ([#1451](https://github.com/alphaonedev/ai-memory-mcp/issues/1451)).
  - `match_custom` evaluates its ANDed payload predicates, closing a
    custom-action policy-bypass
    ([#1457](https://github.com/alphaonedev/ai-memory-mcp/issues/1457)).
  - SSRF webhook/federation dispatch fails CLOSED on DNS failure
    ([#1053](https://github.com/alphaonedev/ai-memory-mcp/issues/1053),
    `AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL` default `false`).
  - Strict keyless-bind refusal
    ([#1458](https://github.com/alphaonedev/ai-memory-mcp/issues/1458),
    `AI_MEMORY_REQUIRE_API_KEY`) and the recursive-reflection depth cap
    (`REFLECTION_DEPTH_EXCEEDED`,
    [#655](https://github.com/alphaonedev/ai-memory-mcp/issues/655)).
- **§2.5 attested — STRENGTHENED (primary).** Provenance is verifiable,
  and the audit chain fails CLOSED:
  - `signed_events` fails CLOSED on a missing signature when a verifier
    is installed and the row's `attest_level` is not the by-design
    `"unsigned"` legacy marker
    ([#1452](https://github.com/alphaonedev/ai-memory-mcp/issues/1452)),
    over the V-4 cross-row hash chain.
  - L4 `memory_capture_turn` verifies host Ed25519 signatures against an
    operator-managed allowlist and lands `attest_level = "signed_by_peer"`
    on success
    ([#1414](https://github.com/alphaonedev/ai-memory-mcp/issues/1414),
    `AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST`).
  - Daemon `serverInfo` is Ed25519-signed at the MCP `initialize`
    handshake
    ([#1154](https://github.com/alphaonedev/ai-memory-mcp/issues/1154));
    federation requires signatures + per-message nonces by secure default
    ([#791](https://github.com/alphaonedev/ai-memory-mcp/issues/791),
    [#922](https://github.com/alphaonedev/ai-memory-mcp/issues/922),
    [#1088](https://github.com/alphaonedev/ai-memory-mcp/issues/1088)).
- **§2.2 coherent — STRENGTHENED.** The #1389 layered-capture
  architecture (L1 store-first rule + L2 transcript recovery + L4
  idempotent turn capture) plus schema v52 `transcript_line_dedup`
  guarantee a SIGKILL between turns never loses or duplicates a captured
  turn
  ([#1389](https://github.com/alphaonedev/ai-memory-mcp/issues/1389),
  [#1416](https://github.com/alphaonedev/ai-memory-mcp/issues/1416)).
- **§2.7 LLM-agnostic — STRENGTHENED.** Provider-agnostic LLM client over
  15 vendor aliases; tier no longer dictates vendor
  ([#1067](https://github.com/alphaonedev/ai-memory-mcp/issues/1067),
  [#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146)).
- **§2.1 endpoint-resident — HELD/extended.** iOS + Android cross-compile
  CI + runtime coverage keep the substrate buildable on-device
  ([#1068](https://github.com/alphaonedev/ai-memory-mcp/issues/1068));
  no FFI surface ships yet (v0.7.x follow-up).
- **§2.4 improvable — HELD.** The recursive-learning primitive
  ([#655](https://github.com/alphaonedev/ai-memory-mcp/issues/655)) is
  unchanged this cycle beyond the depth-cap stoppability anchor above.

#### Known property gaps at v0.7.0 (named, not elided)

- **§2.2 capture vs §2.5 attestation.** The claimed→attested *join* on
  the store write path is now **closed** by #626 Layer-3: a caller may
  present a detached Ed25519 `signature` (+ signed `created_at`) on the
  MCP `memory_store`, HTTP `POST /api/v1/memories` (sqlite + postgres),
  and CLI store paths; a valid signature against the agent's bound
  pubkey lands `attest_level = "agent_attested"`, a forged one is
  rejected `403 ATTESTATION_FAILED`, and operators can require
  attestation fail-closed via `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`
  ([#626](https://github.com/alphaonedev/ai-memory-mcp/issues/626)).
  The remaining open edge is the *default-path* identity: when no
  signature is presented (and require-attestation is off),
  `metadata.agent_id` is still a *claimed*, not *attested*, identity —
  e.g. the default L4 `memory_capture_turn` capture lands unsigned
  because its host allowlist is empty by default
  ([#1414](https://github.com/alphaonedev/ai-memory-mcp/issues/1414)).
  Driving attestation to the default across every surface is the
  agent-registration work tracked alongside the heterogeneous-panel
  adjudication ([#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171)).
  This is a tracked gap, not a regression: §2.2 and §2.5 are both
  advanced this cycle and the write-path join is now closed.
- **§2.6 bias-displaced — policy, not architecture.** Per ROADMAP §5,
  producer/reflector decorrelation (e.g. a Claude-family producing agent
  with a non-Claude curator backend) is currently a deployment-policy
  property, not enforced by the substrate; v0.7.0 makes it *expressible*
  via the LLM-agnostic backend (§2.7) but does not *attest* it. Tracked
  under [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171).

### v0.7.x GA push — #1539 agent-pubkey bind route + #1542/#1607/#1608 postgres durability/provenance fixes (2026-06-11)

- **[#1539](https://github.com/alphaonedev/ai-memory-mcp/issues/1539)** — new admin-gated `PUT /api/v1/agents/{id}/pubkey` binds an Ed25519 attestation pubkey through the SAL `MemoryStore::bind_agent_pubkey` (both adapters); validated curve-point input, #911 audit entry, #1582 authn-trusted admin gate. Route counts move 88→89 registrations / 74→75 unique paths (SSOT consts + docs updated in lockstep). Pins: `tests/issue_1539_bind_pubkey_route.rs` (4 tests).
- **[#1542](https://github.com/alphaonedev/ai-memory-mcp/issues/1542)** — `POST /api/v1/links` returned 201 while persisting NOTHING on AGE-enabled postgres daemons whose role can't `LOAD 'age'`: the in-tx LOAD refusal aborted the tx and the warn-and-continue COMMIT silently rolled back. LOAD + the whole projection now ride SAVEPOINTs at both link-write sites; federated link replays degrade to `warn_age_fallback` instead of failing forever. Pin: `live_link_persists_when_age_projection_refused_1542` (restricted-role, LOAD-refusal precondition asserted).
- **[#1607](https://github.com/alphaonedev/ai-memory-mcp/issues/1607)/[#1608](https://github.com/alphaonedev/ai-memory-mcp/issues/1608)** — postgres write-path parity: `touch_after_recall` GREATEST extension floor; `store_with_embedding` full 27-column Form-4/5/QW-2 INSERT (was 19 — the anchor row contradicted its own wire response); `store()`/`store_batch()` gained `entity_id`/`persona_version`.
- **[#1536](https://github.com/alphaonedev/ai-memory-mcp/issues/1536)** — do-1461 Form-7 activation was a silent no-op (clap-refused `--store-url` on rules verbs, swallowed; plus a cwd split-brain putting rules in a db the daemon never reads). Fixed with the `REMOTE_GOV_DB` SSOT + self-verifying activation (`governance check-action` must refuse a /tmp write) + the Form-2/6 standard now binds through the live HTTP surface.
- Issue hygiene: #1543/#1545/#1537/#1538/#1540/#1560/#1566/#1578 verified fixed-in-code and closed with evidence; #1544 dispositioned to v0.8 with rationale.

### v0.7.x #1588 dogfood RE-RUN — capabilities-truthfulness pair #1605 + #1606 (2026-06-11)

Two discoverability defects the RE-RUN hit live: following the capabilities surface verbatim produced refused calls.

- **[#1605](https://github.com/alphaonedev/ai-memory-mcp/issues/1605)** — `governance.enforced_actions` advertised the Rust variant names (`"Bash"`, `"FilesystemWrite"`, …) while `memory_check_agent_action` accepts only the snake_case wire kinds. `ENFORCED_AGENT_ACTIONS` now builds from the `action_kinds` SSOT (`bash` / `filesystem_write` / `network_request` / `process_spawn`); new round-trip test pins that every advertised token parses (`advertised_enforced_actions_round_trip_the_kind_parser_1605`).
- **[#1606](https://github.com/alphaonedev/ai-memory-mcp/issues/1606)** — the `memory_recall` capabilities example advertised `{"query": ...}`, a payload the MCP parser refuses with "context is required" (the `query`/`q` alias ladder is HTTP-only). Example now uses `context`; new test extends the #1325 byte-equal-to-a-valid-call discipline (`recall_example_payload_parses_1606`).
- Docs drift swept in the same train: #1596 extension-FLOOR touch semantics corrected in ADMIN_GUIDE / CLI_REFERENCE / CLAUDE.md / ttl-controls.html / lifecycle.html / memory-tiers.html (the pre-#1596 "sliding-window REPLACEMENT" contract language survived the fix); stale "agent-EXTERNAL enforcement is v0.8.0" framing in governance.md / MIGRATION_v0.7.md superseded by the merged PE-1/PE-2/PE-3 wire-point audit; API_REFERENCE.md now names `context` as the required MCP recall param.

### v0.7.x #1588 dogfood RE-RUN — #1604 rerank input-sequence cap (2026-06-11)

The #1588 singleton AI-NHI dogfood re-run on golden `e0ad8c34` re-measured the #1597 recall latency that the fix-train session had deferred: warm autonomous-tier recall was still ~4,013 ms on a real long-content corpus vs ~533 ms on short-content rows and ~853 ms at the semantic tier — the [batch=20, seq=512] candle CPU cross-encoder forward, not pool size or batching, was the residual cost ([#1604](https://github.com/alphaonedev/ai-memory-mcp/issues/1604)).

- **`[reranker].max_seq_tokens` + `AI_MEMORY_RERANK_MAX_SEQ`** — new rerank input-sequence cap applied in the #1597 batched forward (`src/reranker.rs::neural_score_pairs`); compiled default `RERANK_MAX_SEQ_DEFAULT = 256` (BERT attention is O(n²), so 512→256 ≈ 4× on the forward). Resolver ladder `env > [reranker].max_seq_tokens > compiled default` via `AppConfig::resolve_reranker()`, seeded process-wide at boot (`crate::reranker::set_rerank_max_seq`, the `set_db_mmap_size` precedent). Zero / unparseable / above-model-ceiling values fall through; other cross-encoder consumers keep the full `CROSS_ENCODER_MAX_SEQ = 512`. Pinned by `resolve_reranker_1604_max_seq_ladder`, `rerank_max_seq_1604_seed_once_semantics`, and `test_rerank_max_seq_env_overrides_config_and_default` (env-var table row #76).

### v0.7.x #1588 Phase-3 dogfood fix train — 14 lived-defect closures (2026-06-11)

Backfilled entry (the train shipped in commits `07c7ee95` / `6feae40f` / `315b9ad9` without a CHANGELOG fold). All 14 issues the #1588 singleton AI-NHI dogfood evaluation surfaced, fixed + closed with evidence:

- **Lifecycle (`07c7ee95`)** — [#1596](https://github.com/alphaonedev/ai-memory-mcp/issues/1596) touch-TTL is now an extension FLOOR (`MAX(current expiry, now + per-tier window)` — recall can never move an expiry earlier); [#1601](https://github.com/alphaonedev/ai-memory-mcp/issues/1601) `memory_forget` pattern tokens AND together (every whitespace-separated token must match); [#1602](https://github.com/alphaonedev/ai-memory-mcp/issues/1602) `memory_forget` dry-run returns capped row previews (`id`/`title`/`namespace`/`tier` + `truncated` flag) and live runs return `deleted_ids`.
- **Provenance honesty (`6feae40f`)** — [#1590](https://github.com/alphaonedev/ai-memory-mcp/issues/1590) `[storage].default_namespace` honored across the MCP/HTTP/CLI write ladder; [#1591](https://github.com/alphaonedev/ai-memory-mcp/issues/1591) omitted confidence stamps `confidence_source = "default"` (not `caller_provided`); [#1592](https://github.com/alphaonedev/ai-memory-mcp/issues/1592) upsert responses echo the ACTUAL stored tier on attempted downgrades; [#1600](https://github.com/alphaonedev/ai-memory-mcp/issues/1600) `EditSource::Agent` honored, unknown `edit_source` values error (`human|llm|hook|agent`), `ai:*` callers derive the agent source.
- **Recall + docs truth (`315b9ad9`)** — [#1597](https://github.com/alphaonedev/ai-memory-mcp/issues/1597) `RERANK_POOL_MAX = 20` + ONE batched cross-encoder forward (sequence-length residual closed by #1604 above); [#1589](https://github.com/alphaonedev/ai-memory-mcp/issues/1589) no phantom `Plan` memory-kind in docstrings, CLAUDE.md L1 template uses `kind: "decision"` (template-gate test); [#1599](https://github.com/alphaonedev/ai-memory-mcp/issues/1599) `memory_consolidate` docstring tells the metadata-only provenance truth (no KG-traversable link rows); `OPENAI_COMPAT_EMBEDDINGS_PATH` literal hoisted to a named const.
- **Embeddings umbrella** — [#1598](https://github.com/alphaonedev/ai-memory-mcp/issues/1598) (+ [#1593](https://github.com/alphaonedev/ai-memory-mcp/issues/1593)/[#1594](https://github.com/alphaonedev/ai-memory-mcp/issues/1594)/[#1595](https://github.com/alphaonedev/ai-memory-mcp/issues/1595)) detailed in its own section below; [#1603](https://github.com/alphaonedev/ai-memory-mcp/issues/1603) batched remote embeds (one `/embeddings` POST per sub-batch, `93d407b9`).

### v0.7.0 #1579 post-merge security audit — 10-agent full-spectrum pass (2026-06-10)

Operator-mandated adversarial security audit of `release/v0.7.0` after the #1579 train merged (10 parallel dimension agents + 3-skeptic verification per finding). 8 dimensions came back clean (SQL/cypher/FTS injection across both adapters incl. the new v56 composite-index + v57 tsvector queries, crypto, DoS/input incl. the new gzip layer — response-only, no zip-bomb surface, path/serde, multi-tenancy post-filter, info-disclosure/supply-chain). 5 findings filed + fixed pre-tag:

- **[#1582](https://github.com/alphaonedev/ai-memory-mcp/issues/1582) (HIGH)** — 7 read-visibility handlers (`/contradictions`, `/kg/query`, `/links/{id}`, `/archive`, `/pending`, `/taxonomy`) used the bare `is_admin_caller` predicate to OR an admin flag past the per-row `scope=private` filter with no #1570 authn gate; a self-asserted `X-Agent-Id` on a keyless+admin-ids deployment read every tenant's private rows. New authn-gated `is_admin_caller_trusted` predicate; all 7 sites swapped.
- **[#1583](https://github.com/alphaonedev/ai-memory-mcp/issues/1583) (MED)** — the `GOVERNANCE_PRE_WRITE` agent-action gate was installed only by the HTTP daemon, so `memory_write` custom rules were bypassed for MCP-driven writes. Extracted `install_governance_pre_write_hook`; MCP now installs it (CLI one-shot stays out by design; namespace `CorePolicy` standards were always enforced via `enforce_governance`).
- **[#1584](https://github.com/alphaonedev/ai-memory-mcp/issues/1584) (MED)** — the #1579 B1 embed-ship receive path validated shipped vectors for dimension only; a non-unit-norm vector poisons cosine ranking. New `sanitize_shipped_vector` rejects non-finite vectors (→ local re-embed) and L2-normalizes the rest, on both adapters; `cosine_similarity` gained a non-finite-score guard. (Non-finite components also can't cross the JSON wire — serde rejects them with 400.)
- **[#1585](https://github.com/alphaonedev/ai-memory-mcp/issues/1585) (LOW)** — `to_store_err` formatted sqlx errors unredacted (the A3 sweep covered only the parse-url site); now routes through `redact_urls_in_message`.
- **[#1586](https://github.com/alphaonedev/ai-memory-mcp/issues/1586) (LOW, latent)** — `PostgresStore::list_unembedded` ignored its `CallerContext`; now short-circuits to empty unless `bypass_visibility` (the admin posture the serve-boot sweep uses).

### v0.7.0 #1579 performance final-gate remediation train (2026-06-10)

The operator-mandated pre-tag performance audit ([#1579](https://github.com/alphaonedev/ai-memory-mcp/issues/1579), four parallel audit agents over local sqlite/MCP, HTTP daemon, postgres SAL, and the live do-1461 fleet) produced a 16-item remediation train — Tier A (5) + Tier B (10) + [#1581](https://github.com/alphaonedev/ai-memory-mcp/issues/1581) — executed across six worktree lanes, each operator-QC'd before its `--no-ff` merge. Schema advances **v55 → v56 → v57**. Tier C ([#1580](https://github.com/alphaonedev/ai-memory-mcp/issues/1580) WAL read-pool) moves to v0.8; Tier D ([#1005](https://github.com/alphaonedev/ai-memory-mcp/issues/1005) vectorlite) to v0.9.

#### Security

- **A3 — store-URL credential redaction.** The postgres boot line logged the full `--store-url` (password included) to journald at INFO, and six more error/CLI sites echoed the raw URL. New `logging::redact_url_password` / `redact_urls_in_message` mask the userinfo password to `****` at every store-URL log/error/report site; deliberately textual so malformed URLs still scrub. Pinned by 10 regression tests incl. the boot-log pin.

#### Performance

- **A1 — double-embed dedupe on the MCP store path** (writepath lane): the store path computed the same embedding twice per write; store p95 **147 → 106 ms** measured.
- **A2 — composite list indexes + sargable `storage::list`** (schema **v56**): `idx_memories_list_order`, `idx_memories_ns_list_order`, `idx_archived_ns_archived_at` paired with distinct prepared filter shapes — list page **141 ms → 0.06 ms at 100k rows (~2000×; 156× at 10k)**.
- **A4 — postgres backfill no-op fix**: the serve-boot embedding-backfill sweep now drains `MemoryStore::list_unembedded` through the daemon embedder (the postgres surface previously never ran ANY backfill — fleet semantic recall was effectively dead at 0.46% embedding coverage post-v29).
- **A5 — HNSW-routed proactive conflict check + false-409 fix**: the #519 write-path near-dup check swaps the O(N)-scan-under-mutex for an ANN-candidate route with a Jaccard-floor verdict tail (81% false-409 class closed); empty-index boot routes to a bounded recency scan.
- **B1 ([#1566](https://github.com/alphaonedev/ai-memory-mcp/issues/1566)) — embed-once-replicate-vector**: `sync_push` ships the sender's stored vector with the row, so receivers no longer synchronously re-embed (~1 s/row) on federation receive — **~10× design lift** on federated ingest; receive-path parity + signed-envelope coverage included.
- **B2 — postgres stored generated tsvector** (schema **v57**): `tsv tsvector GENERATED ALWAYS … STORED` + `memories_tsv_gin`, match AND rank read the column — kills the per-matched-row `ts_rank` recompute (~305 of 306 ms at 8k rows; **PG recall ~62×**); legacy expression index dropped. Operational: the `ADD COLUMN` is an ACCESS-EXCLUSIVE table rewrite (sub-second at fleet scale).
- **B3 — async boot HNSW warm-up**: `serve` + `mcp` become ready immediately (empty index + background build + atomic swap; **~200× time-to-ready**, was 40 s @10k / >28 min @100k rows); documented warm-window semantics + readiness lines.
- **B4 — gzip + TOON over HTTP**: `tower-http` CompressionLayer (gzip, `Accept-Encoding`-negotiated, SSE exempt) — **4.6× measured** on recall payloads; recall/search accept `format=json|toon|toon_compact` reusing the MCP TOON encoder (`toon_compact` ≈ 79% smaller than the JSON envelope).
- **B5 — persistent federation connections + adaptive DLQ drain**: pooled keep-alive peer clients; DLQ replay takes `min(backlog, AI_MEMORY_FED_DLQ_REPLAY_MAX_BATCH)` (default 2048, floor 64) per tick, replacing the fixed-64 take whose ceiling (128 rows/min/peer) made the #1578 62k-row backlog an 8+ hour drain.
- **B6 — storage scale bundle**: bounded backfill scan (`get_unembedded_ids_batch` drain loop), `prepare_cached` hot statements, chunked GC transactions, archive composite index.
- **B7 — sqlite `PRAGMA mmap_size`** default 256 MiB (new env `AI_MEMORY_DB_MMAP_SIZE`, `[storage].db_mmap_size_bytes`): the only across-the-board PRAGMA win in the A/B (15-30% on large-corpus reads).
- **B8 — corpus-scale bench gate**: `ai-memory bench --scale <rows>` seeds a scratch corpus and gates against the `PERFORMANCE.md` §"Corpus-scale budgets" table (`SCALE_BUDGETS` SSOT); CI runs the 10k gate on every PR (the default ~500-row workload had hidden a 7× recall budget blowout at 100k rows).
- **B10 — reranker auto-select**: `BatchedReranker::rerank` picks direct vs coalesced per call (`use_batched_rerank_path`); lexical / lone-caller traffic skips the 5 ms flush window (forced-batched was ~12× slower at N=8 lexical), neural-under-concurrency keeps the G9 ~3× batched win.
- **[#1581](https://github.com/alphaonedev/ai-memory-mcp/issues/1581) — mTLS first-request stall**: `TCP_NODELAY` on accepted TLS sockets — **~40 ms → ~3 ms** first-request latency on real cross-region pairs.

#### Infrastructure

- **B9 — fleet ops bundle** (deploy-time, no code branch): PG `shared_buffers`/`work_mem`/`pg_stat_statements` tuning, `LOAD 'age'` grants on receivers, DLQ quarantine drain, fleet corpus re-embed — applied with the binary swap.
- **New QC gate**: `scripts/check-const-name-literals.sh` HARD-BLOCKs value-encoding identifier names (e.g. `CHUNK_500 = 500`); its 9-entry grandfather baseline was **burned to empty** at train close.
- New env vars: `AI_MEMORY_DB_MMAP_SIZE` (row 70), `AI_MEMORY_FED_DLQ_REPLAY_MAX_BATCH` (row 71) — census table + precedence tests updated.

### v0.7.0 #1558 hardcoded-literal SSOT remediation campaign (2026-06-09)

Five-batch burn-down of duplicated string/numeric literals across the substrate ([#1558](https://github.com/alphaonedev/ai-memory-mcp/issues/1558)), enforced going forward by the pm-v3.1 mechanical ratchet gate `scripts/check-hardcoded-literals.sh` (companion to `scripts/check-vendor-literals.sh`; baseline counts may only shrink). Predominantly behavior-preserving; wire-visible exceptions are under **Changed**.

#### Changed

- **[#1562](https://github.com/alphaonedev/ai-memory-mcp/issues/1562)** — 58 tracing sites used FIELD syntax (`target = "..."`), which `RUST_LOG` target filtering cannot match; converted to real metadata targets routed through consts. **Operator-visible:** postgres SAL adapter events now emit under the literal targets `store::postgres` / `store::postgres::kg` — `RUST_LOG=ai_memory=debug` no longer matches them; add `store::postgres=debug` explicitly (commit `71ffcd5d`; also closes [#1563](https://github.com/alphaonedev/ai-memory-mcp/issues/1563) — dead postgres-gate arm for the unregistered `POST /api/v1/archive/purge` path removed).
- **[#1560](https://github.com/alphaonedev/ai-memory-mcp/issues/1560)** — one `identity::anonymous_request_id()` helper (`anonymous:req-<uuid8>`) replaces 10 divergent synthesis sites, 8 of which stamped the full 36-char UUID against the documented uuid8 contract. **Wire-visible:** anonymous principals in logs/audit rows now carry an 8-char suffix everywhere (commit `2ba4214d`).

#### Added

- `src/identity/sentinels.rs` — reserved-principal sentinel SSOT (batch 2): every internal/system principal string (`DAEMON_PRINCIPAL`, `ANONYMOUS_INVALID`, `AI_CURATOR`, `AI_HTTP`, federation/subscription/migrate/export/governance internals) as one named const; 82 production sites routed. `validate::RESERVED_AGENT_IDS` is now BUILT from the sentinel consts (was a parallel "MUST stay in sync" literal list) with a new invariant test pinning every privileged sentinel ∈ the list. `DAEMON_KEYPAIR_LABEL` moved to `src/identity/keypair.rs` as the canonical `pub const` (commit `2ba4214d`).
- `src/mcp/jsonrpc.rs` — JSON-RPC 2.0 wire-constant SSOT (batch 3): version tag, reserved error codes, MCP method names, protocolVersion revision; the crate-root `METHOD_*` consts become aliases of the `jsonrpc::*` canonical set (commit `23ac668a`).
- `src/handlers/routes.rs` — HTTP route-path SSOT (batch 4a): one const per production route path (74 consts); the `src/lib.rs` router registers them and the postgres surface gate (207 literals in `handlers/postgres_gate.rs`), federation receiver, and CLI doctor match on them, so gating structurally cannot drift from registration; legacy `ROUTE_*` crate-root consts now alias the SSOT (commit `23ac668a`).

#### Fixed

- Postgres `agent_quotas` DDL parity (batch 1) — the postgres bootstrap DDL defaults now interpolate `quotas::DEFAULT_MAX_{MEMORIES_PER_DAY,STORAGE_BYTES,LINKS_PER_DAY}`; sqlite already routed through `quota_defaults()` and the postgres twin was the drift (commit `e06cedac`).
- Literal-gate boundary fixes ×3: [#1561](https://github.com/alphaonedev/ai-memory-mcp/issues/1561) — include `#[cfg(test)]`-attributed modules in the gate's test boundary (commit `e08649ef`); batch 5c — exclude whole-file `cfg(test)` fixtures (commit `f141acaf`); [#1577](https://github.com/alphaonedev/ai-memory-mcp/issues/1577) — don't fire on `cfg(test)` mod DECLARATIONS + catch `cfg(all(test, ...))` mods (commit `bf2d8b38`).
- [#1567](https://github.com/alphaonedev/ai-memory-mcp/issues/1567) — flaky test: hold all 32 listeners alive through the #1201 port-uniqueness assert (commit `cf3da837`).

#### Documentation

- Federation operational findings (documented posture, no code change): [#1565](https://github.com/alphaonedev/ai-memory-mcp/issues/1565) — the default `--quorum-timeout-ms 2000` is same-DC-tuned; cross-region quorum pushes hit `deadline_exceeded` → DLQ, and the reference 3-region deploy runs `FED_QUORUM_TIMEOUT_MS=8000` (`deploy/do-1461/provision/lib.sh`). [#1566](https://github.com/alphaonedev/ai-memory-mcp/issues/1566) — an embedding-dimension migration NULLs stored vectors, and receivers used to synchronously re-embed on federation receive (~1 s/row), inflating quorum latency + DLQ pressure during the backfill window. **Resolved by the #1579 train (B1 embed-once-replicate-vector, 2026-06-10):** `sync_push` now ships the sender's stored vector with the row, so the receive path no longer re-embeds.

### v0.7.0 postgres write-path scaling — #1472 epic + #1473 read-path sibling (2026-06-02/03)

Vertical/federated scaling load tests surfaced a Postgres write ceiling that did NOT lift with vCPU. Root-caused to two non-sargable query shapes on the postgres SAL adapter (`src/store/postgres.rs`), not the SQLite single-writer limit. Each fix was proved with a live PG16 `EXPLAIN` plan-shape probe (sargable equality → `Index Cond` vs. the prior `Seq Scan`/`Filter`), gated (fmt + clippy::pedantic + full suite), and committed to `release/v0.7.0`.

#### Performance

- **[#1472](https://github.com/alphaonedev/ai-memory-mcp/issues/1472)** — scope the per-write subscription dispatch from a full-table `Seq Scan` to a sargable namespace-prefix byte-range scan, and route the forensic-audit fsync off the request-thread mutex. On a bare-metal PG16 control the write ceiling lifted **33 → 290 rps (8.5×)**; the metal-control sweep measured **358 → 1067 rps (3.0×)** end-to-end (commits `8bdd7a177`, `4fb063b7c`).
- **[#1473](https://github.com/alphaonedev/ai-memory-mcp/issues/1473)** — make `PostgresStore::list()`'s namespace filter sargable. The optional-filter idiom `($1 IS NULL OR namespace = $1)` is non-sargable under sqlx's generic prepared-statement plan (the planner can't prove `$1` non-null at plan time, so it emits a `Seq Scan` even for an explicit namespace); `list()` now emits a bare `namespace = $1` equality when a namespace is supplied, which plans as an `Index Cond` on `memories_namespace_idx`. Live PG16 `EXPLAIN (GENERIC_PLAN)`: sargable form `Index Cond` cost 11.28 vs. OR-NULL `Filter` cost 47.51 (commit `4fc5e411f`).

#### Tests

- **[#1474](https://github.com/alphaonedev/ai-memory-mcp/issues/1474)** — lockstep-bump the QUAL-10 `src/store/postgres.rs` module-size ceiling 15_500 → 15_650 for the #1472 dispatch fix's +142 LOC; the lockstep bump had been missed in `4fb063b7c` and surfaced as a RED `qual_10` gate (the `--lib` subset that gated the merge does not run the `tests/` integration binaries) (commit `6ba2f3f8c`).
- **[#1473](https://github.com/alphaonedev/ai-memory-mcp/issues/1473)** — new `tests/issue_1473_list_namespace_sargable.rs` proves the plan SHAPE (not wall-clock) via `EXPLAIN (GENERIC_PLAN)` + `SET enable_seqscan = off`, gated on `feature = "sal-postgres"` and skipped without `AI_MEMORY_TEST_POSTGRES_URL` (commit `4fc5e411f`).
- **[#1475](https://github.com/alphaonedev/ai-memory-mcp/issues/1475)** — replace the immediate post-dispatch semaphore-drain assert in `tests/subscriptions_no_thread_spawn_per_subscriber.rs` with a poll-until-drained loop (30 s deadline, 50 ms cadence) so a slow CI host no longer flakes while a genuine permit leak still trips the deadline (commit `c24d0e67a`).

### v0.7.0 security-review epic #1450 — 9-finding hardening sweep (2026-05-31)

Full-spectrum multi-agent security review of the v0.7.0 substrate. Each finding was fixed 1:1 with a regression test, gated (fmt + clippy::pedantic + full suite + audit), and committed to `release/v0.7.0`. Parent epic **[#1450](https://github.com/alphaonedev/ai-memory-mcp/issues/1450)**.

#### Security

- **[#1451](https://github.com/alphaonedev/ai-memory-mcp/issues/1451)** — gate the optimistic-update write path through `GOVERNANCE_PRE_WRITE` on both sqlite + postgres so a versioned `memory_update` can no longer bypass governance (parity with the insert/supersede paths). New `tests/governance_update_hook_1451.rs` (commit `2853b43d2`).
- **[#1452](https://github.com/alphaonedev/ai-memory-mcp/issues/1452)** — `signed_events` now fails CLOSED on a missing signature when a verifier is installed and the row's `attest_level` is not the by-design `"unsigned"` legacy marker, instead of silently accepting it. New `tests/signed_events_fail_closed_1452.rs` (commit `39c05b46b`).
- **[#1453](https://github.com/alphaonedev/ai-memory-mcp/issues/1453)** — reject path-traversal (`..`, absolute escapes) in `memory_skill_export` resource paths via a canonicalization guard (commit `ed301a4fb`).
- **[#1454](https://github.com/alphaonedev/ai-memory-mcp/issues/1454)** — manual `Debug` impls for `AppConfig` + `LlmSection` redact `api_key` as `<redacted>` so a `{:?}` print or tracing line can never leak the credential (commit `a9ea69c21`).
- **[#1455](https://github.com/alphaonedev/ai-memory-mcp/issues/1455)** — shared fail-CLOSED `governance_consultation_unavailable[_inner]` helpers on daemon startup; transient governance-consultation errors block the write unless the operator opts into `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` (commit `148a77eef`).
- **[#1457](https://github.com/alphaonedev/ai-memory-mcp/issues/1457)** — `match_custom` now evaluates the optional ANDed payload predicates (`namespace_glob` / `tier` / `title_contains`) that were previously declared but never checked, closing a custom-action policy-bypass gap; absent referenced payload fields fail safe (no match) (commit `70fed368f`).
- **[#1458](https://github.com/alphaonedev/ai-memory-mcp/issues/1458)** — extracted a testable `api_key_bind_guard` + `require_api_key_strict` (`AI_MEMORY_REQUIRE_API_KEY`) out of `bootstrap_serve`; a keyless bind to a non-loopback host warns, and strict mode refuses the bind outright (commit `148a77eef`).
- **[#1459](https://github.com/alphaonedev/ai-memory-mcp/issues/1459)** — cap LLM + embedder HTTP responses at 16 MiB (`read_capped_bytes`/`_json`/`_text`, content-length pre-check then streamed accumulation) so a malicious or runaway backend can't exhaust daemon memory (commit `9876d2ab6`).

#### Docs

- **[#1456](https://github.com/alphaonedev/ai-memory-mcp/issues/1456)** — document the `SAFETY` invariant for the cross-encoder `mmap` load in `reranker.rs` (commit `3085c6f54`).

### #626 Layer-3 — claimed→attested agent_id closure on the store write path (2026-06-01)

Closes the §2.2-↔-§2.5 *join* on the write path named in the "Known
property gaps" note above: a remote caller can now cryptographically
attest a memory write at store time, and the substrate verifies it
fail-closed rather than trusting the claimed `metadata.agent_id`.
Parent epic **[#626](https://github.com/alphaonedev/ai-memory-mcp/issues/626)**;
decorrelation theme cross-referenced from
**[#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171)**.

The bounded architecture lift landed across C1–C8: C1 `SignableWrite`
signing + C2 pubkey wire validator (`cb6ecdd51`), C3 bind/fetch agent
pubkey in registration metadata (`bd173cf81`), C4 `verify_write` +
`attest_write` gate + helpers (`8e6d29c39`, `7e290f981`, `46a49e409`),
C5 CLI `bind-key`/`revoke-key` + `--sign` (`c58fea751`, `44ec4a4e0`).
This batch completes the surface with C6 + C7:

#### Added

- **C7 — store-path signature wire across all three surfaces.** A caller
  may present a standard-base64 detached Ed25519 `signature` over the
  canonical `SignableWrite` envelope (`agent_id` + `namespace` + `title`
  + `kind` + `created_at` + `sha256(content)`) plus the `created_at` it
  signed. On the MCP `memory_store` tool, the HTTP `POST /api/v1/memories`
  route (both the sqlite and the postgres SAL paths), and the CLI store
  path, the daemon verifies the signature against the agent's bound
  public key and stamps `metadata.attest_level = "agent_attested"` on
  success (adopting the signed `created_at` verbatim). A forged signature
  is rejected with `403 ATTESTATION_FAILED`; a presented signature
  without a paired `created_at`, or with a malformed / stale / post-dated
  `created_at`, is rejected with `400`. New `signature` + `created_at`
  optional fields on the MCP `StoreRequest` and the HTTP `CreateMemory`
  DTOs; new `ATTESTATION_FAILED` error code.
- **`AI_MEMORY_REQUIRE_AGENT_ATTESTATION`** (env table row #48) — a
  fail-CLOSED opt-in. When truthy (`1`/`true`), any store write lacking a
  caller-presented signature is rejected with `403 ATTESTATION_FAILED`
  instead of landing `attest_level = "claimed"`; default `false`
  preserves the v0.6.x permissive posture. Mirrors the federation
  `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` secure-opt-in convention.
- **`prepare_signed_store` shared helper** (`src/identity/attest.rs`) —
  single decode + freshness-window (±`ATTEST_CREATED_AT_SKEW_SECS` =
  300s) validator shared by every write surface so the 400/403 wire
  wording stays byte-identical across MCP, HTTP, and CLI.

#### Tests (C6)

- **`tests/agent_attestation_integrity.rs`** — end-to-end HTTP
  integration over `POST /api/v1/memories` (sqlite): signed write stamps
  `agent_attested` + adopts `created_at`; forged signature → `403`
  `ATTESTATION_FAILED`; signature without `created_at` → `400`; required
  attestation rejects an unsigned write → `403`.
- **`tests/agent_attestation_postgres.rs`** — the same matrix over the
  postgres SAL create path (`create_memory_postgres`) via the fake-PG
  harness (`StorageBackend::Postgres` + `SqliteStore`), covering the
  async `stamp_attestation_async` gate that the sqlite suite never
  reaches.
- MCP `memory_store` unit tests (signed → attested, forged → reject,
  missing/stale `created_at` → error) and `prepare_signed_store` unit
  tests; new `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` truthy-parse pin in
  `tests/config_precedence.rs`.

### v0.7.0 three-surface parity + AttestLevel + SSOT batch (2026-05-30/31)

#### Added

- **[#1443](https://github.com/alphaonedev/ai-memory-mcp/issues/1443)** — `ai-memory expand` CLI subcommand for LLM query-expansion, achieving three-surface parity with the `memory_expand_query` MCP tool + `POST /api/v1/expand_query` HTTP route. CLI count 78→79 (default) / 80→81 (`sal`); SSOT consts + `tests/cli_subcommand_count_invariant.rs` re-pinned (commit `f869eae8c`).
- **[#1416](https://github.com/alphaonedev/ai-memory-mcp/issues/1416)** — HTTP `POST /api/v1/capture_turn` mirrors the MCP `memory_capture_turn` L4 tool through the SAL `capture_turn_idempotent` method so postgres-backed daemons gain a callable L4 turn-capture surface (HTTP route count → 88).
- **[#1427](https://github.com/alphaonedev/ai-memory-mcp/issues/1427)** — `ai-memory store` gains `--kind` / `--citations` / `--source-uri` / `--source-span` / `--entity-id` flags for Form-4/Form-6 parity with the MCP store path.
- **[#1428](https://github.com/alphaonedev/ai-memory-mcp/issues/1428)** — `ai-memory update` gains `--metadata` / `--source-uri` / `--expected-version` flags routed through the optimistic-concurrency gate.
- **[#1430](https://github.com/alphaonedev/ai-memory-mcp/issues/1430)** — extend the `AttestLevel` enum with `SignedByPeer` + `DaemonSigned` variants.
- New SSOT const families in `src/lib.rs`: `ROUTE_*` + `METHOD_*` (**[#1437](https://github.com/alphaonedev/ai-memory-mcp/issues/1437)**), `KIB`/`MIB`/`GIB` byte units, `Memory::FIELD_COUNT`, `MemoryScope` enum, `META_KEY_*` substrate-metadata keys, and `inbox_namespace()` / `INBOX_NAMESPACE_PREFIX` helpers; plus an MCP tool-call param-name SSOT with a parity invariant test.

#### Changed

- Standardize on Rust **MSRV 1.96** across the toolchain.
- **Packaging** — decommission the Ubuntu Launchpad PPA channel; reframe the APT distribution path PPA → `.deb` across docs.
- **LLM substrate** — switch IronClaw A2A + docs examples to OpenRouter Gemma 4 26B, superseding the prior xAI Grok 4.3 curator wiring (ai-memory product line only).
- SSOT migrations (no behavior change): `AttestLevel` literals → `AttestLevel::*.as_str()` (**[#1431](https://github.com/alphaonedev/ai-memory-mcp/issues/1431)**, completed in `89e02ddd3` — the final 17 production emit/compare sites across 9 files, incl. the full `federation_signing_check` path + the governance audit daemon-signing tag, now route through the const); orphan `attest_level="signed"` offload row → `SelfSigned` (**[#1438](https://github.com/alphaonedev/ai-memory-mcp/issues/1438)**); visibility predicates → `META_KEY_*`/`MemoryScope` helpers (**[#1436](https://github.com/alphaonedev/ai-memory-mcp/issues/1436)**); `Tier` parsers → `Tier::from_str` (**[#1432](https://github.com/alphaonedev/ai-memory-mcp/issues/1432)**); `HEADER_AGENT_ID` / `HEADER_CONTENT_TYPE` / `MIME_JSON` / HTTP error-code literal sweeps.

#### Fixed

- **[#1439](https://github.com/alphaonedev/ai-memory-mcp/issues/1439)** — build the CLI recall embedder on a dedicated std thread to avoid a tokio reactor deadlock.
- **[#1440](https://github.com/alphaonedev/ai-memory-mcp/issues/1440)** — daemon must not clobber the operator-configured LLM model with the tier-default Ollama id.
- **[#1442](https://github.com/alphaonedev/ai-memory-mcp/issues/1442)** — service-daemon LLM-key wiring: launchd/systemd units don't inherit shell-rc exports, so the key is now threaded through the unit environment.
- **[#1445](https://github.com/alphaonedev/ai-memory-mcp/issues/1445)** — align the HTTP `expand_query` response envelope key to `expanded_terms` for three-surface parity.
- **[#1444](https://github.com/alphaonedev/ai-memory-mcp/issues/1444)** — prune the stale `for_admin` allowlist entry for `power.rs`.
- **[#1387](https://github.com/alphaonedev/ai-memory-mcp/issues/1387)** — CI `Run tests` (ubuntu-latest) failure root-caused to runner disk exhaustion (`ld` Bus error at the doctest link step), not a flake; fixed by freeing disk before the test step.

### v0.7.0 #1389 layered-capture architecture — L1+L2+L4 production-shipped (2026-05-28→2026-05-30)

The substrate's first-line answer to the #1388 RCA — operator-agent test-plan dialog lost on tmux lockup + SIGKILL. Layered-defense capture architecture canonical in `global/policies` memory `f62cb182`:

- **L1 — Agent discipline.** New `src/recover/nag.rs` `CaptureNagWatcher` with two-tier thresholds (primary 5 turns, escalation 20 turns) emits stderr WARN + `capture_lag` signed events when an agent goes N turns without a `memory_store` call after a substantive user prompt. Wired into MCP `handle_request` dispatch loop per **[#1398](https://github.com/alphaonedev/ai-memory-mcp/issues/1398)**. CLAUDE.md §"Hard rule — `memory_store` FIRST" block (commit `7e98485`) is the agent-side enforcement; the watcher is the substrate-side enforcement. 10 unit tests pin the contract.
- **L2 — Recover-on-boot.** New `src/recover/{mod,parsers/*,transcript_paths}.rs` + `src/cli/commands/recover_previous_session.rs` provides cross-session context rehydration from host transcripts. Resolves per-host transcript paths (Claude Code / Codex / Gemini / auto), parses JSONL turn streams, gap-replays missing turns into ai-memory through the shared `transcript_line_dedup` table (v52). New CLI subcommand: `ai-memory recover-previous-session` — CLI count grew **77 → 78** (default build) / **79 → 80** (`--features sal` or `--features sal-postgres`); SSOT consts `ai_memory::EXPECTED_CLI_SUBCOMMANDS_{DEFAULT,SAL}` + mechanical parity test `tests/cli_subcommand_count_invariant.rs` block silent future drift.
- **L4 — Protocol fix.** New `memory_capture_turn` MCP tool (`src/mcp/tools/capture_turn.rs`) gives hosts a wire-stable turn-boundary persistence API per RFC-0001 (`docs/rfc/RFC-0001-mcp-turn-capture.md`). MCP `--profile full` tool count grew accordingly; the tool count drift gate at `.github/workflows/tool-count-drift.yml` pins the new total. Reference host-adapter shims under `clients/host-adapter-shim/{bash,node,python}/`.
- **L3 — Substrate watcher.** DEFERRED to v0.7.x pending operator dep approval per CLAUDE.md sole-authority (the `notify` crate needs operator-reviewed introduction per `b5461c1e`). Tracked under **[#1389](https://github.com/alphaonedev/ai-memory-mcp/issues/1389)** EPIC.

### v0.7.0 #1389 schema v52 — `transcript_line_dedup` table (2026-05-28)

New table backing RFC-0001 idempotency: composite key `(host_pubkey_b64, line_sha256)` with a `memory_id` FK into `memories(id)`. Both L4 `memory_capture_turn` and L2 `recover_from_transcript` share this dedup row to ensure a SIGKILL between turns never produces a duplicate memory on subsequent rehydration. Lockstep sqlite + postgres migration: `migrations/sqlite/0044_v52_transcript_line_dedup.sql` + `src/store/postgres.rs::migrate_v52` (additive table-create + 2 indexes). Schema constant `CURRENT_SCHEMA_VERSION` bumped 51 → 52 in both adapters; the substrate-doc tests (`current_schema_version_for_tests` SSOT accessor) re-pin the value.

### v0.7.0 substrate hardening — v3 NHI assessment defects + Form-4 wire-truthfulness (2026-05-30)

- **[#1383](https://github.com/alphaonedev/ai-memory-mcp/issues/1383)** (D-v3-1) — persona `mentioned_entity_id` extraction was incomplete on the metadata-only ingest path; postgres branch now denormalises the entity ref on every insert path (commit `0d9b129c`).
- **[#1384](https://github.com/alphaonedev/ai-memory-mcp/issues/1384)** (D-v3-2) — namespace-standard parser silently dropped unknown enum values; now emits a WARN on silent fallback so operator-facing audit picks up the drift (commit `7c19ef0c`).
- **[#1385](https://github.com/alphaonedev/ai-memory-mcp/issues/1385)** (D-v3-3) — HTTP POST `/api/v1/memories` silently dropped the caller-supplied `kind`; both branches of `create_memory` now thread `body.kind` through to the Memory row (commit `28a16f69`). 24/24 Form 6 vocab tests still pass.
- **[#1411](https://github.com/alphaonedev/ai-memory-mcp/issues/1411)** (sister to #1385, discovered while fixing it) — HTTP POST `/api/v1/memories` ALSO silently dropped the caller-supplied `citations` / `source_uri` / `source_span` (Form 4 fact-provenance). Both branches now thread the validated body fields through; new `tests/http_create_memory_form4_provenance_round_trips.rs` (248 LOC, 2 tests) pins the wire-truthfulness contract (commit `615bf5e92`).

### v0.7.0 ship-gate CI-flake closure sweep (2026-05-27)

Closes the three CI flakes filed after the 2026-05-22 SHIP-RECOMMENDED dossier so the integrated `release/v0.7.0` HEAD returns to all-platform-green:

- **[#1372](https://github.com/alphaonedev/ai-memory-mcp/issues/1372)** — `arch_14_route_count_invariant` was failing on `Check (windows-latest)` because the test used literal `\n` anchors against `src/lib.rs`, but the Windows checkout converts `\n` → `\r\n` via `core.autocrlf=true`. Fix: `.replace("\r\n", "\n")` normalization on read in `tests/route_count_invariant.rs` (PR [#1375](https://github.com/alphaonedev/ai-memory-mcp/pull/1375), merge commit `5feca2864`). Verified `Check (windows-latest)` GREEN on PR CI run 26533974559.
- **[#1373](https://github.com/alphaonedev/ai-memory-mcp/issues/1373)** — `Check (ubuntu-latest)` was ENOSPC'ing at the `libai_memory.rlib` release link step. The cumulative `cargo test` + `cargo install cargo-audit` + `cargo build --release` exceeded the ubuntu-latest runner's ~14 GiB free disk ceiling. Fix: pure-shell "Free disk before release build" step in `.github/workflows/ci.yml` that prunes `.NET / CodeQL / Android SDK / GHC` (~35 GiB recoverable) + `cargo clean --profile dev`; gated to `matrix.os == 'ubuntu-latest'` (PR [#1376](https://github.com/alphaonedev/ai-memory-mcp/pull/1376), merge commit `0ed79e176`). Verified `Check (ubuntu-latest)` GREEN on PR CI run 26539354137. No new GitHub Actions added per the project no-external-code-injection rule.
- **[#1334](https://github.com/alphaonedev/ai-memory-mcp/issues/1334)** — CLAUDE.md §"Architecture" and §"Key Modules" both framed the 79→81 CLI subcommand gap as `--features sal-postgres` only, and called `schema-init` "postgres-only". Both framings were wrong: `Migrate` + `SchemaInit` are both gated `#[cfg(feature = "sal")]` per `src/daemon_runtime.rs:311,322` and unlocked by `sal` alone (PR [#1377](https://github.com/alphaonedev/ai-memory-mcp/pull/1377), merge commit `0e30d23f6`). Per the issue's own framing this docs-drift had contributed to false-positive defect filings (#1329); the corrected framing matches the source-of-truth cfg gates.

Same sweep also closed the following pre-existing low-/medium-severity flakes filed 2026-05-25/26 that did not reproduce on the integrated HEAD (per pm-v3.3 flake-not-reproducing-on-head discipline; ai-memory `global/policies` memory `9be30f12-c0ae-4774-b675-5f0b123d0ad8`):

- **[#1374](https://github.com/alphaonedev/ai-memory-mcp/issues/1374)** — `Per-Module Coverage Thresholds` + `Code Coverage` were flagged as failing with `graph "memory_graph" already exists` AGE noise on workflow run 26531463497, but both jobs returned SUCCESS on PR CI run 26533974559 (10-line CRLF-only change cannot affect AGE paths). Closed as transient.
- **[#1332](https://github.com/alphaonedev/ai-memory-mcp/issues/1332)** — DNS-resolver-environment-dependent flake; passes consistently on current HEAD + the full parallel `cargo test` returned GREEN on the most recent PR CI macOS Check. Closed as flake-not-reproducing.
- **[#1333](https://github.com/alphaonedev/ai-memory-mcp/issues/1333)** — `form_1_synthesis` was flagged with "11 failures under `--test-threads > 1`"; all 19 pass under `--test-threads=4` on current HEAD. Closed as flake-not-reproducing.
- **[#1279](https://github.com/alphaonedev/ai-memory-mcp/issues/1279)** — `issue_1201_concurrent_listeners_get_unique_ports` flake under Postgres feature gate; passes consistently on current HEAD + Postgres feature gate returned GREEN on the most recent PR CI run (26m10s). Closed as flake-not-reproducing.
- **[#1336](https://github.com/alphaonedev/ai-memory-mcp/issues/1336)** — claimed pre-existing clippy errors in `benches/hnsw_rebuild_async.rs`; `cargo clippy --all-targets -- -D warnings -D clippy::all -D clippy::pedantic` returns exit 0 with no diagnostics on current HEAD (silently landed during one of the post-`1e33b51d6` refactor passes). Closed as already-fixed.

#### Integrated-HEAD verification (pm-v3.3 recompile-retest discipline)

- `cargo build --release` — exit 0 (3m40s, fresh-binary recompile at HEAD `0e30d23f6`)
- `AI_MEMORY_NO_CONFIG=1 cargo test --release --no-fail-fast` — **7,332 passed | 0 failed | 16 ignored | 312 suites total | 309 test binaries** (a strict superset of the 2026-05-22 dossier's 7,321 / 0 / 0 across 269 binaries; ignored ones are the postgres + AGE + network-bound tests that self-skip without `AI_MEMORY_TEST_POSTGRES_URL` / `AI_MEMORY_TEST_AGE_URL` set)
- `cargo fmt --check` — exit 0
- `cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic` — exit 0, no diagnostics
- `cargo clippy --all-targets -- -D warnings -D clippy::all -D clippy::pedantic` — exit 0, no diagnostics
- `cargo audit` — exit 0, 529 deps scanned, 0 vulnerabilities

Per-PR CI evidence covered each fix's load-bearing platform:

- PR #1375: `Check (windows-latest)` GREEN (1h0m47s) at workflow run 26533974559 / job 78157803589 — the substrate validation of the CRLF normalization.
- PR #1376: `Check (ubuntu-latest)` GREEN (33m04s) at workflow run 26539354137 / job 78176642966 — the substrate validation of the disk-cleanup workflow change.

### v0.7.0 Phase-1 + Wave-A audit-merge campaign (2026-05-25/26)

Documents the **10-PR Phase-1 substrate-fix campaign** that closed the heterogeneous AI NHI assessment defects surfaced via issue [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) (Opus 4.7 Phase-1 report), plus the **Wave-A audit-merge campaign** (PRs [#1346](https://github.com/alphaonedev/ai-memory-mcp/pull/1346)–[#1351](https://github.com/alphaonedev/ai-memory-mcp/pull/1351)) that fixed the SEC / ARCH / QUAL / TEST / PERF lane findings from the 6-agent full-spectrum review.

#### Fixed

- **[#1315](https://github.com/alphaonedev/ai-memory-mcp/issues/1315)** — wire-layer regression discovery / stale-binary diagnosis lesson; surfaced the pm-v3.3 recompile-retest discipline (CLAUDE.md C5 step 7).
- **[#1317](https://github.com/alphaonedev/ai-memory-mcp/issues/1317)** — Phase-1 substrate fix.
- **[#1319](https://github.com/alphaonedev/ai-memory-mcp/issues/1319)** — Phase-1 substrate fix.
- **[#1320](https://github.com/alphaonedev/ai-memory-mcp/issues/1320)** — Phase-1 substrate fix.
- **[#1321](https://github.com/alphaonedev/ai-memory-mcp/issues/1321)** — Phase-1 substrate fix.
- **[#1324](https://github.com/alphaonedev/ai-memory-mcp/issues/1324)** — `capabilities.transcripts.status.enabled` live overlay (`SELECT COUNT(*) FROM memory_transcripts`) — verified at `src/mcp/tools/capabilities.rs:419-453`. Pre-fix the envelope advertised `planned: true, enabled: false` unconditionally.
- **[#1325](https://github.com/alphaonedev/ai-memory-mcp/issues/1325)** — `reflect.depth` caller-asserted cap with `CALLER_DEPTH_MISMATCH` enforcement; `pub depth: Option<i64>` with `#[serde(default)]` (`src/mcp/tools/reflect.rs:143-219,455-460`). schemars `input_schema()` derives directly from `ReflectRequest` so the wire schema reflects the field.
- **[#1326](https://github.com/alphaonedev/ai-memory-mcp/issues/1326)** — Phase-1 substrate fix.
- **[#1327](https://github.com/alphaonedev/ai-memory-mcp/issues/1327)** — Phase-1 substrate fix.
- **[#1331](https://github.com/alphaonedev/ai-memory-mcp/issues/1331)** — Phase-1 substrate fix.
- **[#1340](https://github.com/alphaonedev/ai-memory-mcp/issues/1340)** — Phase-1 substrate fix.
- **[#1341](https://github.com/alphaonedev/ai-memory-mcp/issues/1341)** — Phase-1 substrate fix.

#### Added

- **[#1343](https://github.com/alphaonedev/ai-memory-mcp/issues/1343)** — new CI / substrate primitive landed alongside the 10-PR train.
- **Wave-A audit-merge campaign (PRs [#1346](https://github.com/alphaonedev/ai-memory-mcp/pull/1346)–[#1351](https://github.com/alphaonedev/ai-memory-mcp/pull/1351))** — six post-Phase-1 lane fixes from the 6-agent full-spectrum review:
  - **TEST-5 / TEST-6** — CLI env-var discipline (`AI_MEMORY_*` resolution invariants pinned in `tests/config_precedence.rs`).
  - **ARCH-1** — postgres governance parity (SAL `MemoryStore` trait surface alignment between sqlite + postgres adapters).
  - **PERF-1** — `spawn_blocking` placement audit (offload sync DB work off the tokio reactor on hot paths).
  - **PERF-2** — recall-path lock-contention fix (single-connection mutex narrowed on the HTTP daemon hot path).
  - **QUAL-3** — governance fail-CLOSED saturation; `#1054` policy mechanically enforced across every consultation site.
  - **ARCH-5** — atomisation recursion depth cap (mirrors `#1325` reflect.depth pattern for the atomisation curator).

#### Docs

- **[#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171)** — Opus 4.7 Phase-1 report (heterogeneous AI NHI assessment) published; surfaced the 10-PR Phase-1 campaign + the pm-v3.3 recompile-retest discipline (ai-memory `global/policies` superseding `cd8ede94-3376-4837-b570-9d975290ae08`).

### Documentation

- **Add `docs/cli-design-rationale.md`** — documents why the CLI surface omits a flat `ai-memory reflect` verb despite providing `ai-memory store` and `ai-memory recall`. Reflection composes with the §2.6 bias-displacement architecture (cross-model reflection boundary); the CLI surfaces reflection through actor-named higher-level verbs (`curator --reflect`, `consolidate`) rather than as a flat primitive verb. The substrate primitive remains accessible via `ai-memory mcp` JSON-RPC for debugging and bridge tooling. `ROADMAP.md` §17 cross-references this rationale alongside the existing quality-gate enumeration.

### refactor(#1174) — pm-v3.1 Variables + Constants + Vendor-Neutrality 10-PR train (2026-05-24/25)

Closes [#1174](https://github.com/alphaonedev/ai-memory-mcp/issues/1174) (parent) with unanimous ZERO-DEFECTS-CONFIRMED across three independent decorrelated codegraph-driven QC audits per pm-v3.2 NO FAIL MISSION closure discipline (ai-memory `global/policies` memory `2cb15d34-2399-4611-a020-df6ef91683fe`): Audit A literal enumeration (0 substrate violations across all 6 gated categories), Audit B structural call-graph (25 callers of `DEFAULT_NAMESPACE`, 46 of `SECS_PER_HOUR`, 185 of `tool_names::MEMORY_*`, 132 of `Tier::*.as_str()`, 36 cross-surface refs of `RuntimeContext::global()` — every abstraction exceeds expected minimums), Audit C regression-invariance fault injection (6 contrived violations × 6 categories all caught by `scripts/check-vendor-literals.sh` with cleanup-clean + final-clean exit 0 = GATE-LOAD-BEARING-CONFIRMED).

**Wave 1 — substrate const extraction (6 PRs).** `src/mcp/registry::tool_names` module with 73 canonical MCP tool-name consts ([#1187](https://github.com/alphaonedev/ai-memory-mcp/pull/1187)); `crate::HEADER_CONTENT_TYPE` / `crate::MIME_JSON` HTTP wire consts ([#1188](https://github.com/alphaonedev/ai-memory-mcp/pull/1188)); `crate::SECS_PER_HOUR` (3_600) / `SECS_PER_DAY` (86_400) / `SECS_PER_WEEK` (604_800) named time constants ([#1185](https://github.com/alphaonedev/ai-memory-mcp/pull/1185)); `crate::llm::BACKEND_OLLAMA` substrate-vendor literal sweep ([#1184](https://github.com/alphaonedev/ai-memory-mcp/pull/1184)); `crate::DEFAULT_NAMESPACE` ("global") with explicit disambiguation from `crate::quotas::GLOBAL_NAMESPACE` ("_global") so the storage default and the quota sentinel can no longer be conflated at call sites ([#1190](https://github.com/alphaonedev/ai-memory-mcp/pull/1190)); typed `Tier::Short.as_str()` / `Mid.as_str()` / `Long.as_str()` raw-string sweep ([#1186](https://github.com/alphaonedev/ai-memory-mcp/pull/1186)).

**Wave 2 — static-state extraction + cross-surface containers (5 PRs).** `ACTIVE/OVERRIDE_PERMISSIONS_MODE` dual-source-of-truth collapsed into a single `RwLock` ([#1191](https://github.com/alphaonedev/ai-memory-mcp/pull/1191)); Class A SHOULD statics extracted into `AppState` / metrics registry ([#1195](https://github.com/alphaonedev/ai-memory-mcp/pull/1195)); test fixtures deflaked from vendor-specific `"claude"` literals via fresh canonical `"nhi"`/`"api"` constants in `tests/common::FIXTURE_SOURCE` ([#1189](https://github.com/alphaonedev/ai-memory-mcp/pull/1189)); per-vendor CLI-binary `WrapStrategy` table extracted from `src/cli/wrap.rs` into a new sibling `src/llm_cli_wrap.rs` module ([#1199](https://github.com/alphaonedev/ai-memory-mcp/pull/1199), closes [#1183](https://github.com/alphaonedev/ai-memory-mcp/issues/1183)); **NEW** `src/runtime_context.rs` with `pub struct RuntimeContext` + process-wide `OnceLock<Arc<RuntimeContext>>` singleton (`RuntimeContext::global()` / `global_arc()`) carrying MUST-class statics (`hooks_hmac_secret`, `max_decompressed_bytes`, `audit: Arc<AuditState>`) + SHOULD-class statics (`recall_tracker`, `keypair_cache`) — `AppState.runtime: Arc<RuntimeContext>` threads the singleton onto the HTTP daemon (73 `AppState { ... }` literals updated across production + test trees), MCP stdio + CLI reach the same singleton via the `OnceLock` ([#1204](https://github.com/alphaonedev/ai-memory-mcp/pull/1204), closes [#1192](https://github.com/alphaonedev/ai-memory-mcp/issues/1192) + [#1196](https://github.com/alphaonedev/ai-memory-mcp/issues/1196) + [#1205](https://github.com/alphaonedev/ai-memory-mcp/issues/1205)).

**Wave 3 — load-bearing lint-gate enforcement (1 PR).** `scripts/check-vendor-literals.sh` ([#1200](https://github.com/alphaonedev/ai-memory-mcp/pull/1200)) HARD-BLOCKs (a) vendor-monoculture literals (`"claude" | "openai" | "xai" | "anthropic" | "gemini" | "deepseek" | "groq" | "ollama" | "grok" | "mistral" | "cohere" | "huggingface"`) outside the 7-file substrate carve-out (`src/llm.rs`, `src/config.rs`, `src/mine.rs`, `src/validate.rs`, `src/cli/wrap.rs`, `src/llm_cli_wrap.rs`, `src/harness.rs`) and (b) `Duration::from_secs(3600 | 86400 | 604800 | 3_600 | 86_400 | 604_800 | 7200 | 21600 | 172800)` magic numbers anywhere in production code. The gate's own `--self-test` mode injects a contrived `"anthropic"` literal, verifies the gate trips, then cleans up — providing a CI-side canary against future detection-logic decay. Wired into `.github/workflows/c8-precheck.yml` alongside the existing four cargo gates (fmt + clippy + test + audit). Documented in `CLAUDE.md` §"Lint gates (issue #1174 PR10)".

**Wire impact.** The PR9 ([#1189](https://github.com/alphaonedev/ai-memory-mcp/pull/1189)) `source: "claude"` → `source: "nhi"` / `"api"` test-fixture flip changes the `source` field on memories stored by the test harness only — production daemons preserve caller-supplied `source` verbatim (no live wire change). The PR4 ([#1184](https://github.com/alphaonedev/ai-memory-mcp/pull/1184)) `"ollama"` substrate sweep is internal-only — all wire surfaces continue to accept and emit the literal string `"ollama"` as a backend name. The PR #1199 WrapStrategy module move is purely internal — `src/cli/wrap.rs`'s public surface is unchanged (the move split detection logic from the per-vendor table).

**Adjacent testing-loop discipline fixes (6 issues, filed at moment of discovery per pm-v3 mandate).** [#1175](https://github.com/alphaonedev/ai-memory-mcp/issues/1175) — `memory_reflect` MCP handler hardcoded `source = "claude"` (vendor-monoculture wire defect, fixed in handler). [#1176](https://github.com/alphaonedev/ai-memory-mcp/issues/1176) — `memory_reflect` MCP approval-gate dropped caller-supplied metadata in pending submissions (fixed in pending-bundle preserving full metadata). [#1193](https://github.com/alphaonedev/ai-memory-mcp/issues/1193) — `Check (macos-latest)` CI timing-flake under parallel-test load (fixed in [#1203](https://github.com/alphaonedev/ai-memory-mcp/pull/1203) via `MACOS_TIMING_BUDGET_MULT = 10` on `src/bench.rs` + 9 hooks tests; hybrid Option-1 multiplier + Option-2 quarantine fallback). [#1194](https://github.com/alphaonedev/ai-memory-mcp/issues/1194) — `Postgres feature gate` CI flake (`postgres-backed serve never became ready`); fixed in [#1202](https://github.com/alphaonedev/ai-memory-mcp/pull/1202) with shared `tests/common::wait_for_http_ready` health-check loop (exponential backoff 50ms → 1s cap, 5min overall timeout) replacing 14 hand-rolled `for _ in 0..50 { sleep(100ms) }` 5s-budget polls across postgres+AGE test files. [#1201](https://github.com/alphaonedev/ai-memory-mcp/issues/1201) — `tests/webhook_coverage.rs` mock-HTTP port-collision flake under parallel-binary load; root cause was wiremock 0.6's `MOCK_SERVER_POOL` recycling ephemeral ports between pool members combined with detached `std::thread::spawn` HTTP POSTs from `subscriptions::dispatch_event_with_details` — straggler dispatches from prior tests landed on recycled mocks corrupting siblings' request counts. Fixed in [#1210](https://github.com/alphaonedev/ai-memory-mcp/pull/1210) with two-layer isolation: (1) bypass the wiremock pool by binding a dedicated `127.0.0.1:0` `TcpListener` per test and handing it to `MockServer::builder().listener(...)` so the kernel cannot recycle the port until the listener drops at test end, (2) per-test UUID path (`/hook/<uuid>`) so foreign POSTs cannot be mis-counted, (3) bind retry on EADDRINUSE (5×50ms backoff). [#1206](https://github.com/alphaonedev/ai-memory-mcp/issues/1206) — `daemon_mode_timeout_still_trips_with_drain_task_running` rewritten in [#1211](https://github.com/alphaonedev/ai-memory-mcp/pull/1211) using `tokio::test(flavor = "current_thread")` + explicit `tokio::time::pause()` between two-phase fixture (`start_paused = true` failed because auto-advance leapt over the child `fork+exec` cold-start before its first response), lifting the macOS quarantine PR #1203 had introduced as Option-2 fallback. [#1207](https://github.com/alphaonedev/ai-memory-mcp/issues/1207) + [#1208](https://github.com/alphaonedev/ai-memory-mcp/issues/1208) — executor spawn-retry-with-backoff for transient `EAGAIN`/`ENOMEM`/`EMFILE`/`ETXTBSY` errnos (libc-constant-driven, unix-only via `cfg(all(test, unix))` gate on the fault-injection block + `cfg(unix)` on the classifier itself) + `FailMode::Closed` switch on `on_index_eviction_fires_with_full_payload` so spawn failures surface hard as `ChainResult::Deny` instead of masquerading as `Allow` + `AI_MEMORY_TEST_TIMING_BUDGET_MULT` env-var multiplier on `src/hooks/timeouts.rs::class_deadline` (cfg-gated to test/debug builds, optimizer constant-folds to no-op in release) — landed in [#1209](https://github.com/alphaonedev/ai-memory-mcp/pull/1209) with 6 new pinning tests for the multiplier branches + 5 unit tests for the spawn-retry classifier (`issue_1207_is_transient_spawn_errno_classification`, `_spawn_retry_first_attempt_succeeds`, `_non_transient_errno_surfaces_immediately`, `_recovers_from_transient_eagain`, `_exhaustion_surfaces_last_error`).

**Cargo gates.** All 4 gates green on every PR's CI before merge: `cargo fmt --check`, `AI_MEMORY_NO_CONFIG=1 cargo clippy --tests -- -D warnings -D clippy::all -D clippy::pedantic`, `AI_MEMORY_NO_CONFIG=1 cargo test` (suite count grew from 6903 to 6988 across the train), `cargo audit` (529 deps, 0 vulnerabilities).

**Known follow-up.** [#1212](https://github.com/alphaonedev/ai-memory-mcp/issues/1212) tracks the pre-existing `hnsw::d1_968_tests::concurrent_writes_during_rebuild_consistent_968` flake under `SAL-only feature gate` CI (HNSW async-rebuild double-buffer race under heavy parallel-test load; unrelated to PR #1211's fake-clock scope, surfaced by its CI as testing-loop discipline). Fix in flight on a separate branch.

### fix(config, #1168) — `memory_capabilities.models.*` drift from the v0.7.x #1146 unified resolver (2026-05-24)

Closes [#1168](https://github.com/alphaonedev/ai-memory-mcp/issues/1168). Pre-fix `handle_capabilities_with_conn` and `handle_capabilities_with_conn_v3` reported `models.embedding`, `models.llm`, and `models.cross_encoder` from the compiled [`TierConfig`] preset rather than from `AppConfig::resolve_llm` / `resolve_embeddings` / `resolve_reranker`. Every other LLM-init surface — boot banner (`src/cli/boot.rs`), MCP/HTTP daemon LLM client (`src/daemon_runtime.rs`), curator LLM (`src/cli/curator.rs`), `ai-memory doctor` reachability probe — was migrated to the unified resolver in #1146; the capabilities surface was missed.

**Symptom.** With `[llm] backend = "xai", model = "grok-4.3"` in `~/.config/ai-memory/config.toml`, the boot banner correctly reported `llm: xai:grok-4.3` and the daemon talked to xAI Grok, but `memory_capabilities` returned `"models": { "llm": "gemma4:e4b" }` (the compiled autonomous-tier preset). NHI agents and operator dashboards consulting the capabilities wire got a stale answer that disagreed with the actual LLM client wiring. Runtime correctness was unaffected; the defect was strictly observability.

**Fix.**
- **NEW** `pub struct ResolvedModels { llm, embeddings, reranker }` in `src/config.rs` bundling the three resolver outputs into a single triple consumed by the capabilities surface.
- **NEW** `AppConfig::resolve_models()` wraps the three existing resolvers (`resolve_llm`/`resolve_embeddings`/`resolve_reranker`) so production wrappers thread one struct.
- **NEW** `ResolvedModels::from_tier_preset(&TierConfig)` back-compat constructor synthesises a resolver triple from the compiled tier preset for tests + the legacy `TierConfig::capabilities()` shim — byte-equal output to the pre-#1168 wire shape on every tier.
- **NEW** `TierConfig::capabilities_with_resolved(&self, &ResolvedModels)` is the production entry point. Display logic mirrors the boot banner (`src/cli/boot.rs:420-424`): Ollama backend → bare model id; other backends → `backend:model`; embedder/reranker still honour the tier-preset disable flag.
- **CHANGED** `build_capabilities_overlay`, `handle_capabilities_with_conn`, `handle_capabilities_with_conn_v3` (`src/mcp/tools/capabilities.rs`) gain a required `&ResolvedModels` parameter — no `Option<>`, no silent fall-through. A fn-pointer signature assertion in the new regression test file pins this so a future refactor that drops the parameter fails to compile.
- **CHANGED** `ToolDispatchCtx::resolved_models` (`src/mcp/mod.rs::ToolDispatchCtx`) + `handle_request` slot 2 + the `dispatch_memory_capabilities` forward.
- **CHANGED** `AppState::resolved_models: Arc<ResolvedModels>` (`src/handlers/transport.rs:294`) + `get_capabilities` forward (`src/handlers/system.rs:72,87`).
- **CHANGED** `run_mcp_server` builds the triple once outside the stdio loop (`src/mcp/mod.rs::run_mcp_server`); `bootstrap_serve` builds it once into `AppState` (`src/daemon_runtime.rs::bootstrap_serve`).

**Live MCP probe verification.** Against the live operator config (`[llm] backend = "xai", model = "grok-4.3"`), `printf JSONRPC | ai-memory mcp --profile full | jq '.models'` returns `{"llm": "xai:grok-4.3", "embedding": "nomic-embed-text-v1.5", "embedding_dim": 384, "cross_encoder": "ms-marco-MiniLM-L-6-v2"}` — matches the boot banner + the actual LLM client wiring.

**Test coverage.** 13 new regression tests in `tests/issue_1168_capabilities_resolver_drift.rs` pin: (1) resolver wins for the xAI/grok-4.3 defect on V2 + V3, (2) Ollama bare-model display, (3) `[embeddings]` operator override surfaces, (4-5) reranker enable/disable + model override, (6) keyword-tier embedder-disable wins over stale config, (7) `from_tier_preset` byte-equal to legacy `tier.capabilities()` across all four tier kinds, (8) V2/V3 envelope parity, (9) fn-pointer signature assertion blocks regressions, (10) no-LLM tiers report `models.llm == "none"`, (11) `ResolvedModels::default()` baseline, (12) `build_capability_models` display rules unit-tested across all four LLM-backend shapes (none/Ollama/xAI/OpenAI). All 4685 existing capabilities tests pass unchanged via the back-compat shim.

**Known follow-up.** [#1169](https://github.com/alphaonedev/ai-memory-mcp/issues/1169) tracks `models.embedding_dim` — still sourced from the tier preset (`EmbeddingModel::dim`), drifts silently when an operator picks an embedder model not in the `EmbeddingModel` enum. Out of scope for #1168 (the resolver-drift core defect is fully closed); will land as a separate v0.7.x follow-up.

**Cargo gates.** `cargo fmt --check` ✓ · `cargo clippy --lib --tests -- -D warnings -D clippy::all -D clippy::pedantic` ✓ · `AI_MEMORY_NO_CONFIG=1 cargo test` ✓ (4737/4738 — single unrelated DNS-flake in `subscriptions::tests::test_validate_url_dns_fails_closed_on_dns_failure_1053` passes in isolation and is documented as environment-dependent) · `cargo audit` ✓ (no vulnerabilities, 529 deps scanned).

### Added

### feat(embeddings, #1598) — substrate-native API embeddings + `ai-memory reembed` (2026-06-11)

Closes [#1598](https://github.com/alphaonedev/ai-memory-mcp/issues/1598) (and with it [#1593](https://github.com/alphaonedev/ai-memory-mcp/issues/1593), [#1594](https://github.com/alphaonedev/ai-memory-mcp/issues/1594), [#1595](https://github.com/alphaonedev/ai-memory-mcp/issues/1595)). The #1067 provider-agnostic substrate now extends to the embedder.

- **`[embeddings]` fully API-capable** — `backend` accepts any #1067 vendor alias (`openrouter`, `openai`, `gemini`, …), `openai-compatible` (self-hosted HF TEI / vLLM / llama.cpp-server `/v1/embeddings`), or `ollama` (default). New fields: `base_url` (synonym of `url`; wins when both set), `api_key_env` XOR `api_key_file` (mode 0400 enforced; inline `api_key` rejected at parse time, mirroring `[llm]`), `dim` (override for models outside `KNOWN_EMBEDDING_DIMS`).
- **New env vars** (per-field precedence env > `[embeddings]` > legacy flat > compiled default): `AI_MEMORY_EMBED_BACKEND`, `AI_MEMORY_EMBED_BASE_URL`, `AI_MEMORY_EMBED_MODEL`, `AI_MEMORY_EMBED_API_KEY` (secret). Source consts `crate::config::ENV_EMBED_*`.
- **Fail-closed embedder boot (#1593)** — construction failure degrades semantic recall to keyword mode with a loud stderr ERROR; the chat LLM client is NEVER reused for embeddings (supersedes the #1143 boot-site heuristic).
- **Truthful capabilities (#1594)** — `memory_capabilities` reports the LIVE posture: `embedder_loaded = false` (and `recall_mode_active = "degraded"`) when the remote embedder is failing at request time.
- **Resilient backfill (#1595)** — per-row fallback on batch failure, skip-with-WARN on poison rows, Ollama `truncate: true`.
- **`ai-memory reembed [--namespace <ns>] [--dry-run] [--batch <n>] [--json]`** — vector-space migration tool; re-embeds the corpus under the currently-resolved backend/model. CLI subcommand counts: 79 → 80 default build, 81 → 82 under `--features sal` (`EXPECTED_CLI_SUBCOMMANDS_{DEFAULT,SAL}`).
- **`ai-memory doctor` "Embeddings Reachability (#1598)" section** — probes ollama `/api/tags` or OpenAI-compatible `/embeddings` with the resolved Bearer key; PASS/WARN/CRIT + provenance facts; GPU-policy WARN when `backend = ollama` resolves on a host with no compatible GPU.
- **`KNOWN_EMBEDDING_DIMS`** gained `google/gemini-embedding-2` (3072) + IBM Granite entries.
- **Docs** — two new enterprise reference architectures (`docs/reference-architecture/enterprise-cpu-memory{,-gpu}.md`: CPU+Memory API-embeddings shape, CPU+Memory+GPU local-Ollama shape) registered in the Pages nav, plus a full-spectrum drift sweep across CLAUDE.md / docs/ / README / Pages.

- feat(quotas, #1156): per-namespace K8 quota dimension extension (schema v50). Extends `agent_quotas` PRIMARY KEY from `(agent_id)` to `(agent_id, namespace)` so per-namespace quota allotments hold even when a single agent operates across many namespaces. Pre-v50 rows backfill to the `_global` sentinel namespace, preserving pre-v50 row accounting verbatim. NSA CSI MCP recommendation (c) — defense-in-depth blast-radius controls. Both adapters now at `CURRENT_SCHEMA_VERSION = 50` (`src/storage/migrations.rs` sqlite ladder + `src/store/postgres.rs::migrate_v50()` postgres mirror with `ALTER TABLE ... ADD COLUMN namespace TEXT NOT NULL DEFAULT '_global'` + PK swap + index). New migration file `migrations/sqlite/0042_v50_per_namespace_quota.sql`; 14 integration tests in `tests/per_namespace_quota.rs`.

### feat(mcp, #1154) — daemon serverInfo Ed25519 signing at MCP initialize handshake (2026-05-23)

Closes [#1154](https://github.com/alphaonedev/ai-memory-mcp/issues/1154) (the last remaining partial-coverage edge on the NSA CSI MCP security framework). Substrate-side cryptographic identity attestation at the MCP handshake boundary — the second half of the defense against NSA CSI concern (j) Tool invocation path confusion.

- **New module** `src/mcp/server_identity.rs` (≈360 LOC including doc-comments + 20 unit tests) — declares `DaemonIdentityToSign` struct, `canonical_bytes_for_identity` deterministic JSON canonicaliser, `build_signed_identity` Ed25519 signer, and `verify_signed_identity` round-trip helper. Canonical-bytes discipline mirrors the existing governance-rule signing pattern at `src/governance/rules_store.rs:541`.
- **MCP initialize arm** (`src/mcp/mod.rs`) now constructs and signs an `ai_memory_identity` block on every initialize response when the daemon has an Ed25519 keypair on disk. The block carries `schema_version` (per the SSOT `CURRENT_SCHEMA_VERSION` constant at `src/storage/migrations.rs:532`), `daemon_id` (the resolved daemon `agent_id`), `public_key` (URL-safe base64 of the Ed25519 verifying key), `signed_at` (RFC3339 handshake timestamp), and `signature` (Ed25519 over the canonical bytes of the four preceding fields).
- **TOFU pin workflow** — clients capture the `signature` on first connect and refuse subsequent connects that present a different signature. Closes the tool-name collision attack surface where a misconfigured or adversarial second memory server advertises the same MCP tool names as the legitimate ai-memory daemon.
- **Backwards compatibility — purely additive.** Per MCP / JSON-RPC convention clients ignore unknown response fields. v0.6.4 / v0.7.0 clients continue to function identically. When the daemon has NO keypair on disk (`load_daemon_signing_key` returns `None`), the `ai_memory_identity` block is OMITTED — preserving the v0.7.0 "continuing unsigned" posture from `src/main.rs:116-118`.
- **Zero hot-path impact.** Initialize fires ONCE per MCP session, not on the recall hot path. The Ed25519 sign over ~150 bytes of canonical identity costs ~10-50µs on modern hardware — the 50ms recall p95 budget is untouched.
- **`pub const fn current_schema_version()`** added to `src/storage/migrations.rs` as the production-facing alias of the `_for_tests` SSOT accessor. The new module reads this to publish the schema version in the signed identity block.
- **Test coverage** — 47 dedicated tests pin the contract: 20 module-level unit tests + 27 integration tests in `tests/mcp_initialize_server_signing.rs`. Coverage breakdown:
  - Happy path: signed block present, signature verifies, all five fields well-formed
  - Field-level assertions: schema_version matches SSOT, daemon_id matches resolved agent_id, public_key matches `kp.public_base64()`, signed_at matches input timestamp
  - No-keypair fallback: omitted block when keypair argument is `None` or public-only
  - Backwards compatibility: legacy v0.6.x clients can still parse `serverInfo.name` and `serverInfo.version`
  - Tampering rejection: any post-sign mutation of daemon_id, schema_version, public_key, signed_at, or signature byte breaks verification
  - Malformed-input rejection: non-object inputs, missing required fields, non-string field types, garbage base64, wrong-length keys
  - Cross-rotation TOFU detection: different daemon keypair → distinguishable signature
  - Determinism: identical inputs produce byte-identical canonical bytes and signatures
  - Performance smoke: single sign sub-5ms, 1000 signs under 1 second, 10k no-keypair calls under 10ms
  - Schema-version drift: published schema_version always tracks `CURRENT_SCHEMA_VERSION` constant
- **Zero regression on existing handshake tests** — `mcp_initialize_handshake_succeeds`, `mcp_call_memory_store_then_memory_recall_roundtrip`, `mcp_list_tools_returns_expected_count`, `test_mcp_initialize` (legacy), and all 8 `d4_*_initialize_round_trip` harness coverage tests continue to pass unchanged.
- **Cargo gates green** — `cargo build --lib`, `cargo clippy --lib --tests -- -D warnings -D clippy::all -D clippy::pedantic`, all targeted test suites.

This closure moves the substrate's NSA CSI MCP coverage from **9 of 10 + 1 partial** at v0.7.0 baseline to **10 of 10 structurally addressed** at v0.7.x. All public-facing compliance documentation (docs/compliance/nsa-csi-mcp.html, docs/compliance/nsa-csi-mcp-security-mapping.md, docs/compliance/honest-limitations.md, docs/compliance/index.html, docs/at-a-glance.html, docs/index.html, README.md badge) has been updated to reflect the 10/10 milestone.

### docs(compliance, #1153) — NSA CSI MCP Security Compliance evidence pair (2026-05-23)

Closes [#1153](https://github.com/alphaonedev/ai-memory-mcp/issues/1153) (NSA CSI MCP Security Audit — AI NHI Start Prompts). Procurement-grade public-facing compliance documentation mapping ai-memory v0.7.0 substrate-level primitives to the National Security Agency Cybersecurity Information document on Model Context Protocol security (U/OO/6030316-26 | PP-26-1834, Version 1.0, May 2026).

- **`docs/compliance/nsa-csi-mcp.html`** — dedicated GitHub Pages compliance page (public-facing, procurement-grade). 10 of 10 NSA security concerns + 7 of 7 NSA recommendations + 5 of 5 real-world incident classes structurally addressed, with per-concern and per-recommendation anchor sections, file references, and verification commands for independent procurement-reviewer audit.
- **`docs/compliance/index.html`** — Compliance & Procurement landing page. Hero presents the procurement-grade evidence pair (NSA CSI mapping + honest-limitations companion); adjacent procurement artefacts (Memory Portability Spec v1, ship-gate evidence, A2A-gate evidence, MCP Registry presence); active gap-fix tracking (#1154, #1155, #1156).
- **`docs/compliance/nsa-csi-mcp-security-mapping.md`** — point-by-point mapping document (Task E). 8 sections: front matter, concern mapping table, recommendation mapping table, per-concern narrative (10 paragraphs), per-recommendation narrative (7), real-world incident class coverage (CVE-2025-49596 substrate-native verify-* alternative), honest-limitations cross-reference, citation + non-endorsement disclaimer.
- **`docs/compliance/honest-limitations.md`** — honest-limitations companion document (Task F). Substrate-boundary framing — documents what ai-memory fundamentally cannot defend against regardless of any compliance framework: boundaries below the substrate (OS kernel, filesystem tampering by root, hardware attestation, side-channels, operator keypair compromise) and boundaries above the substrate (LLM hallucination, consumer ignoring exposed provenance signals, prompt injection at LLM input layer, operator policy authoring errors, application-layer authentication beyond agent_id). Modeled on Microsoft AGT `LIMITATIONS.md` discipline.
- **`docs/compliance/_inventory/v0.7.0-capabilities.json`** — machine-readable source-of-truth inventory (Task I). 27 substrate primitives catalogued, each with codegraph anchor (`mcp__codegraph__codegraph_search` / `codegraph_node` references), file path + line numbers, GitHub issue/PR references, grep verification commands, and `verified_in_v0_7_0` boolean. Reproducible at commit `4add7a8528d4c16d696b391ec6e2890269669a84` on `release/v0.7.0`.
- **`docs/compliance/_inventory/v0.7.0-summary.md`** — human-readable rollup of the inventory: 5 newly-documented defensive layers Task I surfaced (RequestValidator input validation, multi-layer DoS defense, substrate-native verify-* family, MCP client attestation, SQLCipher encryption-at-rest), 4 originating-brief corrections applied (schema v48→v49, atom_span→source_span, test count "13k+"→6,961, Memory Portability Spec v1.1→v1), 3 v0.7.x gap-fix candidates (#1154/#1155/#1156).
- **`docs/compliance/_inventory/mcp-registry-submission.json`** — Task H MCP Registry submission metadata. Status: `prepared_pending_operator_authorisation`. Actual submission to the external registry remains operator-gated.
- **Citation additions** — `docs/rationale/academic-context.md` and `docs/RECURSIVE_LEARNING.md` both add NSA CSI document citation as the procurement-grade companion to the Pearl 2009 and Ortega/de Freitas 2026 academic citations.
- **Landing page highlights** — `README.md` adds NSA CSI MCP shield (10/10 concerns + 7/7 recs); `docs/index.html` adds NSA CSI link to hero meta + Compliance & Procurement card to docs grid; `docs/at-a-glance.html` (Atlas) adds 10/10 NSA CSI stat-num + featured compliance card in the Visualization Atlas with cyan border for procurement spotlight.

**Headline coverage at v0.7.0:** 10/10 NSA concerns + 7/7 NSA recommendations structurally addressed at the substrate layer. Tool invocation path confusion (concern j) is PARTIAL at v0.7.0 — captures clientInfo at MCP initialize but does not yet sign serverInfo; full structural closure tracked under #1154 daemon serverInfo Ed25519 signing (v0.7.x follow-up).

**Verification methodology:** codegraph (tree-sitter AST) primary; grep secondary for literal-text capture. Every claim on every public-facing compliance page traces to a `capability_id` in the JSON inventory; every `capability_id` traces to a file path + line number + (where applicable) GitHub issue or PR reference. Verifiable from a fresh checkout via the verify commands documented in `docs/compliance/nsa-csi-mcp.html` §"For procurement reviewers".

**Non-endorsement:** The mapping is one-directional — ai-memory's substrate-level posture relative to NSA-issued guidance. The National Security Agency, the Department of Defense, and the United States Government do not endorse, certify, or recommend ai-memory, AgenticMem, AlphaOne LLC, or any commercial product. References to the NSA document follow its reproduction guidance.

### feat(config, #1146) — enterprise configuration standard (2026-05-22)

Closes [#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146)
(subsumes [#1143](https://github.com/alphaonedev/ai-memory-mcp/issues/1143)).
Consolidates the previously-fragmented configuration surface
(legacy flat fields, `~/.claude.json` `mcpServers.*.env` block,
SessionStart hook env, compiled tier presets, process env) into a
single canonical sectioned schema with one resolver every surface
consumes.

- **Schema v2** — `[llm]` / `[llm.auto_tag]` / `[embeddings]` /
  `[reranker]` / `[storage]` sections in `~/.config/ai-memory/config.toml`,
  plus an explicit `schema_version = 2` field. Legacy v0.6.x flat
  fields continue to parse (deprecation WARN on first load) and will
  be removed in v0.8.0.
- **Canonical resolvers** — `AppConfig::resolve_llm` /
  `resolve_llm_auto_tag` / `resolve_embeddings` / `resolve_reranker` /
  `resolve_storage`. Uniform precedence: CLI > AI_MEMORY_LLM_* env >
  section > legacy fields > compiled default. Resolved shapes carry
  provenance tags (`ConfigSource`, `KeySource`) surfaced by the boot
  banner and `ai-memory doctor`.
- **Single-entry LLM constructor** — `OllamaClient::build_from_resolved`
  replaces every inline env-vs-tier-preset match across 6 LLM-init
  sites (MCP stdio, HTTP daemon, curator-primitives entrypoint,
  atomise CLI, curator CLI, boot banner).
- **Inline-key rejection at parse time** — `[llm].api_key = "<literal>"`,
  `api_key_env + api_key_file` mutex, and the same mutex on
  `[llm.auto_tag]` are all refused. Loader falls back to
  `AppConfig::default()` on rejection so the daemon still boots.
- **`api_key_file` mode 0400 enforcement** — reuses #1055 escape hatch
  (`AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS=1`).
- **New CLI**: `ai-memory config migrate [--dry-run]
  [--also-clean-claude-json]` — rewrites a legacy v1 config to v2
  shape with a timestamped `.bak`. Idempotent.
- **`ai-memory doctor` LLM reachability probe** — new section
  `LLM Reachability (#1146)` resolves the canonical LLM config and
  probes the endpoint with the resolved Bearer key. 7-bucket severity
  partition: INFO (200), WARN (401/403/429/5xx), CRIT (4xx other /
  network / DNS / TLS).
- **Boot banner upgrade** — reports `llm=<backend>:<model>` (e.g.
  `llm=xai:grok-4.3`) when backend is non-Ollama; the historic
  `llm=<model>` shape is preserved for Ollama backends so existing
  scrapers continue to match. Closes the operator-visible defect that
  triggered the campaign (boot banner reporting compiled tier preset
  `gemma4:e4b` while the MCP server was actually routing to
  `xai/grok-4.3`).
- **`ResolvedLlm::Debug` redacts api_key** to `<redacted>`.
- **19 unit tests** pin resolver precedence, inline-key rejection,
  mutex enforcement, alias-fallback API-key resolution, `api_key_env`
  and `api_key_file` paths (incl. 0400 perms check), legacy alias
  canonicalisation, backfill-batch env override, reranker bool→table
  fold, Debug redaction, and v1→v2 migration shape.

Migration: existing v0.6.x deployments boot unchanged with a one-line
WARN nudging them to run `ai-memory config migrate`. Operators who
previously inlined `AI_MEMORY_LLM_API_KEY` in `~/.claude.json`
`mcpServers.memory.env` can migrate the key to `config.toml`
`[llm].api_key_env = "XAI_API_KEY"` (referencing a shell-injected env
var) or `[llm].api_key_file = "/path/to/key"` (mode 0400 file).

### feat(llm, #1067) — provider-agnostic LLM substrate (2026-05-21)

Closes [#1067](https://github.com/alphaonedev/ai-memory-mcp/issues/1067)
(supersedes [#1066](https://github.com/alphaonedev/ai-memory-mcp/issues/1066)).
The historical Ollama-only `OllamaClient` is now a provider-agnostic
LLM substrate. Two wire shapes (Ollama-native `/api/chat` + `/api/embed`
with no auth; OpenAI-compatible `/v1/chat/completions` + `/v1/embeddings`
with `Authorization: Bearer …`) cover every spec-compliant vendor — one
code path each.

- **New `LlmProvider` enum** — `Ollama` | `OpenAiCompatible { api_key }`.
- **New `OllamaClient::from_env()` constructor** reads
  `AI_MEMORY_LLM_BACKEND` (selector + 15 vendor aliases) +
  `AI_MEMORY_LLM_BASE_URL` (per-alias override) +
  `AI_MEMORY_LLM_API_KEY` (Bearer secret) +
  `AI_MEMORY_LLM_MODEL` (vendor-specific identifier). Per-vendor
  fallback API-key env vars honoured: `OPENAI_API_KEY`,
  `XAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` (or
  `GOOGLE_API_KEY`), `DEEPSEEK_API_KEY`, `MOONSHOT_API_KEY` (or
  `KIMI_API_KEY`), `DASHSCOPE_API_KEY` (or `QWEN_API_KEY`),
  `MISTRAL_API_KEY`, `GROQ_API_KEY`, `TOGETHER_API_KEY`,
  `CEREBRAS_API_KEY`, `OPENROUTER_API_KEY`, `FIREWORKS_API_KEY`.
- **`OllamaClient::new_openai_compatible(base_url, model, api_key)`**
  constructor for direct instantiation.
- **15 pre-filled vendor aliases**: `openai`, `xai`, `anthropic`,
  `gemini`, `deepseek`, `kimi` (= `moonshot`), `qwen` (= `dashscope`),
  `mistral`, `groq`, `together`, `cerebras`, `openrouter`,
  `fireworks`, `lmstudio`, plus the generic `openai-compatible`
  escape hatch.
- **`generate()` / `embed_text()` / `is_available()` / `ensure_model()`
  branch on provider.** Strict `is_success()` semantics preserved on
  `is_available` (regression caught by
  `wiremock_tests::test_is_available_returns_false_on_500_response`
  during QC).
- **`build_llm_client` consults `AI_MEMORY_LLM_BACKEND` first.** When
  set, routes through the provider-agnostic path regardless of tier.
  Legacy ollama-only fallback preserved when the env var is unset
  AND the tier has a default `llm_model`. **Tier gating removed** —
  LLM communication is now tier-independent; tier still gates
  embedder + reranker.
- **`infra/lan-parity-test/docker-compose.yml`** updated: `pg-age`
  switched to `build: Dockerfile.pg-age-vector` (#1065),
  `ic-parity-alice` + `ic-parity-bob` set `AI_MEMORY_LLM_BACKEND=xai`
  + `AI_MEMORY_LLM_MODEL=${AI_MEMORY_LLM_MODEL:-grok-4}` +
  `XAI_API_KEY=${XAI_API_KEY:?…}` (REQUIRED via `:?` syntax).
  Healthcheck switched to `CMD-SHELL` with `X-API-Key` so the auth
  middleware doesn't 401 the probe.

**Adoption-funnel widener.** Pre-#1067 the autonomous tier required
local Ollama, forcing every customer to procure / power / maintain a
GPU. Post-#1067 customers pick from a deployment matrix that spans
Raspberry Pi / cellphone IoT edge ($0/mo) to enterprise multi-GPU
clusters ($10k+/mo). The substrate is identical; only the env vars
change. ROADMAP §1067 documents the 10-posture matrix.

**Auto-tag chat-shape follow-up (commit
[`7c7c102a2`](https://github.com/alphaonedev/ai-memory-mcp/commit/7c7c102a2),
wiremock test refresh at
[`06c3965a8`](https://github.com/alphaonedev/ai-memory-mcp/commit/06c3965a8)).**
The IronClaw-on-Grok-4.3 Docker runtime smoke surfaced that pre-fix
`auto_tag` routed through `generate_with_body` (hardcoded to Ollama's
`/api/generate` text-completion endpoint). xAI / OpenAI / DeepSeek /
Kimi / Qwen / etc. don't expose `/api/generate` — only
`/v1/chat/completions`. Fix routes `auto_tag` through the new
`generate_with_model_override` helper which uses the provider-aware
chat-shape (`/api/chat` for Ollama, `/v1/chat/completions` for
OpenAI-compat). Model override (`gemma3:4b` → `grok-4.3`) preserved
across both paths.

Same commit also closes two unrelated 6-agent-review items:

- **postgres `list.agent_id` filter** — `MemoryStore::list` now
  honours the `agent_id` filter on postgres (was silently ignored,
  returning every row regardless of the filter).
- **memory ID path-traversal hardening** — `validate_memory_id`
  rejects `/` `\` `..` `\0` and control chars defense-in-depth ahead
  of any future export-path feature.

### ci(#1068) — mobile target CI coverage (Posture-1a 3-layer ship, 2026-05-21)

Closes [#1068](https://github.com/alphaonedev/ai-memory-mcp/issues/1068).
Lands the three-layer CI coverage for the v0.7.0 Posture-1a (Edge /
Mobile) row from [#1067](https://github.com/alphaonedev/ai-memory-mcp/issues/1067) —
ai-memory's claim to run on iPhone + Android via `aarch64-apple-ios`
and `aarch64-linux-android`.

- **Layer 1 — Cross-compile gate (`.github/workflows/ci.yml`).** New
  `mobile-cross-compile` matrix job: `aarch64-apple-ios` on
  macos-latest, `aarch64-linux-android` on ubuntu-latest with NDK
  r26d via `nttld/setup-ndk` (CC/AR/LINKER env wired to android24-clang
  so rusqlite's bundled SQLite C blob compiles against the Android
  sysroot). Both run `cargo check --no-default-features
  --features sqlite-bundled --lib` on every PR + push to `release/**`.
  Skipped on docs-only PRs.
- **Layer 2 — Release artifacts (`.github/workflows/release.yml`).**
  `mobile-ios` job builds `aarch64-apple-ios` + `aarch64-apple-ios-sim`
  + `x86_64-apple-ios` as static libs, combines via
  `xcodebuild -create-xcframework` into `AiMemory.xcframework` with
  a cbindgen-generated C header + `module.modulemap`, publishes
  `ai-memory-ios.xcframework.tar.gz` + `.sha256`. `mobile-android`
  job builds aarch64 / armv7 / x86_64 / i686 -linux-android `.so` files
  in canonical `jniLibs/<abi>/` layout, publishes
  `ai-memory-android.tar.gz` + `.sha256`. Gated on stable
  (non-prerelease) tags. Until `#[no_mangle] extern "C"` items land
  in `src/lib.rs` (v0.7.x follow-up), the C header is a stub.
- **Layer 3 — Simulator / emulator runtime
  (`.github/workflows/mobile-runtime.yml`).** `ios-simulator` runs
  `tests/mobile_runtime.rs` on iPhone 15 via `xcrun simctl spawn`
  (macos-latest, `aarch64-apple-ios-sim`). `android-emulator` runs
  the same binary on a KVM-accelerated Android API-30 emulator via
  `reactivecircus/android-emulator-runner@v2`. Gated on `release/**`
  push + `workflow_dispatch` (PRs run iOS arm only to keep cost down).
  13 scoped tests under `tests/mobile/` cover fs sandboxing +
  WAL/SHM sibling cleanup, FTS5 + PRAGMA journal_mode round-trip,
  HNSW build/query + zero-vector NaN pin, candle CPU tensor + matmul
  smoke, reqwest + wiremock OpenAI-compat TLS round-trip.
- **`Cargo.toml` `[lib]` `crate-type`** extended to `["rlib", "staticlib", "cdylib"]`
  so the static lib (iOS) + dynamic lib (Android) artifacts can
  actually link. `rlib` default preserved for every other consumer.
- **Docs:** `README.md` new "Mobile platform support (v0.7.0 Posture-1a)"
  section after Install; `CLAUDE.md` new "Mobile target support"
  subsection under Architecture; `ROADMAP.md` cut-list "Mobile SDKs"
  row cross-links #1067 + #1068.

Cost-cap: ~$10/month at v0.7.0 release cadence vs. the $50-150
ceiling the spec set (Android emulator runs gated to `release/**`
push + `workflow_dispatch` only).

### fix(ship-readiness batch, 2026-05-21) — 6-agent review #1015 / #1027 / #1050 / #1065

Closes [#1015](https://github.com/alphaonedev/ai-memory-mcp/issues/1015) /
[#1027](https://github.com/alphaonedev/ai-memory-mcp/issues/1027) /
[#1050](https://github.com/alphaonedev/ai-memory-mcp/issues/1050) /
[#1065](https://github.com/alphaonedev/ai-memory-mcp/issues/1065).
Commit
[`e10830887`](https://github.com/alphaonedev/ai-memory-mcp/commit/e10830887).
Four discrete fixes from the 6-agent v0.7.0 code+security review.

- **#1015 (MEDIUM after restatement) — `rule_cache.rs` doc drift.**
  The module-doc claimed "every write to `governance_rules` from the
  SAME cache-aware caller calls `RuleCache::invalidate_all`" — false.
  No production caller of `rules_store::insert` / `remove` /
  `set_enabled` / `update_signature` invokes `invalidate_all`. Fix:
  module-doc replaced with the honest contract —
  **invalidate-on-restart-only at v0.7.0**. Documents that
  substrate `rules_store` mutators do NOT hold an `Arc<RuleCache>`,
  rule writes happen exclusively via CLI (separate process — daemon
  cache cannot observe sibling writes), the daemon does NOT expose
  an HTTP / MCP rule-write surface at v0.7.0, and operators must
  restart `ai-memory serve` for CLI-side rule changes to take effect.
- **#1027 (CRITICAL) — `run_gc` HTTP route missing `require_admin`
  gate.** `src/handlers/admin.rs:492` `run_gc` emitted an audit row
  but did NOT enforce admin-allowlist membership. Any API-key holder
  could trigger the GC sweep which permanently DELETEs every row
  past `expires_at`. Fix: prepend
  `require_admin(&app, &headers, "run_gc")?` matching the shape of
  `export_memories` (#957) + `forget_memories` (#956). Non-admin
  callers now get `403 FORBIDDEN` before any state change.
- **#1050 (CRITICAL) — `memory_share` advertised but dispatch arm
  missing.** Wire-contract break: `registered_tools()` shipped
  `memory_share`, the handler at `src/mcp/share.rs::handle_share`
  exists, capabilities v3 reports `callable_now=true` under any
  profile containing `Family::Power` — but `TOOL_DISPATCH_TABLE`
  (`src/mcp/mod.rs`) contained no `register_mcp_tool!("memory_share", …)`
  arm. `tools/call memory_share` returned `-32601 unknown tool`. Fix
  adds `dispatch_memory_share(ctx)` wrapper + `register_mcp_tool!`
  arm + two regression tests
  (`every_registered_tool_has_dispatch_arm_1050` +
  `every_dispatch_arm_has_registered_tool_1050`) that pin the
  invariant in both directions so this class of drift cannot recur.
- **#1065 (INFRA) — lan-parity compose uses bare apache/age image.**
  The SAL postgres adapter's `init schema` fails on
  `extension "vector" is not available` because
  `apache/age:release_PG16_1.6.0` doesn't carry pgvector, leaving
  alice + bob IronClaw containers restart-on-failure indefinitely.
  Fix: `infra/lan-parity-test/docker-compose.yml` `pg-age` service
  now uses `build: { dockerfile: Dockerfile.pg-age-vector }` so the
  image layers `postgresql-16-pgvector` on top via apt. Same pattern
  applies to any postgres+AGE deployment with vector recall —
  [`docs/postgres-age-guide.md`](docs/postgres-age-guide.md).

### fix(postgres SAL, 2026-05-21) — #1024 trait update version bump + #1026 run_gc transactional

Closes [#1024](https://github.com/alphaonedev/ai-memory-mcp/issues/1024) /
[#1026](https://github.com/alphaonedev/ai-memory-mcp/issues/1026).
Commit
[`71baf2956`](https://github.com/alphaonedev/ai-memory-mcp/commit/71baf2956).

- **#1024 (CRITICAL) — trait `update` silently skipped version
  bump (Gap-1 contract break on postgres).** `MemoryStore::update`
  SET list omitted `version = version + 1` on postgres. SQLite trait
  bumps it in `src/storage/mod.rs`; the inherent helper
  `update_with_expected_version` (NOT on the trait) was the only
  postgres-side path that bumped version. Result: a postgres-backed
  daemon answering `PUT /api/v1/memories/:id` WITHOUT `If-Match`
  routed through the trait method and left `version` permanently at
  1 — concurrent optimistic-concurrency detection silently broken on
  postgres while the surface looked identical to sqlite. Fix:
  append `version = version + 1` to the SET clause.
- **#1026 (CRITICAL) — `run_gc` archive+delete was NOT transactional
  on postgres.** Fix wraps the archive INSERT + DELETE in a single
  transaction so partial archive+delete state cannot leak after a
  worker panic / network hiccup mid-sweep.

### infra(lan-parity, 2026-05-21) — duplicate `AI_MEMORY_LLM_MODEL` compose keys

Commit
[`360cdb769`](https://github.com/alphaonedev/ai-memory-mcp/commit/360cdb769).
Both `ic-parity-alice` + `ic-parity-bob` carried two
`AI_MEMORY_LLM_MODEL` keys after the #1067 env-var bundle landed,
which broke YAML parsing under stricter parsers. Duplicates removed;
the canonical `${AI_MEMORY_LLM_MODEL:-grok-4}` form is retained.

### refactor(#964) — typed-errors audit on substrate-public API (Wave-2 Tier-B4, 2026-05-21)

Closes #964: full audit of remaining `anyhow::Result<T>` returns on
the substrate-public API surface (handlers, MCP tools, CLI, SAL trait,
storage layer). The issue body's hypothesis was that ~1180 sites
remained mechanical-conversion candidates after #962.

**Audit results** — full per-category table at
[`docs/internal/typed-errors-audit-964.md`](docs/internal/typed-errors-audit-964.md).

- **0 sites converted.** The substrate-public API is already fully
  typed at every layer-crossing boundary post-#962.
- **35 remaining `anyhow::Result` uses** across `src/` (71 raw matches,
  35 actual code sites after excluding `use` imports and doc
  references) fall into four non-substrate-public categories:
  internal helpers (file-private), trait surfaces for plug-in
  extension points (`BackgroundSweeper`, `Embedder`, `LlmCurator`),
  test mock impls (`#[cfg(test)]`), and boot-path entry points
  (`run_mcp_server`, `run_embedding_backfill`, `main`).
- **Substrate-public layer counts at audit time:** 0 `anyhow::Result`
  in `src/handlers/*.rs` (21 files); 0 in `src/store/{mod,sqlite,postgres}.rs`
  (SAL); 67 `StoreResult<T>` trait methods + 175 adapter
  implementations.
- The `anyhow::Result<T>` returns inside `src/storage/mod.rs` are
  the OUTER WRAPPER for typed `StorageError` variants emitted via
  `anyhow::Error::new(StorageError::…)`, downcast at the handler
  boundary via `MemoryError::from(anyhow::Error)`. This is the
  load-bearing pattern #962 established to preserve byte-identical
  wire format while threading typed errors across the layer
  boundary. Removing the wrapper would break the pin-tested
  `.contains("ambiguous ID prefix")` / `.starts_with("link refused:
  reflection cycle")` consumer contract.
- Path B closure (audit + closure-as-evidence) — the issue's
  LOW-ROI hypothesis is confirmed.

**Docs:**

- `docs/internal/typed-errors-audit-964.md` — canonical record of
  the audit, per-category inventory of remaining anyhow sites, and
  the rationale for why the conversion would be counter-productive
  given the post-#962 design.

### docs(#989) — D1.8 docs sweep for the post-D1.x registry split (Wave-2 Tier-D1, 2026-05-21)

Closes #989. Documentation reconciliation for the #972 D1.1 → D1.7
landings (#982 through #988, all closed before this sweep). No code
change — every codebase tweak the recipe references already shipped.

- **`CLAUDE.md` § "Adding New Functionality"** — verified the
  post-#987 "New MCP tool" recipe is current. Added a "wire trimmer
  (post-D1.6 schemars metadata strip)" subsection enumerating the
  fields `strip_docs_from_tools` removes from the bare `tools/list`
  payload: top-level `docs`, `inputSchema.description`,
  `inputSchema.$schema`, `inputSchema.title`, every nested
  `description` under `inputSchema.definitions.*` and
  `inputSchema.properties.*`, and long string `default` values
  (>32 chars).
- **`src/mcp/tools/README.md` (NEW)** — per-tool module pattern
  guide. Covers the file layout, required exports
  (`<Tool>Request` + `<Tool>Tool` + `impl McpTool` + handler),
  parity-test pattern via `crate::mcp::parity_test_helpers::*`, the
  schemars `#`-prefix description quirk + `#[schemars(description
  = "...")]` workaround, the wire-trimmer behaviour, and the
  verbose-drilldown escape hatch (`memory_capabilities { verbose:
  true }`).
- **`docs/v0.7.0/release-notes.md`** — new "v0.7.0 ship-readiness
  session 2026-05-21 — registry refactor (Wave-2 Tier-D1)" section
  near the top summarising D1.1 → D1.7 closure: 73 / 73 schemars-
  derived `McpTool` impls, `tool_definitions()` collapsed from
  ~1100 lines to a 4-line iteration, wire-shape parity test pinning
  against the pre-D1.6 snapshot, per-profile snapshot tests, and the
  compile-time schema ↔ handler invariant.
- **`docs/audience/developer.html`** — verified the "New MCP tool"
  recipe describes the post-#987 modular pattern correctly (no
  edits needed; #1008 already landed the recipe text).
- **`README.md`** — verified the "73 MCP tools" capability framing
  does not carry stale "hand-coded" language (no edits needed).

### refactor(#970) — enum proliferation audit (Wave-2 Tier-D3, 2026-05-21)

Closes #970: full audit of `pub enum` definitions in `src/models/`,
`src/governance/`, and the related `src/audit.rs` / `src/config.rs` /
`src/approvals.rs` / `src/daemon_runtime.rs` surfaces the issue body
implicates ("Memory tier / Memory kind / Memory link relation /
Governance level / Action / Scope").

**Audit results** — full per-enum table at
[`docs/internal/enum-proliferation-audit-970.md`](docs/internal/enum-proliferation-audit-970.md).

- 22 `pub enum` definitions in the target surface; 38 across the
  broader sweep.
- **Zero byte-identical variant-set pairs.** Name-similarity does
  not imply semantic overlap: three "Tier" enums have zero variant
  overlap (memory lifecycle vs confidence bucket vs feature
  capability); five "Decision" enums each carry a different payload
  on their non-`Allow` variants because each models a different
  contract (TOML rule row, K9 pipeline output, external-action
  engine verdict, operator submission, substrate-hook G4).
- **Zero consolidations performed.** Path B closure (audit +
  per-enum doc clarification) — the issue's LOW-ROI hypothesis is
  confirmed; consolidating any pair would force one side to gain
  unused variants or lose distinguishing variants, both make the
  wire contracts worse.

**Inline doc-comment cross-references added** to the close-call
enums so a future reader hitting the symbol via grep doesn't
conclude they're interchangeable:

- `Tier` / `ConfidenceTier` / `FeatureTier` — three orthogonal axes
  sharing only the descriptive `Tier` substring.
- `governance::Decision` — full sibling-enum index in the docstring
  linking to `RuleDecision`, `agent_action::Decision`,
  `GovernanceDecision`, `approvals::Decision`.
- `GovernedAction` / `governance::Op` — substrate-action vs K9-op
  vocabulary distinction (different wire strings, different variant
  counts, different load-bearing surfaces).
- `audit::VerifyFailureKind` / `governance::audit::VerifyFailureKind`
   — same name, different chain shape; the audit chain hashes line
  bytes + line counter, the forensic chain signs rows with Ed25519
  and has no line counter.

**Docs:**

- `docs/internal/enum-proliferation-audit-970.md` — canonical record
  of the audit + the per-enum table + the "Why the issue's
  hypothesis was wrong" rationale.

### perf(#965) — MCP Connection pooling audit: premise invalid, no pool needed (Wave-2 Tier-B5, 2026-05-21)

Closes #965: Refactor Wave-2 Tier-B5 was filed under the premise that
"MCP stdio path holds a single `Arc<Mutex<Connection>>` that
serialises every tool dispatch." Sub-agent H performed the Phase 1
audit; the premise is **verifiably false** against current `HEAD`:

- `src/mcp/mod.rs::run_mcp_server` — opens a plain
  `rusqlite::Connection` via `db::open`. There is no `Arc`, no
  `Mutex`.
- `src/mcp/mod.rs::run_mcp_server` (stdio loop) — The stdio loop is
  `for line in stdin.lock().lines()` — **synchronous and
  single-threaded by JSON-RPC stdio protocol design**. One request
  in, one response out; the next line cannot be read until the
  current one's response is flushed.
- `src/mcp/mod.rs::handle_request` — takes a plain
  `&rusqlite::Connection`. No shared-state wrapper.
- `src/mcp/mod.rs::ToolDispatchCtx::conn` — typed as
  `&'a rusqlite::Connection`. No shared-state wrapper.
- All 56+ `dispatch_memory_*` wrappers take `&ToolDispatchCtx` and
  forward `ctx.conn` as `&Connection`. No tool acquires a lock; no
  tool serialises on a shared mutex.

**Conclusion.** There is no lock contention because there is no
concurrent access. Adding `r2d2` to a single-threaded stdio loop
would add a dependency + per-acquire latency (~µs) for zero
throughput benefit — JSON-RPC stdio at the protocol level serialises
requests regardless of the underlying Connection topology. The
Wave-1 codebase-analysis claim (issue #842 Tier-B bullet) conflated
the HTTP daemon's `Arc<Mutex<(Connection, ...)>>` shape
(`src/handlers/transport.rs:22`) with the MCP path, which has
always been a plain `&Connection`.

**Action taken.**

- Three regression tests in `src/mcp/mod.rs::tests::issue_965_audit_*`
  pin the audit invariants at compile + runtime:
  - `issue_965_audit_tool_dispatch_ctx_holds_plain_connection_ref` —
    compile-time check that `ToolDispatchCtx::conn` is
    `&rusqlite::Connection`.
  - `issue_965_audit_handle_request_takes_plain_connection_ref` —
    compile-time check that `handle_request`'s first argument is
    `&rusqlite::Connection`.
  - `issue_965_audit_serial_dispatch_50_calls_through_single_connection`
    — runtime stress: 50 sequential `memory_store` dispatches
    through a single Connection, asserts every response is
    `error: None` and all 50 rows land in the underlying SQL store.
    This is the meaningful stress shape that the single-threaded
    MCP stdio architecture admits — concurrent dispatch is
    impossible at the stdio JSON-RPC layer.
- `CLAUDE.md` §"MCP server" — new threading-model note that
  documents the single-threaded stdio invariant and explicitly
  states why `Arc<Mutex<Connection>>` is the wrong shape for this
  layer (HTTP path is separate; that's a follow-up).
- `PERFORMANCE.md` — MCP tool dispatch budget row updated to
  reflect the single-threaded ceiling: throughput is bounded by
  the slowest tool's wall-clock, not by lock contention.

**HTTP path documented-but-not-changed.** The HTTP daemon's
`Db = Arc<Mutex<(Connection, PathBuf, ResolvedTtl, bool)>>` shape in
`src/handlers/transport.rs:22` IS a real contention point under
concurrent HTTP load (Axum's task pool admits parallel handler
execution). That refactor is a separate piece of work — tracked
separately and explicitly NOT bundled into this commit per the
audit boundary.

### refactor(#966) — Shared RequestValidator across handlers / MCP / CLI (Wave-2 Tier-C1, 2026-05-21)

Closes #966. Introduces `pub struct RequestValidator` in `src/validate.rs` —
the canonical fluent surface every wire-entry layer (HTTP handlers, MCP tools,
CLI subcommands) now routes DTO-bundling validation through. Pre-#966 the
same `validate_id` + `validate_namespace` + `validate_agent_id` + ... chains
were duplicated across 87 HTTP routes (73 unique URL paths), 73 MCP tools, and 81 CLI subcommands (79 in the default build, 81 with `--features sal` or `--features sal-postgres`);
adding a new cross-field invariant required three audited per-surface edits.

**New surface (zero-cost facade — methods only, no per-call state):**

- `RequestValidator::validate_create(&CreateMemory)` — full DTO field +
  cross-field gate
- `RequestValidator::validate_update(&UpdateMemory)` — partial-update gate
- `RequestValidator::validate_memory(&Memory)` — import / federation receive
  / admin restore stricter gate
- `RequestValidator::validate_link_triple(&source, &target, &relation)` —
  cross-field self-link gate (relation-set + identical-id refusal)
- `RequestValidator::validate_consolidate(&ids, &title, &summary, &namespace)`
  — multi-id consolidation gate (≥2, ≤100, dedup, field-level title/content/ns)
- `RequestValidator::validate_id_and_namespace(&id, &ns)` — the dominant
  pre-#966 duplication bundle (>20 handler sites + >15 MCP sites)
- `RequestValidator::validate_owner_write(&id, &ns, &agent_id)` — id +
  namespace + #977-hardened agent_id ownership write preamble
- `RequestValidator::validate_confidence_and_priority(c, p)` — numeric range
  bundle for callers that synthesize a custom DTO (bulk-create postgres path)
- `ValidationError { field, reason }` — typed failure with explicit field
  attribution; `Display` mirrors the legacy `bail!` shape verbatim so wire-side
  assertions (`error.contains("namespace")`) keep passing without churn

**Sites migrated** (14 files, 22 call-site edits):

- HTTP handlers (9 files): `create.rs`, `memories.rs`, `memories_query.rs`,
  `links.rs`, `kg.rs`, `power_consolidation.rs`, `federation_receive.rs`,
  `federation_signing_check.rs`, `admin.rs`
- MCP tools (4 files): `consolidate.rs`, `link.rs`, `verify.rs`, `kg_invalidate.rs`
- CLI (1 file): `daemon_runtime.rs` (`ai-memory import` validate_memory loop)

**Behaviour:** byte-equal. The facade methods delegate to the existing
`validate_create` / `validate_update` / etc. free functions; the `ValidationError`
→ `anyhow::Error` blanket conversion keeps every `if let Err(e) = ... { e.to_string() }`
site unchanged. The original free functions are preserved as the lowest-level
primitive (callers that pass individual `&str` fields without a DTO still use
`validate::validate_id(...)` directly).

**Tests:** 14 new `RequestValidator::*` tests added under `validate::tests`;
all 143 validate tests + the full 4841-test lib suite remain green.

**Docs:**

- `CLAUDE.md` §"Key Modules" — `validate.rs` row reworded to advertise the
  facade alongside the per-field primitives.

### refactor(#961) — SAL boundary cleanup (Wave-2 Tier-B1, 2026-05-21)

Closes #961: handler-side audit + cleanup of `src/storage/` (legacy direct-sqlite +
typed-error origin) vs `src/store/` (SAL trait + adapters) duplication.

**Audit results** — full per-handler bucket table at
[`docs/internal/sal-boundary-audit-961.md`](docs/internal/sal-boundary-audit-961.md).

- 13 `crate::storage::*` references in `src/handlers/`. After audit: 12 are typed-error
  downcasts (`StorageError::AmbiguousIdPrefix`, `VersionConflict`, `GovernanceRefusal`)
  that the SAL `StoreError` enum does not currently carry — kept with a fresh
  `// SAL-bypass intentional (#961):` comment explaining the contract and pointing at
  the SAL-side `store_err_to_response` mapping that the postgres branch uses instead.
- 127 `db::*` direct-sqlite calls in handlers. After audit: all are inside the
  canonical `if Postgres { app.store...; return; }` dispatch guard; the
  `postgres_route_gate` middleware backstops these so they never reach a
  postgres-backed daemon. Bucket: C (legitimate sqlite-only legacy path retained for
  v0.7.0 binary parity).

**Conversions performed:**

- `src/handlers/federation_receive.rs:603` — `crate::storage::resolve_governance_policy`
  → `db::resolve_governance_policy` (alias hygiene; the rest of the file uses `db::*`).
  Pure rename, no behavior change.
- `src/handlers/federation_signing_check.rs:172` — postgres-parity correction. Pre-fix
  the postgres-receive path stamped reflection rows with the compiled-in default
  `max_reflection_depth` cap (the comment said "`resolve_governance_policy` is
  sqlite-only today", which became stale once the SAL trait wired the method on both
  adapters). Post-fix: routes through `app.store.resolve_governance_policy(&namespace)`
  so postgres-backed daemons honour operator-set per-namespace caps the same way sqlite
  already did via `sync_push`.

**Docs:**

- `CLAUDE.md` §"Key Modules" — `storage/` and `store/` rows reworded to reflect the
  post-#961 contract (storage/ is sqlite SQL primitives + typed legacy errors;
  store/ is the canonical SAL trait + adapters that new DB ops land on first).
- `CLAUDE.md` §"Adding New Functionality" — new "New database operation" paragraph
  documenting the trait-first workflow (trait → SqliteStore → PostgresStore → handler).
- `docs/internal/sal-boundary-audit-961.md` — canonical record of the audit + the
  per-handler-file bucket counts.

### refactor(#969) — JSON Value serialization redundancy audit (2026-05-21)

Wave-2 Tier-D2 audit of `serde_json::to_value` / `from_value` call
sites. Closed with targeted refactor + audit doc per the issue body's
"collapse to single shape per surface" hypothesis. Findings:

- **~245 call sites scanned**; ~209 are test fixtures (legitimate
  `from_value(json!({…}))` partial-construct pattern against
  `#[serde(default)]` fields), ~110 are `to_value(schema)` for MCP
  tool registry, ~70 are production-code wire/DB boundary
  conversions (postgres JSONB binding, federation receive, MCP
  response envelopes, governance payloads), **6 sites were genuine
  redundancy targets**.
- **R1 (3 sites collapsed):** `MemoryDelta` now derives `PartialEq`.
  Pre-#969 `ChainResult` (`src/hooks/chain.rs:177`), `HookDecision`
  (`src/hooks/decision.rs:135`), and `Decision`
  (`src/governance/mod.rs:188`) all hand-rolled equality routed
  through `serde_json::to_value(a).ok() == serde_json::to_value(b).ok()`
  on the (mistaken) premise that `serde_json::Value` was not
  `PartialEq`. `serde_json::Value` derives `Eq + PartialEq + Hash`
  (`serde_json-1.0/src/value/mod.rs:115`); the real blocker for
  `derive(Eq)` is `MemoryDelta`'s `Option<f64>`, which is
  `PartialEq` but not `Eq`. Three hand-rolled `impl PartialEq` blocks
  deleted (~30 lines of branch-matching boilerplate); now plain
  `derive(PartialEq)`.
- **R3 (1 hot-path double-convert collapsed):**
  `src/mcp/tools/store/mod.rs:276,306` called
  `serde_json::to_value(&mem).unwrap_or_default()` twice in the same
  function (K9 permission gate then K3 governance gate) on the same
  read-only `mem`. Hoisted to a single `mem_payload` shared across
  both gates. Saves one clone+serialise per `memory_store` invocation
  on the hot path.
- **Sites intentionally NOT touched:** every
  `src/handlers/hook_subscribers.rs` site (security-critical surface,
  per scope directive); every `src/store/postgres.rs` site (canonical
  JSONB binding boundary); every `src/federation/receive.rs` site
  (canonical peer→typed-Memory wire boundary); the four
  `handlers/{create,admin,memories_query,kg}.rs`
  `payload_for_pending` sites (input-pipeline fail-closed pattern,
  not a 500-response surface — empty `{}` fallback is the deliberate
  fail-closed default the governance gate handles).

Audit doc: `docs/internal/json-value-redundancy-audit-969.md`.

### perf(#968) — HNSW async rebuild + double-buffering (Wave-2 Tier-C3)

The HNSW vector-index rebuild path is no longer synchronous. Prior to this
change every rebuild ran on the request thread: `build_hnsw(&all_entries)`
is CPU-bound (O(N log N) with constant factors that put 100k vectors at
~3-10s on commodity hardware), and the producer's `insert()` call blocked
until the new graph was ready. Search callers contending on the same
inner mutex blocked too — recall p95 spiked from <20 ms to multi-second
on the 200-overflow / 100k-cap edges.

The fix is a double-buffer pattern with background-task swap-in:

- `active` (inside `IndexState`) serves reads. Search holds the inner
  mutex just long enough to collect valid IDs + iterate HNSW results;
  the build itself never runs under this lock.
- `warming: Arc<Mutex<Option<RebuildResult>>>` is the swap-in slot. A
  background `std::thread` (HNSW build is CPU-bound; no tokio runtime
  needed) builds the new graph from a snapshot of `all_entries`, then
  drops it into `warming`. On the next call to `try_swap_warming()`
  (invoked from search, insert, and the `rebuild` shim's post-join
  path) the warmed graph atomically replaces `active`. The mutex hold
  spans only the `std::mem::swap` — microseconds.
- Concurrent writes during rebuild flow into overflow + all_entries
  normally. The swap captures the OVERFLOW LENGTH AT SNAPSHOT TIME
  (not all_entries.len()) and drains only the prefix that's now in
  the new graph; entries inserted after the snapshot remain in
  overflow for the next cycle. No write is ever dropped.
- Rebuild failures: a panic inside the build thread leaves `warming`
  untouched (None); `active` is unchanged. A `RebuildGuard` drop-RAII
  clears the `rebuild_in_flight` AtomicBool whether the build
  succeeded or panicked.

Operator-visible perf win: at the 100k cap eviction edge, `insert()`
returns in microseconds instead of blocking for the multi-second graph
build. Search p95 during rebuild measured at 43 µs (vs. a v0.6 baseline
of seconds) — see `cargo bench --bench hnsw_rebuild_async`.

Four regression tests pin the contract in `hnsw::d1_968_tests`:
`rebuild_async_does_not_block_search_968`,
`rebuild_failure_leaves_active_unchanged_968`,
`concurrent_writes_during_rebuild_consistent_968`,
`rebuild_swap_is_atomic_968`.

The pre-existing synchronous `rebuild()` is preserved as a shim that
delegates to `rebuild_async().join() + try_swap_warming()` so the v0.6
test contract ("the graph is rebuilt by the time this returns") is
unchanged. New code should call `rebuild_async()` directly.

### v0.7.0 ship-readiness session 2026-05-21 — MCP-registry D1.6 split (#987)

- **`refactor(#987)`** — `src/mcp/registry.rs::tool_definitions()` body
  collapsed from the original ~1100-line hand-coded `json!({...})`
  macro to a four-line iteration over the new
  `registered_tools()` function. Each tool's catalog row is now
  derived from its per-tool `McpTool` impl
  (`crate::mcp::registry::McpTool`) via
  `RegisteredTool::of::<T>()`; the schemars `JsonSchema` derive on
  the per-tool `<ToolName>Request` struct produces the `inputSchema`
  on the wire. Net diff: −958 LOC inside `tool_definitions()`,
  +228 LOC of registry scaffolding + tests.

  Phase 1 closed the McpTool coverage gap for 5 lifecycle tools that
  D1.4/D1.5 had not migrated: `memory_delete`, `memory_promote`,
  `memory_forget`, `memory_update`, `memory_gc`. Phase 2 added the
  `RegisteredTool` struct + `registered_tools()` iterator. Phase 3
  collapsed `tool_definitions()`. Phase 4 added a 6-test wire-shape
  regression suite (`src/mcp/registry.rs::d1_6_987_tests`) that pins
  the post-D1.6 catalog against a stored pre-D1.6 snapshot
  (`tests/snapshots/tool_definitions_pre_d1_6.json`).

  Wire-shape allowed-diffs (post-D1.6):
  - Property order (schemars sorts; legacy was insertion-ordered)
  - `default: null` on Option<T> fields vs. typed legacy defaults
  - `additionalProperties: false` added by schemars (tightening)
  - `minimum`/`maximum` range constraints absent (no
    `#[schemars(range)]` on the request struct yet — addable post-D1.7)
  - Empty-struct `inputSchema.properties` backfilled to `{}` by
    `RegisteredTool::to_value()` so the wire shape stays uniform

  Side fix surfaced during enumeration: `src/mcp/tools/share.rs` had
  a `McpTool` impl but was never declared as a submodule of
  `src/mcp/` (orphaned by an earlier refactor). Restored
  `#[path = "tools/share.rs"] mod share;` in `src/mcp/mod.rs` and
  added the missing `version: 1` field to the share row constructor
  (v45 schema Gap-1 drift) so the impl compiles and
  `registered_tools()` can name it. Handler dispatch is still
  missing (tracked separately under #224).

  The "New MCP tool" recipe in `CLAUDE.md` was updated to reflect
  the new contract: define `<ToolName>Request` + `McpTool` impl in
  `src/mcp/tools/<name>.rs`, register in `registered_tools()`, add
  dispatch arm. The pre-D1.6 step "add JSON definition in
  `tool_definitions()`" is gone — `tool_definitions()` is now a
  four-line iteration.

### v0.7.0 ship-readiness session 2026-05-21 — MCP-registry D1.7 (#988)

- **`test(#988)`** D1.7 — schemars-derived registry test campaign.
  Closes the D1.6 (#987) follow-up by pinning the wire shape of
  `tools/list` against committed snapshots and the schema↔handler
  invariant against a deserialise round-trip.

  - **Per-profile `tools/list` snapshots** (5 new files under
    `tests/snapshots/tools_list_<profile>.json` — `core`, `graph`,
    `admin`, `power`, `full`). Each snapshot is the canonical
    2-space-indented JSON with **sorted object keys** at every
    level, so a future schemars-property-ordering bump absorbs
    into the canonicaliser instead of flipping every line. The
    new test file at `tests/mcp_tools_list_snapshots.rs` builds
    each profile via `tool_definitions_for_profile(&Profile::<f>())`
    and asserts byte-equality with the snapshot;
    `AI_MEMORY_BLESS_SNAPSHOTS=1` blesses an intentional change in
    one shot. Full profile snapshot is 73 tools — pins #862's
    canonical count alongside the existing
    `Profile::full().expected_tool_count()` assertion.
  - **Schema↔handler parity invariant** for 5 representative
    tools (`memory_store`, `memory_recall`, `memory_capabilities`,
    `memory_pending_approve`, `memory_link`) at
    `tests/mcp_schema_handler_parity.rs`. Each test pulls the
    `inputSchema.properties` map for the tool out of
    `tool_definitions()`, synthesises a JSON payload with one
    type-compatible placeholder per advertised property, and
    `serde_json::from_value`-ing the payload into the
    corresponding `<Tool>Request` struct. If deserialisation
    succeeds, the handler can extract every advertised field —
    closing the class of bug the pre-D1.6 catalog produced (e.g.
    `memory_capabilities.accept` carrying stale `enum:
    ["v1","v2"]` while the handler had been V1/V2/V3 since A5).
    Per-tool unit tests under `src/mcp/tools/<name>.rs::d1_x_*_tests`
    already pin parity via `derived_props_for`/
    `assert_property_set_parity`; the integration tests layer the
    runtime deserialise check on top so a future regression that
    re-introduces hand-coded schema entries surfaces at runtime
    too. Full coverage of all 73 tools is D1.8 (#989)'s job —
    keeping the budget here at 5 tools mirrors D1.5 (#986)'s
    representative-coverage discipline.
  - **Test-only re-export bundle** at
    `ai_memory::mcp::schema_handler_parity_test_exports::*`
    (`#[doc(hidden)]` so it stays out of the rustdoc surface)
    exposing the 5 representative `<Tool>Request` structs to the
    integration test. Mirrors the existing
    `dispatch_handle_link_for_test` / `handle_archive_purge_for_test`
    pattern; production wire paths still resolve through
    `McpTool::input_schema()`.
  - **C5 token-budget ceiling bump** in
    `tests/token_budget_guard.rs` — trimmed-wire ceiling raised
    from 5000 → 11000 cl100k tokens. The post-D1.6 schemars-derived
    `tools/list` carries per-property `additionalProperties`,
    `format`, and `[T, "null"]` type-array nodes the legacy
    hand-coded payload didn't (measured ~9825 cl100k tokens
    post-D1.6); the 11K ceiling leaves ~1175-token headroom for
    future schema additions. Verbose ceiling unchanged (17K).
    Partial compensation comes from D1.8 (#989) when the
    trimmer's allow-list filtering of schemars metadata lands.

  Gate posture: `cargo fmt --check` GREEN; `cargo clippy
  --no-default-features --features sal,sal-postgres,sqlite-bundled
  --lib --tests -- -D warnings -D clippy::all -D clippy::pedantic`
  GREEN; 5/5 PASS on the snapshot tests; 5/5 PASS on the parity
  tests; 162/162 PASS on the lib `d1_` test set (pre-existing
  D1.1-D1.6 coverage still green).

### v0.7.0 ship-readiness session 2026-05-21 — gate-rerun closures + drift sweep

After the PR #820 merge + the 6-agent review's TB1/TB2 (#977/#978) landed, a
ship-readiness gate-rerun session on 2026-05-21 surfaced four classes of
follow-up work and one perf-regression revert. Audit trail below.

#### Test-fixture drift from the overnight admin-gate cluster

The overnight admin-gate cluster (#936-#960 + #977/#978) correctly tightened
production behavior so non-admin callers can no longer reach 25+ admin-gated
endpoints. Three test fixture surfaces still asserted pre-tightening
behavior:

- **`#997`** — `tests/handler_postgres_branches_fake_pg.rs` (commit
  [`a8b424fc0`](https://github.com/alphaonedev/ai-memory-mcp/commit/a8b424fc0)):
  8 tests asserting `200 OK` on admin-gated routes (stats, agents, archive,
  archive/stats, taxonomy, namespaces, quota/status, forget). Updated to
  assert `403 FORBIDDEN` with the gate-closing issue (#943/#946/#945/#960/#942)
  cited in each comment. Pattern mirrors the existing
  `pg_export_returns_envelope` (#957) test. 89/89 PASS post-fix.
- **`#998`** — `tests/integration.rs` (commit
  [`325477dcd`](https://github.com/alphaonedev/ai-memory-mcp/commit/325477dcd)):
  the #976/#980 timing collision — `cmd()` and `OneshotDaemon` seeded
  `admin_agent_ids` with the pre-#980 `"*"` wildcard, but #980 made the
  wildcard arm `#[cfg(test)]`-only in the lib (and integration tests link the
  lib without `cfg(test)`, so the arm is dead code). Fix: concrete admin id
  `INTEGRATION_TEST_ADMIN = "ai:integration-test-admin"`, new
  `curl_get_as_admin` / `curl_post_as_admin` / `route_get_as_admin` /
  `route_post_as_admin` helpers, 14 admin-gated call sites updated across 8
  failing tests. 8/8 PASS post-fix.
- **`#1000`** — `tests/l07_3_chunk_d_http_surface.rs` (commit
  [`599347b3c`](https://github.com/alphaonedev/ai-memory-mcp/commit/599347b3c)):
  same root cause as #998. Fix: `TEST_ADMIN_ID = "ai:l07-3-test-admin"`,
  `get_uri_as_admin` + `post_json_as_admin` helpers, 13 admin-gated call sites
  updated (8 GETs + 5 forget POSTs). 160/160 PASS post-fix.

#### Clippy-pedantic regression from #985 future-proofing

- **`#981`** — `tests/postgres_touch_batch.rs` and 9 other fixtures (commits
  [`c2a2d2294`](https://github.com/alphaonedev/ai-memory-mcp/commit/c2a2d2294)
  + [`a19d1b6d6`](https://github.com/alphaonedev/ai-memory-mcp/commit/a19d1b6d6)):
  `#985`'s future-proofing change added `..Memory::default()` rest-pattern to
  106 integration test fixtures so a new `Memory` field lands without
  rewriting every fixture at once. 10 of those fixtures happened to specify
  all 26 current `Memory` fields, which trips `clippy::needless_update` under
  `-D clippy::all -D clippy::pedantic`. Per-site `#[allow]` doesn't work
  where the literal is a method-call receiver (expression-attribute,
  experimental). Fix: file-level `#![allow(clippy::needless_update)]` on the
  10 offending fixture files. Preserves #985's future-proofing intent
  exactly; covers every `Memory { ... }` literal in the file with no behavior
  change.

#### RuleEngineCache perf-regression revert

- **`#990`** (regression report) / revert at commit
  [`8a18c19f3`](https://github.com/alphaonedev/ai-memory-mcp/commit/8a18c19f3):
  `#983` (commit `0ac363f3c`) introduced a process-wide `RuleEngineCache`
  keyed on `AgentAction::kind()` alone. Multi-connection integration tests
  (e.g. `tests/governance_a2a_rules.rs::disabled_rule_at_peer_b_does_not_enforce_even_if_enabled_at_a`)
  hit cross-conn cache poisoning: peer_b's empty rule list was cached under
  `"filesystem_write"` and returned to peer_a's subsequent lookup. Production
  daemon has one connection so the bug was invisible there, but the
  correctness invariant ("two independent SQLite connections never share rule
  state") was broken. Revert restored 5/5 PASS on the governance_a2a_rules
  suite. The 0.5-3ms-per-write perf gain is recoverable post-ship via the
  redesign tracked at **`#991`** (per-Connection UUID-wrapped cache).

#### Orphan-commit audit-trail reconciliation

Five overnight commits forward-referenced issue numbers `#981`-`#985` for
unrelated perf/test/fix work; those numbers were filed for the present
session's clippy regression (`#981`) and the `#972` MCP-registry split
(`#982`-`#989`), leaving the original commits' issue refs pointing to
unrelated surfaces. Retroactive bookkeeping issues filed and closed to
restore the audit trail:

- **`#992`** ([commit `25aaad36a`](https://github.com/alphaonedev/ai-memory-mcp/commit/25aaad36a))
  — HNSW `semantic_phase` batch fetch via `get_many` (was tagged `#981`).
- **`#993`** ([commit `844a48328`](https://github.com/alphaonedev/ai-memory-mcp/commit/844a48328))
  — recall handler lock-acquisition order inversion (was tagged `#982`).
- **`#994`** ([commit `0ac363f3c`](https://github.com/alphaonedev/ai-memory-mcp/commit/0ac363f3c))
  — `RuleEngineCache` (was tagged `#983`; reverted via `#990`; redesign at `#991`).
- **`#995`** ([commit `b51fbb424`](https://github.com/alphaonedev/ai-memory-mcp/commit/b51fbb424))
  — `require_admin` returns 400 instead of `anonymous:invalid` sentinel
  (was tagged `#984`).
- **`#996`** ([commit `d450c6e25`](https://github.com/alphaonedev/ai-memory-mcp/commit/d450c6e25))
  — future-proof 106 fixtures with `..Memory::default()` rest-pattern (was
  tagged `#985`).

Each new `#981`-`#985` carries a cross-reference comment pointing at its
retro counterpart. Commit subjects on the original five remain untouched
(history preserved); the breadcrumbs to the actual work surface live in the
retro issue bodies + cross-ref comments.

#### `#972` MCP tool-registry split (planning)

Per operator directive 2026-05-21 ("take all 9 Wave-2 Tier-B/C/D carve-outs
in v0.7.0"), the originally-3-4-week `#972` (MCP tool registry schema-binding
tightening) was split into 8 dependency-graphed sub-issues. Filed:

- **`#982`** D1.1 — schemars dep + `McpTool` trait + PoC on
  `memory_capabilities` (foundation, blocks all others).
- **`#983`** D1.2 — schema generation pipeline (JsonSchema derive + parity
  test).
- **`#984`** D1.3 — migrate 5 default `--profile core` tools to per-tool
  schemars (depends on D1.1+D1.2; proves pattern).
- **`#985`** D1.4 — migrate ~25 tools in `core`+`graph`+`governance`
  families. Parallel-safe with D1.5.
- **`#986`** D1.5 — migrate ~40 tools in `power`+`meta`+`archive`+`other`
  families. Parallel-safe with D1.4.
- **`#987`** D1.6 — delete the giant `tool_definitions()` `json!` macro after
  all per-tool modules land.
- **`#988`** D1.7 — test campaign (per-profile `tools/list` snapshots +
  compile-time schema↔handler invariant + token-budget gate).
- **`#989`** D1.8 — docs sweep (CLAUDE.md "New MCP tool" recipe,
  release-notes, CHANGELOG, per-tool README).

#### Wave-2 Tier-C2 — recall dispatch DTO (`#967`)

- **`#967` — refactor: `recall_response` and `handle_recall` collapse
  17+ positional args into the canonical `RecallRequest` DTO**.
  Pre-#967 the three recall surfaces (HTTP, MCP, CLI) each marshalled
  17+ scalar parameters one-by-one through `recall_response` /
  `handle_recall` / `run_with_embedder`. Adding a new wire field
  (Form-6 `kinds`, Form-4 `has_citations`, `session_id`,
  `confidence_tier`, …) meant editing four signatures and four
  call sites.

  Sub-A's D1.3 #984 work already introduced `RecallRequest` in
  `src/mcp/tools/recall.rs` for schemars-derived schema. #967
  promotes the struct to `src/models/recall_request.rs` so all three
  surfaces marshal into it ONCE — one struct serves both schemars
  derivation AND runtime dispatch (option (a) in the issue rubric).

  - Constructors per surface: `from_mcp_params(&Value)` /
    `from_http_query(&RecallQuery)` / `from_http_body(&RecallBody)` /
    `from_cli_args(&cli::recall::RecallArgs)`.
  - `KindsFilter` enum promoted alongside; backward-compat re-export
    from `mcp::tools::recall::KindsFilter`.
  - HTTP `recall_response`: 15 positional args → 5 (DTO + 3 entry-
    handler-resolved scalars + caller principal). The legacy
    `apply_recall_scope_defaults` tuple helper is replaced by
    `splice_recall_scope_into(&mut RecallRequest, &AppState)` which
    mutates the DTO in place — request shape stays authoritative
    through the rest of the handler. Net: -44 LOC in the HTTP
    handler.
  - MCP `handle_recall`: split into a thin `&Value`-accepting wrapper
    + canonical `handle_recall_dto(conn, req: &RecallRequest, ...)`.
    The 18 in-line `params["foo"].as_*()` extractions collapse into
    typed DTO accessors. `parse_kinds_filter` deleted — its
    responsibility is now on `KindsFilter::parse()` on the canonical
    DTO with the Cluster-E COR-4 #767 contract pinned in unit tests.
  - CLI: no production changes; `cli::recall::RecallArgs` was already
    the CLI's DTO. `from_cli_args` constructor provides the canonical
    bridge.
  - D1.4 (#985) parity test green: 44/44 PASS. D1.3 (#984)
    recall_parity test green: 7/7 PASS. Saturation-on-`u64::MAX`
    contract preserved via constructor-level clamp + new regression
    tests (`from_mcp_params_limit_u64_max_saturates`,
    `from_mcp_params_budget_tokens_u64_max_saturates`).
  - 18 new unit tests in `src/models/recall_request.rs` cover
    constructor happy / missing-context / full-field-set / kinds-
    array+CSV / COR-4 declared-empty / saturation / round-trip serde.

#### Documentation drift umbrella

- **`#999`** — umbrella issue for the v0.7.0 doc + GitHub Pages
  reconciliation against the overnight cluster (#936-#960, #977-#980, #997,
  #998, #1000, revert #990). Three categories of stale claims targeted: (1)
  `AI_MEMORY_ADMIN_AGENT_IDS=*` recommendations (`*` no longer works post
  #980; explicit admin ids required), (2) `permissions.mode = advisory`
  default claims (now `enforce` per v0.7.0 secure default), (3) "open"
  admin-plane endpoints (now require `X-Agent-Id` matching the
  `admin_agent_ids` allowlist on 25+ routes). Sweep + verification covered
  by the CHANGELOG entries above; the explicit-recommendation drift was
  largely already corrected by the time the sweep ran (README, governance.md,
  ADMIN_GUIDE.md, MIGRATION_v0.7.md, decision-maker.html all carry the
  correct v0.7.0 statements).

### v0.7.0 6-agent release-review tag-blockers (TB1 + TB2)

After PR #820 merged the 259-commit ship-hardening bundle into
`release/v0.7.0`, a 6-agent code-security review surfaced two
tag-blocking findings + 16 high-priority items. The two tag-blockers
landed first on the `fix/v070-tag-blockers-from-6agent-review` branch:

- **`#977` — CRITICAL · reserved-name authz bypass on the wire**
  ([commit `d81df2d7c`](https://github.com/alphaonedev/ai-memory-mcp/commit/d81df2d7c)).
  `validate_agent_id("daemon")` accepted the string at
  `src/validate.rs:233-246`; `resolve_http_agent_id` returned the
  header value verbatim. A wire caller setting `X-Agent-Id: daemon`
  (or the same via MCP-tool `agent_id` field, HTTP body `agent_id`
  field) reached `CallerContext.principal == "daemon"` and bypassed
  every cross-tenant ownership gate that carved out `caller ==
  "daemon"` as the internal-admin path (9 production sites across
  `src/handlers/{parity,links,kg,hook_subscribers}.rs` +
  `src/mcp/tools/namespace.rs`). Sister bypass on `"system"` at
  `hook_subscribers.rs:412,577,699` (legacy-unowned marker, plus
  unowned-claim rewrite). Fix splits `validate_agent_id` into
  `validate_agent_id_shape` (shape-only, used by `keypair::load`/
  `generate`/`ensure_keypair`/on-disk `.pub` scan so the daemon's own
  `DAEMON_KEYPAIR_LABEL = "daemon"` self-signing keypair still loads)
  + `validate_agent_id` (wire-side: shape + reserved-name reject for
  `daemon`/`system`/`federation-catchup`/`subscription-dispatch`/
  `ai:http-internal`/`ai:migrate`/`export-internal`/`governance-internal`).
  Internal `CallerContext::for_admin(...)` constructions bypass the
  validator by design. 7-case regression suite at
  `tests/security_reserved_agent_ids_977.rs`.
- **`#978` — HIGH · federation `sync_since` legacy-row visibility bypass**
  ([commit `5bd43f0bd`](https://github.com/alphaonedev/ai-memory-mcp/commit/5bd43f0bd)).
  `src/handlers/federation_sync_since.rs:107-115` `has_ownership_signal`
  carve-out projected any row that lacked BOTH `metadata.scope` AND
  `metadata.agent_id` through the federation pull UNCHANGED — same
  cross-tenant leak surface the visibility-gate cluster
  (#940/#942/#944/#946/#947/#948/#956/#959/#960/#974/#976) closed on
  every other handler. Fix drops the carve-out; new
  `federation_projectable` predicate honours operator-explicit
  `metadata.federation_share == true` (strict-bool — string `"true"`
  and integer `1` do NOT pass), falls through to
  `crate::visibility::is_visible_to_caller` for every other row.
  `AI_MEMORY_FED_SYNC_TRUST_PEER=1` full-dump escape hatch preserved
  for legacy peers. 7-case regression suite at
  `tests/federation_legacy_row_visibility_978.rs`; `#239` baseline
  fixture updated to stamp the explicit opt-in.

### v0.7.0 ship-hardening bundle backfill (121 issues from PR #820 merge)

The 259-commit merge into `release/v0.7.0` (PR #820, merge commit
`ea4b6e2ad`) contained 160 unique issue references. The
`[Unreleased]` section above already documented the largest themes
(#973 provenance deconfliction, #800 Batman activation, #850
RuleEngine, #819 hermetic tests, #851 HTTP error sanitization, #855
env-var ladder, #857-#864 NHI re-run batch, #884-#895 + #973 Gap 1-7
sprint). The 121 entries below close the audit-trail gap for the
remaining issues so the commit log is fully reachable from the
CHANGELOG. Each entry cites the issue number + a one-line summary
distilled from the matching commit subject. Issues without a
dedicated commit subject are referenced from other commits' bodies
(folded-in work, umbrella tracking) and noted as such.

#### Refactor Wave continuation (post-Tier-A1-A7)

- **`#866`** — split `create_memory` into 6 stage helpers
  (agent_id → on_conflict → embed-before-lock → governance → insert →
  fanout).
- **`#867`** — `mcp::handle_request` → registry-table dispatch.
- **`#871`** — split `recall_hybrid_with_telemetry` into stage helpers.
- **`#873`** — `clippy.toml` — `too-many-lines-threshold = 250`.
- **`#880`** — `GovernancePolicy` decomposition (#793-PR-3): flat → 7
  nested sub-structs with `#[serde(flatten)]` for byte-identical wire
  JSON.
- **`#881`** — `store.rs` decomposition (#793-PR-4).
- **`#856`** — multi-agent worktree discipline section in CLAUDE.md
  (in-repo half of the harness-side fix tracked under same number).
- **`#869`** — patch `unwrap_or_default` sites across `handlers/` that
  silently swallow serialization failures.
- **`#878`** — plan-c entrypoint peer-reach preflight + bridge-network
  recipe (operator-facing).
- **`#879`** — plan-c recovery runbook for colima disk-lock.

#### Provenance + capabilities continuation (Gap 1-7 + post-tag fix-batch)

- **`#897`** — restore `src/handlers/http.rs` coverage to 73.19% (was
  14.71% vs 42 floor).
- **`#899`** — cross-test forensic-sink bleed root-cause + regression pin.
- **`#900`** — `PostgresStore::store` round-trips `source_uri` +
  Form-4/Form-5 columns.
- **`#903`** — prune stale schema-version literals in `boot.rs` +
  `config.rs`.
- **`#906`** — thread `source_uri` through `memory_update` storage path
  end-to-end.
- **`#913`** — admin audit-trail emits — full HTTP+MCP+CLI sweep.
- **`#931`** — emit broadcast entry-line + postgres branch trace logs.
- **`#932`** — wire postgres subscription dispatch + HTTP
  `create_memory` webhook fire.
- **`#934`** — route alias `/api/v1/find_paths` → `kg_find_paths` +
  field-name compat (`from_id`/`to_id` aliases for back-compat).
- **`#935`** — forward `x-api-key` on federation catchup GET.
- **`#950`** — postgres subscription dispatch on
  `update/delete/promote/link_create/restore/archive`.

#### Security + visibility cluster (NHI tightening, post-#948)

- **`#929`** — scope MCP ownership gate to explicit-identity callers
  only.
- **`#936`** — MCP `archive_purge` owner gate + `as_admin` opt-in.
- **`#937`** — `delete_memory` sqlite caller-vs-row-owner gate.
- **`#938`** — `kg_invalidate` caller-vs-source-memory-owner gate.
- **`#940`** — `archive_restore` + `archive_by_ids` sqlite
  caller-vs-row-owner gate.
- **`#941`** — folded into #940 owner-gate sweep (no standalone commit).
- **`#942`** — `search_memories` + `forget_memories` caller-owner gates.
- **`#943`** — `list_archive` + `archive_stats` admin gates.
- **`#944`** — `kg_timeline` caller-vs-source-memory-owner gate.
- **`#945`** — `list_namespaces` + `get_taxonomy` +
  `get_namespace_standard_qs` admin gates.
- **`#946`** — folded into the admin-gate sweep + legacy-unowned
  carve-out + lib test fixture wildcard (commit
  `e0e0b55ae`).
- **`#947`** — sqlite legacy path visibility post-filter on `power.rs`
  + `kg.rs`.
- **`#948`** — `sync_since scope=private` visibility gate.
- **`#949`** — admin-role gate on all 7 skill HTTP routes.
- **`#951`** — consolidate `is_visible_to_caller` into non-sal-gated
  visibility module.
- **`#952`** — cfg-gate 6 stale `let _ = X` discards to non-sal profile
  only.
- **`#953`** — C8 caller-context allowlist precheck + CI gate.
- **`#954`** — extract canonical caller-vs-row-owner ownership-gate
  helper.
- **`#955`** — drop `CallerContext::for_agent` literals in non-test
  production code.
- **`#956`** — admin-role gate + provenance restamp on
  `/api/v1/import`.
- **`#957`** — admin-role gate on `/api/v1/export` (close cross-tenant
  corpus exfil).
- **`#959`** — `get_links` visibility post-filter on both backends.
- **`#960`** — folded into the admin-gate + legacy-unowned carve-out
  sweep (commit `e0e0b55ae`).
- **`#974`** — folded into the admin-gate + legacy-unowned carve-out
  sweep (commit `e0e0b55ae`).
- **`#976`** — integration test fixtures align with post-#940/#942/
  #946/#948 gates.

#### NHI provenance lockdown (write-path stamp is header-only post-#907)

- **`#874`** — body `metadata.agent_id` no longer overrides
  authenticated `X-Agent-Id` on the write-path provenance stamp
  (security-high, prevents fake-attribution).
- **`#901, #905, #907`** — siblings of #874 across additional handlers
  (folded references in #874 + #907 commit bodies; no dedicated
  commit per number).
- **`#902, #904, #908, #909, #911, #912`** — folded references in the
  NHI hardening sweep.

#### Postgres + SAL parity

- **`#925`** — `SET LOCAL search_path` in AGE entry points (lan-parity
  isolation).
- **`#926`** — fix lan-parity compose peer-preflight deadlock +
  Dockerfile reference.
- **`#927`** — switch 2 integration tests to per-principal GET helpers.
- **`#928`** — folded reference in the postgres-fixes batch (no
  standalone commit).
- **`#930`** — folded reference in the postgres `update_memory` SAL
  rewrite (commit body of #874/#931).
- **`#939`** — folded reference in the postgres visibility-gate sweep.
- **`#910`** — `postgres_touch_batch` caller matches row owner (SAL
  filter).

#### Federation hardening (signing + nonce + replay)

- **`#791`** — federation per-message Ed25519 signing header.
- **`#793`** — folded references in the federation-signing series
  (no standalone commit; tracked under the #791 umbrella).
- **`#921`** — folded reference in the federation-nonce series.
- **`#922`** — cargo fmt — wrap long `federation_nonce_cache` line in
  test fixtures.

#### Batman Mode write-time-investment continuation (#800 7-form series)

- **`#803`** — per-tool `examples` in `memory_capabilities` `ToolEntry`.
- **`#804`** — AUR PKGBUILD + version-pinning guidance for adoption
  Gap #3.
- **`#805`** — Batman-active write-path latency budgets + v0.7.1
  attack plan.
- **`#806`** — federation/quotas at population scale (N=100 agents,
  M=50 ops each).
- **`#807`** — wire Batman Mode CI gate as REQUIRED PR gate.
- **`#809`** — substrate-resident NHI Persona + model-agnostic cookbook
  + maximum coverage.
- **`#810, #811, #812`** — persona signing pipeline gaps closed
  end-to-end via #813.
- **`#813`** — persona signing pipeline — close #810, #811, #812
  end-to-end.
- **`#815`** — sign `reflects_on` edges from `storage::reflect` via
  threaded keypair.
- **`#816`** — wire curator auto-persona sweep with daemon keypair.
- **`#820`** — PR #820 ship-hardening bundle umbrella issue.
- **`#821`** — dedup governance test helpers into `tests/common/mod.rs`.
- **`#822`** — `rules sign-seed` honors `--key-dir` (dual-layout dir →
  singleton fallback).
- **`#823`** — bump schema literal 42→43 in `s75` + `wt_1_a` tests.
- **`#824`** — bump macOS hook-exec test timeout 30s → 60s.
- **`#825`** — file-wide `#![allow(clippy::too_many_lines)]` for
  postgres-feature build.

#### Doc + infra hardening

- **`#838, #839, #840, #843, #844, #845`** — folded references in the
  Lane-5 documentation drift remediation block above (no standalone
  commits; covered by the comprehensive sweep that touched ~14 doc
  files).
- **`#846`** — v0.7 vs v0.8 recursive-learning roadmap comparison doc.
- **`#848`** — `memory_persona_generate` cross-namespace aggregation.
- **`#868`** — inline test discipline for `handlers/http.rs`.
- **`#870, #872`** — folded references in the doc-drift remediation.
- **`#875`** — align HTML doc surfaces to v0.7.0 numbers.
- **`#876`** — NHI calibration prompts use canonical 71-tool count
  source.
- **`#877`** — auto-migrate embedding column dim to model-canonical
  dim.

#### Typed-error envelopes (post-`deny_message` helper #971)

- **`#962`** — promote substrate refusals to typed `StorageError`
  envelope.
- **`#963`** — wire typed `GovernanceRefusal` through `Deny` variant
  (Phase 1 + Phase 2).
- **`#971`** — extract canonical `deny_message` helper for governance
  refusals.
- **`#975`** — `source_uri` composition + visibility gate parity on
  reciprocal endpoint.

#### Release-gate meta (not closed in this bundle)

- **`#832`** — folded reference in the v0.7.0 release-gate meta tracking
  (umbrella, remains open through the operator's 8-tier gate).
- **`#833, #834`** — Track E1 (DO CPU hive) / Track E2 (AWS GPU burst)
  remain FROZEN per operator decision (operator-$-gated). Issues
  referenced in CHANGELOG so the link from commit → tracker is intact.
- **`#835`** — clean A2A test pages.

#### Long-standing carryover closed under the v0.7.0 windowing

- **`#224, #311`** — folded into the visibility-gate cluster + NHI
  provenance lockdown (no dedicated commit; closed via the post-#948
  sweep).
- **`#228`** — E2E content encryption at rest (X25519 +
  ChaCha20-Poly1305). NOTE: shipped as MVP module
  (`src/encryption/`); the wire-up to `db::insert*`/`db::get` is the
  H4 follow-up tracked under the 6-agent-review High set.
- **`#518`** — session-aware `memory_recall` with recently-accessed
  boost.
- **`#519`** — proactive contradiction detection on `memory_store`.
- **`#652`** — folded reference in the recursive-learning #655 Task
  series (no standalone commit; closed via #655 sub-tasks).
- **`#718`** — A2A campaign harness cross-repo integration contract.
- **`#736`** — cookbook/atomisation recipes 02 + 03 + README.
- **`#797`** — bootstrap SCHEMA crashes on legacy DBs — strip v36+
  partial indexes from sqlite+postgres bootstrap, fix Windows
  `skill_register` path separator, unrot `postgres_schema_parity`.
- **`#798`** — folded into #797 (single commit closes both).
- **`#827`** — parent issue: per-module coverage residuum (split into
  #838 + #839 + #840 — `store.rs` row closed at parent level, the
  three child modules closed in prior coverage commits).
- **`#917`** — folded reference in the post-#874 NHI hardening sweep.

#### Wire-format compatibility statement (v0.6.x → v0.7.0 upgrade)

The 6-agent compat review flagged the following source-level breaks
that operators upgrading from v0.6.x must know about. **HTTP / MCP /
CLI wire shape stays additive throughout** — every visible response
body, capabilities envelope, federation payload, and signed-event
JSON either reads byte-identical to v0.6.x or extends additively via
`#[serde(default)]` / `skip_serializing_if`. The breaks below are
all RUST source-API and do not affect external clients consuming the
HTTP/MCP wire formats.

1. **`GovernancePolicy` flat → nested** (#880). Field path rewrites:
   `policy.write` → `policy.core.write`, same for `promote`/`delete`/
   `approver`/`inherit`/`max_reflection_depth`. Wire JSON unchanged
   (preserved via `#[serde(flatten)]`); only Rust call sites move.
2. **`GovernanceDecision::Deny(String)` → `Deny(GovernanceRefusal)`**
   (#963). `Display` byte-identical to pre-#963. Pattern-match consumers
   read `refusal.reason` (or `refusal.to_string()` for the canonical
   wire shape).
3. **SAL trait signatures gain `&CallerContext`** (#910 / #936).
   `MemoryStore::archive_purge(older_than_days)` →
   `archive_purge(&CallerContext, older_than_days)`;
   `MemoryStore::find_paths(source_id, target_id, ...)` →
   `find_paths(&CallerContext, ...)`. Out-of-tree `MemoryStore` impls
   thread the new arg.
4. **`CallerContext` gains required `bypass_visibility: bool`** (#910).
   Struct-literal callers add the field; the `for_admin`/`for_agent`
   constructors are the supported path and unaffected.
5. **`MemoryError` gains `RefusedByGovernanceGate(GovernanceRefusal)`
   variant** (#963). Exhaustive `match` on `MemoryError` without a
   wildcard arm needs a new arm (wire `code()` = `GOVERNANCE_REFUSED`
   + `status()` = 403 stay identical to the existing
   `RefusedByGovernance(String)` variant).
6. **Federation receivers reject unsigned/no-nonce `/sync/push` by
   default** (#791, #922). Pre-v0.7.0 peers without Ed25519 keys are
   rejected with 401. Operator escape hatch:
   `AI_MEMORY_FED_REQUIRE_SIG=0` + `AI_MEMORY_FED_REQUIRE_NONCE=0`
   during peer rollout. Cut over to signed-by-default once every peer
   in the federation has its Ed25519 keypair installed.

### Added

- **Capabilities v3 `provenance_substrate_layer` narrative surface** (Item C from v0.7.0 provenance deconfliction, issue [#973](https://github.com/alphaonedev/ai-memory-mcp/issues/973)). New `CapabilityProvenanceSubstrateLayer` + `SpecReferences` structs in `src/config.rs` ship a one-shot narrative summary of the substrate's do-calculus posture so an LLM agent reading `memory_capabilities` can self-describe accurately without parsing the seven Provenance Gap blocks individually. The default helper carries the v0.7.0 source-verified `enforcement_layers` list (`form_4_fact_provenance`, `form_6_memory_kind`, `form_7_agent_external_governance`, `signed_events_v4_chain`, `seven_gap_framework`), the two `honest_limitations` axes (intra-session hallucination is consumer-LLM responsibility; federation reliability is DLQ-tracked, not silent-drop), and vendor-neutral spec_references (Pearl 2009 + Ortega & de Freitas 2026). Honesty-discipline: every entry in `enforcement_layers` corresponds to an actually-shipped feature with a grep anchor in the helper docstring. Wired into `CapabilitiesV3::to_v3()` so MCP + HTTP both surface it. 7 integration tests pin posture / source-verified `enforcement_layers` / honest_limitations axes / vendor-neutral spec_references / summary word budget / serde round-trip / serde-default empty-JSON tolerance. Backward-compat preserved via `#[serde(default)]` on every field.
- **`docs/provenance.md` — academic grounding section** (Item A, issue [#973](https://github.com/alphaonedev/ai-memory-mcp/issues/973)). New "Academic grounding" section at the top of the Form 4 fact-provenance doc cites Pearl's do-calculus (2009) and Ortega & de Freitas (2026) as the theoretical anchor for why Form 4 + the 7-level Provenance Gap framework are the right substrate-level distinctions. Procurement-reviewer anchor.
- **`docs/RECURSIVE_LEARNING.md` — substrate-vs-application boundary section** (Item B, issue [#973](https://github.com/alphaonedev/ai-memory-mcp/issues/973)). Clarifies that the Ortega "delusion amplification" result is a training-layer phenomenon; ai-memory operates at the storage layer and stops *cross-session* delusion amplification while leaving *intra-session* hallucination as the consumer-LLM's responsibility. Adds a second axis: the substrate's evidence claim depends on federation reliability (v48 `federation_push_dlq` from [#933](https://github.com/alphaonedev/ai-memory-mcp/issues/933)) as much as on cryptographic attestation.
- **`docs/rationale/academic-context.md` — public-facing explainer** (issue [#973](https://github.com/alphaonedev/ai-memory-mcp/issues/973)). New procurement-team-audience document mapping the Pearl + Ortega & de Freitas + de Freitas RL/diffusion papers to ai-memory's substrate-level discipline. Walks the five mechanisms (Form 4 + Form 6 + Form 7 + signed-events V-4 chain + seven-gap framework), the plain-English translation, the honest limits (no truth guarantee — traceability guarantee), and the AgenticMem commercial layer. Posted-eligible.

### Changed

- **`ROADMAP.md` — doc-drift correction blocks on §7.3 and §17** (Item D, issue [#973](https://github.com/alphaonedev/ai-memory-mcp/issues/973)). Both sections were dated 2026-04-29 and 5+ weeks stale. Added explicit doc-drift notes citing live schema v48 on both ladders (in lockstep), 73 MCP tools at `--profile full` per `Profile::full().expected_tool_count()`, 7-level Provenance Gap framework #884-#890 all shipped, Batman Forms 1-6 + Form 7 implemented (with the canonical-bytes signing fix `3cdec59`), recursive learning #655 Tasks 1-8 all shipped, federation push DLQ + replay worker. Authoritative-references discipline: read from `src/storage/migrations.rs` + `src/store/postgres.rs:424` + `Profile::full().expected_tool_count()` + `docs/v0.7.0/release-notes.md` + this CHANGELOG `[Unreleased]` section, not from hardcoded numbers in the body of ROADMAP.md (which go stale).
- **`CLAUDE.md` — `CURRENT_SCHEMA_VERSION` references v47 → v48**. Two stale references in the Key Modules table + Database section updated to reflect the #933 federation_push_dlq schema bump.


- **`docs/batman-active-mode.md` + `docs/batman-active-mode.html` — operator how-to for Batman Mode activation** (issue [#800](https://github.com/alphaonedev/ai-memory-mcp/issues/800)). v0.7.0 ships 6 of 6 Batman write-time-investment forms + the 7th (all `IMPLEMENTED`) but a default install is **Batman-capable, not Batman-active**: opt-ins off, operator key absent, R001–R004 unsigned and disabled, curator daemon not running, namespace policies for Form 5 shadow_mode + Form 6 auto_classify default off. New operator-facing how-to walks the 7-step activation recipe (operator keygen → sign-seed → enable R001–R004 → curator daemon → optional reflection-pass → namespace policies → permanence), per-OS persistence (launchd plist for macOS, systemd user unit for Linux, Task Scheduler for Windows), verification block, rollback path, and the known wart that `ai-memory rules keygen` writes to `<config-dir>/operator.key` while `rules enable` looks in `<config-dir>/keys/operator.key`. GitHub Pages atlas wired into the Internals dropdown of `docs/index.html`. Cross-linked from `docs/governance.md` and `README.md` v0.7.0 highlights. Acceptance test suite at `scripts/batman-mode-acceptance.sh` pins all 7 forms against a Batman-active install.
- **`RuleEngine` — unified rule-load + decision routing for governance** (issue [#850](https://github.com/alphaonedev/ai-memory-mcp/issues/850), Wave-2 Tier-A2). Single `pub struct RuleEngine { rules: Vec<Rule> }` in `src/governance/agent_action.rs` exposes `load_for_action(conn, action)` + `from_rules(Vec<Rule>)` + `evaluate(agent_id, action) -> Decision` + `rules()`. Three legacy entry-point functions (`check_agent_action`, `check_agent_action_no_audit`, `count_matching_rules`) collapse to thin wrappers; `check_agent_action_deferred` transitively uses RuleEngine via `_no_audit`. Combinator semantics preserved verbatim (first-refusal-wins, warn-short-circuit, log-silent, L1-6 signature gate). 286 lines added, 77 lines deleted. Adding a new severity variant or matcher field now touches one engine, not three loops.
- **`force_no_operator_pubkey_for_test()` — thread-local test guard for `resolve_operator_pubkey`** (issue [#819](https://github.com/alphaonedev/ai-memory-mcp/issues/819)). `#[cfg(test)] pub fn` in `src/governance/rules_store.rs` returns a RAII guard that forces pubkey resolution to return `None` for the duration of the current scope on the current thread. Eliminates env-mutation races between parallel tests and matches clean-HOME CI behavior on dev hosts that have staged an operator.key.pub. 15 tests across `governance::agent_action::tests`, `mcp::check_agent_action::tests`, and `mcp::rule_list::tests` patched to hold the guard; all now pass on dev hosts where they previously failed.
- **`sanitize_bulk_row_error` / `bad_request_opaque` / `internal_error_response` — HTTP error sanitization helpers** (issue [#851](https://github.com/alphaonedev/ai-memory-mcp/issues/851), Wave-2 Tier-A3 SECURITY). `pub fn` exposures in `src/handlers/mod.rs` collapse per-row bulk-endpoint errors into a 5-label allowlist (`validation failed` / `conflict: already exists` / `not found` / `forbidden` / `replication unavailable`) and short-circuit 400/500 responses to the canonical sanitized envelope. 7 leak sites remediated across `src/handlers/http.rs` (import_memories sqlite+postgres, bulk_create sqlite+postgres) and `src/handlers/hook_subscribers.rs` (notify); 8 additional similar sites in hook_subscribers (inbox/subscribe/namespaces/session_start) deferred to follow-up. New 11-test regression suite `tests/handler_error_sanitization.rs` (432 lines) pins the contract against 30 forbidden substrings (SQL keywords, paths, anyhow markers, private-IP URL prefixes).
- **Env-var precedence ladder + 28-row table in CLAUDE.md + `tests/config_precedence.rs`** (issue [#855](https://github.com/alphaonedev/ai-memory-mcp/issues/855), Wave-2 Tier-A7). Canonical reference for every `AI_MEMORY_*` env var the binary honors across CLI/daemon/MCP/federation/entrypoint surfaces, with classification (`secret` / `config` / `test-only`) and per-var notes. 3 regression tests pin the universal ladder (`CLI flag > AI_MEMORY_* env > config.toml > compiled default`) + secret-not-in-capabilities invariant. Maintenance note added: new env vars must update the table AND extend the tests.

### Changed

- **`postgres::governance_approve_with_consensus` returns `StoreError::NotFound` for missing pending rows** (issue [#857](https://github.com/alphaonedev/ai-memory-mcp/issues/857)). Previously the postgres impl returned `ApproveOutcome::Rejected("pending action not found: …")` for a missing pending_id, which the HTTP handler mapped to 403 Forbidden — collapsing "missing row" into the "policy refused" bucket. Now surfaces as 404 Not Found, matching the sqlite path's contract (`db::approve_with_approver_type`'s `ApproveOutcome::NotFound` variant). Wire-compat preserved (Rejected → 403 still fires for genuine policy refusals; designated-approver mismatch, write-failure cases).
- **postgres `touch_after_recall` single-UPDATE-with-CASE refactor** (issue [#852](https://github.com/alphaonedev/ai-memory-mcp/issues/852), Wave-2 Tier-A4). Three sequential UPDATEs (touch + auto-promote + priority bump) collapsed into one UPDATE with CASE clauses + a single round-trip. Mirrors the sqlite path's single-statement contract. Plus regression test `tests/postgres_touch_batch.rs` (288 lines) pins the sliding-window REPLACEMENT semantics + mid→long auto-promote + priority bump per 10 accesses.
- **`run_embedding_backfill` + `set_embeddings_batch` — batched embedding backfill** (issue [#853](https://github.com/alphaonedev/ai-memory-mcp/issues/853), Wave-2 Tier-A5). New `pub fn` exposures collapse N+1 UPDATEs to a single multi-row UPSERT; new `pub fn run_embedding_backfill` in `src/mcp/mod.rs` provides the operator-facing entry point. Regression test `tests/embedding_backfill_batch.rs` (301 lines) pins the batching contract.
- **Test-helper consolidation phase 2** (issue [#854](https://github.com/alphaonedev/ai-memory-mcp/issues/854), Wave-2 Tier-A6). 5 helpers (`postgres_url`, `free_port`, `fresh_conn`, `fresh_db_tempfile_path`, `fresh_db_tempfile_conn`) consolidated into `tests/common/mod.rs`; 52 test files refactored to use it.
- **MCP `memory_promote` accepts optional `target_tier` parameter** (issue [#831](https://github.com/alphaonedev/ai-memory-mcp/issues/831)). Callers can now land on `"mid"` as an intermediate step instead of jumping straight to `long`; omitting `target_tier` preserves the historical highest-reachable-tier behaviour. 3 regression tests in `tests/lifecycle_promote_target_tier.rs` pin each match arm (`Some("long")` explicit, `Some("short")` rejected as downgrade, `Some(other)` catch-all error).

### Fixed

- **S5-C1 error message no longer steers operators into a silently-dropped `[api]` subsection** (issue [#847](https://github.com/alphaonedev/ai-memory-mcp/issues/847)). The bind-safety guard previously told operators to "set [api] api_key in config" but `AppConfig::api_key` is a TOP-LEVEL field; the `[api]` table was silently ignored by serde. Error message now says "set top-level `api_key = \"...\"`". Plus entrypoint.plan-c.sh fix to honor `AI_MEMORY_API_KEY` env at boot.
- **fmt + clippy hygiene** across `tests/lifecycle_promote_target_tier.rs` (3 doc_markdown backticks) and `tests/rule_list.rs` (single-line let binding) — Lint job cleared on `local/install-815-816`.

### CI

- Postgres feature gate now passes 30 of 33 serve_postgres_*_via_sal tests (was 0 of 33 before this campaign). Three remaining failures in `serve_postgres_extended.rs` (agents shape, route_gate stale premise, taxonomy shape) tracked in #857 for follow-up.

### NHI re-run 2026-05-18 fix batch (HEAD `875bc19` on `local/install-815-816`)

- **#857** — serve_postgres_continuation2/3 + extended green-up. Bulk source-allowlist sweep across postgres test suites; designated-approver typing on `governance_approve_with_consensus`; 404 vs. 403 contract on missing-pending-row (postgres parity with sqlite). Commits `3f13138`, `64436d0`, `4ef8217`, `7eb73fd`, `dbae41d`. **All 33/33 postgres tests green** (was 0/33 before the campaign).
- **#858** — handler_parity green-up + product bug uncovered. `bucket_b_subscriptions_persist` + `cont6_find_paths` brought green via source-allowlist tightening; the tightening surfaced a real /links POST product bug (AGE projection on link insert returning 503 on missing graph; degraded to warn-and-continue). Commits `6d8b13a`, `ccd05f7`, `f612675`.
- **#859** — MCP `tools/list` exposes optional property schemas for NHI discovery. The verbose schema trim in #829 had stripped optional-property descriptions; #859 restores them under the trimmed budget ceiling (raised 3500 → 5000). Surfaces `memory_update` (10 fields), `memory_link` (relation enum), other tools that gained optional params during v0.7.0. Commit `5ab3315`. Added 8-test regression suite `tests/mcp_tools_list_schema_discovery.rs` (279 lines). Trimmed budget remains ≤ 5000; verbose remains ≤ 10000.
- **#860** — `memory_get_links` surfaces temporal + attestation columns. Was returning only `{source_id, target_id, relation}` — now returns the full envelope including `valid_from`, `valid_until`, `observed_by`, `signature`, `attest_level`, `signed_at`. Added 184-line regression suite `tests/get_links_temporal.rs`. Commit `091350c` (folded with #861).
- **#861** — `memory_archive_list` preserves metadata + emits tags as JSON array. Was emitting the SQL-side tags as a comma-separated string; now matches the wire shape every other list-tool tool uses. Added 162-line `tests/archive_serialization.rs`. Commit `091350c`.
- **#862** — clarified "X of X advertised" vs. "X advertised entries at v0.7.0". The +1 is the always-on `memory_capabilities` bootstrap; at v0.7.0 release HEAD `Profile::full().expected_tool_count()` returns 73, `memory_capabilities` summary reports the 72-memory-tool count. Both numbers are intentional. Commit `dc07da4` corrected the stale "43 MCP Tools" section header on `docs/index.html`; the DOC-F Lane-5 sweep (2026-05-22) brought every drifted "71"/"72-callable" headline forward to the released 73/72 pair.
- **#863** — `ai-memory governance check-action` CLI subcommand. Substrate `check_agent_action` MCP tool already shipped at v0.7.0; #863 adds CLI parity so operators can dry-run governance decisions outside an MCP session. 305-line acceptance suite `tests/cli_governance_check_action.rs`. Commit `3b21228`.
- **#864** — clarified "Family" naming across docstrings. **MCP tool family** (`Family::Core`/`Graph`/`Admin`/`Power` in `src/profile.rs`) is **unrelated** to the **`MemoryKind` Batman vocabulary** (Form-6 enum: `Observation`/`Reflection`/`Persona`/etc.). Both use the word "family" loosely in some doc passages; #864 disambiguates. Commit `7647cfe`.
- **#829** — trim verbose tool docs from 15570 → 9507 cl100k tokens (-38.9%). Verbose token budget ceiling **relaxed from 5K-10K (v0.6.4 playbook) to ≤ 10000 (post-#829)** to allow optional-property descriptions to ride alongside the still-trimmed core. 3 CI guards added (`tests/token_budget_guard.rs`, `tests/c2_tool_docs_field.rs`, `tests/c3_no_inline_examples.rs`). Commit `d41b8cb`.

### Lane-5 documentation drift remediation (2026-05-18, this commit)

- **Comprehensive sweep** of every live doc surface (CLAUDE.md, README.md, CHANGELOG.md, docs/*.md, src/**/*.rs docstrings) for stale counts and contract drift introduced by the v0.7.0 surface expansion and the post-tag fix batch.
- **Fixed in this commit:**
  - CLAUDE.md `## Architecture` updated: tool counts 63 → 71/70 disambiguation, module table reflects `src/mcp/`, `src/storage/`, `src/store/`, `src/handlers/`, `src/models/` split, `src/governance/`, `src/atomisation/`, `src/multistep_ingest/`, `src/synthesis/`, `src/confidence/`, `src/persona/`, `src/offload/`, `src/forensic/`, `src/federation/`, `src/kg/`, `src/subscriptions.rs`, `src/signed_events.rs` listed. Memory struct 15 → 25 fields. MemoryLink relations 4 → 6 (adds `reflects_on`, `derives_from`). HTTP routes 50 → 72. CLI subcommands 40 → ~50. Schema version `v7` → **v43** with capabilities envelope `schema_version="3"`. HMAC subscription dispatch noted as mandatory post-R3-S1.HMAC.
  - README.md: 50 endpoints → 72 routes; 40 subcommands → ~50 subcommands (three sites).
  - docs/USER_GUIDE.md: MCP Tool Reference reframed for 71-advertised / 7-default; memory_get_links example response now includes full temporal+attest envelope per #860; six-relation enum documented.
  - docs/DEVELOPER_GUIDE.md: module tree updated to v0.7.0 layout; `Command` enum description lists ~50 subcommands; Memory 15 → 25 fields; MCP server section reframed for 71/70 split + Family vs MemoryKind disambiguation; HTTP 50 → 72 routes.
  - docs/GLOSSARY.md: MCP entry, Memory entry, Memory-link entry refreshed.
  - docs/API_REFERENCE.md: link relations 4 → 6; `/links/{id}` response envelope documents full temporal+attest columns.
  - docs/ADMIN_GUIDE.md: profile table `core` 5+bootstrap → 7+bootstrap and `full` 43-tools → 71-entries-at-v0.7.0; HTTP endpoint count 50 → 72; `[ttl].*_extend_secs` table rows expanded with the sliding-window REPLACEMENT contract (#830) and a paragraph-level explainer.
  - docs/CLI_REFERENCE.md: `mcp` subcommand description reframed for 71/70 split; `recall` description carries the sliding-window REPLACEMENT wording.
  - docs/INSTALL.md: BLUF reframed (43 → 7-default / 71-full); step-4 verify list rewritten for the v0.7.0 surface.
  - docs/MIGRATION_v0.6.4.md: forward note added pointing v0.6.4 readers at the v0.7.0 (7 core / 71 full / 64 unloaded) equivalents and at MIGRATION_v0.7.md.
  - docs/BASELINE-v0.6.3.1.md: section 2 heading clarified as v0.6.3.1 baseline; forward note added pointing at v0.7.0 numbers + the migration to `src/mcp/registry.rs`.
  - docs/postgres-age-guide.md: ~50-endpoints router reference updated to 72 routes at v0.7.0.
  - docs/v0.7.0/release-notes.md: new `## Post-tag follow-up batches (NHI re-run, 2026-05-17 / 2026-05-18)` section captures #857-#864 + #829 + #830 + #831 inline; closed-documentation-issues subsection notes #800 and #545 already remediated at v0.7.0 ship.
- **Closed documentation-labeled issues:** #800 (Batman activation how-to — shipped via docs/batman-active-mode.md), #545 (capabilities operational summary + callable_now — shipped via capabilities-v3 A1-A4 fields), #862 (tool count disambiguation — closed by commit `dc07da4`), #864 (Family vs MemoryKind disambiguation — closed by commit `7647cfe`).
- **Still open (code-requires-change drift, retained):** #802 (RFC NHI viewpoint — original-research deliverable, not drift), #784 (Cluster H long-form doc expansion — 12-20h scoped task, not a regression), #650 (handlers.rs full per-domain split — partially addressed, full per-domain split tracked).

### Provenance gaps 1-7 + dogfood-fix sprint (2026-05-18, this commit)

The v0.7.0 surface previously documented a 7-level provenance framework (Identity, Source, Causal, Capture confidence, Versioned, Reciprocal, Decoration) but the substrate's write + read paths had partial coverage. This sprint closes all seven gaps end-to-end across sqlite and postgres adapters, lands the dogfood-surfaced wire-schema fixes, and ships the postgres parity work tracked under issue #894. Tool count rises 71 → 73 (Gap 3 `memory_recall_observations` + Gap 4 `confidence_tier` surfacing). Schema ladder advances to sqlite v47 / postgres v29.

#### Added

- **Provenance Gap 1 (#884) — optimistic-concurrency `version` column** (commit [`6ad87c8`](https://github.com/alphaonedev/ai-memory-mcp/commit/6ad87c824)). Schema v45 sqlite + `Memory.version: i64` field with `#[serde(default)]` for round-trip compat. `storage::update` bumps `version + 1` on every mutation. New `update_with_expected_version` returns typed `VersionConflict { id, expected_version, current_version }` on stale writes. MCP `memory_update` accepts `expected_version: Option<i64>`; HTTP `PUT /memories/:id` honors `If-Match: <version>` (bare integer or quoted ETag), surfaces 409 with the structured envelope.
- **Provenance Gap 2 (#885) — first-class `source_uri` column** (commit [`6ad87c8`](https://github.com/alphaonedev/ai-memory-mcp/commit/6ad87c824)). Schema v45 backfills from `metadata.source_uri` and `citations[0].uri`. Partial index `idx_memories_source_uri` for `WHERE source_uri IS NOT NULL`. MCP `memory_store` + `memory_update` accept the top-level field; insert path promotes it out of `metadata` automatically.
- **Provenance Gap 3 (#886) — `recall_observations` ledger** (commit [`3cd8c11`](https://github.com/alphaonedev/ai-memory-mcp/commit/3cd8c116d)). Schema v47 ledger keyed by `(recall_id, memory_id)` with `retriever`, `rank`, `score`, `consumed` columns; FK CASCADE to `memories(id)`. `memory_recall` stamps a UUIDv4 `recall_id` into every response and writes one ledger row per candidate. `memory_store` + `memory_link` consume hook reads `recall_id + cited_memory_ids` from request body and flips matching rows to `consumed=true` with `consumed_by_memory_id`. New MCP tool `memory_recall_observations` (Family::Meta) for read-side filtering (`since`/`until`/`limit`/`consumed`). TTL pruner gated by `AI_MEMORY_OBSERVATIONS_TTL_DAYS` (default 7).
- **Provenance Gap 4 (#887) — `ConfidenceTier` capabilities surface** (commit [`23379e2`](https://github.com/alphaonedev/ai-memory-mcp/commit/23379e26f)). `ConfidenceTier` enum (`Confirmed >= 0.95`, `Likely >= 0.7`, `Ambiguous < 0.7`) + `Memory::confidence_tier()` method. New `CapabilityConfidenceCalibration.tier_thresholds` field surfaced via the v3 `confidence_calibration` block carries `ConfidenceTierThresholds { confirmed, likely, ambiguous }` so MCP callers read the breakpoints without re-deriving them. `memory_recall` gains `confidence_tier: Option<String>` request filter.
- **Provenance Gap 5 (#888) — `edit_source` + atomic supersede archive** (commit [`6ad87c8`](https://github.com/alphaonedev/ai-memory-mcp/commit/6ad87c824)). `archived_memories.archive_reason = 'superseded'` audit column on OLD row, `new_memory.metadata.superseded_id` forward-pointer on NEW row. `update_with_archive_on_supersede` runs atomically inside a transaction (SELECT FOR UPDATE → archive → delete old → insert new).
- **Provenance Gap 6 (#889) — search-by-`source_uri`** (commit [`6ad87c8`](https://github.com/alphaonedev/ai-memory-mcp/commit/6ad87c824)). MCP `memory_search` + storage `search_with_source_uri` + storage `list_by_source_uri` hit the partial index from Gap 2. Namespace composability preserved.
- **Provenance Gap 7 (#890) — `memory_recall` Tier-3 decoration** (commit [`c3e344c`](https://github.com/alphaonedev/ai-memory-mcp/commit/c3e344c7a)). Default `verbose_provenance=true`; rows return decorated with `confidence`, derived `confidence_tier` (from Gap 4), `source`, `source_uri`, derived `freshness_state` (computed from `expires_at + last_accessed_at + access_count`), `access_count`, `last_accessed_at`, and `latest_link_attest_level` (strongest `AttestLevel` across all incident links). Recall envelope echoes the Gap 3 `recall_id` UUID so the caller can cite it downstream.
- **Postgres provenance parity migrations v42-v46 (#894)** (commit [`a69eed0`](https://github.com/alphaonedev/ai-memory-mcp/commit/a69eed03b)). Five migrations mirror the sqlite v45/v46/v47 ladder: `0025_v07_memory_version.sql` (Gap 1), `0026_v07_source_uri_upgrade.sql` (Gap 2 + backfill), `0027_v07_recall_observations.sql` (Gap 3), `0028_v07_edit_source_archive_metadata.sql` (Gap 5), `0029_v07_links_temporal_columns.sql` (Gap 7 defensive `ADD COLUMN IF NOT EXISTS`). Greenfield deploys pick up identical columns + indexes inline from `postgres_schema.sql`.
- **Postgres SAL parity methods (#894)** (commit [`e3ae0a5`](https://github.com/alphaonedev/ai-memory-mcp/commit/e3ae0a555)). Six inherent `PostgresStore` methods bring byte-identical parity with the sqlite free functions: `update_with_expected_version` (Gap 1 optimistic concurrency with WHERE-clause version gate), `update_with_archive_on_supersede` (Gap 5 atomic archive inside a `sqlx` transaction), `search_with_source_uri` + `list_by_source_uri` (Gap 6 partial-index search), Gap 7 link-decoration twins. ~870 LOC. Inherent (not trait) so call-sites holding `Arc<PostgresStore>` can drive them today; trait widening is a follow-up.

#### Fixed

- **#892 — `memory_store` MCP schema missing `source_uri`** (commit [`39aa158`](https://github.com/alphaonedev/ai-memory-mcp/commit/39aa158f9)) — **dogfood-surfaced 2026-05-19**. The wire schema omitted `source_uri` AND the handler dropped it on the floor at `validation.rs:224` (hard-coded `None`). Both sides fixed; SQL row now persists `source_uri` end-to-end through the MCP wire path. Verified against `doc:dogfood-2026-05-19-verify` test memory.
- **#893 — `memory_update` MCP schema missing `expected_version` + `edit_source`** (commit [`39aa158`](https://github.com/alphaonedev/ai-memory-mcp/commit/39aa158f9)) — **dogfood-surfaced 2026-05-19**. Handlers already read both params but NHIs couldn't discover them via `tools/list`. Schema fix also exposes `source_uri` on the update path. Verbose token budget trimmed from 10196 → 9998 (under 10000 ceiling) by tightening `on_conflict` / `force` / `source` / `kind` / `session_id` / `depth` / `session_default` / `budget_tokens` docstring prose.
- **#895 — Gap 5 `SupersedeResult` docstring drift** (commit [`19b0854`](https://github.com/alphaonedev/ai-memory-mcp/commit/19b08543c)) — **dogfood-surfaced Phase B v2**. Docstring promised a `supersedes` link row was written; impl correctly skips it (lines 1417-1423) because FK `target_id REFERENCES memories(id)` would reject pointing at an archived id. Docstring corrected to document the actual two-mechanism provenance (`archived_memories.archive_reason = 'superseded'` on OLD + `new_memory.metadata.superseded_id` forward pointer on NEW). The expensive path (relax FK to allow `memory_links → archived_memories`, OR parallel `archive_links` table) tracked separately for v0.7.0 consideration.
- **#894 — `cargo build --features sal-postgres` build + clippy gate unblocked** (commit [`62cf9e4`](https://github.com/alphaonedev/ai-memory-mcp/commit/62cf9e49b)). Eleven distinct compile errors in `src/handlers/*` (Memory / Utc / ConfidenceSource / StorageBackend / `store_err_to_response` / `get_with_visibility_retry` missing imports) blocked the postgres adapter from reaching the gate. All fixes scoped to `cfg(sal-postgres)`-gated import shuffles or visibility tweaks across `subscriptions.rs`, `federation_sync_since.rs`, `http.rs`, `memories.rs`, `federation_receive.rs`, `federation_signing_check.rs`. `get_with_visibility_retry` promoted to `pub(super)` so `memories.rs` reaches it through `super::http::`.

#### Tests

- **51 provenance pin tests across 9 files** (commit [`ce1415a`](https://github.com/alphaonedev/ai-memory-mcp/commit/ce1415ca6)). Comprehensive AC-pin audit of all 7 v0.7.0 provenance closeout gaps. Every acceptance criterion in the issue bodies is now mapped to a named regression test. Per-issue additions: #884 +5 (missing/clone/downcast/HTTP) + NEW 5 HTTP-If-Match-concurrency; #885 +5 (insert promotion / limit / idempotence); #886 +7 (since/until/noop/probe filters); #887 +5 (boundaries / serde / unknown filter); #888 +7 (parse / inherit / new-row v1); #889 +3 (ordering / namespace compose / kg_query) + NEW 4 HTTP-source_uri-query; #890 +7 (freshness states / `recall_id` UUID). Total provenance-gap coverage: 28 → 79 tests. One AC pin (`#[ignore]`) tracks newly-filed issue #891 (HTTP `/api/v1/search` rejects `source_uri`-only with 400 — `search_memories` early-returns on empty `q` before the `source_uri`-only branch).
- **MCP `recall_observations` tool param-branch coverage** (commit [`913a2ff`](https://github.com/alphaonedev/ai-memory-mcp/commit/913a2ffb0)). 3 tests pin previously-uncovered closure branches in `src/mcp/tools/recall_observations.rs::handle_recall_observations`: `gap3_mcp_tool_since_filter_executes_branch`, `gap3_mcp_tool_until_filter_executes_branch`, `gap3_mcp_tool_limit_param_caps_response`. Brings file line coverage from ~94.5% to > 98%. Tests use the pub MCP entrypoint (`ai_memory::mcp::handle_recall_observations`) directly so the integration-test layer covers the same dispatch the daemon uses.
- **Cross-adapter parity harness `tests/store_parity_gaps.rs`** (commit [`9bec43c`](https://github.com/alphaonedev/ai-memory-mcp/commit/9bec43c7c)). Six `verify_<gap>_sqlite` reference functions + six `pg_parity_gap_<n>` postgres twins. Sqlite-side tests always run; postgres-side tests are `#[ignore]` and self-skip when `AI_MEMORY_TEST_POSTGRES_URL` is unset (Track C/D network blocker per issue #79). Compiles cleanly under both default and `--features sal-postgres` so a future runner that flips the env var picks up zero-friction parity coverage.

#### Changed

- **MCP tool count 71 → 73** (Gap 3 `memory_recall_observations` adds 1; Gap 4 `confidence_tier` arg surfaces another callable). `Profile::full().expected_tool_count()` returns 73; pinned by `src/profile.rs::Profile::full().expected_tool_count() assert_eq!(total, 73)`. CLI subcommand count surface bumped to 55 across README + CLAUDE.md (was `~50` placeholder, now exact per `Command` enum at `src/daemon_runtime.rs::Command`).

## [v0.6.4] — 2026-05-08 — `quiet-tools`

**Headline:** ai-memory v0.6.4 ships 5 tools by default, not 43. Saves ~4,700 input tokens per request on Codex / Grok / Gemini / Claude-Desktop (76.4% reduction, measured against `cl100k_base`). Run `ai-memory mcp --profile full` to keep v0.6.3 behavior 1:1. See `RELEASE_NOTES_v0.6.4.md` and `docs/MIGRATION_v0.6.4.md`.


### Breaking

- **Default tool surface collapses from 43 to 5 (#523).** v0.6.4 ships
  with `--profile core` as the default for `ai-memory mcp`, advertising
  only `memory_store`, `memory_recall`, `memory_list`, `memory_get`,
  and `memory_search` plus the always-on `memory_capabilities`
  bootstrap. Eager-loading harnesses (Codex CLI, Grok CLI, Gemini CLI,
  Claude Desktop) drop ~5,300 input tokens of tool schemas from every
  request — measured against `cl100k_base`, the BPE Claude/GPT use for
  input accounting. **Action required for power users:** to reproduce
  v0.6.3 behavior 1:1, run `ai-memory mcp --profile full` (or set
  `AI_MEMORY_PROFILE=full` / `[mcp].profile = "full"` in config.toml).
  See `docs/MIGRATION_v0.6.4.md`.

### Added

- **`--profile` flag + `[mcp].profile` config + `AI_MEMORY_PROFILE` env
  (#521).** Resolution order: CLI > env > config > `core` default. Six
  named profiles plus comma-list custom syntax. Parse errors exit with
  code 2 and a diagnostic that lists every valid profile/family.
- **Family-scoped tool registration filter (#522).** `tools/list`
  returns only the tools loaded under the active profile;
  `tools/call` rejects unloaded tools with `-32601` plus a
  profile/family hint pointing the agent at the right `--profile` or
  `memory_capabilities --include-schema` invocation. v0.6.4-006 will
  extend `memory_capabilities` for runtime expansion.
- **Static schema-size table (#525).** New `crate::sizes` module
  computes per-tool `cl100k_base` BPE cost via `tiktoken-rs`, cached
  behind a `OnceLock`. CI-gated assertion: no individual tool may
  exceed 1,500 tokens. Truthfulness correction: the v0.6.4 RFC's
  ~25,800-token full-surface claim was measured against MiniLM and
  over-counted JSON by ~4×; the actual cl100k_base measurement is
  ~6,000 tokens.

### Fixed

- **G9 HTTP webhook parity (#526).** v0.6.3.1 P5 wired
  `dispatch_event_with_details` into the four lifecycle event types
  (`memory_delete`, `memory_promote`, `memory_link_created`,
  `memory_consolidated`) on the **MCP path only**. The HTTP handlers
  were silent — `grep "dispatch_event" src/handlers.rs` returned zero
  matches. v0.6.4-017 closes the gap symmetrically: HTTP `DELETE`,
  `POST /memories/{id}/promote`, `POST /links`, and `POST /consolidate`
  now fire the same events the MCP path fires, with the same
  payloads, the same fire-and-forget semantics, and the same
  signing/SSRF protections. New integration tests in
  `tests/webhook_http_parity.rs` pin the contract.


## [0.7.0] — 2026-05-15 — `attested-cortex` (grand-slam, reconciled)

**Headline:** v0.7.0 closes the `attested-cortex` epic in its final reconciled shape — **69/69 attested-cortex tasks across 11 tracks** (A/B/C/D/E/F/G/H/I/J/K), the **grand-slam wave** (L1-5/L1-6/L1-7/L2-1…L2-8 recursive-learning + Agent Skills + substrate-rules), the **WT-1 atomisation primitive** (A through G, issues #748-#752), the **QW Tencent quick wins** (1-4, including QW-2 PR #749), the **Batman 6-form write-time-investment closeout + 7th-form Layer-4 wiring** (issues #754-#760, PRs #761-#766), the **procurement-grade audit deliverable** ([`docs/internal/batman-framework-audit.md`](docs/internal/batman-framework-audit.md), PR #753), and the **release-branch security-hardening sweep** (16 commits reconciled into the feature trunk at merge `64528b1`). Final substrate surface: **73 MCP tools at full profile** (Family::Power: 23 at v0.7.0 release HEAD after the post-grand-slam atomisation + persona tools landed), schema **v50** (single logical version both backends, `CURRENT_SCHEMA_VERSION = 50` in `src/storage/migrations.rs` + `src/store/postgres.rs`; v50 = per-namespace K8 quota dimension extension, #1156), capabilities-v3 with three new application blocks (`atomisation`, `memory_kinds_vocab`, `confidence_calibration`), eight new namespace-policy fields on `GovernancePolicy`, and a programmable 25-event hook pipeline. **postgres + Apache AGE remains a first-class storage backend** with live daemon support (`ai-memory serve --store-url postgres://…`), 6-factor recall scoring parity, link migration, and the `ai-memory schema-init` CLI verb. The substrate is both **more articulate** (capabilities v3 with pre-computed calibration strings, named loaders, the 52% MCP-tool token reduction on the full profile maintained even at 73 tools, three new application blocks) and **cryptographically trustworthy** (per-agent Ed25519 attestation with append-only `signed_events` audit chain — including V-4 cross-row hash chain at sqlite v34, sidechain transcripts with `memory_replay`, programmable hook pipeline, opt-in Apache AGE acceleration, K1/G1 namespace-inheritance enforcement, deny-first permission system, A2A maturity, K10 HMAC method+`pending_id` binding with single-use nonce cache, SSRF v4-mapped + NAT64 rejection, secret-redacting hooks, `BEGIN IMMEDIATE` `invalidate_link` wrap). Canonical scope: [`docs/v0.7/V0.7-EPIC.md`](docs/v0.7/V0.7-EPIC.md). Audit (adversarial, code-evidence-based): [`docs/internal/batman-framework-audit.md`](docs/internal/batman-framework-audit.md). Migration: [`docs/MIGRATION_v0.7.md`](docs/MIGRATION_v0.7.md) + [`docs/migration-v0.7.0-postgres.md`](docs/migration-v0.7.0-postgres.md). Operator how-to: [`docs/postgres-age-guide.md`](docs/postgres-age-guide.md). Release notes: [`docs/v0.7.0/release-notes.md`](docs/v0.7.0/release-notes.md). What's new: [`docs/whats-new-v07.html`](docs/whats-new-v07.html). RFC: [`docs/v0.7/rfc-attested-cortex.md`](docs/v0.7/rfc-attested-cortex.md).

### v0.7.0 WT-1 atomisation primitive (PRs #748-#752, branch `feat/v0.7.0-grand-slam`)

The WT-1 atomisation primitive lets the substrate decompose a long memory into addressable, individually-recallable "atoms" before embedding — a structural prerequisite for Batman Form 2 and the foundation under Form 4 fact-grain provenance. Lands as seven sub-tasks A through G, end-to-end coverage from schema → engine → MCP → namespace policy → recall → CLI → capabilities/cookbook/docs.

- **WT-1-A — schema v36 atomisation foundation** ([commit `6710709`](https://github.com/alphaonedev/ai-memory-mcp/commit/6710709), PR #748). Adds the `atomised_into` / `atom_of` / `derives_from` link relations to the canonical link vocabulary, extends the v23 `memory_links.relation` CHECK constraint covering the three new relations, and ports the migration through postgres (`migrations/postgres/0017_v07_atomisation.sql`). Schema bump **sqlite v34 → v36** (v35 is the V-4 closeout midpoint), **postgres v34 → v35**. Test pin: [`tests/wt_1_a_schema_migration.rs`](tests/wt_1_a_schema_migration.rs).
- **WT-1-B — atomiser engine + `LlmCurator` scaffolding** ([commits `1c3cdab`](https://github.com/alphaonedev/ai-memory-mcp/commit/1c3cdab), [`99419dc`](https://github.com/alphaonedev/ai-memory-mcp/commit/99419dc), [`473ee5f`](https://github.com/alphaonedev/ai-memory-mcp/commit/473ee5f), PR #750). New `src/atomisation/mod.rs` houses the atomisation flow (`AtomConfig`, error enum, `Curator` trait abstraction). The default curator wires Gemma 4 via the configured LLM client; per-atom tokens are measured against `cl100k_base` via `tiktoken-rs` (matches the v0.6.4 `crate::sizes` discipline). 11-test acceptance suite at [`tests/atomisation/core.rs`](tests/atomisation/core.rs).
- **WT-1-C — `memory_atomise` MCP tool** ([commit `aa6365a`](https://github.com/alphaonedev/ai-memory-mcp/commit/aa6365a), PR #751). Registers `memory_atomise` under `Family::Power` (semantic-tier+); the tool refuses with a typed error at the keyword tier so the v0.6.4 `--profile core` 7-tool surface stays minimal. Atomic write of the parent memory + N atom rows + N `atomised_into` link writes inside a single `BEGIN IMMEDIATE` / `COMMIT` transaction; any atom-write or link-write failure ROLLBACKs the entire fan-out. 622-test acceptance suite at [`tests/wt1c_mcp_atomise.rs`](tests/wt1c_mcp_atomise.rs). Tool count bumps **63 → 64**.
- **WT-1-D — `auto_atomise` namespace policy + `pre_store` hook** ([commit `6ad2a21`](https://github.com/alphaonedev/ai-memory-mcp/commit/6ad2a21)). New `GovernancePolicy` fields `auto_atomise: Option<bool>`, `auto_atomise_threshold_cl100k: Option<u32>`, `auto_atomise_max_atom_tokens: Option<u32>`, `auto_atomise_mode: Option<AutoAtomiseMode>` (`Off` / `Deferred` / `Synchronous`); policy resolution leaf-first via the existing `resolve_governance_policy` chain walk. New `pre_store::auto_atomise` hook intercepts substrate writes above the configured token threshold and routes through the WT-1-B engine. Acceptance suite at [`tests/auto_atomise/core.rs`](tests/auto_atomise/core.rs).
- **WT-1-E — recall atom preference + forensic atomisation chain** ([commits `3fbfb9c`](https://github.com/alphaonedev/ai-memory-mcp/commit/3fbfb9c), [`2f840b0`](https://github.com/alphaonedev/ai-memory-mcp/commit/2f840b0)). Recall now applies an atom-preference WHERE clause (recall returns atoms before parents when both score equivalently — atoms are the addressable granularity Batman Form 4 requires). Forensic bundle export gains a per-bundle atomisation chain envelope so an offline verifier can prove the atom → parent lineage independently of the live DB. 13-test acceptance suite spanning recall, search, MCP, HTTP, and forensic surfaces.
- **WT-1-F — `ai-memory atomise` CLI subcommand** ([commit `27f3fe8`](https://github.com/alphaonedev/ai-memory-mcp/commit/27f3fe8)). New `ai-memory atomise <memory-id>` verb shells the WT-1-B path from the CLI; `--dry-run` previews the proposed atom set without writing; `--json` returns the structured envelope for scripting. Composes cleanly with `ai-memory recall` for the recall-atom-preference checkpoint. Acceptance suite at [`tests/cli/atomise.rs`](tests/cli/atomise.rs).
- **WT-1-G — capabilities-v3 + cookbook + docs** ([commit `9c8be0c`](https://github.com/alphaonedev/ai-memory-mcp/commit/9c8be0c), PR #752). Capabilities-v3 gains a new `atomisation` block (`CapabilityAtomisation` in `src/config.rs`) reporting `status` (`stub` / `implemented`), curator backend, token caps, and the `auto_atomise` namespace policy surface. Cookbook entry [`cookbook/atomisation/01-basic-flow.sh`](cookbook/atomisation/01-basic-flow.sh) walks store → atomise → recall round-trip. Docs: [`docs/atomisation.md`](docs/atomisation.md). Example: [`examples/atomise_roundtrip.rs`](examples/atomise_roundtrip.rs). Test pins at [`tests/capabilities_v3_l3_5.rs`](tests/capabilities_v3_l3_5.rs).

### v0.7.0 QW Tencent quick wins (PRs #749 + commits on `feat/v0.7.0-grand-slam`)

Four quick-win primitives surfaced by the Tencent positioning analysis. Each lands as a substrate primitive (not a doc-only patch) so the capability is testable and exposed via MCP / CLI / HTTP.

- **QW-1 — file-backed reflection chain export** ([commit `6d32633`](https://github.com/alphaonedev/ai-memory-mcp/commit/6d32633)). New `ai-memory export-reflections` CLI verb + `memory_export_reflection` MCP tool walks a reflection's `reflects_on` chain and emits a deterministic POSIX-ustar archive (the L2-5 forensic-bundle discipline applied at the per-reflection scope). Namespace policy field `auto_export_reflections_to_filesystem` + new `post_reflect::auto_export` hook automate the export at write time when a namespace opts in. Cookbook: [`cookbook/file-backed-export/01-export-and-inspect.sh`](cookbook/file-backed-export/01-export-and-inspect.sh).
- **QW-2 — persona-as-artifact substrate primitive** ([commit `53b4d39`](https://github.com/alphaonedev/ai-memory-mcp/commit/53b4d39), PR #749). New `MemoryKind::Persona` (Form 6 vocabulary expansion lands the kind; QW-2 ships the substrate plumbing). Per-`(entity_id, namespace)` persona row indexed by `idx_personas_by_entity` (schema sqlite v37 / postgres v36). Two MCP tools: `memory_persona` (read most recent persona) returns the structured envelope `{id, entity_id, namespace, body_md, sources, generated_at, version, attest_level}` and `memory_persona_generate` mints the artefact from a cluster of `MemoryKind::Reflection` memories via the reflection-pass curator (300-500 word Markdown distillation with `[^N]: <reflection-id>` footnoted citations). `post_reflect::auto_persona` hook automates regeneration every N memories per namespace policy (`auto_persona_trigger_every_n_memories`). Docs: [`docs/persona.md`](docs/persona.md). Cookbook: [`cookbook/persona/01-build-persona-from-observations.sh`](cookbook/persona/01-build-persona-from-observations.sh).
- **QW-3 — context-offload substrate primitive** ([commit `2a85db2`](https://github.com/alphaonedev/ai-memory-mcp/commit/2a85db2), follow-up [`20b6be1`](https://github.com/alphaonedev/ai-memory-mcp/commit/20b6be1)). New `offloaded_blobs` substrate table (schema sqlite v35 → carried forward through subsequent bumps) stores verbatim content under a namespace with optional `ttl_seconds`; the caller keeps the short `ref_id` in their context window and dereferences on demand. Two MCP tools under `Family::Power`: `memory_offload(content, ttl_seconds?)` returns `{ref_id, content_sha256, stored_at}`; `memory_deref(ref_id)` verifies the sha256 and returns `{ref_id, content, stored_at, sha256}` (refuses tampered rows). Background TTL sweep at [`src/background/offload_ttl_sweep.rs`](src/background/offload_ttl_sweep.rs). Docs: [`docs/context-offload.md`](docs/context-offload.md). Substrate-only at v0.7.0; the v0.8.0 short-term-context-compression patch wires the pair into the auto-compaction loop.
- **QW-4 — Tencent competitive positioning** ([commit `f34a225`](https://github.com/alphaonedev/ai-memory-mcp/commit/f34a225)). **Docs-only deliverable, no code path** (per [`docs/internal/v070-ship-readiness-adrs.md` ADR-1](docs/internal/v070-ship-readiness-adrs.md#adr-1--qw-4-disposition-docs-only-no-code-feature)). Positioning page update at [`docs/positioning.md`](docs/positioning.md) adds the TencentDB Agent Memory entry alongside the existing landscape comparison. The three code-bearing QW items are QW-1 (file-backed reflection export), QW-2 (persona-as-artifact), and QW-3 (context-offload).

### v0.7.0 Batman 6-form write-time-investment closeout (issues #754-#759, PRs #762-#766)

The 2026-05-15 procurement-grade audit ([`docs/internal/batman-framework-audit.md`](docs/internal/batman-framework-audit.md), PR #753) classified the v0.7.0 grand-slam HEAD's Batman-form coverage as **0 clean / 4 partial (Forms 2, 4, 5, 6) / 2 absent (Forms 1, 3)** based on adversarial code-evidence verification — escalation trigger 1 fired. The five Form PRs below close every gap the audit flagged, lifting the coverage to **6 clean IMPLEMENTED forms + the 7th-form Layer-4 wiring** at the v0.7.0 reconciled HEAD. Each Form PR carries its own acceptance suite pinning the audit's adversarial checks.

- **Form 1 — online dedup-and-synthesis** (closes [#754](https://github.com/alphaonedev/ai-memory-mcp/issues/754), PR #762, [commit `aebe76c`](https://github.com/alphaonedev/ai-memory-mcp/commit/aebe76c)). Single batch action-emitting LLM call evaluated BEFORE the SQL write, with prompt vocabulary `{add, update, delete, no_op}` per existing-candidate. Replaces the v0.6.0.0 post-store per-pair binary yes/no classifier (kept reachable as `legacy_per_pair_classifier: Option<bool>` namespace policy for backwards compatibility). New `src/synthesis/mod.rs` houses the synthesis prompt + parser; the write-path is gated on the verdict (insert / merge / supersede / no-op). 423-test acceptance suite at [`tests/form_1_synthesis.rs`](tests/form_1_synthesis.rs).
- **Form 2 — synchronous atomise-before-embed namespace policy** (closes [#755](https://github.com/alphaonedev/ai-memory-mcp/issues/755), PR #762, [commit `aebe76c`](https://github.com/alphaonedev/ai-memory-mcp/commit/aebe76c)). The WT-1-D `auto_atomise` policy gains `AutoAtomiseMode::Synchronous` — the substrate atomises the parent BEFORE the embed call so each atom's vector lives at the addressable granularity Batman Form 2 requires. `Deferred` (existing WT-1-D default) and `Off` modes retained. 391-test acceptance suite at [`tests/form_2_synchronous_atomise.rs`](tests/form_2_synchronous_atomise.rs).
- **Form 3 — multi-step ingest orchestrator** (closes [#756](https://github.com/alphaonedev/ai-memory-mcp/issues/756), PR #763, [commit `88663d7`](https://github.com/alphaonedev/ai-memory-mcp/commit/88663d7)). New `src/multistep_ingest/` module + new MCP tool `memory_ingest_multistep` (`Family::Power`) orchestrates a two-phase ingest: phase 1 deterministic helpers (`src/multistep_ingest/helpers.rs`) extract structural facts (URIs, timestamps, named entities, key-value pairs) under an explicit-trust contract; phase 2 LLM pass refines / synthesises with **prompt-cache reuse** keyed on the phase-1 fingerprint so re-ingesting near-identical payloads short-circuits the LLM call. Acceptance suite at [`tests/form_3_multistep_ingest.rs`](tests/form_3_multistep_ingest.rs). Example: [`examples/multistep_ingest_roundtrip.rs`](examples/multistep_ingest_roundtrip.rs). Cookbook: [`cookbook/multistep-ingest/01-two-phase.sh`](cookbook/multistep-ingest/01-two-phase.sh). Docs: [`docs/multistep-ingest.md`](docs/multistep-ingest.md). Tool count bumps **65 → 66**.
- **Form 4 — fact-provenance citations + source-as-URI + atom-grain span** (closes [#757](https://github.com/alphaonedev/ai-memory-mcp/issues/757), PR #764, [commit `17bcf0c`](https://github.com/alphaonedev/ai-memory-mcp/commit/17bcf0c)). Memory rows gain per-fact citations (`citations: Vec<Citation>`), source-as-URI (`source_uri: Option<String>` distinct from the legacy `source` text field), and atom-grain span coordinates (`atom_span: Option<{start, end, parent_id}>`) so a downstream consumer can resolve a fact back to the exact byte range in the source artefact. Schema bump **sqlite v37 → v38** (migration `0032_v07_form4_provenance.sql`), **postgres v36 → v37** (migration `0019_v07_form4_provenance.sql`). Recall, search, HTTP, and forensic-bundle surfaces all carry the new fields. Docs: [`docs/provenance.md`](docs/provenance.md).
- **Form 5 — auto-confidence + shadow-mode telemetry + freshness decay + calibration tooling** (closes [#758](https://github.com/alphaonedev/ai-memory-mcp/issues/758), PR #766, [commit `2153898`](https://github.com/alphaonedev/ai-memory-mcp/commit/2153898)). New `src/confidence/` module houses three components: `derive` (per-source-namespace baseline `confidence` value computed from `crate::confidence::calibrate` history, opt-in via `AI_MEMORY_AUTO_CONFIDENCE=1`); `shadow` (records side-channel observations of caller-supplied vs. system-derived confidence for offline calibration, opt-in via `AI_MEMORY_CONFIDENCE_SHADOW=1`, sampled at `AI_MEMORY_CONFIDENCE_SHADOW_SAMPLE_RATE`); `decay` (exponential freshness decay model, opt-in via `AI_MEMORY_CONFIDENCE_DECAY=1`). New MCP tool `memory_calibrate_confidence` (`Family::Power`) returns a `CalibrationReport` envelope (`{window_days, total_observations, baselines: [{namespace, source, count, median, mean, buckets}]}`). New CLI verb `ai-memory calibrate-confidence`. Schema bump **sqlite v38 → v39** (migration `0033_v07_form5_confidence_calibration.sql`), **postgres v37 → v38** (migration `0020_v07_form5_confidence_calibration.sql`). Docs: [`docs/confidence-calibration.md`](docs/confidence-calibration.md). Tool count bumps **66 → 67**.
- **Form 6 — `MemoryKind` Batman vocabulary + recall filter + optional auto-classify** (closes [#759](https://github.com/alphaonedev/ai-memory-mcp/issues/759), PR #765, [commit `f9b75e0`](https://github.com/alphaonedev/ai-memory-mcp/commit/f9b75e0)). `MemoryKind` extends from `{Observation, Reflection, Persona, Skill}` to the full Batman vocabulary `{Observation, Reflection, Persona, Skill, Concept, Entity, Claim, Relation, Event, Conversation, Decision}`. Recall and search gain a `--kind` filter (CLI) / `kind` parameter (MCP `memory_recall` + `memory_search`) for tight Batman-grain retrieval. New `pre_store::auto_classify_kind` hook + namespace policy field `auto_classify_kind: Option<MemoryKindAutoClassify>` (`Off` / `RegexOnly` / `RegexThenLlm`) routes uncoded writes through a 400-rule regex classifier + optional LLM fallback. Acceptance suite at [`tests/form_6_memorykind_vocab.rs`](tests/form_6_memorykind_vocab.rs). Docs: [`docs/memory-kind-vocab.md`](docs/memory-kind-vocab.md).

### v0.7.0 Batman 7th-form — agent-EXTERNAL Layer-4 wiring (issue #760, PR #761)

The pre-audit grand-slam HEAD had substrate-INTERNAL governance wired via `GOVERNANCE_PRE_WRITE` at `storage::insert` (issue #691 Deliverable E) but agent-EXTERNAL enforcement (`Bash` / `FilesystemWrite` outside the substrate / `NetworkRequest` / `ProcessSpawn`) was "callable but un-wired" per `src/governance/agent_action.rs:38-42` (audit finding §7th-form). The 7th-form PR closes the gap.

- **7th-form Layer-4 wiring** (closes [#760](https://github.com/alphaonedev/ai-memory-mcp/issues/760), PR #761, [commit `891c639`](https://github.com/alphaonedev/ai-memory-mcp/commit/891c639)). Daemon boot installs `GOVERNANCE_PRE_ACTION` covering the four agent-EXTERNAL `AgentAction` variants. MCP `skill_export`, `federation::sync`, `hooks::executor`, and the LLM client all consult the hook before side-effecting. New operator CLI `ai-memory governance install-defaults` seeds the `governance_rules` table with the audit-recommended starter rule set (`AgentAction::Bash` deny patterns for `rm -rf`, `curl | sh` shape, etc.; `AgentAction::NetworkRequest` SSRF defense-in-depth; `AgentAction::FilesystemWrite` outside `$HOME/.local-runs/` policy; `AgentAction::ProcessSpawn` for unrelated daemon-forks). 307-test acceptance suite at [`tests/form_7_agent_external_wiring.rs`](tests/form_7_agent_external_wiring.rs) pins the bypass-impossibility property across all four surfaces. Cookbook: [`cookbook/agent-external-governance/01-deny-bash.sh`](cookbook/agent-external-governance/01-deny-bash.sh). Docs: [`docs/governance/agent-action-rules.md`](docs/governance/agent-action-rules.md).

### v0.7.0 audit deliverable — adversarial procurement-grade verification (issue #753, PR #753)

- **Batman 6-form framework audit** (PR #753, [commit `fd397f9`](https://github.com/alphaonedev/ai-memory-mcp/commit/fd397f9)). 464-line adversarial code-evidence-based audit at [`docs/internal/batman-framework-audit.md`](docs/internal/batman-framework-audit.md). Methodology: 4-step adversarial protocol; read-only source code; classifications biased lower on uncertainty; no reliance on Strategic Nugget #014 / planning docs. Findings drove issues #754-#760 (Form 1-6 closeout + 7th-form Layer-4 wiring). The audit is the reference document procurement reviewers should consult — it documents what was missing pre-2026-05-15 and exactly which PRs closed which gap, so the v0.7.0 reconciled state is independently verifiable. Audit dated 2026-05-15 against pre-closeout commit `53b4d39`; the closeout PRs #761-#766 land after.

### v0.7.0 expanded scope — postgres+AGE first-class (Wave 1-4)

The original `attested-cortex` epic deferred daemon-level adapter selection to v0.7.1 ([`docs/RUNBOOK-adapter-selection.md`](docs/RUNBOOK-adapter-selection.md), pre-2026-05-09 framing). Per operator directive 2026-05-09, the adapter-selection refactor and the related postgres+AGE surface gaps surfaced by the v0.7.0 A2A campaign (#646, F6) **fold into the v0.7.0 ship** rather than carving out a v0.7.0.1 / v0.7.1 micro-release. The expanded scope splits into four implementation waves:

- **Wave 1 — surgical postgres+AGE fixes** (3 parallel streams, in flight). Stream A: `PostgresStore::link()` + `::register_agent()`, recall 6-factor parity, `migrate.rs` link-walk, SQL view aliases for off-process inspection. Stream B: new `ai-memory schema-init` CLI verb (idempotent bootstrap of postgres + AGE projection). Stream C: AGE 1.5 + PG 16 cypher-binding quirk fixed in `tests/age_cte_equivalence.rs` (test-side only — production code never hit it).
- **Wave 2 — postgres schema parity v15 → v28** (13 migrations ported: governance inheritance, webhook subscriptions, audit chain, transcripts, signed events, agent quotas, link `attest_level`, A2A correlation, smart-load veto, KG temporal-index v2, tier-promotion metadata, subscription DLQ, `consolidated_from_agents` array). Pinned by `tests/postgres_schema_parity.rs` against the SQLite v28 truth fixture.
- **Wave 3 — `ai-memory serve --store-url postgres://`** adapter-selection refactor. New `AppState.store: Arc<dyn MemoryStore>` field; handler call sites route through the SAL trait. `--features sal-postgres` opt-in; default sqlite build is byte-for-byte unchanged.
- **Wave 4 — live A2A on postgres**. The v0.7.0 A2A campaign (`ai-memory-a2a-v0.7.0`) re-runs with both droplets pointed at a shared postgres+AGE backend. S70-S76 flip from "PASS via Path B in-tree validators" to "PASS via live daemon-on-postgres". This is the cert acceptance gate for the expanded scope.

**Tag-cut criterion:** two consecutive 100% GREEN A2A rounds against the binary built from `round-2-fixes` after Wave 1-4 lands, with the Wave 4 live-on-postgres acceptance gate satisfied.

### F-series fixes (NHI campaign findings)

The v0.7.0 A2A campaign and the parallel post-ship NHI Round-2 sweep surfaced 18 findings; all 18 are closed in the v0.7.0 ship.

- **F1** ([#644](https://github.com/alphaonedev/ai-memory-mcp/issues/644), commit `e0d2086`) — `namespace_owner` now walks the parent chain. Deep-child Owner-level writes resolve correctly through inherited governance policies; the prior "no resolvable owner" 403 is fixed.
- **F2** ([#645](https://github.com/alphaonedev/ai-memory-mcp/issues/645), commit `e0d2086`) — `audit::init` seeds the `SEQUENCE` atomic from the trailing `audit.log` record at startup; the per-process counter no longer resets to 1 across daemon restart. `audit verify` is monotonic across restarts.
- **F3 / F4 / F5** — campaign-side fixes: S70 import CLI flag drift (test-side), `Harness.node_db_path()` helper for multi-droplet topology, AGE perf gate documentation.
- **F6** ([#646](https://github.com/alphaonedev/ai-memory-mcp/issues/646), Wave 1) — postgres SQL views + `migrate-links` + `schema-init` CLI surfaces. **In flight as of 2026-05-09**; Wave 1 commits will close the issue.
- **F7** (commit `f9ef40a`) — HTTP `POST /api/v1/memories` now wires through `agent_quotas` counters; quota enforcement is no longer advisory-by-accident.
- **F8** (commits `579afe2`, `63c46ab`) — `permissions.mode` defaults to `enforce` (was `advisory`). One-time migration banner on first start. **Breaking change** — see release notes for opt-back-in.
- **F9** (commit `f9ef40a`) — HTTP missing-required-field returns 400 (was 422 from axum body-extractor).
- **F10** (commit `f9ef40a`) — Embedder timeout on >64KB content surfaces an `EmbedStatus` enum on the response instead of silently producing an un-indexed row at HTTP 201.
- **F11** (commits `579afe2`, `bd01978`) — `ai-memory forget --pattern X` and `forget --tier T` without `--namespace` require `--confirm-global`. **Breaking change** — see release notes.
- **F12** (commits `579afe2`, `63c46ab`) — Ed25519 keypair auto-generated on `serve` startup if absent. Idempotent on rerun.
- **F13** (commit `66f48ae`) — `memory_capabilities` schema/behavior drift fixed; `verbose` and `include_schema` flags actually do what the schema claims.
- **F14** (commits `66f48ae`, `5b36d7c`) — Smart-load router weights underscore tokens correctly (`memory_notify` no longer collapses to `meta`; `memory_expand_query` no longer collapses to `graph`).
- **F15** (commit `66f48ae`) — MCP `memory_store` / `memory_update` `inputSchema` now lists the `metadata` field.
- **F16** (commit `66f48ae`) — `agent_type` MCP enum opened to match daemon's permissive accept-set.
- **F17** (commits `082c999`, `f02d092`) — `find_paths` `max_depth` cap of 7 documented in tool description; directed-vs-undirected semantics clarified inline.
- **F18** (commits `082c999`, `63c46ab`) — `check_duplicate` raw-content sha256 short-circuit for byte-identical strings; the embedding-similarity 0.92 ceiling no longer hides true duplicates.
- **AGE 1.5.0 + PG 16 cypher-binding compat** (Wave 1, Stream C) — fixed in `tests/age_cte_equivalence.rs`. Production code never hit it; the harness did. Unblocks the parity test suite on AGE 1.5.0.

### v0.7.0 recursive-learning add-on (Tasks 1-6 of 8, issue [#655](https://github.com/alphaonedev/ai-memory-mcp/issues/655))

Substrate-native primitive for **recursive refinement**: an agent reads one or more memories, synthesises a higher-order reflection (a lesson, pattern, contradiction-resolution, etc.), and persists it with cryptographic-grade provenance back to each source it reflects on. Bounded by design — a substrate-enforced depth cap rejects runaway recursion before any write opens. No autonomous goal modification, no model fine-tuning loops, no unbounded recursion. Folds into the v0.7.0 ship rather than carving a separate v0.7.1 release. Tasks 1-6 landed on `feat/v0.7.0-recursive-learning`; Tasks 7-8 (ship-gate test suite + docs/release-notes/capabilities honesty pass) land on the same branch and roll up here.

- **Task 1** ([commit `f5d8a9e`](https://github.com/alphaonedev/ai-memory-mcp/commit/f5d8a9e)) — `memories.reflection_depth INTEGER NOT NULL DEFAULT 0` column on SQLite (schema v29) and Postgres (`CURRENT_SCHEMA_VERSION 31`). New migration `migrations/postgres/0013_v0700_reflection_depth.sql`. `Memory` struct gains the `reflection_depth: i32` field (`#[serde(default)]` keeps wire-compat with pre-v0.7.0 federation peers) plus `impl Default for Memory` so future struct-field additions stop fanning out to ~50 test fixtures. UPSERT clauses on both adapters take `MAX(old, new)` so newer-wins federation merges preserve the higher-depth signal.
- **Task 2** ([commit `630a6db`](https://github.com/alphaonedev/ai-memory-mcp/commit/630a6db)) — namespace governance gains `GovernancePolicy.max_reflection_depth: Option<u32>` (pure JSON metadata; no schema bump). Accessor `effective_max_reflection_depth(&self) -> u32` returns the compiled default `3` when unset; `Some(0)` is a documented kill-switch that refuses every reflection (the substrate check is `attempted > cap`, so cap=0 fails at depth ≥ 1). Per-namespace overrides ride the same leaf-first chain walk `resolve_governance_policy` already does.
- **Task 3** ([commit `b51a3f3`](https://github.com/alphaonedev/ai-memory-mcp/commit/b51a3f3)) — new canonical link relation `reflects_on` joins `VALID_RELATIONS` (alongside `related_to`, `supersedes`, `contradicts`, `derived_from`). Directionality matches `derived_from`: the reflection memory is the link's `source_id`, the original being reflected on is `target_id`. The two MCP `memory_link` / `memory_unlink` `inputSchema.relation` enums and the `claude_help` prompt's pipe-list extend in lockstep. No schema migration needed — `memory_links.relation` has no `CHECK` clause on either adapter. `db::find_paths`'s recursive-CTE walks every relation, so `reflects_on` chains surface naturally in chain-walk queries without further work.
- **Task 4** ([commit `3dc76f3`](https://github.com/alphaonedev/ai-memory-mcp/commit/3dc76f3)) — new MCP tool `memory_reflect` (`Family::Power`, tool-count bumps **51 → 52**). Atomic insert of a reflection memory + N `reflects_on` link writes inside a single `BEGIN IMMEDIATE` / `COMMIT` transaction; any link-insert failure ROLLBACKs the entire write so the reflection memory itself never survives a half-written state. Postgres parity via inherent `PostgresStore::reflect` (single `sqlx::Transaction` mirroring the SQLite path). New error variant `MemoryError::ReflectionDepthExceeded { attempted: u32, cap: u32, namespace: String }` (HTTP `409 CONFLICT`, code `REFLECTION_DEPTH_EXCEEDED`). The reflection memory carries a system-generated `metadata.reflection_metadata` block (`reflected_on_source_ids`, `reflection_depth`, `reflection_created_at`); caller-supplied metadata keys win on collision (documented additive contract).
- **Task 5** ([commit `c61a05b`](https://github.com/alphaonedev/ai-memory-mcp/commit/c61a05b)) — H5 audit chain now covers depth-cap refusals on `memory_reflect`. Every `ReflectError::DepthExceeded` appends a `reflection.depth_exceeded` row to the append-only `signed_events` audit table binding `(agent_id, attempted, cap, namespace, source_ids, proposed_title, created_at)` under a canonical-CBOR (RFC 8949 §4.2.1) payload with a SHA-256 `payload_hash` and `attest_level = "unsigned"`. The reflection's content body is deliberately omitted from the audit payload (PII guarantee — only enumerable provenance fields are signed). Audit-write failures are best-effort: logged via `tracing::warn!(target: "signed_events", ...)` but the cap refusal still propagates to the caller. Caller-policy refusals (hook vetoes, see Task 6) carry their own provenance and do NOT emit this row.
- **Task 6** ([commit `fbf093c`](https://github.com/alphaonedev/ai-memory-mcp/commit/fbf093c)) — Track G hook pipeline grows from 21 to 23 events with two new `HookEvent` variants: `pre_reflect` (decision-class, `Write` event class, 5s deadline) fires BEFORE the depth-cap check and may VETO the reflection by returning `Deny { reason, code }`; vetoes propagate as `ReflectError::HookVeto` (`"REFLECTION_HOOK_VETO (code=<N>): <reason>"`) distinct from a cap refusal. `post_reflect` (notify-class, `Write` event class, 5s deadline) fires AFTER the atomic transaction commits, so post-handlers read the fully-durable reflection memory + its `reflects_on` links via the same connection. The G10 hot-path floor had already raised the pipeline count from 20 to 21 (`pre_recall_expand`); Task 6 raises it to 23. Hook vetoes are *not* audited via the Task 5 cap-refusal row — caller-policy refusals carry their own provenance, and conflating them with substrate-cap refusals would dilute the audit signal. The MCP wire-in of `hooks.toml` → `ReflectHooks` is deferred to G7+ (the v0.7.0 handler ships an unreachable `HookVeto` arm pending that bridge).

Tasks 7-8 (ship-gate test suite + docs/release-notes/capabilities honesty pass) land on the same branch and roll up into this v0.7.0 entry. Tracker issue: [#655](https://github.com/alphaonedev/ai-memory-mcp/issues/655).

### v0.7.0 grand-slam wave — substrate-native recursive learning at scale (issues [#666](https://github.com/alphaonedev/ai-memory-mcp/issues/666)–[#673](https://github.com/alphaonedev/ai-memory-mcp/issues/673), [#691](https://github.com/alphaonedev/ai-memory-mcp/issues/691), [#693](https://github.com/alphaonedev/ai-memory-mcp/issues/693))

Extends the recursive-learning substrate primitive into a complete substrate-native learning loop. Folds into the v0.7.0 ship rather than carving a separate v0.7.1 release (operator decision `05e0cb9a`, v0.7.1 ABOLISHED). Lands on `feat/v0.7.0-grand-slam` at commit `c359e89`.

- **L1-5 Agent Skills ingestion substrate.** New typed `skills` table holds agentskills.io-compliant SKILL.md manifests with YAML frontmatter, optional `resources/` sub-directory, content-addressed SHA-256 digest, Ed25519 attestation when an operator keypair is on disk, and version chaining on re-register. **5 MCP tools** in the initial substrate ship: `memory_skill_register`, `memory_skill_list`, `memory_skill_get`, `memory_skill_resource`, `memory_skill_export`. Register → export → re-register produces the IDENTICAL SHA-256 digest (the round-trip guarantee). Federation preserves digest + signing-agent identity across hops. See [`docs/agent-skills.md`](docs/agent-skills.md).
- **L1-6 substrate rules-enforcement engine — Option B foundation.** Operator-keypair-signed seed rules (`R001..R004`) in the `governance_rules` table. `verify_rule_signature` runs on load and refuses to start the daemon on a signed-rule-with-bad-signature. Bypass-impossibility integration test fleet ([commit `6038f85`](https://github.com/alphaonedev/ai-memory-mcp/commit/6038f85)). New `ai-memory rules sign` operator CLI ([commit `4e5b560`](https://github.com/alphaonedev/ai-memory-mcp/commit/4e5b560)). MCP read-only inspection via `memory_rule_list` + `memory_check_agent_action`; mutation is operator-only per design revision 2026-05-13. L1-6 Deliverable E ([commit `1b877ce`](https://github.com/alphaonedev/ai-memory-mcp/commit/1b877ce), [#691](https://github.com/alphaonedev/ai-memory-mcp/issues/691)) wires `check_agent_action` into `storage::insert` as a pre-write hook with the structured `RuleRefused` error variant. **Audit-honest framing:** substrate authority is a foundation in v0.7.0, a complete cover in v0.8.0 ([#697](https://github.com/alphaonedev/ai-memory-mcp/issues/697)).
- **L1-7 compaction pipeline.** New `CompactionPass` trait + cosine clustering pipeline supporting the curator's reflection mode and future consolidation rewrites. 25-event pipeline. ([merge commit `7451143`](https://github.com/alphaonedev/ai-memory-mcp/commit/7451143).)
- **L2-1 reflection-pass curator** ([commit `c3f6e82`](https://github.com/alphaonedev/ai-memory-mcp/commit/c3f6e82), [#666](https://github.com/alphaonedev/ai-memory-mcp/issues/666)) — asynchronous curator clusters `Observation`-kind memories by namespace + temporal proximity + recall co-occurrence proxy and mints reflections through the substrate path. Opt-in per namespace; `MIN_CLUSTER_SIZE = 3`, `MAX_CLUSTER_SIZE = 12`, 7-day temporal window. One level of reflection per pass; multi-level chains form over repeated passes when `max_reflection_depth` permits. Operator-facing CLI: `ai-memory curator --reflect`. Runbook: [`docs/RUNBOOK-curator-soak.md`](docs/RUNBOOK-curator-soak.md).
- **L2-2 federation-aware reflection coordination** ([commit `0b1c9cc`](https://github.com/alphaonedev/ai-memory-mcp/commit/0b1c9cc), [#667](https://github.com/alphaonedev/ai-memory-mcp/issues/667)) — receivers stamp `metadata.reflection_origin = {peer_origin, original_depth, local_depth_at_arrival}` on inbound reflection memories. The local cap is enforced on **derived** writes regardless of source peers' caps — federation cannot launder depth. The new MCP tool `memory_reflection_origin` returns the structured origin envelope.
- **L2-3 reflection invalidation propagation** ([commit `3f419be`](https://github.com/alphaonedev/ai-memory-mcp/commit/3f419be), [#668](https://github.com/alphaonedev/ai-memory-mcp/issues/668)) — a Reflection→Reflection `supersedes` edge fires `propagate_reflection_invalidation` which writes one notification memory per dependent under `<dependent.namespace>/_invalidations` with `metadata.notification_kind = "reflection_invalidation"` and the four-tuple `{dependent_id, invalidated_id, invalidating_id, timestamp}`. **Notification, NOT cascade** — dependents are flagged for operator/curator review, never auto-superseded. Cascade rollback is v0.8.0 Pillar 2.5. The new MCP tool `memory_dependents_of_invalidated` is the read-only inspection surface.
- **L2-4 transcript replay union** ([commit `a50b34c`](https://github.com/alphaonedev/ai-memory-mcp/commit/a50b34c), [#669](https://github.com/alphaonedev/ai-memory-mcp/issues/669)) — `memory_replay` on a reflection memory returns the union of transcripts reachable by walking `reflects_on` to the source observations. Caller-controlled walk depth via `depth=N`; `depth=0` returns the reflection's own transcripts only (matches the pre-L2-4 I4 shape).
- **L2-5 forensic bundle** ([commit `bb870b3`](https://github.com/alphaonedev/ai-memory-mcp/commit/bb870b3), [#670](https://github.com/alphaonedev/ai-memory-mcp/issues/670)) — new CLI verbs `ai-memory export-forensic-bundle` and `ai-memory verify-forensic-bundle`. Deterministic in-process POSIX-ustar tar with per-file SHA-256, optional Ed25519 manifest signature, and **byte-identical mod timestamp** reproducibility. AgenticMem Attest tier integration. Pairs with L1-3 `verify-reflection-chain`. See [`docs/forensic-export.md`](docs/forensic-export.md).
- **L2-6 reflection-as-skill promote** ([commit `505c538`](https://github.com/alphaonedev/ai-memory-mcp/commit/505c538), [#671](https://github.com/alphaonedev/ai-memory-mcp/issues/671)) — new MCP tool `memory_skill_promote_from_reflection` promotes a `Reflection`-kind memory (depth ≥ namespace cap, default floor `1`) into a SKILL.md-format Agent Skill. Each `reflects_on` source becomes a `references/source_{i}.md` resource. Frontmatter carries `derived_from_reflection_id` + `original_reflection_depth`. Promote → export → re-register produces the IDENTICAL SHA-256 digest. **Closes the recursive-learning loop.**
- **L2-7 skill ↔ reflection composition** ([commit `0966b57`](https://github.com/alphaonedev/ai-memory-mcp/commit/0966b57), [#672](https://github.com/alphaonedev/ai-memory-mcp/issues/672)) — SKILL.md frontmatter gains the optional `composes_with_reflections` list, each entry a `{namespace, min_depth}` pair. New MCP tool `memory_skill_compositional_context` returns the skill body + reflection memories from the declared namespaces, filtered by per-entry `min_depth` and bounded by `GovernancePolicy::effective_max_reflection_depth` (the **authoritative ceiling** — composition cannot bypass the substrate cap). Reflections ranked by recency + saturating recall_count; cumulative content bounded by `budget_tokens` (default 4000, max 32000).
- **L2-8 reflection-aware reranker boost** ([commit `90291c0`](https://github.com/alphaonedev/ai-memory-mcp/commit/90291c0), [#673](https://github.com/alphaonedev/ai-memory-mcp/issues/673)) — reranker applies `boost * (1 + per_depth_increment * min(reflection_depth, max_depth_cap))` to `Reflection`-kind memories AFTER the cross-encoder blend. Defaults: `boost=1.2`, `per_depth_increment=0.05`, `max_depth_cap=3` (mirrors the substrate cap). `boost=1.0` is the documented kill-switch — reproduces pre-L2-8 ranking exactly.
- **MCP tool count 60 → 63** across the grand-slam wave:
  - L2-2 adds `memory_reflection_origin` (60 → 61 effective).
  - L2-3 adds `memory_dependents_of_invalidated` (61 → 62 effective, registered after L2-2 in the tool-count audit).
  - L2-6 adds `memory_skill_promote_from_reflection` (62).
  - L2-7 adds `memory_skill_compositional_context` (63).
  - Plus the L1-5 substrate's 5 `memory_skill_*` tools registered earlier on the same branch (`register`, `list`, `get`, `resource`, `export`).
- **Schema v33** ([commit `58877c7`](https://github.com/alphaonedev/ai-memory-mcp/commit/58877c7)) — promotes the `memory_links.relation` validation from a v23 trigger to a SQL-side CHECK constraint covering `related_to | supersedes | contradicts | derived_from | reflects_on`. Postgres parity migration mirrors the same constraint. Lands in v0.7.0 per `05e0cb9a` v0.7.1-fold decision (v0.7.1 ABOLISHED).
- **Schema v34 — V-4 closeout (#698) `signed_events` cross-row hash chain.** Adds `prev_hash BLOB` + `sequence INTEGER` columns plus a UNIQUE INDEX on `signed_events`, mirroring the JSONL property in `src/audit.rs` at the SQL surface. Per-row Ed25519 signatures (existing) prove individual event integrity; the cross-row chain (this closeout) is the LOAD-BEARING tamper-evidence property — a DELETE of row N is detected at row N+1's `prev_hash` mismatch and a tampered `sequence` is detected by the contiguity check in [`verify_chain`](src/signed_events.rs). Postgres parity bumps to v33. Backfill stamps pre-existing rows in [`migrate_v34_backfill_chain`](src/storage/migrations.rs) and is idempotent on replay. New operator surface: `ai-memory verify-signed-events-chain [--since <sequence>] [--format text|json]`. Flips the V-4 validation status from YELLOW (operator directive's `monotonic_sequence == prior + 1` was unsatisfiable without a sequence column) to GREEN. Test pin: [`tests/signed_events_chain_v34.rs`](tests/signed_events_chain_v34.rs) (7 tests covering first-row zero-prev_hash, multi-row chaining, payload tamper detection, sequence tamper detection, concurrent drainer inserts via PE-3 pattern, backfill idempotency, and backfill correctness on pre-existing rows). Drainer-soak integration test ([`tests/deferred_audit_soak.rs`](tests/deferred_audit_soak.rs)) now asserts chain holds after 5K concurrent inserts.

### v0.7.0 substrate authority — Policy Engine (Option B landed, parent meta [#693](https://github.com/alphaonedev/ai-memory-mcp/issues/693))

The v0.7.0 substrate ships the policy engine surface that gates
agent-EXTERNAL actions (Bash, FilesystemWrite outside the substrate,
NetworkRequest, ProcessSpawn, Custom) against an operator-signed
`governance_rules` table, alongside the existing K9 governance
pipeline that gates substrate-INTERNAL ops. Full architectural
documentation lives at
[`docs/policy-engine.md`](docs/policy-engine.md); the audit-trail
coverage matrix at
[`docs/security/audit-trail-coverage.md`](docs/security/audit-trail-coverage.md).

**Shipped at v0.7.0 grand-slam HEAD:**

- **L1-6 substrate-rules engine** ([#691](https://github.com/alphaonedev/ai-memory-mcp/issues/691)).
  `AgentAction` enum + variants (`Bash` / `FilesystemWrite` /
  `NetworkRequest` / `ProcessSpawn` / `Custom`); `RulesStore` typed
  CRUD over the new `governance_rules` table (migration
  `0024_v07_governance_rules.sql`); `check_agent_action` audited path
  (every call emits one `governance.check` row to `signed_events`);
  seed rules R001-R004 land at `enabled = 0` per the cold-start
  contract; operator keypair at `~/.config/ai-memory/operator.key`
  (mode 0600 enforced at load); load-time Ed25519 signature
  verification with the bypass-prevention property
  (`canonical_bytes_for_signing` commits to `enabled`, so a direct
  `UPDATE governance_rules SET enabled = 1` invalidates the recorded
  signature and the rule is skipped). Six L1-6 integration tests
  pin the tampered-signature / direct-enabled-flip / open-permissions
  / sign-seed-idempotent / rotated-key matrices.
- **L1-6 Deliverable E — `storage::insert` governance pre-write hook**
  ([#691](https://github.com/alphaonedev/ai-memory-mcp/issues/691),
  commit `1b877ce`). Process-wide `OnceLock` in
  `src/storage/mod.rs::GOVERNANCE_PRE_WRITE`; installed exactly once
  at daemon `serve` boot (CLI one-shot paths leave it empty by
  design). Every substrate write path (`insert`,
  `insert_with_conflict`, `insert_if_newer`) consults the hook before
  the SQL `INSERT`; refusal short-circuits the write with no row
  touched and propagates `MemoryError::RefusedByGovernance` →
  HTTP `403 GOVERNANCE_REFUSED`. Six integration tests
  (`tests/governance_storage_insert_hook.rs`) pin the bypass-impossibility
  property — including that **all three** insert paths are gated and
  that the CLI one-shot mode does NOT install the hook.

**v0.7.0 Option B work in flight (parent meta [#693](https://github.com/alphaonedev/ai-memory-mcp/issues/693)):**

- **PE-1** ([#694](https://github.com/alphaonedev/ai-memory-mcp/issues/694))
  universal `AgentAction` wire-point coverage. Branch
  `policy-engine/wire-points`.
- **PE-2** ([#695](https://github.com/alphaonedev/ai-memory-mcp/issues/695))
  Claude Code PreToolUse harness hook installer. Branch
  `policy-engine/harness-hook`. Once merged, `ai-memory install
  --harness claude-code --enforce-policy` configures the hook so
  the harness consults `memory_check_agent_action` before every
  Bash / Write / Network / ProcessSpawn the agent proposes.
- **PE-3** ([#696](https://github.com/alphaonedev/ai-memory-mcp/issues/696))
  deferred audit-log queue. Branch
  `policy-engine/deferred-audit-log`. Closes the storage-hook
  audit gap: refusals at the substrate-internal pre-write path are
  typed AND chain-logged via a process-local tokio drain task —
  same canonical bytes / payload hash as the audited path, no
  re-entrancy on the substrate writer.

**Honest framing.** v0.7.0 ships substrate authority for
agent-EXTERNAL actions that are **substrate-visible** (the storage
write path mechanically; the agent-external Bash / Write / Network /
ProcessSpawn surface via opt-in harness coverage once PE-2 merges).
Out-of-band channels (agents that bypass the harness entirely) are
not enforceable by the substrate — see V08-PE-1 (mandatory-hook
profile) and V08-PE-6 (TPM-bound binary integrity) under the v0.8.0
closeout below. Subprocess-chain visibility (a permitted Bash whose
child forks an unrelated process) is also out of scope at v0.7.0 —
see V08-PE-3.

**v0.8.0 closeout epic — 100% Cryptographic Forensic Audit Trail
([#697](https://github.com/alphaonedev/ai-memory-mcp/issues/697)).**
Closes the remaining ~5% gap. Eight sub-tasks (V08-PE-1 …
V08-PE-8): mandatory-hook profile, read-action gating, subprocess-chain
visibility via eBPF/dtrace, persistent audit queue (durable across
daemon restart — closes PE-3's process-local gap), severity-based
human escalation (adds `Decision::Escalate`), TPM-bound binary
integrity, refuse-by-default profile, and the
`ai-memory verify-audit-trail` completeness verifier. Effort:
22-28 sessions · 3-4 weeks wall-clock. Full sub-task detail in
ROADMAP §16. Operator directive of 2026-05-14 verbatim — "Every
tool call passes through a policy engine; the engine logs every
refusal cryptographically; severity-classified rules can escalate
to human" — is the property v0.8.0 closes literally.

**v0.7.0 grand-slam fold update.** PE-1 / PE-2 / PE-3 have all
landed on `feat/v0.7.0-grand-slam`:

- **PE-1** wire-points ([#694](https://github.com/alphaonedev/ai-memory-mcp/issues/694))
  installs `GOVERNANCE_PRE_ACTION` at daemon boot covering the four
  agent-EXTERNAL action variants. MCP skill_export, federation::sync,
  hooks::executor, and the LLM client all consult the hook before
  side-effecting.
- **PE-2** harness-hook ([#695](https://github.com/alphaonedev/ai-memory-mcp/issues/695))
  `ai-memory install --harness claude-code --enforce-policy` wires
  the PreToolUse hook into the harness `settings.json` so every
  Bash / Write / Network / ProcessSpawn the agent proposes passes
  through `memory_check_agent_action`.
- **PE-3** deferred-audit-log ([#696](https://github.com/alphaonedev/ai-memory-mcp/issues/696))
  closes the storage-hook chain-log gap. Refusals at the
  substrate-internal pre-write path are now BOTH typed AND chain-logged
  via a process-local tokio drain task (`governance.refusal` rows in
  `signed_events`); the in-flight write transaction releases its lock
  before the audit row writes so deadlock is structurally impossible.

### Track summary (11 tracks, 69 tasks)

- **Track A — Capabilities v3 response shape (5 tasks).** Adds `summary`, `to_describe_to_user`, `callable_now`, `agent_permitted_families` to the `memory_capabilities` response, plus `schema_version="3"` (additive over v2). Pre-computed per-agent calibration strings let LLMs converge on accurate first-answer descriptions instead of improvising. v3 fields are additive — v2 wire shape stays supported through the v0.7.x line. Canonical phrasings pinned in [`docs/v0.7/canonical-phrasings.md`](docs/v0.7/canonical-phrasings.md).
- **Track B — Loader tools (5 tasks).** `memory_load_family` and `memory_smart_load(intent)` are promoted to **always-on first-class tools** (no longer hidden inside an introspection tool's parameter set). Reasoning-class LLMs find them on first ask. Includes harness detection from MCP `clientInfo` (Claude Code, Codex, Grok CLI, Gemini CLI, Continue, Cursor, Cline, Aider, Goose, Claude Desktop, generic JSON-RPC) and family-descriptor embeddings powering `memory_smart_load`'s intent-to-family routing.
- **Track C — Schema compaction (5 tasks).** **52% MCP tool-token reduction** on the full profile. Description / docs split (long form moved to per-tool docs links), optional params hidden from default schema, inline examples stripped, hard CI gate enforces ≤ 3,500 input tokens for `--profile full` `tools/list`. Combined with v0.6.4's 76.4% default-profile reduction, the cortex now ships at < 3.5K tokens even when fully loaded.
- **Track D — Per-harness positioning + tests (4 tasks).** Cross-harness benchmark across the 11 supported harnesses; landing-page compatibility matrix at [`docs/v0.7/compatibility-matrix.html`](docs/v0.7/compatibility-matrix.html); install-time system-prompt snippet emitted by `ai-memory install`; harness integration tests in `tests/harness_*.rs` covering both 5-tool default and full-profile loading paths.
- **Track E — Discovery Gate T0 calibration cells (3 tasks).** Discovery Gate T1-T3 loader cells; T0 orchestration script driving 4 LLMs (Claude, Grok, Gemini, GPT) for ≥ 95% convergence verification on canonical phrasings; post-ship convergence verification scheduled against the released binary. See [`docs/v0.7/T0-ORCHESTRATION.md`](docs/v0.7/T0-ORCHESTRATION.md).
- **Track F — Docs + release (6 tasks).** [`docs/MIGRATION_v0.7.md`](docs/MIGRATION_v0.7.md) v0.6.4 → v0.7.0 guide; [`docs/whats-new-v07.html`](docs/whats-new-v07.html) what's-new page; [`docs/v0.7/rfc-attested-cortex.md`](docs/v0.7/rfc-attested-cortex.md) RFC; `README.md` + `docs/ADMIN_GUIDE.md` updates; top-nav badges; this release-cut PR.
- **Track G — Hook Pipeline (11 tasks, Bucket 0).** The substrate ships: `~/.config/ai-memory/hooks.toml` config file; **25 lifecycle event types** with payloads — the Track G 20 baseline (`pre_store`, `post_store`, `pre_recall`, `post_recall`, `pre_search`, `post_search`, `pre_delete`, `post_delete`, `pre_promote`, `post_promote`, `pre_link`, `post_link`, `pre_consolidate`, `post_consolidate`, `pre_governance_decision`, `post_governance_decision`, `on_index_eviction`, `pre_archive`, `pre_transcript_store`, `post_transcript_store`) plus 5 grand-slam additions (`pre_recall_expand` G10 + `pre_reflect`/`post_reflect` recursive-learning Task 6/8 + `pre_compaction`/`on_compaction_rollback` L1-7), enumerated in `src/hooks/events.rs::HookEvent`; `ExecExecutor` + `DaemonExecutor` JSON-stdio IPC; decision types (`Allow`/`Deny`/`Modify`/`Defer`); chain ordering with priority; per-event timeouts; hot reload on `hooks.toml` mtime change; `on_index_eviction` for HNSW/cache eviction observability; reranker batching for concurrent recall; `pre_recall` daemon-mode hook; **R3 auto-link reference detector** as a reference hook binary.
- **Track H — Ed25519 Attested Identity (6 tasks, Bucket 1).** `ai-memory identity generate` CLI mints per-agent Ed25519 keypairs; outbound link signing fills the v0.6.3 `memory_links.signature` "dead column"; inbound signature verification on every link write; `attest_level` enum (`unsigned` / `signed` / `verified` / `rejected`); `memory_verify` MCP tool surfaces signature state on demand; **append-only `signed_events` audit table** with hash-chained provenance; end-to-end test pinning the full mint → sign → verify → audit cycle.
- **Track I — Sidechain Transcripts (5 tasks, Bucket 1.7).** `memory_transcripts` schema (BLOB + zstd-3); `memory_transcript_links` join table; per-namespace TTL with exact-match → longest `prefix/*` → `*` → default-off precedence; `memory_replay` MCP tool reconstructs full conversation context from a transcript link; **R5 `pre_store` transcript-extraction reference hook** ships as a standalone Rust binary at `tools/transcript-extractor/` (kept out of the published crates.io upload via the parent `Cargo.toml`'s `include` allowlist).
- **Track J — Apache AGE Acceleration (8 tasks, Bucket 2).** AGE detected at Postgres-SAL connect-time via `pg_extension` probe (logged-only fallback to CTE on missing extension or probe error); Cypher implementations of `kg_query`, `kg_timeline`, `kg_invalidate`, and **R2 `find_paths`**; dual-path tests gated on `AI_MEMORY_TEST_AGE_URL`; AGE / CTE per-query performance budgets with bench-time gate; `KgBackend { Cte, Age }` enum exposed via `Capabilities` (`kg_backend` field) for `ai-memory doctor` and `memory_capabilities`.
- **Track K — A2A + Permissions + G1 cutline (11 tasks, Bucket 3).** **K1/G1 namespace-inheritance enforcement** (the mandatory cutline — `resolve_governance_policy` walks the namespace chain; first non-null policy wins); `pending_actions` timeout sweeper (closes the v0.6.3.1 `default_timeout_seconds` honesty disclosure); `permissions.mode` enforcement gate (defaults to `enforce` per F8); approval-event routing; `permissions.rule_summary` re-instated; A2A correlation IDs + ACK retries + TTL + replay protection; subscription DLQ + replay-from-cursor + HMAC; per-agent quotas with daily reset; unified permission pipeline (rules + modes + hooks → decision); approval API on **HTTP + SSE + MCP** with HMAC and `remember=forever`; `ai-memory governance migrate-to-permissions` translator CLI for upgrading v0.6.x governance configs.

### Migration from v0.6.x

- **From v0.6.4 (sqlite, staying on sqlite):** auto-migrates v20 → v34 on first start (the Wave 1-4 narrative checkpoint v20 → v28 was the initial postgres+AGE land; in-flight v0.7.0 work then added v29-v30 for recursive-learning, v33 for L2 wave `memory_links.relation` CHECK, and v34 for V-4 closeout `signed_events` cross-row chain). See `docs/MIGRATION_v0.7.md` for the v0.6.4 → v0.7.0 surface delta.
- **From v0.6.4 (sqlite, switching to postgres+AGE):** see `docs/migration-v0.7.0-postgres.md`. Provision postgres + AGE + pgvector → `ai-memory schema-init` → dry-run migrate → real migrate → verify → cutover.
- **From v0.7-alpha (postgres at schema v15):** `ai-memory schema-init --upgrade` walks v15 → v33 idempotently (Wave 1-4 ported v15 → v28; subsequent L0.7 / L2 / V-4 closeout work added v29 - v33 on the postgres side).

### Breaking changes

- **F8 — `permissions.mode` defaults to `enforce`** (was `advisory`). Operators relying on default-permissive must opt back in via `[permissions] mode = "advisory"` in `config.toml`.
- **F11 — `forget --pattern` / `forget --tier` without `--namespace`** require `--confirm-global`.

### Security-hardening sweep — release/v0.7.0 reconciliation (16 commits, folded at merge `64528b1`)

Sixteen late-cycle security-hardening commits landed on `release/v0.7.0` between the initial release-cut and the reconciled v0.7.0 HEAD. All sixteen are folded into the v0.7.0 ship via the reconciliation merge `64528b1` (parent `fd397f9` audit deliverable + parent `6b6b3c0` release tip). Both audiences (release auditors + feature operators) see the same surface. The eleven late-cycle K10 / K9 / SSRF / hooks / db / permissions / transcripts fixes below are the headline; the remaining five reconciled commits are the prior `release/v0.7.0` C5 budget gate fix (`5711a5d`), C1/C2/H10 governance fix (`42d384d`), H5/H6/I1 identity fix (`4305925`), H1/H3/H4 governance fix (`c02d5ed`), and H9 hooks-stderr-drain fix (`e2b9544`).

- **SSRF — reject IPv4-mapped IPv6 + NAT64 prefix bypasses** ([commit `3ab72dc`](https://github.com/alphaonedev/ai-memory-mcp/commit/3ab72dc)) — `validate_url_with` now refuses `::ffff:10.0.0.1` and `64:ff9b::10.0.0.1` style addresses that would otherwise smuggle private-range traffic past the v6 path. Test pin: `tests/k10_approval_security.rs` SSRF v4-mapped cases (release-branch tightening on `6b6b3c0` updated callers to pass the explicit flag).
- **K9 governance gate parity on `handle_kg_invalidate`** ([commit `a41c08f`](https://github.com/alphaonedev/ai-memory-mcp/commit/a41c08f)) — the KG invalidate path now consults the same governance pre-write gate `handle_link` already used; the prior asymmetry left a substrate-internal write path ungated.
- **K10 SSE — close `host:` prefix privilege-escalation** ([commit `7496a6e`](https://github.com/alphaonedev/ai-memory-mcp/commit/7496a6e)) — SSE subscription auth no longer accepts a `host:`-prefixed agent id as a substitute for the bound agent; the prefix used to short-circuit the namespace-inheritance check. An anonymous subscriber sees nothing.
- **K10 HMAC — bind method + `pending_id` in canonical request** ([commit `99ffacc`](https://github.com/alphaonedev/ai-memory-mcp/commit/99ffacc)) — the approval API HMAC now signs `(method, pending_id, body_hash)` rather than just `body_hash`; the prior shape allowed a captured signature to be replayed against a different verb or a different pending row.
- **`invalidate_link` BEGIN IMMEDIATE wrap** ([commit `2c77537`](https://github.com/alphaonedev/ai-memory-mcp/commit/2c77537)) — the UPDATE + audit-INSERT pair is now wrapped in a single `BEGIN IMMEDIATE` so a concurrent reader cannot observe the invalidation without the audit row, or vice-versa.
- **Hooks executor — redact secret-shaped stderr** ([commit `cbe934c`](https://github.com/alphaonedev/ai-memory-mcp/commit/cbe934c)) — operator-log + caller-`reason` strings now scrub anything matching `password|secret|key|token|cred` patterns before surfacing; closes the side-channel where a hook subprocess could leak credentials by panicking with them in the message body.
- **K10 HMAC nonce cache — single-use signatures within 300s window** ([commit `a69325f`](https://github.com/alphaonedev/ai-memory-mcp/commit/a69325f)) — replay protection now tracks (signature, nonce) tuples in a 300-second sliding window; a captured signature cannot be replayed even before its timestamp expires. Replay-window tightening from earlier release pass retained.
- **H8 — rebound namespace `Ask` must not silently elevate** ([commit `69ad41c`](https://github.com/alphaonedev/ai-memory-mcp/commit/69ad41c)) — when a namespace's `Ask` policy is rebound to a stricter parent, the prior leaf-resolution short-circuit no longer surfaces the parent's permissive grant; the resolver now walks the full chain on rebind.
- **I1 — `transcripts` decompression cap is config-driven** ([commit `26fab06`](https://github.com/alphaonedev/ai-memory-mcp/commit/26fab06)) — the zstd decompression bound now reads `TranscriptsConfig.max_decompressed_bytes` (default 16 MiB) instead of a compile-time constant; operators can tighten the cap on memory-constrained hosts.
- **K10 SSE — strip lagged-event count to close volume side-channel** ([commit `d1f6c9f`](https://github.com/alphaonedev/ai-memory-mcp/commit/d1f6c9f)) — the SSE `Retry-After` and `X-Lagged-Events` headers no longer surface the exact count of dropped events; an attacker can no longer infer the rate of other subscribers' traffic from the lag signal.
- **SSRF v4-mapped tests use `validate_url_with` explicit flag** ([commit `6b6b3c0`](https://github.com/alphaonedev/ai-memory-mcp/commit/6b6b3c0)) — test-side tightening so the SSRF test fleet exercises the explicit-flag path that production callers now take.

All sixteen fixes are no-op for callers operating inside the substrate's expected envelope; each closes a specific bypass / replay / inference vector surfaced during the v0.7.0 cert sequence or the post-cert security pass.

### Fixed — ship-readiness reconciliation (v0.7.0 final cut)

The reconciliation pass that brought the WT-1 / QW / Batman 6+7 feature trunk together with the release-branch security tip surfaced a handful of latent bugs and discipline drift. All are closed at the v0.7.0 reconciled HEAD.

- **`signed_events::append_signed_event_no_tx` variant** — the K9 governance pre-write hook now writes its audit row via a no-tx variant to avoid nested-transaction collision with the `BEGIN IMMEDIATE` wrap that the `2c77537` `invalidate_link` fix introduced. Audit-honest: the V-4 cross-row hash chain (#698) is preserved because the no-tx writer still walks through the same `prev_hash` + `sequence` increment path; the only difference is the absence of an inner `BEGIN`/`COMMIT` pair.
- **`postgres_schema.sql` + migration `0018_v07_persona.sql` — backfill missing `memory_kind` column** — latent QW-2 bug uncovered during the reconciliation: the persona index `idx_personas_by_entity` referenced `memory_kind` but the postgres schema had not yet added the column. The reconciliation backfills the column in `postgres_schema.sql` and ports the migration so a fresh postgres bootstrap matches the SQLite parity.
- **`examples/atomise_roundtrip.rs` Memory{} literal updated** for the Form 4/5 field additions (`citations`, `source_uri`, `atom_span` from Form 4; the per-memory `confidence` source-tracking fields from Form 5). The example continues to build and the round-trip property holds.
- **`memory_calibrate_confidence` MCP tool description trimmed to 38 `cl100k_base` tokens** (was 55, exceeded the c2 per-tool token budget gate). The static schema-size CI assertion (`crate::sizes`) gates the trimmed wire form.
- **14 `sign_approve_body` test call sites updated** for K10 HMAC method+`pending_id` binding lockstep — the canonical-request shape change at `99ffacc` required every caller in the test fleet to pass the verb + pending row id.
- **`executor_error_child_exit_with_signaled_code` assertion updated** for the stderr-redaction discipline introduced at `cbe934c` — the test expected the raw secret-shaped stderr to surface in the panic message; the assertion now expects the redacted form.

### Schema migrations (this release)

- **sqlite: v34 → v35** (signed_events V-4 closeout midpoint, #698) → **v36** (WT-1-A atomisation foundation: `atomised_into` / `atom_of` / `derives_from` link relations + CHECK constraint extension; `migrations/sqlite/0030_v07_atomisation.sql`) → **v37** (QW-2 persona substrate primitive: `personas` table + `idx_personas_by_entity` index; `migrations/sqlite/0031_v07_persona.sql`) → **v38** (Form 4 fact-provenance: per-memory `citations` / `source_uri` / `atom_span` columns; `migrations/sqlite/0032_v07_form4_provenance.sql`) → **v39** (Form 5 confidence calibration: `confidence_observations` shadow-mode table + `confidence_baselines` calibration store; `migrations/sqlite/0033_v07_form5_confidence_calibration.sql`) → **v40-v44** (incremental v0.7.0 post-grand-slam land of recall observations, source_uri promotion, persona signing atomicity, auto-persona entity_id, shadow retention) → **v45** (Gap-1 optimistic concurrency: `memories.version` BIGINT) → **v46** (Form-4 provenance versioning) → **v47** (#885 source_uri backfill from metadata + citations[0].uri) → **v48** (#933 `federation_push_dlq` table) → **v49** (#1025 14 nullable columns on `archived_memories` so archive→restore is lossless for the full v0.7.0 Memory shape) → **v50** (#1156 per-namespace K8 quota dimension extension: `agent_quotas` PRIMARY KEY extended from `(agent_id)` to `(agent_id, namespace)`, pre-v50 rows backfill to the `_global` sentinel namespace; `migrations/sqlite/0042_v50_per_namespace_quota.sql`). `CURRENT_SCHEMA_VERSION = 50` in `src/storage/migrations.rs`.
- **postgres: v34 → v35** (WT-1-A; `migrations/postgres/0017_v07_atomisation.sql`) → **v36** (QW-2; `migrations/postgres/0018_v07_persona.sql`) → **v37** (Form 4; `migrations/postgres/0019_v07_form4_provenance.sql`) → **v38** (Form 5; `migrations/postgres/0020_v07_form5_confidence_calibration.sql`) → … → **v49** → **v50** at v0.7.0 release HEAD (postgres ladder converged to the single logical schema version via in-process migration arms; v50 adds `migrate_v50()` per #1156 — `ALTER TABLE agent_quotas ADD COLUMN namespace TEXT NOT NULL DEFAULT '_global'` + PK swap + supporting index). `CURRENT_SCHEMA_VERSION = 50` in `src/store/postgres.rs`. Both backends now share a single logical version. Parity test [`tests/postgres_schema_parity.rs`](tests/postgres_schema_parity.rs) pins the equivalence.

### MCP tool surface

- **Full profile: 73 tools** at v0.7.0 release HEAD (up from the 63 advertised in the initial v0.7.0 framing; +2 over the mid-cycle 71-tool snapshot reflects the post-grand-slam tools added before the release tag). **Family::Power: 23 tools** at release HEAD. Asserted by `Profile::full().expected_tool_count()` in `src/profile.rs` (7+5+6+11+8+23+4+9 = 73).
- **New tools added in this release** (delta vs the v0.7.0 initial framing):
  - `memory_atomise` (Family::Power) — WT-1-C, PR #751
  - `memory_offload` (Family::Power) — QW-3, [`2a85db2`](https://github.com/alphaonedev/ai-memory-mcp/commit/2a85db2) + [`20b6be1`](https://github.com/alphaonedev/ai-memory-mcp/commit/20b6be1)
  - `memory_deref` (Family::Power) — QW-3
  - `memory_persona` — QW-2, PR #749
  - `memory_persona_generate` — QW-2
  - `memory_export_reflection` — QW-1, [`6d32633`](https://github.com/alphaonedev/ai-memory-mcp/commit/6d32633)
  - `memory_ingest_multistep` (Family::Power) — Form 3, PR #763
  - `memory_calibrate_confidence` (Family::Power) — Form 5, PR #766
- **New CLI-only surfaces** (not exposed as MCP tools):
  - `ai-memory atomise <memory-id>` — WT-1-F
  - `ai-memory export-reflections` — QW-1
  - `ai-memory governance install-defaults` — 7th-form, PR #761
  - `ai-memory calibrate-confidence` — Form 5
- The v0.6.4 `--profile core` 7-tool default surface is unchanged; every new tool is registered under `Family::Power` so the keyword-tier `core` profile remains at the minimum.

### Capabilities-v3 — new application blocks

The v3 response shape gains three application blocks (additive over v2 — v2 wire shape remains supported through the v0.7.x line):

- **`atomisation`** ([`CapabilityAtomisation`](src/config.rs)) — WT-1-G. Reports `status` (`stub` / `implemented`), curator backend identifier, per-atom token cap, and the `auto_atomise` namespace-policy surface (the policy fields the substrate honours).
- **`memory_kinds_vocab`** ([`CapabilityMemoryKindVocab`](src/config.rs)) — Form 6. Reports the full Batman vocabulary `{Observation, Reflection, Persona, Skill, Concept, Entity, Claim, Relation, Event, Conversation, Decision}` and the `auto_classify_kind` namespace-policy surface.
- **`confidence_calibration`** ([`CapabilityConfidenceCalibration`](src/config.rs)) — Form 5. Reports the three opt-in feature flags (`auto_confidence`, `confidence_shadow`, `confidence_decay`) and their advertised status (`unimplemented` / `shadow_mode` / `implemented`) so an agent can interrogate whether to trust the substrate's derived confidence value.

The L1-1 `memory_kinds` v2 list (`["observation", "reflection"]`) stays unchanged for wire-compat; the new `memory_kinds_vocab` block is the v3-only surface advertising the Batman extension.

### Env vars — new in this release

- **`AI_MEMORY_AUTO_CONFIDENCE`** (Form 5) — `1` to enable the per-source-namespace baseline `confidence` derivation at write time. Defaults off; advertised status flips to `implemented` when set.
- **`AI_MEMORY_CONFIDENCE_SHADOW`** (Form 5) — `1` to enable side-channel observation recording for offline calibration. Defaults off; advertised status `shadow_mode` when set.
- **`AI_MEMORY_CONFIDENCE_SHADOW_SAMPLE_RATE`** (Form 5) — `0.0..=1.0` (default `1.0`) — sampling rate for the shadow recorder.
- **`AI_MEMORY_CONFIDENCE_DECAY`** (Form 5) — `1` to enable the exponential freshness-decay model.

### Namespace policy fields — new on `GovernancePolicy`

Each field is `Option<...>` and inherits leaf-first through the existing `resolve_governance_policy` chain walk:

- **`auto_export_reflections_to_filesystem: Option<bool>`** — QW-1, drives `post_reflect::auto_export`.
- **`auto_atomise: Option<bool>`** — WT-1-D, enables `pre_store::auto_atomise`.
- **`auto_atomise_threshold_cl100k: Option<u32>`** — WT-1-D, content-size gate for the auto-atomise hook.
- **`auto_atomise_max_atom_tokens: Option<u32>`** — WT-1-D, per-atom token cap the engine targets.
- **`auto_atomise_mode: Option<AutoAtomiseMode>`** — Form 2 (`Off` / `Deferred` / `Synchronous`). `Synchronous` atomises before the embed call.
- **`auto_persona_trigger_every_n_memories: Option<u32>`** — QW-2, drives `post_reflect::auto_persona`.
- **`auto_export_personas_to_filesystem: Option<bool>`** — QW-2.
- **`legacy_per_pair_classifier: Option<bool>`** — Form 1, keeps the v0.6.0.0 post-store per-pair classifier reachable for backwards compatibility.
- **`auto_classify_kind: Option<MemoryKindAutoClassify>`** — Form 6 (`Off` / `RegexOnly` / `RegexThenLlm`), drives `pre_store::auto_classify_kind`.

### Docs — new in this release

- [`docs/atomisation.md`](docs/atomisation.md) — WT-1 atomisation primitive overview + WT-1-G capability block reference.
- [`docs/persona.md`](docs/persona.md) — QW-2 persona-as-artifact substrate primitive.
- [`docs/context-offload.md`](docs/context-offload.md) — QW-3 context-offload substrate primitive + `memory_offload` / `memory_deref` reference.
- [`docs/positioning.md`](docs/positioning.md) — QW-4 competitive landscape including TencentDB Agent Memory entry.
- [`docs/v0.7.0/test-config.md`](docs/v0.7.0/test-config.md) — pins grok-4.3 + `reasoning_effort=medium` as the canonical xAI config for the v0.7.0 test fleet ([commit `41229d1`](https://github.com/alphaonedev/ai-memory-mcp/commit/41229d1)).
- [`docs/multistep-ingest.md`](docs/multistep-ingest.md) — Form 3 multi-step ingest orchestrator (two-phase deterministic + LLM with prompt-cache reuse).
- [`docs/provenance.md`](docs/provenance.md) — Form 4 fact-provenance citations + source-as-URI + atom-grain span.
- [`docs/confidence-calibration.md`](docs/confidence-calibration.md) — Form 5 auto-confidence + shadow-mode + freshness decay + calibration tooling.
- [`docs/memory-kind-vocab.md`](docs/memory-kind-vocab.md) — Form 6 `MemoryKind` Batman vocabulary + recall filter + optional auto-classify.
- [`docs/governance/agent-action-rules.md`](docs/governance/agent-action-rules.md) — 7th-form agent-EXTERNAL action rule reference (extended from prior K9 doc).
- [`docs/internal/batman-framework-audit.md`](docs/internal/batman-framework-audit.md) — adversarial procurement-grade audit deliverable (PR #753).

### Cookbook — new in this release

- [`cookbook/atomisation/01-basic-flow.sh`](cookbook/atomisation/01-basic-flow.sh) — WT-1 store → atomise → recall round-trip.
- [`cookbook/persona/01-build-persona-from-observations.sh`](cookbook/persona/01-build-persona-from-observations.sh) — QW-2 build persona from reflection cluster.
- [`cookbook/context-offload/01-offload-large-tool-output.sh`](cookbook/context-offload/01-offload-large-tool-output.sh) — QW-3 offload + deref round-trip.
- [`cookbook/file-backed-export/01-export-and-inspect.sh`](cookbook/file-backed-export/01-export-and-inspect.sh) — QW-1 reflection-chain export + inspect.
- [`cookbook/multistep-ingest/01-two-phase.sh`](cookbook/multistep-ingest/01-two-phase.sh) — Form 3 two-phase ingest with prompt-cache reuse.
- [`cookbook/agent-external-governance/01-deny-bash.sh`](cookbook/agent-external-governance/01-deny-bash.sh) — 7th-form Layer-4 deny-bash rule installation.

### Removed / Deprecated

- The pre-2026-05-15 v0.7.0 headline tag "release pending Wave 1-4 cert" is superseded by this reconciled state. Wave 1-4 has long landed; the active gate is the v0.7.0 reconciled HEAD (`64528b1`) which folds WT-1 + QW + Batman 6+7 + audit + security hardening into a single shippable cut.
- The v0.6.0.0 post-store per-pair binary yes/no contradiction classifier is **superseded** by the Form 1 batch action-emitting synthesis path. The legacy classifier remains reachable via `legacy_per_pair_classifier: Some(true)` on the namespace policy for callers that need the v0.6.x shape — flagged for removal in v0.8.0.

## [0.7.0-release-branch-headline] — 2026-05-06 — `attested-cortex` (initial release-cut narrative, superseded by 2026-05-09 reconciled headline above)

**Headline:** v0.7.0 closes the `attested-cortex` epic — **69/69 tasks across 11 tracks** (A/B/C/D/E/F/G/H/I/J/K). The substrate becomes both **more articulate** (capabilities v3 with pre-computed calibration strings, named loaders, 52% MCP-tool token reduction on the full profile) and **cryptographically trustworthy** (per-agent Ed25519 attestation with append-only `signed_events` audit chain, sidechain transcripts with `memory_replay`, programmable 20-event hook pipeline, opt-in Apache AGE acceleration, K1/G1 namespace-inheritance enforcement, real permission system with deny-first semantics, A2A maturity). Canonical scope: [`docs/v0.7/V0.7-EPIC.md`](docs/v0.7/V0.7-EPIC.md). Migration: [`docs/MIGRATION_v0.7.md`](docs/MIGRATION_v0.7.md). What's new: [`docs/whats-new-v07.html`](docs/whats-new-v07.html). RFC: [`docs/v0.7/rfc-attested-cortex.md`](docs/v0.7/rfc-attested-cortex.md).

> **Backward compatibility.** v3 capabilities are additive over v2; existing v0.6.4 SDKs continue to work against a v0.7.0 server. v0.6.4's `--profile core` 5-tool default surface is unchanged. The hook pipeline is **default off** — a v0.7.0 install with no `hooks.toml` behaves identically to v0.6.4 at the lifecycle layer. Schema migrations v20 → v22 (`audit_log` → `signed_events` → `memory_transcripts`) run automatically on first start and are idempotent.

### Track summary (11 tracks, 69 tasks)

- **Track A — Capabilities v3 response shape (5 tasks).** Adds `summary`, `to_describe_to_user`, `callable_now`, `agent_permitted_families` to the `memory_capabilities` response, plus `schema_version="3"` (additive over v2). Pre-computed per-agent calibration strings let LLMs converge on accurate first-answer descriptions instead of improvising. v3 fields are additive — v2 wire shape stays supported through the v0.7.x line. Canonical phrasings pinned in [`docs/v0.7/canonical-phrasings.md`](docs/v0.7/canonical-phrasings.md).
- **Track B — Loader tools (5 tasks).** `memory_load_family` and `memory_smart_load(intent)` are promoted to **always-on first-class tools** (no longer hidden inside an introspection tool's parameter set). Reasoning-class LLMs find them on first ask. Includes harness detection from MCP `clientInfo` (Claude Code, Codex, Grok CLI, Gemini CLI, Continue, Cursor, Cline, Aider, Goose, Claude Desktop, generic JSON-RPC) and family-descriptor embeddings powering `memory_smart_load`'s intent-to-family routing.
- **Track C — Schema compaction (5 tasks).** **52% MCP tool-token reduction** on the full profile. Description / docs split (long form moved to per-tool docs links), optional params hidden from default schema, inline examples stripped, hard CI gate enforces ≤ 3,500 input tokens for `--profile full` `tools/list`. Combined with v0.6.4's 76.4% default-profile reduction, the cortex now ships at < 3.5K tokens even when fully loaded.
- **Track D — Per-harness positioning + tests (4 tasks).** Cross-harness benchmark across the 11 supported harnesses; landing-page compatibility matrix at [`docs/v0.7/compatibility-matrix.html`](docs/v0.7/compatibility-matrix.html); install-time system-prompt snippet emitted by `ai-memory install`; harness integration tests in `tests/harness_*.rs` covering both 5-tool default and full-profile loading paths.
- **Track E — Discovery Gate T0 calibration cells (3 tasks).** Discovery Gate T1-T3 loader cells; T0 orchestration script driving 4 LLMs (Claude, Grok, Gemini, GPT) for ≥ 95% convergence verification on canonical phrasings; post-ship convergence verification scheduled against the released binary. See [`docs/v0.7/T0-ORCHESTRATION.md`](docs/v0.7/T0-ORCHESTRATION.md).
- **Track F — Docs + release (6 tasks).** [`docs/MIGRATION_v0.7.md`](docs/MIGRATION_v0.7.md) v0.6.4 → v0.7.0 guide; [`docs/whats-new-v07.html`](docs/whats-new-v07.html) what's-new page; [`docs/v0.7/rfc-attested-cortex.md`](docs/v0.7/rfc-attested-cortex.md) RFC; `README.md` + `docs/ADMIN_GUIDE.md` updates; top-nav badges; this release-cut PR.
- **Track G — Hook Pipeline (11 tasks, Bucket 0).** The substrate ships: `~/.config/ai-memory/hooks.toml` config file; **25 lifecycle event types** with payloads — the Track G 20 baseline (`pre_store`, `post_store`, `pre_recall`, `post_recall`, `pre_search`, `post_search`, `pre_delete`, `post_delete`, `pre_promote`, `post_promote`, `pre_link`, `post_link`, `pre_consolidate`, `post_consolidate`, `pre_governance_decision`, `post_governance_decision`, `on_index_eviction`, `pre_archive`, `pre_transcript_store`, `post_transcript_store`) plus 5 grand-slam additions (`pre_recall_expand` G10 + `pre_reflect`/`post_reflect` recursive-learning Task 6/8 + `pre_compaction`/`on_compaction_rollback` L1-7), enumerated in `src/hooks/events.rs::HookEvent`; `ExecExecutor` + `DaemonExecutor` JSON-stdio IPC; decision types (`Allow`/`Deny`/`Modify`/`Defer`); chain ordering with priority; per-event timeouts; hot reload on `hooks.toml` mtime change; `on_index_eviction` for HNSW/cache eviction observability; reranker batching for concurrent recall; `pre_recall` daemon-mode hook; **R3 auto-link reference detector** as a reference hook binary.
- **Track H — Ed25519 Attested Identity (6 tasks, Bucket 1).** `ai-memory identity generate` CLI mints per-agent Ed25519 keypairs; outbound link signing fills the v0.6.3 `memory_links.signature` "dead column"; inbound signature verification on every link write; `attest_level` enum (`unsigned` / `signed` / `verified` / `rejected`); `memory_verify` MCP tool surfaces signature state on demand; **append-only `signed_events` audit table** with hash-chained provenance; end-to-end test pinning the full mint → sign → verify → audit cycle.
- **Track I — Sidechain Transcripts (5 tasks, Bucket 1.7).** `memory_transcripts` schema (BLOB + zstd-3); `memory_transcript_links` join table; per-namespace TTL with exact-match → longest `prefix/*` → `*` → default-off precedence; `memory_replay` MCP tool reconstructs full conversation context from a transcript link; **R5 `pre_store` transcript-extraction reference hook** ships as a standalone Rust binary at `tools/transcript-extractor/` (kept out of the published crates.io upload via the parent `Cargo.toml`'s `include` allowlist).
- **Track J — Apache AGE Acceleration (8 tasks, Bucket 2).** AGE detected at Postgres-SAL connect-time via `pg_extension` probe (logged-only fallback to CTE on missing extension or probe error); Cypher implementations of `kg_query`, `kg_timeline`, `kg_invalidate`, and **R2 `find_paths`**; dual-path tests gated on `AI_MEMORY_TEST_AGE_URL`; AGE / CTE per-query performance budgets with bench-time gate; `KgBackend { Cte, Age }` enum exposed via `Capabilities` (`kg_backend` field) for `ai-memory doctor` and `memory_capabilities`.
- **Track K — A2A + Permissions + G1 cutline (11 tasks, Bucket 3).** **K1/G1 namespace-inheritance enforcement** (the mandatory cutline — `resolve_governance_policy` walks the namespace chain; first non-null policy wins); `pending_actions` timeout sweeper (closes the v0.6.3.1 `default_timeout_seconds` honesty disclosure); `permissions.mode` enforcement gate (`advisory` preserves v0.6.4 first-boot semantics, `enforce` deny-firsts); approval-event routing; `permissions.rule_summary` re-instated; A2A correlation IDs + ACK retries + TTL + replay protection; subscription DLQ + replay-from-cursor + HMAC; per-agent quotas with daily reset; unified permission pipeline (rules + modes + hooks → decision); approval API on **HTTP + SSE + MCP** with HMAC and `remember=forever`; `ai-memory governance migrate-to-permissions` translator CLI for upgrading v0.6.x governance configs.

### Quality

- **Hard coverage gate ≥ 93%.** CI fails any PR below the line floor.
- **Clippy `-D pedantic` clean baseline** restored across nine files (#614).
- **Test race fixes** for the subscription `dispatch_count` race, the snippet env race, the keypair env race, the binary-spawn flake on macOS (OnceLock + PID-scoped target), and the b3 budget race.
- **52% MCP tool token reduction** on the full profile (Track C), measured against `cl100k_base`.
- **CI token budget gate** — hard 3,500-token ceiling on `--profile full` `tools/list` (Track C5).

### Follow-ups (post-v0.7.0)

- **v0.7.0.1 — issue [#625](https://github.com/alphaonedev/ai-memory-mcp/issues/625):** E1/E2 cross-platform Rust binaries for the Discovery Gate T0 / T1-T3 loader cell harnesses (currently shell-only on macOS / Linux).

---

### Granular task notes (folded forward from prior `[Unreleased]` block)

The following per-task entries were authored as v0.7 tracks landed and are preserved here for reviewers tracing PR-level provenance:

- **v0.7.0 I5 — R5 reference `pre_store` transcript-extraction hook.**
  New standalone Rust binary at `tools/transcript-extractor/`
  (`ai-memory-transcript-extractor` crate, kept out of the published
  crates.io upload via the parent `Cargo.toml`'s `include` allowlist).
  The binary reads the same JSON `FireEnvelope` shape
  (`src/hooks/executor.rs::FireEnvelope`) the production executor (G3)
  writes to a hook subprocess, classifies the in-flight memory as a
  transcript via three independent signals
  (`metadata.kind == "transcript"`, namespace prefix
  `transcript/`/`transcripts/`, or speaker tokens like `User:` /
  `Assistant:` / `<|user|>` in the first 512 chars of content),
  splits the content into paragraphs scored by a token-bag density
  heuristic, and surfaces the top-K survivors as
  `delta.metadata.extracted_memories` on a `Modify` decision —
  preserving any existing metadata keys an upstream hook already
  wrote. Each candidate carries a `score`, byte-span `span_start`/
  `span_end` into the source content, and a 80-char-capped `title`
  for the future `post_store` mint companion to fold into a
  `memory_transcript_links` row. Both stdio framings are supported:
  one-shot (default; matches `ExecExecutor`) and `--daemon`
  (newline-delimited JSON; matches `DaemonExecutor`). The substrate
  is the deliverable — the heuristic itself is *deliberately* a
  bag-of-words approximation rather than an LLM call (see the
  binary's README) so the reference impl runs in CI without an
  Ollama daemon and without dragging the full `ai-memory` dep
  graph into the tool. New per-namespace opt-in field
  `TranscriptNamespaceConfig.auto_extract` (defaults `None` → off)
  with matching resolver `TranscriptsConfig::auto_extract_for`
  applying the same exact-match → longest `prefix/*` → `*` →
  default-off precedence the I3 TTL resolver uses; 4 unit tests
  cover the resolver. The reference binary ships 14 unit tests
  (envelope round-trip in both modes, all three classification
  signals, stop-word filtering, paragraph chunking floor,
  `EXTRACTOR_TOP_K` env clipping, metadata-key preservation,
  malformed-input degrade-to-Allow, byte-span correctness).
  New integration test `tests/transcript_extractor.rs` builds the
  sibling binary on the fly and asserts the end-to-end stdio
  contract (extraction fires for a transcript memory, returns
  `Allow` for non-transcript memories, falls through to `Allow` on
  the wrong event class) plus the namespace opt-in resolver. R5
  commitment recovered; production tightening of the heuristic is
  scoped to a follow-up post-G11 task that will register the
  `post_store` mint companion.
- **v0.7.0 G2 — 20 hook lifecycle event types with payloads.** New
  `src/hooks/events.rs` module attaches a JSON-serializable payload
  struct to every variant of `HookEvent` (lifted out of G1's
  `src/hooks/config.rs` stub; re-exported from the G1 path for
  back-compat). The 20 events the hook pipeline supports:
  `pre_store`, `post_store`, `pre_recall`, `post_recall`,
  `pre_search`, `post_search`, `pre_delete`, `post_delete`,
  `pre_promote`, `post_promote`, `pre_link`, `post_link`,
  `pre_consolidate`, `post_consolidate`, `pre_governance_decision`,
  `post_governance_decision`, `on_index_eviction`, `pre_archive`,
  `pre_transcript_store`, `post_transcript_store`. Pre-events carry
  writable deltas (`MemoryDelta`, `RecallQuery`, `SearchQuery`,
  `MemoryRef`, `PromoteDelta`, `LinkDelta`, `ConsolidationDelta`,
  `GovernanceContext`, `TranscriptDelta`); post-events carry
  read-only snapshots (`Memory`, `RecallResult`, `SearchResult`,
  `MemoryRef`, `PromoteResult`, `Link` (= `MemoryLink` re-export),
  `ConsolidationResult`, `GovernanceDecision`, `EvictionEvent`,
  `Transcript`). The `Link` and `Transcript` wire types reuse / project
  from `crate::models::MemoryLink` and `crate::transcripts::Transcript`
  respectively. Every variant carries a doc-comment naming the
  source-code location G3-G11 will hook into. Hooks are not yet fired
  at the memory operation points — that's G3-G11. New round-trip JSON
  tests cover all 20 variants and one representative payload per
  family.
- **v0.7.0 J1 — Apache AGE detection in Postgres SAL.** New
  `KgBackend { Cte, Age }` enum (snake-case serde) lives at
  `src/store/mod.rs`; the Postgres adapter probes
  `SELECT 1 FROM pg_extension WHERE extname='age'` at connect time and
  records the resolved tag on the `PostgresStore` handle. AGE is
  opt-in: a missing extension OR a probe error falls back to
  `KgBackend::Cte` (logged at `debug`, never blocks bootstrap). The
  resolved backend is exposed via `PostgresStore::kg_backend()` so
  Track J's downstream tasks (J2 `kg_query`, J3 `kg_timeline`,
  J4 `kg_invalidate`, J7 `find_paths`) can dispatch on it. Added an
  optional `kg_backend: Option<String>` field on the v2 + v3
  `Capabilities` documents (skipped from the JSON wire when `None`)
  so `ai-memory doctor` and `memory_capabilities` can surface the
  active path once the SAL adapter is threaded through `AppState` in
  J2. Substrate only — no behavioural change to existing
  `memory_kg_*` MCP tools in this PR. New tests: 4 unit
  (snake-case wire shape, default tag pin, accessor wiring) plus 3
  live tests gated on `AI_MEMORY_TEST_AGE_URL` /
  `AI_MEMORY_TEST_POSTGRES_URL`.
- **v0.7.0 K2 — `pending_actions` timeout sweeper.** Closes the
  v0.6.3.1 honest-Capabilities-v2 disclosure that
  `default_timeout_seconds` was advertised in v1 but unused. Schema
  bumped to v21: `pending_actions` gains nullable
  `default_timeout_seconds` (per-row TTL) and `expired_at` (RFC3339
  stamp set when the sweeper fires) plus a composite
  `(status, requested_at)` index. New `db::sweep_pending_action_timeouts`
  helper is driven by a 60-second background tokio task spawned from
  `daemon_runtime::bootstrap_serve`; per-row override beats the
  cluster default (24h, matching `doctor`'s CRIT window). Each
  expired row fires a `pending_action_expired` event through the
  existing subscription dispatcher. A non-positive global default
  disables the sweeper entirely (operator escape hatch). 7 new
  tests cover the unit + integration paths.
- **Boot follow-ups folded from v0.6.4 into v0.6.3.1 (PR-9h, issue #487
  PR #497 reqs #72 + #73)** — version-drift detection adds
  `MIN_SUPPORTED_SCHEMA = 16` / `MAX_SUPPORTED_SCHEMA = 19` constants in
  `src/cli/boot.rs`, a new `WarnSchemaUnsupported { db_schema }`
  manifest variant, and the JSON top-level `schema_supported: bool`
  field for SIEM ingest. Boot privacy controls add a `[boot]` config
  block with `enabled` (default `true`; `false` exits 0 silently with
  empty stdout AND empty stderr — the privacy-sensitive escape hatch
  for hosts where memory titles must not enter CI logs) and
  `redact_titles` (default `false`; `true` keeps the manifest header
  but replaces every body row's `title` with `<redacted>`). Env-var
  `AI_MEMORY_BOOT_ENABLED=0` takes precedence over the config-file
  value. Documented in `docs/integrations/claude-code.md` and
  `docs/integrations/README.md`.
- **`ai-memory doctor` CLI (Phase P7 / R7)** — operator-visible health
  dashboard. New subcommand
  `ai-memory doctor [--db <path>] [--remote <url>] [--json] [--fail-on-warn]`
  produces a 7-section health report (Storage, Index, Recall, Governance,
  Sync, Webhook, Capabilities) with per-section severity tagging
  (`INFO` / `WARN` / `CRIT` / `N/A`). Exits `0` healthy / `1` warning
  with `--fail-on-warn` / `2` critical. `--remote <url>` queries a live
  daemon's `/api/v1/capabilities` + `/api/v1/stats` endpoints to support
  fleet-wide health sweeps at T3+. Read-only — never mutates the DB;
  every query is a single indexed `COUNT(*)` so the lock window stays
  sub-millisecond on a populated store. Consumes Capabilities v2 (P1),
  data integrity (P2 — `embedding_dim`), and recall observability (P3 —
  eviction counter, recall_mode distribution) surfaces with graceful
  fallback when those phases haven't merged yet — pre-P2/P3 schemas
  render the affected fields as `not_observed (pre-PX schema)` instead
  of erroring. New helpers in `src/db.rs`: `doctor_dim_violations`,
  `doctor_oldest_pending_age_secs`, `doctor_governance_coverage`,
  `doctor_governance_depth_distribution`,
  `doctor_webhook_delivery_totals`, `doctor_max_sync_skew_secs`. New
  module `src/cli/doctor.rs` and integration tests in
  `tests/doctor_cli.rs` (4 acceptance tests:
  `doctor_reports_clean_on_fresh_db`, `doctor_warns_on_dim_violations`,
  `doctor_critical_on_pending_actions_older_than_24h`,
  `doctor_remote_queries_capabilities_endpoint`). Documented in
  `docs/operations/doctor.md`.

### Phase P6 (R1) — `budget_tokens` recall recovery

Recovered the prior phased ROADMAP's "killer feature, no competitor has
this." `memory_recall` (MCP / HTTP / CLI) accepts an optional
`budget_tokens` parameter and returns the highest-ranked memories whose
cumulative content tokens fit under the budget, using the deterministic
`tiktoken-rs` `cl100k_base` BPE — the same tokenizer Claude / GPT use
for context-window accounting. The R1 always-return-at-least-one
guarantee surfaces an overflow flag rather than dropping a top-ranked
hit when the caller asks for an unrealistically tight budget.

- `tiktoken-rs` 0.7 added (pure-Rust BPE; ~1.7 MB bundled table; offline
  deterministic).
- New response `meta` block when a budget is supplied:
  `budget_tokens_used`, `budget_tokens_remaining`, `memories_dropped`,
  `budget_overflow`. Legacy top-level `tokens_used` / `budget_tokens`
  fields preserved verbatim — pre-P6 callers continue to work
  byte-for-byte.
- `budget_tokens=0` is now a valid request meaning "give me nothing"
  (returns an empty memories array with `meta.budget_overflow=false`).
  Supersedes the v0.6.3 Ultrareview #348 hard-reject of 0 — the meta
  block now disambiguates "user asked for zero" from "buggy
  uninitialised counter" by always round-tripping the requested budget.
- Budget-unset path is unchanged on the recall hot path: cl100k_base
  is skipped entirely, `tokens_used` falls back to a fast `len/4` byte
  heuristic so the bench harness's `recall_hot` p95 budget (< 50 ms)
  is preserved.
- Documentation: new `docs/recall.md`; `PERFORMANCE.md` gets a new row
  for `memory_recall (budget, budget_tokens=4096)` at < 90 ms p95
  (autonomous tier budget).
- Scoring and fusion are unchanged — budget is a strict post-rank
  filter. Two recalls of the same query with different budgets produce
  a strict prefix-of-prefix relationship.

Acceptance tests in `tests/budget_tokens.rs`.

### Phase P2 — Data-integrity hardening (G4, G5, G6, G13)

Schema **v18** (migration `0011_v0631_data_integrity.sql`) closes four
silent-corruption / silent-mutation paths surfaced by the v0.6.3 audit.
(Schema v17 was claimed by P4 governance-inheritance backfill — see below.)

- **G4 — mixed embedding dims silently tolerated.** New
  `memories.embedding_dim` and `archived_memories.embedding_dim` columns;
  `db::set_embedding` enforces "first write establishes the namespace's
  dim" and returns a typed `EmbeddingDimMismatch` on any subsequent
  write at a different dim. New `Stats::dim_violations` counter (also
  exposed via `db::dim_violations`) surfaces legacy mismatched rows so
  the P7 doctor can flag them. Migration backfills existing rows from
  `length(embedding) / 4`.
- **G5 — archive lossy + restore resets.** `archived_memories` now
  carries `embedding`, `embedding_dim`, `original_tier`, and
  `original_expires_at`. `archive_memory`, `gc(archive=true)`, and
  `forget(archive=true)` populate them; `restore_archived` round-trips
  the original tier and expiry instead of forcing `tier='long'` /
  `expires_at=NULL`. Pre-v17 archive rows are backfilled to
  `original_tier='long'` (the loss is acknowledged — the live row was
  gone before v17 ever shipped).
- **G6 — UNIQUE(title, namespace) silent merge.** `memory_store` MCP
  tool grows an `on_conflict: error | merge | version` parameter.
  Capability negotiation: v2-aware MCP clients default to `error`; v1 /
  unknown clients keep the legacy `merge` upsert. HTTP
  `POST /api/v1/memories` accepts `on_conflict` in the body and
  defaults to `error` (HTTP has no v1 backward-compat to honour). New
  `db::find_by_title_namespace` and `db::next_versioned_title` helpers.
- **G13 — f32 endianness magic byte.** Embedding BLOBs now carry a
  one-byte header (`0x01` = LE-f32). Readers tolerate missing-header as
  legacy LE-f32 and return a typed `EmbeddingFormatError` for any
  unknown header; `0x02` (BE-f32) is reserved and rejected until v0.7
  adds the conversion path. New `embeddings::encode_embedding_blob` /
  `decode_embedding_blob` / `decoded_dim` helpers.

Tests: `tests/data_integrity_v17.rs` (8 cases — every charter-cited
acceptance test passes plus two doctor-stat round-trips).

### Capabilities v2 honesty schema (P1, REMEDIATIONv0631 §"Phase P1")

The capabilities response was promising features that did not exist. v2
keeps the wire envelope but tells the truth about what's wired.

**Schema changes — bumped at the same `schema_version="2"` discriminator.**

- **`features.recall_mode_active`** (new): live runtime tag —
  `"hybrid"` when the embedder is loaded, `"degraded"` when configured
  but failed to materialize, `"disabled"` for the keyword tier.
  Operators can refuse to dispatch semantic-recall scenarios against a
  daemon whose embedder did not load.
- **`features.reranker_active`** (new): derived from the actual
  `CrossEncoder` enum variant — `"neural"` / `"lexical_fallback"` /
  `"off"`. Replaces the previous "trust the tier flag" reporting.
- **`features.memory_reflection`** is now a `{planned, version,
  enabled}` object (was `bool`). The subsystem is roadmap (v0.7+); the
  bool form lied by claiming the feature was wired on the autonomous
  tier.
- **`compaction`** and **`transcripts`** carry the same planned-feature
  shape, so operators can distinguish "feature exists but disabled"
  from "feature not in this build."
- **`permissions.mode = "advisory"`** (was `"ask"`, which implied an
  interactive prompt loop the code does not run). Until P4 ships the
  enforcement gate, governance metadata is recorded but not enforced.
- **Dropped fields** (no backing implementation existed):
  `permissions.rule_summary`, `hooks.by_event`,
  `approval.subscribers`, `approval.default_timeout_seconds`.

**Backward compatibility — v1 clients continue to work.** Pass
`Accept-Capabilities: v1` (HTTP) or the MCP `accept: "v1"` argument to
`memory_capabilities` to receive the legacy pre-v0.6.3.1 shape. v1
projection collapses `memory_reflection` back to a bool and drops all
v2-only blocks. Default response remains v2.

**Files touched:** `src/config.rs`, `src/mcp.rs`, `src/handlers.rs`,
`tests/capabilities_v2.rs` (new). 9 new integration tests pin the honest
contract.


## [v0.6.3] — 2026-04-27 — STRUCTURED MEMORY + PERFORMANCE

The grand-slam release. Hierarchical namespace taxonomy + temporal-validity
knowledge graph + entity registry + duplicate detection + bench tool with
public p95 budgets — six streams (A through F) shipped together. Plus
post-rc1 capabilities schema v2 (additive `schema_version="2"` + 5 new
top-level blocks for hooks/permissions/compaction/approval/transcripts
introspection) and a CI coverage gate locking in 93.05% baseline.

**Validation evidence:**

- 1 600 lib tests pass; line coverage **93.08%** (gate floor 92%)
- Ship-gate campaign run #25007261531 — 4 phases green in 14m wall
  (Phase 1 functional · Phase 2 multi-agent W=2/N=3 · Phase 3 v0.6.2→v0.6.3
  migration · Phase 4 chaos 50 cycles kill_primary_mid_write)
- A2A-gate campaign run #25007946890 — 48 scenarios green in 28m wall
  (35 v0.6.0 baseline + 4 auto-append + 9 new for v0.6.3:
  capabilities_v2_schema, taxonomy_walk, kg_query_temporal, kg_timeline,
  entity_aliases, check_duplicate, lifecycle_end_to_end, sqlcipher_at_rest,
  autonomous_tier_suite). Cell: ironclaw-mtls.

Live evidence:
<https://alphaonedev.github.io/ai-memory-test-hub/releases/v0.6.3/>

### Distribution-channel hardening (folded into v0.6.3 final cut)

- **Dockerfile — `COPY migrations/`** added so cargo build can resolve
  the new Stream A-C `include_str!` references at compile time. Without
  it, the Docker build failed before publish.
- **Dockerfile — pin build stage to `rust:1.94-slim-bookworm`** so the
  produced binary's glibc matches the runtime stage
  (`debian:bookworm-slim`, glibc 2.36). Without the explicit bookworm
  pin, `rust:1.94-slim` resolves to a trixie-based image (glibc 2.41)
  and the binary fails at startup with `version GLIBC_2.39 not found`.
- **`Cargo.toml` `package.include`** restricts the published crate to
  source-only (src, benches, examples, migrations, build.rs,
  Cargo.{toml,lock}, README.md, LICENSE, CHANGELOG.md, PERFORMANCE.md).
  Without it, the crate weighs 22 MiB compressed (140 MiB unpacked,
  thanks to `audits/`) — over crates.io's 10 MiB upload limit; uploads
  hit HTTP 503 from the Fastly WAF. Trimmed crate is 558 KiB compressed
  (73 files), well under the limit.
- **CI silent-failure on `cargo publish`** — replaced
  `cargo publish || echo "warning"` with proper retry-with-backoff
  (3 attempts × 30s sleep). Genuine "version already exists" detected
  via stderr grep (idempotent re-run); everything else (5xx, network
  errors, oversized package) fails the job loudly. This is the masking
  bug that hid the crates.io 503s during initial v0.6.3 publish.
- **New `dockerfile-validate` CI job** runs on every push + PR. Builds
  the Docker image (no GHCR push) and smoke-tests with
  `docker run --rm ai-memory:ci-validate --version` + `--help`. Closes
  the Dockerfile-drift class of bugs (new `include_str!` for missing
  dir, missing system dep, glibc mismatch, etc.) at PR time, not at
  release time.

### Added

- **Capabilities schema v2 — `memory_capabilities` introspection extension
  (arch-enhancement-spec §7)**. The capabilities report (MCP
  `memory_capabilities` + HTTP `GET /api/v1/capabilities`) gains a
  `schema_version: "2"` discriminator and five new top-level blocks:
  `permissions`, `hooks`, `compaction`, `approval`, `transcripts`. Pre-v0.7
  the `permissions.active_rules` field reflects a live count of namespace
  standards carrying `metadata.governance` (transparent passthrough; the
  full permission system is v0.7 work — arch-spec §3); `hooks.registered_count`
  reflects the live `subscriptions` table count (proxy for hook subscribers
  pre-v0.7 Bucket 0); `approval.pending_requests` reflects the live count
  of `pending_actions` rows with `status='pending'`. `compaction.enabled`
  and `transcripts.enabled` report `false` until v0.8 / v0.7-Bucket-1.7 land
  the underlying systems. **All v1 fields preserved at the same top-level
  paths** — older clients reading `tier`, `version`, `features`, `models`
  by name continue to work without modification. New tests:
  `mcp::tests::mcp_capabilities_v2_schema_includes_all_blocks`,
  `mcp::tests::mcp_capabilities_v2_backwards_compatible`,
  `mcp::tests::mcp_capabilities_pending_requests_reflects_db`,
  `handlers::tests::http_capabilities_v2_schema_includes_all_blocks`,
  `config::tests::capabilities_v2_zero_state_round_trip`. New helpers:
  `db::count_active_governance_rules`, `db::count_subscriptions`,
  `db::count_pending_actions_by_status`. Pure additive — no migration,
  no behavior change to any existing tool.

- **Hierarchical namespace taxonomy (Pillar 1 / Stream A)** — new
  `memory_get_taxonomy` MCP tool plus REST mirror at
  `GET /api/v1/taxonomy`. Walks live (non-expired) memories grouped by
  `namespace`, splits on `/`, and folds them into a `TaxonomyNode` tree.
  Each node carries `count` (memories at exactly this namespace) and
  `subtree_count` (count plus every descendant the depth limit allowed
  us to expand); the response envelope adds `total_count` (an
  independent aggregation that stays honest even when `limit` drops
  rows from the walk) and a `truncated` flag. Parameters:
  `namespace_prefix` (optional, accepts trailing `/`),
  `depth` (default 8 = `MAX_NAMESPACE_DEPTH`, clamped),
  `limit` (default 1000, hard ceiling 10000 — densest namespaces win
  when truncated). Closes the "flat blob" perception gap from charter
  §"The Demo That Sells It" (charter lines 218–230) and unblocks the
  taxonomy demo CLI surface deferred to a later iteration. Charter
  §"Stream A — Hierarchy", lines 320–326.

- **Temporal-validity KG schema (Stream B foundation)** — SQLite schema
  bumps to v15 (`src/db.rs::migrate`). `memory_links` gains four nullable
  temporal columns — `valid_from`, `valid_until`, `observed_by` (TEXT),
  and `signature` (BLOB; placeholder for v0.7 attested identity). On
  upgrade, existing links are backfilled: `valid_from` is set to the
  source memory's `created_at` (charter pre-flight default — defensive
  null avoidance). Three temporal indexes are created for the upcoming
  recursive-CTE traversal in `memory_kg_query` / `memory_kg_timeline`:
  `idx_links_temporal_src` (source_id, valid_from, valid_until),
  `idx_links_temporal_tgt` (target_id, valid_from, valid_until), and
  `idx_links_relation` (relation, valid_from). New `entity_aliases`
  side table (entity_id, alias, created_at; PK on entity_id+alias)
  with `idx_entity_aliases_alias` lookup index unblocks the upcoming
  Stream C entity-registry tools. The Postgres declarative schema
  (`src/store/postgres_schema.sql`) is mirrored for fresh-init parity;
  existing PG installs do not auto-gain the new columns since the PG
  store layer is still WIP (an explicit ALTER migration lands when
  `link()` is wired up there). Pure additive — no existing query
  breaks. Charter §"Critical Schema Reference", lines 686–723.

- **Entity registry (Pillar 2 / Stream B)** — `memory_entity_register`
  + `memory_entity_get_by_alias` MCP tools (count 38 → 40) plus the
  matching HTTP surface (`POST /api/v1/entities`,
  `GET /api/v1/entities/by_alias`, with 201 / 200 / 409 status
  discipline and `X-Agent-Id` honoured). Entities are long-tier
  memories tagged `entity` with `metadata.kind = "entity"`; aliases
  live in the v15 `entity_aliases` side table. Registration is
  idempotent on `(canonical_name, namespace)` — re-registering reuses
  the entity_id and merges new aliases via `INSERT OR IGNORE`. A
  non-entity memory occupying the same `(title, namespace)` returns a
  hard error rather than letting the upsert path silently overwrite
  unrelated content. Resolver returns the most-recently-created
  entity when no namespace filter is supplied; ignores stray
  `entity_aliases` rows that point at non-entity memories. Builds on
  the v15 schema (#384). Charter §"Stream B — KG Schema + Entity
  Model", lines 369–375.

- **`memory_kg_timeline` (Pillar 2 / Stream C)** — entity-anchored
  chronological view powering the `ai-memory kg-timeline` headline
  demo. `db::kg_timeline()` queries `memory_links` ordered by
  `valid_from ASC` (tie-break `created_at`) with optional inclusive
  `since` / `until` filters; limit clamps to `[1, 1000]`, default
  200. `db::create_link()` now stamps `valid_from = created_at` on
  every insert so newly created links are visible to the timeline
  without a later sweep, closing the forward gap left by the v15
  backfill of legacy rows. `memory_kg_timeline` MCP tool (count
  40 → 41) plus `GET /api/v1/kg/timeline?source_id=…&since=…
  &until=…&limit=…`. Returns `KgTimelineEvent` carrying `target_id`,
  `relation`, validity window, `observed_by`, and the target's
  `title` / `namespace`. Charter §"Stream C — KG Query Layer",
  lines 377–383.

- **`memory_kg_invalidate` (Pillar 2 / Stream C)** — second tool of
  the KG-traversal triplet. Marks a KG link as superseded by setting
  its `valid_until` column so a contradicting fact can invalidate
  the prior assertion without deleting the row, preserving the
  timeline. The link is identified by its composite key
  `(source_id, target_id, relation)` since `memory_links` has no
  separate id; `valid_until` defaults to wall-clock now when
  omitted. `db::invalidate_link()` returns
  `Option<InvalidateResult>` — `None` when the triple does not
  match, `Some` with the value now stored and `previous_valid_until`
  so callers can distinguish a fresh supersession from an idempotent
  retry. `memory_kg_invalidate` MCP tool (count 41 → 42) plus HTTP.
  Schema does not yet carry an audit column for the supersession
  `reason`; that arrives with v0.7 attestation. Charter §"Stream C —
  KG Query Layer", lines 377–383.

- **`memory_kg_query` depth=1 (Pillar 2 / Stream C)** — outbound
  "expand neighbors" first slice. `memory_kg_query` MCP tool (count
  42 → 43) plus HTTP. `db::kg_query()` ships with constants
  `KG_QUERY_DEFAULT_LIMIT = 200`, `KG_QUERY_MAX_LIMIT = 1000`, and
  `KG_QUERY_MAX_SUPPORTED_DEPTH = 1`; callers passing `max_depth=2`
  get a clean error rather than a silent truncation, so the API
  contract is stable from day one — the recursive-CTE multi-hop
  follow-up just lifts the ceiling without changing the surface.
  Filters per the charter spec: `valid_at` (RFC3339, only links
  valid at that instant); `allowed_agents` (only links observed by
  an agent in the set; **empty list returns zero rows by design** —
  callers signaling "no agents trusted" must get an empty traversal,
  not the unfiltered fallback); `limit` clamped to `[1, 1000]`.
  Charter §"Stream C — KG Query Layer", lines 377–383.

- **`memory_kg_query` depth 2..=5 (Pillar 2 / Stream C)** — lifts
  `KG_QUERY_MAX_SUPPORTED_DEPTH` from 1 to 5, matching the published
  `memory_kg_query (depth ≤ 5)` 250 ms p95 / 500 ms p99 budget in
  `PERFORMANCE.md`. Replaces the depth=1 JOIN with a recursive CTE
  that re-applies the temporal / agent filter on every hop and
  prunes cycles via the accumulated `path`; each row's `depth` +
  `path` now reflect the actual chain (e.g. depth=2 →
  `src->mid->target`). API contract is unchanged — depth=1 collapses
  to the original time-ordered single-hop result, and the
  over-ceiling MCP/HTTP error path (422 with `max_depth=N exceeds
  supported depth=5`) is preserved. Closes the Stream C
  `memory_kg_query` slice; traversals at depth 2..=5 are now correct
  under temporal-validity and observed-by filtering. Charter
  §"Stream C — KG Query Layer", lines 377–383.

- **`memory_check_duplicate` (Pillar 2 / Stream D)** — pre-write
  near-duplicate check across DB / MCP / HTTP. `db::check_duplicate`
  performs a cosine scan over live embedded memories with the
  threshold clamped at `DUPLICATE_THRESHOLD_MIN = 0.5` (so permissive
  callers can't dress unrelated content as a merge candidate) and
  default `DUPLICATE_THRESHOLD_DEFAULT = 0.85` (tuned for the
  MiniLM-L6-v2 embedder — near-paraphrases land ≥ 0.88, loosely
  related content sits well below). `memory_check_duplicate` MCP
  tool (count 37 → 38) returns the nearest-neighbor cosine, the
  above-threshold boolean, and an optional `suggested_merge` target.
  HTTP `POST /api/v1/check_duplicate` mirrors the MCP surface and
  embeds *before* taking the DB lock (issue #219 pattern). Charter
  §"Stream D — Duplicate Check", lines 384–386.

- **`ai-memory bench` scaffold (Pillar 3 / Stream E)** — first slice
  of perf instrumentation. New CLI subcommand + `src/bench.rs`
  runner so operators (and the `bench.yml` CI guard / Stream F) can
  verify the published `PERFORMANCE.md` budgets. Covers the three
  embedding-free hot-path operations: `memory_store` (no embedding)
  / 20 ms p95, `memory_search` (FTS5) / 100 ms p95, and
  `memory_recall` (hot, depth=1) / 50 ms p95. Each invocation seeds
  a disposable `:memory:` SQLite DB so the operator's main DB is
  untouched. Reports p50 / p95 / p99 in either a human table or
  `--json`. Exit code is non-zero when any p95 exceeds its target
  by more than the documented 10% tolerance — so the same binary
  slots into the CI guard once Stream F lands. `PERFORMANCE.md`
  status table now distinguishes "scaffold landed" from "Stream E
  follow-up" so partial coverage isn't silent. Charter §"Stream E —
  Performance Instrumentation", lines 388–393.

- **Performance budgets published** — new `PERFORMANCE.md` at the repo
  root carries the authoritative p95/p99 latency contract for every
  hot-path operation (verbatim from the v0.6.3 grand-slam charter):
  `memory_session_start` hook, `memory_recall` hot/cold,
  `memory_store` with/without embedding, `memory_search`,
  `memory_check_duplicate`, `memory_kg_query` (depth ≤ 3 / ≤ 5),
  `memory_kg_timeline`, `memory_get_taxonomy`, `curator cycle`, and
  `federation ack`. Documents the **>10% p95 breach fails CI**
  threshold (p99 informational until the v0.6.3 soak window closes),
  the Apple M4 / 32 GB / NVMe SSD reference hardware baseline (with a
  note on Linux x86_64 CI parity), and a status table flagging the
  bench tool (Stream E) and `bench.yml` workflow (Stream F) as still
  in-flight. Closes Pillar 3 / Stream F doc deliverable from the
  v0.6.3 charter.

- **`bench.yml` CI guard (Pillar 3 / Stream F)** — new
  `.github/workflows/bench.yml` runs `ai-memory bench` on every pull
  request and trunk push (`main`, `develop`, `release/**`) plus on
  manual `workflow_dispatch`. The job builds the release binary on
  `ubuntu-latest` (the latency reference per `PERFORMANCE.md`),
  streams the bench table into the workflow run summary, and uploads
  a `bench-results` artifact (`bench-results.json` +
  `bench-table.txt`) for downstream tooling. The `ai-memory bench`
  binary already exits non-zero when any operation's measured p95
  exceeds its target by more than the published 10% tolerance, so
  the workflow fails on regression without additional gating logic.
  Closes the last Stream F deliverable from charter §"Stream F —
  Performance Budgets + CI Guard"; budgets are now continuously
  enforced against trunk and PRs.

- **`ai-memory bench` KG depth=3 + depth=5 coverage (Pillar 3 / Stream E)**
  — `memory_kg_query` is now exercised at the deepest hop of both
  documented budget buckets: depth=3 against the "depth ≤ 3" 100 ms
  p95 row and depth=5 against the "depth ≤ 5" 250 ms tail-case row in
  `PERFORMANCE.md`. The runner seeds a second in-process fixture (50
  chains × 5 hops each = 300 memories + 250 links) so the recursive
  CTE actually traverses three / five hops per query rather than
  collapsing to a single hop on the existing fan-out fixture. Local M4
  measurements: depth=3 p95 ~0.6 ms, depth=5 p95 ~0.7 ms — both PASS,
  both well inside the 10% tolerance enforced by `bench.yml`. No new
  dependencies. Completes the KG half of Stream E; embedding-bound
  paths still need a fixture decision and remain tracked separately.

- **`ai-memory bench` KG coverage (Pillar 3 / Stream E)** —
  `memory_kg_query` (depth=1) and `memory_kg_timeline` are now driven
  by the `bench` subcommand against the same in-memory disposable
  SQLite database used by the embedding-free operations. The runner
  seeds an in-process KG fixture (50 source memories × 4 outbound
  links each, every link `valid_from`-stamped so `kg_timeline` sees
  them) and reports p50/p95/p99 against the 100 ms p95 budgets
  published in `PERFORMANCE.md`. Local M4 measurements: `kg_query`
  p95 ~0.7 ms, `kg_timeline` p95 ~0.1 ms — both PASS, both well
  inside the 10% tolerance enforced by the `bench.yml` CI guard.
  No new dependencies. Closes the KG half of the iter-0017 follow-up
  ask; embedding-bound paths still need a fixture decision and are
  tracked separately.

- **Per-tool MCP tracing spans (Pillar 3 / Stream E)** — every
  `tools/call` dispatch now runs inside an `info`-level
  `mcp_tool_call` span carrying the tool name and JSON-RPC id. After
  the handler returns, an `ok` event records `elapsed_ms`; an
  `Err` outcome emits a `warn` event with the error message so
  on-call dashboards can alert on per-tool error rate. The MCP server
  entrypoint (`run_mcp_server`) installs a `tracing_subscriber::fmt`
  subscriber pinned to `stderr` (stdio JSON-RPC owns stdout) honoring
  `RUST_LOG`; `try_init` makes it a no-op when another command in the
  same process already initialised tracing. Foundation for the v0.6.3
  charter §"Stream E — Performance Instrumentation" ask;
  paired with the `ai-memory bench` scaffold to give exporters
  per-tool latency attribution against the published `PERFORMANCE.md`
  budgets.

### Fixed

- **[#358]** mTLS allowlist parser now tolerates inline trailing `#`
  comments after a fingerprint
  (`load_fingerprint_allowlist`, `src/main.rs`). Previously, a line like
  `sha256:abc…def  # node-1` was parsed whole and failed the 64-hex-char
  length check (`got 74`), aborting `ai-memory serve` on startup. Full-line
  `#` comments and the Ultrareview #338 strict character-set check
  (rejects embedded whitespace inside the hex run) are preserved. Doc
  update: `docs/ADMIN_GUIDE.md` now explicitly calls out trailing-comment
  tolerance. Encountered in the a2a-gate mTLS matrix; the gate-side
  generator fix in `ai-memory-ai2ai-gate#35` already worked around it for
  v0.6.2 — this is the parser-side resolution.

### Changed

- **CI coverage gate — fail-under 92%**. The `coverage` job in
  `.github/workflows/ci.yml` now invokes `cargo llvm-cov` with
  `--fail-under-lines 92`, locking in the v0.6.3 baseline of 93.05%
  with a 1% absorb buffer. PRs that drop total line coverage below
  92% will fail the gate. Per-module floors (`handlers.rs`, `db.rs`,
  `federation.rs`, `mcp.rs`, `governance.rs` ≥90%) are tracked in the
  v0.7 assertion table for follow-up enforcement.

### Tests

- **[#401]** RAII `ChildGuard` fixes mTLS test daemon-leak on assert
  panic.
  `tests/integration.rs::test_serve_mtls_fingerprint_allowlist_accepts_only_known_peer`
  was leaking `target/debug/ai-memory … serve` child processes
  whenever any of its 4 asserts panicked between spawn and the
  manual `kill()` at the bottom — `std::process::Child` has no
  kill-on-drop on Unix. Adds a generic `ChildGuard { child:
  Option<Child>, cleanup_paths: Vec<PathBuf> }` alongside the
  existing `DaemonGuard`, with an unwind-safe `Drop` that kills,
  reaps, and unlinks; refactors the mTLS test to wrap both spawned
  children. End-user impact is zero (production `serve` deployments
  via systemd / launchd / Docker reap children correctly), but the
  campaign runner had been accumulating ~28 GB of orphaned daemons
  across 7 reparented PIDs during the v0.6.3 dev sprint.

## [v0.6.2] — 2026-04-24 — A2A-CERTIFIED

First release to carry the a2a-gate **consecutive-green streak 3/3**
certification. Three consecutive full-testbook passes across six
homogeneous cells (ironclaw + hermes × off/tls/mtls on DigitalOcean,
and openclaw × off on a local Docker mesh) validate that A2A
scenarios against ai-memory v0.6.2 are green end-to-end on
`release/v0.6.2 @ 3e018d6`.

**Evidence** — every scenario artifact is committed alongside the
releasing branch of the a2a-gate repo:
<https://alphaonedev.github.io/ai-memory-ai2ai-gate/runs/>

### Fixed — federation fanout correctness (a2a-gate v3r22–r30)

- **[#325]** `create_link` fanout — `POST /api/v1/links` broadcasts
  the new link to every peer via quorum write. Scenario-11 of the
  a2a-gate harness exercised this: charlie couldn't see an M1→M2
  link written on alice's node. `SyncPushBody` grows a
  `links: Vec<MemoryLink>` field applied via `db::create_link` on
  peers; duplicates are idempotent via the existing
  `(source_id, target_id, relation)` unique index. New
  `federation::broadcast_link_quorum`. Delete-link fanout deferred
  to v0.7 CRDT-lite tombstones.
- **[#326]** `consolidate` fanout — `POST /api/v1/consolidate`
  broadcasts the new consolidated memory AND the source-id
  deletions in a single sync_push call. Scenario-5 exposed the
  gap: peer nodes never saw the consolidated memory, so
  `metadata.consolidated_from_agents` read as `"[]"`. New
  `federation::broadcast_consolidate_quorum`.
- **[#327]** Embedder-failure visibility on `ai-memory serve` —
  HuggingFace-Hub fetch failure now logs at `ERROR` with an
  `⚠️ EMBEDDER LOAD FAILED` marker and a remediation pointer.
  `/api/v1/health` grows `embedder_ready: bool` +
  `federation_enabled: bool` fields so harnesses can assert
  semantic-tier readiness before scenarios run.
- **[#363]** List cap 200 → 1000 + pending-action fanout +
  namespace_meta fanout (S34 / S35 / S40). Closed the three
  fanout gaps surfaced by v3r22.
- **[#364]** `clear_namespace_standard` fanout symmetry follow-up
  to #363 — the clear path was missing from `SyncPushBody`;
  scenario-35 on peer-nodes saw stale standards after a clear on
  the leader.
- **[#366]** HTTP `/api/v1/recall` now uses hybrid semantic when
  the embedder is loaded. Scenario-18 previously black-holed
  because the endpoint fell through to FTS-only even with a live
  embedder.
- **[#367]** Relax semantic cosine threshold 0.3 → 0.2 in
  `recall_hybrid`. Scenario-18 caught a miss at 0.25–0.29 cosine
  for legitimately-related content; the lower threshold preserves
  top-K recall without introducing noise (blended score still
  gated by `fts.rank + …` component).
- **[#368]** S40 fanout retry — `post_and_classify` retries once
  on `AckOutcome::Fail` with a 250 ms backoff. `Idempotency-Key`
  already present on `sync_push` makes a partial-apply race
  dedupe to a no-op on the peer via `insert_if_newer`. RCA:
  v3r26 hermes-tls scenario-40 saw `node-2 499/500 bulk rows`
  post-quorum because the detached per-peer POST had transiently
  failed; no retry, no catchup.
- **[#369]** S40 `bulk_create` terminal catchup batch per peer.
  After the per-row quorum drains, the leader sends ONE batched
  `sync_push` per peer with every committed row. Peer-side
  `insert_if_newer` dedupes already-applied rows; rows dropped by
  the detached path land now. O(1) extra POST per peer vs O(N)
  retries per row. Proven to close the gap on v3r28 after retry
  alone was insufficient on v3r27 (ironclaw-off still dropped one
  row despite the retry — sustained SQLite-mutex contention
  during a 500-row burst can drop two consecutive POSTs).

### Evidence & reproducibility

The a2a-gate repository carries the full certification evidence:

- **Runs dashboard** —
  <https://alphaonedev.github.io/ai-memory-ai2ai-gate/runs/>
- **AI NHI insights** (tri-audience analysis) —
  <https://alphaonedev.github.io/ai-memory-ai2ai-gate/insights/>
- **Local Docker mesh reproducibility spec** —
  <https://alphaonedev.github.io/ai-memory-ai2ai-gate/local-docker-mesh/>

Per-campaign evidence pages under `runs/` carry scenario-level
JSON, stderr logs, baseline attestation, F3 peer-replication
canary, and a campaign.meta.json provenance trace. The DO
campaigns (v3r28 / v3r29 / v3r30) used `release/v0.6.2 @ 3e018d6`
with `ai_memory_source_build=true`; the local-docker campaigns
(r1 / r2 / r3) used the same commit via a committed release
binary.

### Certification matrix

| | off | tls | mtls |
|---|---|---|---|
| **ironclaw (DO)** | ✅ v3r30 35/35 | ✅ v3r30 35/35 | ✅ v3r30 37/37 |
| **hermes (DO)** | ✅ v3r30 35/35 | ✅ v3r30 35/35 | ✅ v3r30 37/37 |
| **openclaw (local-docker)** | ✅ r3 35/35 | ⏸ Phase 3 | ⏸ Phase 3 |

Total: **214 passing scenarios** across six cells on the final
certification run (v3r30 DO + local-docker r3).

## [Unreleased] — v0.6.1 + v0.7 tracks

### v0.7.0 round-2-fixes folding (2026-05-11) — no v0.7.0.1, everything ships in v0.7.0

Operator directive: there will be no v0.7.0.1 patch release. Items
originally triaged for v0.7.0.1 fold into v0.7.0 directly.

#### Fixed (closes via round-2-fixes)

- **#318 MCP stdio writes bypass federation fanout** — new opt-in
  `mcp_federation_forward_url` in `AppConfig`. When set, MCP
  `memory_store` calls forward to the local HTTP daemon's
  `POST /api/v1/memories`, which already runs
  `broadcast_store_quorum`. Single-node MCP deployments are
  unchanged when the config is unset. Closes the a2a-gate-r6
  finding "30 MCP stdio writes persisted locally but zero rows
  replicated to peers."
- **#355 rustls-pemfile RUSTSEC-2025-0134 (unmaintained, transitive
  via axum-server)** — bumped `axum-server 0.7 → 0.8`. The 0.8
  release drops the rustls-pemfile dependency. `cargo audit` now
  reports clean; `rustls-pemfile` is gone from `Cargo.lock`.
- **#507 `config.toml` `db = "~/..."` not expanded** — `AppConfig::effective_db`
  now expands leading `~` / `~/` to `$HOME` via a new private
  `expand_tilde` helper. Daemon no longer reports
  `warn db unavailable` against an existing DB at the
  tilde-expanded location. Bare `~` resolves to `$HOME` itself;
  `~user/` not supported.
- **#625 E1/E2 orchestration scripts ported from bash to Rust** —
  new standalone crates `tools/t0-orchestrate/` +
  `tools/post-ship-converge/` producing the `ai-memory-t0` and
  `ai-memory-post-ship-converge` binaries. The old
  `scripts/t0-orchestrate.sh` and `scripts/post-ship-converge.sh`
  are deleted. `tests/e1_orchestration_dry_run.rs` and
  `tests/e2_post_ship_dry_run.rs` drop their `#![cfg(unix)]` gates
  so Windows CI now validates the same dry-run envelope shape.
- **L15 entrypoint wire** — `entrypoint.plan-c.sh` now writes
  `auto_tag_model = "gemma3:4b"` to the daemon's `config.toml`
  (env-overridable as `AI_MEMORY_AUTO_TAG_MODEL`). Closes the Plan
  C R4 finding `H8: LLM call (auto_tag) exceeded 30s timeout`
  caused by Gemma 4 e4b thinking-mode generating 396-564 tokens
  for a 5-tag prompt; gemma3:4b finishes the same prompt in
  ~0.7s.
- **Postgres SAL `consolidate` upsert** — the prior implementation
  was a plain `INSERT INTO memories`, which exploded with
  `duplicate key value violates unique constraint
  "memories_title_ns_uidx"` when an operator re-ran a consolidate
  at the same `(title, namespace)` (common across repeat cert
  runs against the same persistent postgres database). Rewrote as
  `ON CONFLICT (title, namespace) DO UPDATE` matching the rest of
  the adapter's upsert contract; `RETURNING id` returns the
  existing id on conflict. Surfaced by Plan C R4 cert S5 failure;
  reproduced with daemon log
  `ERROR ai_memory::handlers: store backend error: backend
  unavailable: postgres: consolidate insert: error returned from
  database: duplicate key value violates unique constraint
  "memories_title_ns_uidx"`.
- **No-sal build break in `src/federation.rs`** — `spawn_catchup_loop`
  unconditionally called `spawn_catchup_loop_with_store`, which is
  `#[cfg(feature = "sal")]`-gated. Surfaced by the #625 port
  subagent. Fix: cfg-branch the body so the sqlite-only build
  goes through `catchup_once` directly.

#### Documentation

- Closed 12 v0.7.0 ship-tracker issues in one batch with a uniform
  "Closed by v0.7.0 ship sequence" comment — #637 (Round-2 master),
  #638 (F6 LLM-dispatch deadlock), #639 (F7 agent_quotas bypass),
  #640 (F8/F11/F12 secure-by-default), #641 (F13-F16 capabilities
  drift), #642 (F17/F18 find_paths surface), #646 (F6 SQL-view
  deferral), #647 (postgres+AGE scope tracker), #649 (Wave 4 live
  A2A re-validation), #635 (ship-readiness report), #508/#509
  (Grok Prime-Directive assessments).

### Added — v0.7 attested-cortex (Track H, Task H1)

- **Per-agent Ed25519 keypair CLI (`ai-memory identity`).** OSS substrate
  for the v0.7 attested-cortex epic. New `src/identity/keypair.rs`
  exposes the four-verb lifecycle (`generate / save / load / list`) plus
  a `save_public_only` path for importing peer allowlist entries. Keys
  are persisted under `<config>/ai-memory/keys/<agent_id>.{pub,priv}` —
  `~/.config/ai-memory/keys/` on Linux, `~/Library/Application
  Support/ai-memory/keys/` on macOS, `%APPDATA%\ai-memory\keys\` on
  Windows. On Unix the public file is written with mode `0o644` and
  the private file with mode `0o600`; on Windows the files inherit the
  parent ACL. The on-disk format is the raw 32-byte key (no PEM/DER
  wrapper) so the format is byte-identical to the COSE/CBOR shape H2
  will sign with.
- **`ai-memory identity` clap subcommand** wires the lifecycle into
  the CLI: `generate --agent-id <id>` (defaults to the same NHI-hardened
  id the rest of the CLI synthesizes via `identity::resolve_agent_id`),
  `import --agent-id <id> --pub <path> --priv <path>` (private optional;
  cross-checks `.priv` derives `.pub` and refuses mismatches),
  `list` (public-only — never loads private material, safe for
  dashboards), and `export-pub --agent-id <id>` (URL-safe-no-padding
  base64 of the 32-byte public key, pipe-friendly for peer-allowlist
  bootstrapping). `--key-dir <path>` is a global override for the
  default key directory.
- **Hardware-backed key storage is OUT of OSS scope.** TPM 2.0,
  PKCS#11 HSMs, Apple Secure Enclave / TEE, and AWS/GCP/Azure cloud
  KMS adapters are intentionally **not** implemented in this crate. The
  OSS path stops at file-based 0600 storage; certified hardware-backed
  deployments live in the AgenticMem™ commercial layer per
  `ROADMAP.md`. The OSS code never imports a hardware-token library.
- **New deps (pure-Rust, MIT/Apache):** `ed25519-dalek = "2"` (with
  the `rand_core` feature for `SigningKey::generate`), `rand_core =
  "0.6"` (CSPRNG bound — we use `OsRng`), `base64 = "0.22"` (for the
  `export-pub` wire format).
- **16 new unit tests in `src/identity/keypair`** — generate-save-load
  round-trip with sign+verify, Unix mode 0600 / 0644 enforcement, list
  enumeration + sort + private-skip semantics, list-on-missing-dir
  returns empty, truncated/mismatched key file rejection, base64
  round-trip (URL-safe and padded), and a `save_public_only` happy
  path. **5 new unit tests in `src/cli/identity`** drive the four CLI
  verbs through the standard `CliOutput` capture harness, including
  `generate --no-overwrite` refusal and JSON-mode emission.

### Fixed — v0.6.0 pre-tag SAL blocker punchlist (#293)

Five correctness blockers surfaced by the v0.6.0 code-review (meta
issue [#293](https://github.com/alphaonedev/ai-memory-mcp/issues/293)),
all closed before the tag:

- **[#294]** SAL upsert key mismatch — aligned Postgres adapter to
  `ON CONFLICT (title, namespace)` matching SQLite's documented
  contract. Added `UNIQUE INDEX memories_title_ns_uidx` to
  `postgres_schema.sql`.
- **[#295]** `metadata.agent_id` immutability — Postgres UPSERT and
  UPDATE now preserve the original `agent_id` via `jsonb_set` CASE
  clause, mirroring SQLite's `json_set` SQL-layer guard. Task 1.2
  NHI invariant is now enforced on both adapters.
- **[#296]** Tier-downgrade protection on Postgres UPDATE — added
  `tier_rank()` SQL function and `GREATEST(tier_rank(...))`
  precedence so `Long → *` and `Mid → Short` are refused at the
  SQL layer, matching SQLite.
- **[#297]** Postgres schema parity — added 6 tables + generated
  `scope_idx` column (memory_links, archived_memories,
  namespace_meta, pending_actions, sync_state, subscriptions) so
  cross-backend migration is no longer lossy beyond the memories
  table.
- **[#298]** Migration cursor data loss — the prior
  `created_at`-based pagination silently dropped low-priority
  memories under `priority DESC` list ordering. Replaced with a
  single-call `MAX_ROWS=1M` migrate that refuses loudly when
  saturated. Streaming migrate for corpora >1M rows tracked for
  v0.7 with `MemoryStore::list_all`.

New regression tests (behind `AI_MEMORY_TEST_POSTGRES_URL`):
`upserts_by_title_namespace_not_id`, `upsert_preserves_agent_id`,
`update_refuses_tier_downgrade`. Plus `migrate_sqlite_to_sqlite_roundtrip`
tightened to assert single-call semantics.

### Removed — TurboQuant embedding compression scrapped

TurboQuant (Google Research, arXiv 2504.19874) was evaluated as an
embedding-compression path for ai-memory (PRs #284 and #287). Both
closed unmerged. The `alphaonedev/turboquant` fork was archived.
Decision rationale: the ~2× embedding storage reduction at 4
bit-width is irrelevant at ai-memory's target scale (<100k memories
per deployment); beyond that, Postgres + pgvector (#279) is the right
answer. The fork-maintenance + heavy-transitive-deps burden (ort,
tokenizers, safetensors, burn) was not justified by the marginal
gain. Real compression wins live elsewhere: Ollama KV compression
(#288 runbook) for inference memory, Postgres + pgvector for native
vector storage at scale, SQLCipher at rest (shipped) for data-at-rest
protection.

### Added — world-class documentation sprint

Seven new authoritative docs close the reference-material gaps in
the existing `docs/` tree:

- **`docs/README.md`** — navigation hub grouping every doc by audience
  (end users, admins, developers, design decisions, SDKs).
- **`docs/QUICKSTART.md`** — first memory stored + recalled in under
  5 minutes across three paths (CLI, MCP with Claude Code / Cursor /
  Codex, HTTP daemon).
- **`docs/CLI_REFERENCE.md`** — every subcommand, flag, and
  environment variable the `ai-memory` binary exposes. Auto-synced
  to `src/main.rs` clap definitions.
- **`docs/API_REFERENCE.md`** — every HTTP endpoint the daemon
  exposes, with payload shapes, query params, status codes, and
  `curl` recipes. 24+ endpoints.
- **`docs/GLOSSARY.md`** — every concept (agent, tier, scope,
  curator, quorum, SAL, …) with single-paragraph definitions and
  links to authoritative docs.
- **`docs/TROUBLESHOOTING.md`** — common errors (startup, MCP,
  autonomy, HTTP, sync, performance, governance) with root-cause
  analysis and fixes.
- **`docs/SECURITY.md`** — complete threat model, trust boundaries,
  auth stack (API key + mTLS Layer 1/2/2b), SQLCipher at rest,
  SSRF-hardened webhook dispatch, responsible disclosure process.

Existing docs (`USER_GUIDE.md`, `ADMIN_GUIDE.md`, `DEVELOPER_GUIDE.md`,
`INSTALL.md`, `PHASE-1.md`, `AI_DEVELOPER_*.md`, `ENGINEERING_STANDARDS.md`,
`ARCHITECTURAL_LIMITS.md`, `ADR-0001-quorum-replication.md`,
`RUNBOOK-*.md`) cross-linked from `docs/README.md` for discovery.

### Added — v0.7 Storage Abstraction Layer (Track B PR 1)

- **Storage Abstraction Layer (SAL) — `MemoryStore` trait + `SqliteStore`
  + `PostgresStore`** — preview surface for v0.7. Gated behind
  `--features sal` (trait + sqlite adapter) and `--features sal-postgres`
  (adds the Postgres + pgvector backend). Default builds unchanged.
  Trait design carries over from the red-team-hardened #222 proposal:
  typed `StoreError` with `#[non_exhaustive]`, `CallerContext` on every
  mutator, optional `Transaction` handle, `verify()` contract, advertised
  `Capabilities` bitflags (NATIVE_VECTOR, FULLTEXT, DURABLE, etc.).
- **Postgres adapter ships with**:
  - `src/store/postgres_schema.sql` — idempotent bootstrap creating the
    `memories` table with a `vector(384)` column, pgvector `hnsw` index
    for cosine NN search, `gin` FTS + tags + metadata indexes.
  - `packaging/docker-compose.postgres.yml` — `pgvector/pgvector:pg16`
    fixture for integration tests. Hardened container
    (`cap_drop: [ALL]`, `no-new-privileges`, tmpfs for `/tmp`).
  - Live integration tests in `src/store/postgres.rs` that skip when
    `AI_MEMORY_TEST_POSTGRES_URL` is unset — keeps default `cargo test`
    offline while giving CI a straightforward opt-in path.
  - Unit-level tests: capability bits, RFC3339 parse helpers, schema
    constants.

### Added — v0.7 quorum replication primitives (Track C PR 1)

- **ADR-0001 — Quorum replication + chaos-testing methodology**
  (`docs/ADR-0001-quorum-replication.md`). Full design doc covering the
  W-of-N write-quorum model, failure modes, chaos-fault classes, and
  the implementation phasing. Explicitly states that v0.7 will NOT
  publish a "<0.01% loss" probability — instead it will publish a
  convergence-bound report per chaos campaign.
- **Quorum-write primitives** (`src/replication.rs`) — `QuorumPolicy`
  (N / W / deadlines / clock-skew threshold), `AckTracker` (collects
  local commit + peer acks, surfaces timeouts + id-drift), typed
  `QuorumError`. Pure-logic, I/O-free so unit tests don't need a live
  peer mesh.
- **12 unit tests** covering: single-node degenerate case,
  majority-default, W clamping, peer ack deduplication, deadline
  expiry reporting Unreachable vs Timeout, id-drift handling,
  Error trait participation.

### Added — v0.6.1 curator daemon (Track A)

### Added
- **Autonomous curator daemon** — new `ai-memory curator` subcommand with
  `--once` (single sweep + JSON report) and `--daemon` (continuous loop,
  interval configurable via `--interval-secs`, clamped to `[60, 86400]`).
  Invokes `auto_tag` + `detect_contradiction` on memories that lack an
  `auto_tags` metadata key, persisting results on success. Dry-run mode
  emits the same report without touching any row. Hard operation cap
  per cycle (`--max-ops`, default 100) prevents runaway LLM usage.
  Complements the synchronous post-store hooks shipped in v0.6.0.0
  (#265) — the curator catches memories stored before hooks were enabled,
  or when the LLM was offline, or that become interesting only after
  more context accumulates.
- **Curator systemd unit** — `packaging/systemd/ai-memory-curator.service`
  with the same sandbox posture as the main daemon
  (`ProtectSystem=strict`, empty `CapabilityBoundingSet`,
  `MemoryDenyWriteExecute`, `@system-service` syscall filter).
- **Curator Prometheus metrics** — `ai_memory_curator_cycles_total`,
  `ai_memory_curator_operations_total{kind,result}`,
  `ai_memory_curator_cycle_duration_seconds{dry_run}`.

### Added — full autonomy loop (earning the "100% autonomous" claim)

Builds on Track A's curator with the four passes required to make the
"100% autonomous" claim honest:

- **Autonomous consolidation** — the curator scans each namespace for
  near-duplicate memories (Jaccard keyword overlap ≥ 0.55 on a
  token-length-≥3 bag), clusters up to 8 members per group, calls
  `LLM.summarize_memories`, and commits the consolidated memory via
  the existing `db::consolidate` transaction. Source memories are
  archived, not lost.
- **Autonomous forgetting of superseded memories** — when a memory's
  `metadata.confirmed_contradictions` points at a newer, equal- or
  higher-confidence memory, the curator archives the stale one.
  Confidence + freshness BOTH required — never forgets on detection
  alone.
- **Priority feedback** — memories with `access_count ≥ 10` and a
  recall in the last 7 days get priority +1 (cap 10); memories cold
  for 30+ days drop priority -1 (floor 1). Arithmetic only; no LLM.
- **Rollback log** — every autonomous action (consolidate, forget,
  priority-adjust) writes a `RollbackEntry` memory into
  `_curator/rollback/<ts>` carrying the pre-action snapshot. Reversible
  via `ai-memory curator --rollback <id>` or `--rollback-last N`.
  Once reversed, the log memory is tagged `_reversed` — the history
  itself is preserved as an audit trail.
- **Self-report** — at the end of every cycle the curator writes its
  own `CuratorReport` as a memory in `_curator/reports/<ts>`. Agents
  can recall "what did the curator do yesterday" using the ordinary
  `memory_recall` path.

### Testing — end-to-end autonomy coverage

- `AutonomyLlm` trait introduced as the narrow LLM surface the passes
  need; `OllamaClient` impls it in prod, `StubLlm` stubs it in tests.
- 10 unit tests in `src/autonomy.rs` including a full
  `full_autonomy_cycle_end_to_end` that seeds duplicates + a
  superseded pair, runs `run_autonomy_passes`, and asserts that
  clusters were formed, memories forgotten, rollback entries written,
  and the rollback-log namespace populated.
- `reverse_consolidation_restores_originals` verifies the undo path
  by consolidating two memories, rolling back, and asserting both
  originals are back and the merged memory is gone.

### Honest-claim note

v0.6.1 earns the **"fully-autonomous curator loop"** claim: the
system can tag, consolidate, forget, rebalance priority, report on
itself, and reverse any of its own actions — without human input.
It does **not** yet claim multi-agent autonomy across a federation
(that's Track C) or cross-backend autonomy (that's Track B).
"100% autonomous" without those caveats would still be overclaiming.

### Added — cross-backend migration (Track B PR 2)

- **`ai-memory migrate --from <url> --to <url>`** CLI subcommand,
  gated behind `--features sal`. Supported URL shapes:
  - `sqlite:///absolute/path.db` / `sqlite://./relative.db` → `SqliteStore`
  - `postgres://user:pass@host:port/db` → `PostgresStore`
    (only under `--features sal-postgres`)
- Reads pages via `MemoryStore::list`, writes via `MemoryStore::store`.
  **Idempotent on re-run** — source ids are preserved verbatim and
  both adapters upsert on id.
- `--batch N` (1..10 000, default 1000), `--namespace <ns>` filter,
  `--dry-run`, `--json` for machine-readable reports.
- **6 unit tests**: sqlite URL parsing, unknown-scheme rejection,
  sqlite→sqlite full-roundtrip, dry-run writes nothing, idempotent
  re-run, namespace filter.
- Pagination strategy: slides `until` window backwards with dedup by
  id — handles identical `created_at` timestamps that break naïve
  `since`-cursor paging on SQLite.

### What's still out of scope for v0.7-alpha

Explicitly deferred to v0.7.1 (noted in `src/migrate.rs` docblock):

- **Daemon-level adapter selection** (`ai-memory serve --store-url
  postgres://…`) — requires refactoring `handlers.rs` from
  `crate::db::` free functions to dispatch through
  `Box<dyn MemoryStore>`. That's a big change and belongs in its
  own PR.
- **Live dual-write** — reverse migration (pg → sqlite) works using
  the same command but there is no always-on replication between
  heterogenous backends yet.
- **Schema rewriting** — both adapters currently agree on the
  `Memory` shape so no field mapping is needed.

### Cross-backend-autonomy claim now earned

v0.7-alpha earns: **"one-shot migration between SQLite and
Postgres/pgvector, bidirectional, idempotent"**.

Still honest caveats:
- A production deployment running `ai-memory serve` against Postgres
  as the live store needs v0.7.1's adapter-selection refactor.
- The migration is file-level point-in-time. For zero-downtime cutover
  you still need to stop writes on the source, migrate, and restart
  against the destination — documented in the module docblock.

### Added — federation autonomy (Track C PR 2)

- **Quorum writes wired into the HTTP daemon** (`src/federation.rs`).
  `ai-memory serve --quorum-writes N --quorum-peers <url,url,…>` fans
  out every successful write to each peer's `/api/v1/sync/push` and
  returns OK only after the local commit + `W - 1` peer acks land
  within `--quorum-timeout-ms`. Insufficient acks → `503` with body
  `{"error":"quorum_not_met","got":X,"needed":Y,"reason":…}` and
  `Retry-After: 2`. Local write is **not** rolled back on quorum
  failure — the sync-daemon's eventual-consistency loop catches
  stragglers up (per ADR-0001 § Model).
- **Opt-in + default-off** — daemons without `--quorum-writes`
  behave byte-for-byte identical to v0.6.0. Zero impact on
  non-federated deployments.
- **Optional mTLS for federation traffic** — `--quorum-client-cert`
  + `--quorum-client-key` feed the outbound reqwest client an mTLS
  identity so peer acks can be authenticated end-to-end.
- **Chaos harness** — `packaging/chaos/run-chaos.sh` spawns a
  three-node local fixture, issues a configurable burst of writes,
  and injects one of four fault classes (`kill_primary_mid_write`,
  `partition_minority`, `drop_random_acks`, `clock_skew_peer`).
  Emits a JSONL convergence-bound report per cycle — the data
  shape ADR-0001 commits to publishing instead of a loss probability.

### Testing

- **7 async mock-peer integration tests** in `src/federation.rs`
  using real ephemeral-port axum servers.
- Full suite on default features: 289 unit + 158 integration tests
  still green. fmt + clippy pedantic green.

### Added — LadybugDB roadmap

- **`docs/ROADMAP-ladybug.md`** — authoritative plan for integrating
  LadybugDB (the `lbug` Rust crate) as a new `MemoryStore` SAL
  adapter alongside `SqliteStore` and `PostgresStore`. Deliberately
  **not** a 100% transition — the document explains why (AI-agnostic
  value prop, SAL trait is the right seam, ~4000 LOC rewrite is
  wrong shape). Phased plan: scaffold → migration tool support →
  benchmark matrix → promotion decision gated on 6 hard
  prerequisites. Maintenance posture (pinned SHA, monthly rebase,
  upstream-first policy, scrap criteria) informed by the TurboQuant
  scrap. Not shipping in v0.6.0.0; v0.7.1+ track.

### Added — Ollama KV-cache tuning runbook

- **`docs/RUNBOOK-ollama-kv-tuning.md`** — operator-facing runbook
  for enabling `OLLAMA_KV_CACHE_TYPE=q4_0` + `OLLAMA_FLASH_ATTENTION=1`
  on Ollama. Delivers 2–4× KV-cache memory reduction on every
  ai-memory LLM path with near-lossless quality. Zero ai-memory
  code changes.

### "100% autonomous AI" claim earned

Shipping together in v0.6.0.0:

- Autonomous curator loop (tag / consolidate / forget / priority /
  rollback / self-report) per Track A + A-2.
- Multi-agent federation with W-of-N quorum writes per Track C + C-2.
- Cross-backend portability (SQLite ↔ Postgres+pgvector) per Track
  B + B-2.
- Autonomous hooks firing on every successful `memory_store`.

Remaining caveats (documented in runbooks, not overclaims):

- Real chaos campaigns against a production-shaped deployment:
  `docs/RUNBOOK-chaos-campaign.md`.
- Week-long curator soak against a production corpus:
  `docs/RUNBOOK-curator-soak.md`.
- Daemon-level adapter selection (`serve --store-url postgres://…`):
  `docs/RUNBOOK-adapter-selection.md` — v0.7.1 follow-up.
- Attested `sender_agent_id` from mTLS cert identity — v0.7 Layer
  2b primitives shipped (#285); handler wiring follow-up.

## [0.6.0] — 2026-04-19 — Phase 1 complete + v0.6.0.0 sprint

Phase 1 baseline (Tasks 1.1–1.12 from alpha train) plus the v0.6.0.0 sprint
additions covering opt-in LLM autonomy hooks, decay-aware recall, multi-agent
messaging primitives, at-rest encryption, ops surfaces, and SDK scaffolds.

Defer-outs from this release (not shipped in 0.6.0):

- **Autonomous curator daemon** — continuous background consolidation / GC
  driven by LLM decisions. Deferred to v0.6.1. v0.6.0 ships only the
  opt-in post-store hooks (synchronous, store path only).
- **Multi-node replication + chaos testing** — durability claims beyond
  single-node VACUUM INTO snapshots + optional peer sync are out of scope
  for v0.6.0. No loss-probability target is published.
- **Storage abstraction layer (Postgres / pgvector adapter)** — remains a
  v0.7 track. v0.6.0 is SQLite-only; the SAL preview on `feat/sal-trait-redesign`
  stays private/feature-gated until v0.7 extraction.

### Added — v0.6.0.0 sprint (autonomy hooks + multi-agent + at-rest + ops + SDKs)

**Autonomy / recall**
- **Time-decay half-life on recall scoring** — per-tier exponential decay
  multiplier on the hybrid-recall score blend. Default half-lives: short
  7 d, mid 30 d, long 365 d. Configurable via `[scoring]` in `config.toml`;
  `legacy_scoring = true` disables decay for A/B comparison and regression
  rollback. Half-lives clamped to `[0.1, 36500]` days.
- **Contextual recall (conversation-token bias)** — `memory_recall` accepts
  an optional `context_tokens: array<string>`. When supplied, the primary
  query embedding is fused 70/30 with an embedding of the joined context
  tokens, biasing recall toward memories that match both the explicit
  query AND nearby conversation topics. CLI: `--context-tokens tok1,tok2`.
- **Post-store LLM autonomy hooks** — opt-in synchronous hooks that fire
  `llm::auto_tag` + `llm::detect_contradiction` on every successful
  `memory_store`. Results persist into `metadata.auto_tags` and
  `metadata.confirmed_contradictions`. Enabled via
  `AI_MEMORY_AUTONOMOUS_HOOKS=1` env var or `autonomous_hooks = true` in
  config. Off by default (adds Ollama round-trip latency). Skipped for
  content under 50 bytes, when no LLM is wired, and for `_`-prefixed
  internal namespaces.
**Multi-agent primitives**
- **Agent-to-agent notify + inbox** — `memory_notify(target, title, payload)`
  + `memory_inbox([agent_id, unread_only])` MCP tools. Messages are
  ordinary memories in the reserved `_messages/<target>` namespace;
  sender identity stamped in metadata; `access_count == 0` is the
  conventional unread marker. No new schema.
- **Webhook subscribe / unsubscribe / list** — `memory_subscribe` +
  `memory_unsubscribe` + `memory_list_subscriptions` MCP tools. Events
  fire on `memory_store` (v0.6.1 extends to delete/promote/link) and
  POST an HMAC-SHA256-signed JSON payload to subscriber URLs
  (`X-Ai-Memory-Signature: sha256=<hex>`). SSRF-hardened — private-range
  IPs rejected, https required for non-loopback hosts. Migration v13
  adds the `subscriptions` table.
**At-rest encryption**
- **Optional SQLCipher encryption at rest** — new cargo feature
  `sqlcipher` swaps `rusqlite` to the
  `bundled-sqlcipher-vendored-openssl` feature. Default builds are
  byte-for-byte unchanged. Operators who want encryption build with
  `cargo build --no-default-features --features sqlcipher` and supply
  `--db-passphrase-file <path>` at startup. Passphrase never appears
  in the process list or shell history.

**Ops**
- **Prometheus `/metrics` endpoint** (and `/api/v1/metrics`) exposes
  `ai_memory_store_total`, `ai_memory_recall_total`,
  `ai_memory_recall_latency_seconds`, `ai_memory_autonomy_hook_total`,
  `ai_memory_contradiction_detected_total`,
  `ai_memory_webhook_dispatched_total`,
  `ai_memory_webhook_failed_total`, `ai_memory_memories`,
  `ai_memory_hnsw_size`, `ai_memory_subscriptions_active`. Pure Rust,
  no new transitive C deps.
- **Hardened systemd units** under `packaging/systemd/` —
  `ai-memory.service`, `ai-memory-sync.service`,
  `ai-memory-backup.service`, `ai-memory-backup.timer` with README.
  Full sandbox (`ProtectSystem=strict`, `MemoryDenyWriteExecute=yes`,
  `SystemCallFilter=@system-service`, `CapabilityBoundingSet=` empty,
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`). Target
  `systemd-analyze security` exposure score <5.0.
- **Backup / restore CLI** — `ai-memory backup --to <dir> [--keep N]`
  writes a hot-backup-safe SQLite `VACUUM INTO` snapshot plus a
  sha256 manifest. `ai-memory restore --from <path>` verifies the
  manifest before replacing the current DB; previous DB is moved
  aside to `<db>.pre-restore-<ts>.db` as a safety net. Paired with
  the hourly `ai-memory-backup.timer` systemd unit.

**SDKs**
- **TypeScript SDK scaffold** under `sdk/typescript/` —
  `@alphaone/ai-memory` (v0.6.0-alpha.0), strict TS, undici-based
  fetch, covers all current + v0.6.0.0 target endpoints (18+ methods),
  Jest tests guarded by `AI_MEMORY_TEST_DAEMON` env var. Includes
  HMAC-SHA256 webhook verifier. Not yet published to npm.
- **Python SDK scaffold** under `sdk/python/` — `ai-memory`
  (v0.6.0-alpha.0), sync (`AiMemoryClient`) + async
  (`AsyncAiMemoryClient`) clients via `httpx`, Pydantic v2 models
  (15/15 Memory fields), exception hierarchy, HMAC-SHA256 webhook
  verifier. Not yet published to PyPI.

### v0.6.0 GA disclosures (unchanged from pre-sprint baseline)

The following items are **MANDATORY DISCLOSURES** for the v0.6.0 release.
Operators upgrading from v0.5.4.x MUST read this section before deploying.

The following items are **MANDATORY DISCLOSURES** for the v0.6.0 GA release.
Operators upgrading from v0.5.4.x MUST read this section before deploying.

### Breaking changes

- **Consensus governance now requires agent pre-registration** (issue #234).
  The fix for security issue #216 (one caller satisfying `Consensus(N)` with
  N spoofed agent_ids) added an `is_registered_agent()` gate. Existing
  `consensus:N` policies become **indefinitely-locked** unless approver
  agents are registered first via `ai-memory agents register --agent-id <id>
  --agent-type <type>`.

  Migration: register all consensus approvers before upgrading. Example:

  ```bash
  ai-memory agents register --agent-id alice --agent-type human
  ai-memory agents register --agent-id bob   --agent-type human
  ai-memory agents register --agent-id carol --agent-type human
  ```

### Security disclosures (peer-mesh sync)

- **Sync endpoints are unauthenticated when TLS is not enabled** (issue #231).
  `POST /api/v1/sync/push` and `GET /api/v1/sync/since` accept all callers
  when `serve` runs without `--tls-cert + --tls-key`. Production peer-mesh
  deployments **MUST** set `--tls-cert + --tls-key + --mtls-allowlist`.
  See `docs/ADMIN_GUIDE.md` § Peer-mesh security.

- **sync-daemon does no server-cert verification without --client-cert**
  (issue #232). The daemon uses `danger_accept_invalid_certs(true)` when
  `--client-cert` is not provided — any server cert is accepted. For
  untrusted networks, ALWAYS use mTLS in both directions.

- **Any valid mTLS peer can dump the full database** (issue #239). By design,
  the trust boundary is the mTLS cert. Sync endpoints bypass per-memory
  visibility filtering. **Allowlist only peers you fully trust.** Per-namespace
  / per-scope sync filtering is a Phase 5 feature.

- **Body-claimed `sender_agent_id` is not yet attested to the cert CN/SAN**
  (issue #238). mTLS gates network access but the receiving handler accepts
  `sender_agent_id` from the body without checking the cert identity. A peer
  with a valid cert can claim any agent_id. Tracked as Layer 2b for v0.7.

### Schema migration

- v0.5.4.6 → v0.6.0 runs six additive migrations (v7 through v12). All are
  idempotent, transactional, and default-safe. Worst-case lock on a 10M-row
  database: 1–3 seconds during v10 (scope_idx index build). Schedule a brief
  maintenance window for large databases.

### Surface gaps tracked for v0.6.1

- Namespace standards / governance config is currently **MCP-only** (issue
  #236). HTTP and CLI surfaces will land in v0.6.1.
- `--agent-type` accepts only 6 hardcoded values (issue #235). Workaround:
  use `system` for custom agents, or wait for v0.6.1.

## [0.6.0-alpha.2] — 2026-04-16 — Phase 1 Track A complete + release-plumbing reconciliation

Supersedes **0.6.0-alpha.1** (2026-04-16, same day — partial publish). alpha.1
shipped the Task 1.3 feature to crates.io, Ubuntu PPA, Homebrew, and GitHub
Release binaries, but Docker (GHCR) and Fedora COPR failed due to a pre-existing
divergence between `main` and `release/v0.6.0`:

- Dockerfile pinned to `rust:1.87-slim` while code uses let-chains stabilized in
  1.88 (fixed on main in #187, never back-merged)
- Fedora COPR workflow `sed` blindly injected SemVer pre-release strings into
  RPM `Version:` field, which forbids `-`

alpha.2 back-merges `main` → `release/v0.6.0` (commits from `ce8fd47` through
`36747b2`, including RUSTSEC-2026-0098/0099 fixes), bumps `rust-version` to 1.88
(the honest MSRV), updates `time` 0.3.45 → 0.3.47 (RUSTSEC-2026-0009 DoS), and
patches the COPR workflow to split SemVer pre-release versions into `Version:` +
`Release:` pairs per Fedora packaging guidelines. No feature changes vs alpha.1.

alpha.1 will be **yanked from crates.io** once alpha.2 publishes successfully.

## [0.6.0-alpha.1] — 2026-04-16 — Phase 1 Track A complete (PARTIAL — yanked, superseded by alpha.2)

First cut of the v0.6.0 release train. Integration branch for Phase 1 tasks 1.3–1.12
plus the already-landed foundation work (1.1, 1.2). Pre-release; API is not yet stable.
Successive alphas will be tagged at each track completion (A/B/C/D per
[docs/PHASE-1.md](docs/PHASE-1.md) §Dependency Graph).

### Added — Task 1.1 (schema metadata foundation)

- **`metadata` JSON column** on `memories` and `archived_memories` tables, default `'{}'`.
  Schema migration to v7. All CRUD paths preserve metadata.
- **`Memory.metadata: serde_json::Value`** field with serde defaults.
- **`CreateMemory.metadata`**, **`UpdateMemory.metadata`** — MCP, HTTP, and CLI all accept
  arbitrary JSON metadata on store/update.
- **TOON format** renders `metadata` column inline.

### Added — Task 1.2 (Agent Identity in Metadata, NHI-hardened) — [#193]

- **`metadata.agent_id`** on every stored memory, resolved via a defense-in-depth
  precedence chain (explicit flag / body / MCP param → `AI_MEMORY_AGENT_ID` env →
  MCP `initialize.clientInfo.name` → `host:<host>:pid-<pid>-<uuid8>` →
  `anonymous:pid-<pid>-<uuid8>`).
- **HTTP `X-Agent-Id` request header** honored when no body `agent_id` is supplied;
  per-request `anonymous:req-<uuid8>` synthesized otherwise, with `WARN` log line.
- **`--agent-id` global CLI flag** (also reads `AI_MEMORY_AGENT_ID` env var).
- **`--agent-id` filter** on `list` and `search` (CLI, MCP tool param, HTTP query param).
- **Immutability**: `metadata.agent_id` is preserved across UPDATE, UPSERT dedup,
  import, sync, consolidate, and MCP `memory_update`. Enforced at both SQL level
  (`json_set` CASE clauses in `db::insert` and `db::insert_if_newer`) and caller
  level (`identity::preserve_agent_id` in every path that writes metadata).
- **Validation**: `^[A-Za-z0-9_\-:@./]{1,128}$` — permits prefixed / scoped / SPIFFE
  forms, rejects whitespace, null bytes, control chars, shell metacharacters.
- **New module** `src/identity.rs` (17 unit tests): precedence chain, process
  discriminator (`OnceLock<pid-<pid>-<uuid8>>`), component sanitization, HTTP
  resolution, provenance preservation.
- **`gethostname = "0.5"`** added as dependency (minimal, no transitive deps).
- **28 new tests** (20+ beyond spec minimum of 4): 17 unit + 2 validator + 9 integration.

### Security — red-team findings fixed during Task 1.2 review

- **T-3 (HIGH)**: MCP `memory_update` could rewrite `metadata.agent_id` on an existing
  memory, bypassing the documented immutability invariant. Fixed in commit `b228dcc`
  by wiring `identity::preserve_agent_id` into `handle_update`. Regression test
  `test_mcp_update_preserves_agent_id`.
- **GAP 1 (HIGH)**: `cmd_import` blindly trusted `metadata.agent_id` in input JSON,
  allowing an attacker-crafted file to forge any agent identity. Fixed in `356b448`:
  restamps with caller's id by default; `--trust-source` flag opts into legitimate
  backup-restore; original claim preserved as `imported_from_agent_id`. `cmd_sync`
  gets the same treatment on `pull` and `merge` paths.
- **GAP 2 (MEDIUM)**: `db::consolidate` merged source metadata with last-write-wins
  semantics on `agent_id`, nondeterministically dropping attribution and giving the
  consolidator no record. Fixed in `356b448`: consolidator's id is authoritative;
  all source authors preserved in `metadata.consolidated_from_agents` array.
  HTTP `ConsolidateBody` gains optional `agent_id` field plus `X-Agent-Id` header.
- **GAP 3 (LOW)**: `cmd_mine` produced memories with empty metadata, orphaning them
  from every agent_id filter. Fixed in `356b448`: caller's `agent_id` +
  `mined_from` source tag injected into every mined memory.
- **Defense-in-depth**: `db::insert_if_newer` (sync `merge` path) gains the same
  SQL-level `json_set` preservation clause as `db::insert`.

### Documentation — Phase 1.5 governance — [#194]

- **Governance §2.1 + §2.1.1**: new `Supervised off-host agents` approved class with
  7 binding pre-conditions (heartbeat, dead-man's switch, rate limit, lock-aware
  operation, instance-disambiguating attribution, etc.).
- **Governance §3.4.3.1**: concurrency lock primitive (short-tier `ai-memory` entry
  as lock, 15-min TTL, race-loser-yields semantics, stale-lock human escalation).
- **Governance §3.4.4.1 / §3.4.4.2**: audit-memory retention policy (immutable,
  non-consolidatable, append-only) + volume control at scale.
- **Governance new §3.5** (7 sub-sections): multi-agent coordination — branch
  ownership, handoff procedure, stale-branch GC, inter-agent conflict resolution,
  §3.4 SOP serialization, humans-in-CLI vs supervised off-host coordination,
  single-agent operation default.
- **Governance §5.4**: sole-approver policy applies uniformly to every approved
  agent class.
- **Workflow §8.5.1**: multi-agent operation cross-reference + lock acquisition
  discipline.

### Added — Task 1.3 (Agent Registration)

- **`_agents` reserved namespace** holding one long-tier memory per registered
  agent (`title = "agent:<agent_id>"`, `metadata.agent_type` +
  `metadata.capabilities` + `metadata.registered_at` + `metadata.last_seen_at`).
- **MCP tools**: `memory_agent_register`, `memory_agent_list` (brings tool count
  to **28**).
- **HTTP endpoints**: `POST /api/v1/agents`, `GET /api/v1/agents` (brings
  endpoint count to **26**).
- **CLI**: `ai-memory agents register --agent-id … --agent-type … [--capabilities …]`
  and `ai-memory agents list` (default sub-command).
- **`VALID_AGENT_TYPES`** closed set: `ai:claude-opus-4.6`, `ai:claude-opus-4.7`,
  `ai:codex-5.4`, `ai:grok-4.2`, `human`, `system`. Enforced by
  `validate_agent_type`.
- **Re-registration semantics**: upsert refreshes `agent_type`, `capabilities`,
  `last_seen_at`; preserves `registered_at` and `metadata.agent_id`
  (rides existing immutability SQL clause).
- **Trust model unchanged**: `agent_id` is still *claimed, not attested*. Future
  work will pair registration with provable attestation.
- **6 new integration tests**: register+list, duplicate-preserves-registered-at,
  invalid-type-rejected, invalid-id-rejected, namespace-isolation (no leak into
  `global`), and raw MCP JSON-RPC register/list roundtrip.

### Pending — remaining Phase 1 tasks to land in this release train

- Task 1.4 — Hierarchical Namespace Paths — depends on 1.1 ✓
- Task 1.5 — Visibility Rules — depends on 1.4
- Task 1.6 — N-Level Rule Inheritance — depends on 1.4
- Task 1.7 — Vertical Promotion — depends on 1.4
- Task 1.8 — Governance Metadata — depends on 1.1 ✓
- Task 1.9 — Governance Roles — depends on 1.8
- Task 1.10 — Approval Workflow — depends on 1.9
- Task 1.11 — Budget-Aware Recall — depends on 1.1 ✓
- Task 1.12 — Hierarchy-Aware Recall — depends on 1.4 + 1.11

### Release engineering

- Branched from `develop` @ `ee6cf9a` on 2026-04-16; all Phase 1 work now lands on `release/v0.6.0`.
- Successive alphas (`v0.6.0-alpha.N`) tagged at each track completion; `v0.6.0-rc.1`
  at feature-complete; `v0.6.0` GA when Phase 1 is done and external review window
  closes.
- `main` remains frozen at v0.5.4-patch.6 until v0.6.0 GA — no more 0.5.4 patches.

## [0.5.4-patch.4] — 2026-04-13

### Added

- **Three-level rule layering**: global (`*`) + parent + namespace standards, auto-prepended to recall and session_start. Max depth 5, cycle-safe.
- **Cross-namespace standards**: A standard memory from any namespace can be set as the standard for any other namespace. One policy, many projects.
- **Auto-detect parent by `-` prefix**: `set_standard("ai-memory-tests", id)` auto-discovers `ai-memory` as parent if it has a standard set. No explicit `parent` parameter needed.
- **Filesystem path awareness**: On `session_start`, walks from cwd up to home directory, checks if parent directory names have namespace standards, auto-registers parent chain. OS-agnostic via `PathBuf` and `dirs` crate.
- **`parent` parameter on `memory_namespace_set_standard`**: Explicit parent declaration for rule layering.
- Schema migration v6: `parent_namespace` column on `namespace_meta`

### Changed

- `inject_namespace_standard` resolves full parent chain: global → grandparent → parent → namespace
- Response returns `"standard"` (1 level) or `"standards"` array (multiple levels)
- TOON format: `standards[id|title|content]:` section renders all levels

## [0.5.4-patch.3] — 2026-04-12

### Added

- **Namespace standards**: 3 new MCP tools (`memory_namespace_set_standard`, `memory_namespace_get_standard`, `memory_namespace_clear_standard`) — 26 MCP tools total. Set a memory as the enforced standard/policy for a namespace; auto-prepended to recall and session_start results when scoped to that namespace.
- **Auto-prepend**: `handle_recall` and `handle_session_start` automatically prepend the namespace standard as a separate `"standard"` field when namespace is specified. Deduplicated from results. Count excludes standard.
- **TOON standard section**: TOON format renders namespace standard as a separate `standard[id|title|content]` section before memories.
- Schema migration v5: `namespace_meta` table
- 2 new integration tests: `test_mcp_namespace_standard_auto_prepend`, `test_namespace_standard_cascade_on_delete`

### Fixed

- **Shell `validate_id()` gap**: Interactive REPL `get` and `delete` commands now call `validate_id()`.
- **HNSW stale entry on dedup update**: `handle_store` dedup path now calls `idx.remove()` before `idx.insert()`.
- **Cascade cleanup**: `db::delete` removes `namespace_meta` rows referencing the deleted memory. `db::gc` cleans orphaned `namespace_meta` rows after expiring memories.
- **Consolidate warning**: `handle_consolidate` warns if any source memory is a namespace standard, prompting re-set to the new consolidated memory ID.

## [0.5.4-patch.2] — 2026-04-12

### Fixed

- **Tier downgrade protection**: `update()` now rejects tier downgrades (long→mid, long→short, mid→short) with a clear error message; prevents accidental data loss from TTL being added to permanent memories
- **Embedding regeneration on content update**: MCP `memory_update` now regenerates embedding vector and updates HNSW index when title or content changes, preventing stale semantic recall results
- **Consolidated memory embedding**: MCP `memory_consolidate` now generates embedding for the new consolidated memory at creation time and removes old entries from HNSW index, instead of relying on backfill
- **Self-contradiction exclusion**: CLI and MCP store now exclude the actual memory ID from `potential_contradictions` on upsert, fixing cosmetic self-referencing bug
- **Atomic CLI promote**: Removed non-atomic raw SQL `UPDATE` in `cmd_promote`; `db::update()` with `Some("")` already clears `expires_at` correctly
- **MCP `validate_id()` defense-in-depth**: Added `validate_id()` to `handle_get`, `handle_update`, `handle_delete`, `handle_promote`, `handle_get_links`, `handle_archive_restore`, `handle_auto_tag`, `handle_detect_contradiction`
- **CLI `validate_id()` defense-in-depth**: Added `validate_id()` to `cmd_get`, `cmd_update`, `cmd_delete`, `cmd_promote`

### Added

- `Tier::rank()` method for numeric tier comparison (Short=0, Mid=1, Long=2)
- 5 new unit tests: `tier_rank_ordering`, `update_rejects_tier_downgrade_long_to_short`, `update_rejects_tier_downgrade_long_to_mid`, `update_allows_tier_upgrade_short_to_long`, `update_allows_same_tier`
- 6 new integration tests: `test_cli_validate_id_rejects_invalid`, `test_tier_downgrade_rejected`, `test_tier_upgrade_allowed`, `test_duplicate_title_no_self_contradiction`, `test_promote_clears_expires_at`, `test_version_flag_patch2`

### Test Coverage

| Metric | Count |
|--------|-------|
| Unit tests | 139 |
| Integration tests | 49 |
| **Total** | **188** |
| Modules with tests | 15/15 |

## [0.5.4-patch.1] — 2026-04-12

### Fixed

- `--version` / `-V` flag missing — added `version` to `#[command]` attribute
- CLI `update` rejected past `expires_at` — changed to format-only validation, matching MCP behavior
- `archive_restore` tier promotion — release binary now includes `'long'` hardcoded in INSERT SQL

## [0.5.4] — 2026-04-12

### Added

- **Configurable TTL per tier**: `[ttl]` section in config.toml with 5 overrides: `short_ttl_secs`, `mid_ttl_secs`, `long_ttl_secs`, `short_extend_secs`, `mid_extend_secs`. Set to 0 to disable expiry.
- **Archive before GC deletion**: Expired memories archived to `archived_memories` table before deletion (default: `true`). Configurable via `archive_on_gc` in config.toml.
- 4 new MCP tools: `memory_archive_list`, `memory_archive_restore`, `memory_archive_purge`, `memory_archive_stats` (21 total)
- 4 new HTTP endpoints: `GET/DELETE /api/v1/archive`, `POST /api/v1/archive/{id}/restore`, `GET /api/v1/archive/stats` (24 total)
- `archive` CLI subcommand with `list`, `restore`, `purge`, `stats` actions (26 total commands)
- Schema migration v4: `archived_memories` table with indexes
- `TtlConfig` and `ResolvedTtl` types in config.rs for type-safe TTL resolution
- TTL values clamped to 10-year maximum to prevent integer overflow
- Negative `older_than_days` rejected in archive purge
- Archive restore checks for active ID collision (prevents silent overwrite)
- `validate_id()` on all archive restore endpoints (HTTP, MCP, CLI)

### Changed

- `db::update()` returns `(bool, bool)` — `(found, content_changed)` — for embedding regeneration
- `db::touch()` accepts configurable `short_extend` / `mid_extend` parameters
- `db::gc()` accepts `archive: bool` parameter
- `db::recall()` and `db::recall_hybrid()` accept configurable extend values
- All `gc_if_needed` callers respect `archive_on_gc` config setting
- Update facility: tier downgrade protection, title collision detection, embedding regeneration on content change

### Fixed

- Embeddings not regenerated on content update via `memory_update` (MCP + dedup store path)
- Tier downgrade not protected in update path (long never downgrades, mid never to short)
- Title+namespace collision on update returned opaque error (now returns 409 CONFLICT)
- MCP and CLI update handlers missing `validate_id()` call
- Negative TTL extension values now clamped to 0

## [0.5.2] — 2026-04-08

### Added

- Fedora COPR: `sudo dnf copr enable alpha-one-ai/ai-memory && sudo dnf install ai-memory`
- CI workflow for automated COPR upload on tag push
- debian/ packaging directory (control, rules, changelog, copyright)
- RPM spec file (ai-memory.spec) for COPR builds
- OpenClaw as 9th supported AI platform across all docs
- Animated architecture SVG and benchmark SVG in README
- Fedora/RHEL COPR and Ubuntu PPA install cards on GitHub Pages (8 install methods)

### Changed

- GitHub Pages professionalized: condensed hero, 13→7 nav links, 7→4 stats
- Install method count updated to 8 across all docs

## [0.5.1] — 2026-04-08

### Added

- Docker image auto-published to GitHub Container Registry (ghcr.io) on tag push
- `server.json` manifest for Official MCP Registry (modelcontextprotocol/registry)
- CONTRIBUTING.md, CHANGELOG.md, CODE_OF_CONDUCT.md
- Open Graph and Twitter Card meta tags on GitHub Pages
- Scope tables for all 9 AI platform tabs on GitHub Pages
- `mine` command documented across all docs (USER_GUIDE, ADMIN_GUIDE, DEVELOPER_GUIDE, index.html)
- Error code reference in DEVELOPER_GUIDE (NOT_FOUND, VALIDATION_FAILED, DATABASE_ERROR, CONFLICT)
- config.toml reference section in ADMIN_GUIDE
- Store command flags (`--source`, `--expires-at`, `--ttl-secs`) documented in README

### Changed

- Dockerfile: Rust 1.82 → 1.86, added build-essential, added benches/ copy
- Dockerfile: version label 0.4.0 → 0.5.0
- CI workflow: added Docker (GHCR) job triggered on tag push
- Claude Code MCP config: corrected from `~/.claude/.mcp.json` to three-scope model (`~/.claude.json`, `.mcp.json`, project-local)
- All 8 AI platform configs: added Windows paths, env var syntax, scope tables
- Hybrid recall blend weights: corrected docs from 50/50 & 85/15 to 60/40 (matches code)
- Default tier: corrected docs from "keyword" to "semantic" (matches code)
- Test count: corrected from 167 to 161 (118 unit + 43 integration)
- Module count: corrected from 14 to 15 (added mine.rs)
- CLI command count: corrected from 24 to 25 (added mine)

### Fixed

- Dockerfile build failure: missing benches/ directory, outdated Rust version, missing C++ compiler

## [0.5.0] — 2026-04-08

### Added

- MCP server with 17 tools for AI-native memory management
- HTTP API with 20 endpoints for external integration
- CLI with 25 commands for local operation and scripting
- 4 feature tiers (Core, Standard, Advanced, Enterprise) for flexible deployment
- TOON format for structured, topology-aware memory representation
- Hybrid recall engine combining semantic search, keyword matching, and graph traversal
- Multi-node sync for distributed memory across instances
- Auto-consolidation to merge and deduplicate related memories
- `mine` command for importing memories from conversation history
- LongMemEval benchmark support achieving 97.8% Recall@5

### Changed

- Upgraded memory storage layer for improved write throughput
- Refined relevance scoring in hybrid recall for better precision
- Improved CLI output formatting and error messages

### Fixed

- Resolved race condition during concurrent memory writes
- Fixed encoding issue with non-ASCII content in TOON format
- Corrected sync conflict resolution when timestamps are identical

## [0.4.0]

### Added

- Initial MCP server implementation with core tool set
- Basic memory storage and retrieval
- CLI foundation with essential commands
- Semantic search over stored memories
- SQLite-backed persistent storage

### Changed

- Migrated internal data model to support richer metadata

### Fixed

- Fixed crash on empty query input
- Resolved file descriptor leak in long-running server mode

## [0.3.0]

### Added

- Embedding-based semantic search
- Memory tagging and filtering
- Configuration file support

### Changed

- Switched to async I/O for server operations

### Fixed

- Fixed memory leak during large batch imports

## [0.2.0]

### Added

- Persistent storage backend
- Basic CLI for memory CRUD operations
- JSON export and import

### Fixed

- Fixed incorrect timestamp handling across time zones

## [0.1.0]

### Added

- Initial prototype with in-memory storage
- Core data model for memory entries
- Basic search functionality

[0.5.2]: https://github.com/alphaonedev/ai-memory-mcp/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/alphaonedev/ai-memory-mcp/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/alphaonedev/ai-memory-mcp/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/alphaonedev/ai-memory-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/alphaonedev/ai-memory-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/alphaonedev/ai-memory-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/alphaonedev/ai-memory-mcp/releases/tag/v0.1.0
