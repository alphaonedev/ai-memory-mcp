# Migrating from v0.6.4 to v0.7.0 — User-Friendly Plan

> **Who this is for.** Anyone running ai-memory on v0.6.4 today who wants to move
> to v0.7.0 without losing data. Plain English. Code blocks for the actual
> commands. Suitable for laptop-only "just Claude Code" setups all the way through
> single-tenant team deployments on sqlite.
>
> **For the deep technical companion** (every per-form note, every env var,
> every schema-ladder bump) see [`MIGRATION_v0.7.md`](MIGRATION_v0.7.md). This
> document is the calm, walk-me-through-it sibling. It does NOT replace the
> technical guide — it sits in front of it.
>
> **For postgres-backed deployments** see
> [`migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.md). The §5 summary
> below points you there.

---

## 1. TL;DR migration verdict

- **What changes.** The sqlite schema jumps from **v15 → v49** — 11 new columns
  on the `memories` table (citations, source URIs, byte-range spans, memory
  kind, entity id, persona version, confidence provenance + signals + decay
  stamp, optimistic-concurrency `version`, plus the QW-2 `auto_persona_entity_id`
  / PERF-8 `mentioned_entity_id`). New tables: `signed_events` (audit chain),
  `memory_transcripts` + `memory_transcript_links` (sidechain transcripts),
  `agent_skills`, `offloaded_blobs`, `confidence_shadow_observations`,
  `federation_push_dlq`, several more. None of this is destructive — every
  existing row carries forward unchanged and the new columns default to safe
  values for legacy rows.
- **Estimated downtime.** **30 seconds to 2 minutes** for a typical laptop
  database (a few thousand memories). The schema migration runs on the first
  `ai-memory serve` boot after the upgrade, and you're back online as soon as
  it finishes. Bigger databases (100k+ memories) can take up to a few minutes
  because of the QW-2 `auto_persona_entity_id` backfill scan.
- **Rollback supported?** **Yes — via file restore from the pre-upgrade
  backup.** The schema ladder is idempotent on replay but NOT reversible in
  place; once `schema_version` reaches 49, you cannot ALTER the columns away.
  Rollback means stopping the v0.7.0 binary, restoring the `.bak.pre-v07` file
  you took in step 2 of §4, and reinstalling the v0.6.4 binary. Data written
  while you were on v0.7.0 is lost in that rollback — see §7.

---

## 2. Before you start — backup checklist

Stop here until you've ticked all of these boxes. Migration without these is
recoverable in 95% of cases and unrecoverable in 5%, and you won't know which
one you're in until it's too late.

### 2.1 Backup checklist

- [ ] **Database file.** Locate it (default on Linux/macOS:
  `~/.local/share/ai-memory/ai-memory.db`; on some older installs:
  `~/.local/share/ai-memory/memory.db`). Stop the daemon first. Copy the file
  AND its WAL sidecar:
  ```bash
  ai-memory stop                                                # or pkill ai-memory
  cp ~/.local/share/ai-memory/ai-memory.db ~/.local/share/ai-memory/ai-memory.db.bak.pre-v07
  # If you see -wal / -shm sidecar files, copy those too:
  cp ~/.local/share/ai-memory/ai-memory.db-wal ~/.local/share/ai-memory/ai-memory.db-wal.bak.pre-v07 2>/dev/null || true
  cp ~/.local/share/ai-memory/ai-memory.db-shm ~/.local/share/ai-memory/ai-memory.db-shm.bak.pre-v07 2>/dev/null || true
  ```
- [ ] **Verify the backup is readable.** A `.bak` you can't open is not a
  backup:
  ```bash
  sqlite3 ~/.local/share/ai-memory/ai-memory.db.bak.pre-v07 'PRAGMA integrity_check;'
  # Expected output: ok
  sqlite3 ~/.local/share/ai-memory/ai-memory.db.bak.pre-v07 \
    'SELECT user_version FROM pragma_user_version;'
  # Expected output for v0.6.4 installs: 15 (or whatever your version is — note it)
  ```
- [ ] **Config file.** Copy your config too:
  ```bash
  cp ~/.config/ai-memory/config.toml ~/.config/ai-memory/config.toml.bak.pre-v07 2>/dev/null || true
  ```
- [ ] **Identity keypairs.** If you've enrolled any Ed25519 agent identities,
  back them up:
  ```bash
  cp -r ~/.config/ai-memory/keys ~/.config/ai-memory/keys.bak.pre-v07 2>/dev/null || true
  cp ~/.config/ai-memory/operator.key* ~/.config/ai-memory/ 2>/dev/null || true
  ```
  > **Why.** The keypair files (`~/.config/ai-memory/keys/<agent_id>.{pub,priv}`,
  > mode 0600) are NOT regenerable. Lose them and any link that was Ed25519-signed
  > by that agent can no longer be verified against the old public key. v0.7.0
  > does not delete or modify these files, but a `chmod 0400` mistake during a
  > permission-tightening sweep can render them unreadable.
- [ ] **Note your current schema version** for the rollback path:
  ```bash
  sqlite3 ~/.local/share/ai-memory/ai-memory.db 'PRAGMA user_version;'
  # On v0.6.4 you should see 15. Write this down.
  ```
- [ ] **Disk space.** The schema migration creates several new tables and
  indexes. Plan for **roughly 1.3× your current DB size** of free space on
  the partition holding `~/.local/share/ai-memory/`. A 200 MB v0.6.4 DB
  comfortably needs 300 MB free; a 5 GB DB needs 7 GB.
- [ ] **Test plan ready.** Pick one or two recent memories whose content you
  know by heart, so you can `ai-memory recall <topic>` after the migration
  and check they come back unchanged.

### 2.2 Don't migrate yet if any of these are true

- You have an in-flight `ai-memory mine` / `ai-memory import` job. Let it
  finish.
- You have unsynchronised federation peers (pending pushes in the
  subscription queue). Drain first or accept that they re-deliver after
  upgrade.
- You're running a custom `hooks.toml` that depends on v0.6.4 lifecycle event
  names. v0.7.0 ships 25 events (20 baseline + 5 grand-slam additions) — all
  v0.6.4 event names continue to fire, but you should skim
  [`hook-pipeline.md`](hook-pipeline.md) for the new ones before relying on
  them.

---

## 3. The 30-second migration — for the "just my laptop" user

You run Claude Code on one machine, you have one ai-memory database, you're
not federating, you have not customised `hooks.toml` or `config.toml`. Skip
to §4 if any of those are false.

```bash
# 1. Stop whatever's running.
ai-memory stop 2>/dev/null || pkill ai-memory

# 2. One backup before anything else.
cp ~/.local/share/ai-memory/ai-memory.db ~/.local/share/ai-memory/ai-memory.db.bak.pre-v07

# 3. Upgrade the binary. Pick your channel:
brew upgrade ai-memory                                          # Homebrew
# or:
cargo install --git https://github.com/alphaonedev/ai-memory-mcp ai-memory --locked

# 4. Start it back up. The schema migration runs automatically on first boot.
ai-memory start
```

That's it. The first `ai-memory start` after the upgrade walks the schema
ladder v15 → v49 against your DB in place. It's idempotent — if you Ctrl-C
during the migration, restart and the unfinished bumps resume from where they
stopped.

To confirm you landed cleanly:

```bash
ai-memory doctor --tokens                                       # general health
ai-memory recall "anything"                                     # smoke recall
sqlite3 ~/.local/share/ai-memory/ai-memory.db 'PRAGMA user_version;'
# Expected: 49
```

If any of those go sideways, jump to §9 (Troubleshooting).

---

## 4. Step-by-step migration — single-instance sqlite

This is the canonical path for anyone past the 30-second tier — team laptops,
home-lab boxes, hand-managed servers running ai-memory under systemd. Every
step is independently auditable.

### 4.1 Stop the daemon

```bash
ai-memory stop                                                  # graceful shutdown
# Or under systemd:
sudo systemctl stop ai-memory
# Confirm nothing's still holding the file:
lsof ~/.local/share/ai-memory/ai-memory.db                      # should print nothing
```

If `lsof` shows a process, that's a stuck child (often a `mine` import or a
hook daemon). Kill it explicitly before continuing — a hot copy of a sqlite
WAL file is not guaranteed consistent.

### 4.2 Take the backup (per §2.1)

You did this already in §2. Verify once more:

```bash
ls -lh ~/.local/share/ai-memory/ai-memory.db.bak.pre-v07
sqlite3 ~/.local/share/ai-memory/ai-memory.db.bak.pre-v07 'PRAGMA integrity_check;'
```

### 4.3 Install the v0.7.0 binary

```bash
# Homebrew:
brew upgrade ai-memory
ai-memory --version                                             # confirm 0.7.0

# Or build from source:
cargo install --git https://github.com/alphaonedev/ai-memory-mcp ai-memory --locked
ai-memory --version

# Or a release tarball — substitute your platform:
curl -L -o ai-memory.tar.gz \
  https://github.com/alphaonedev/ai-memory-mcp/releases/download/v0.7.0/ai-memory-aarch64-apple-darwin.tar.gz
tar -xzf ai-memory.tar.gz
sudo install -m 0755 ai-memory /usr/local/bin/ai-memory
ai-memory --version
```

### 4.4 First-boot schema migration

Start the daemon. The first boot detects `user_version=15` (your v0.6.4 state)
and walks the ladder up to 49.

```bash
ai-memory serve --foreground 2>&1 | tee ~/.local/share/ai-memory/migrate.log
# Or under systemd:
sudo systemctl start ai-memory
journalctl -u ai-memory -f                                      # tail the log
```

Expected log lines, in rough order:

```
[INFO] opening sqlite db at ~/.local/share/ai-memory/ai-memory.db
[INFO] current schema_version=15, target schema_version=49
[INFO] applying migration 0015..0049 idempotent ladder
[INFO] migration v16 applied (pending_action_timeouts)
[INFO] migration v17 applied (transcripts)
…
[INFO] migration v40 applied (source_uri_backfill: 1247 rows scanned, 312 backfilled)
[INFO] migration v42 applied (auto_persona_entity_id: 89 rows scanned, 17 backfilled)
…
[INFO] migration v49 applied (archived_memories full carry)
[INFO] schema_version=49 — ladder complete
[INFO] HTTP API listening on 127.0.0.1:9077
[INFO] MCP stdio dispatch ready
```

Typical duration on a workstation laptop:

| DB size           | Memories | Expected migration time |
|-------------------|---------:|-------------------------|
| Fresh / <100 MB   |    <10k  | <5 seconds              |
| Personal corpus   |    <50k  | 5–20 seconds            |
| Active workspace  |   <250k  | 20–60 seconds           |
| Large team        |   <1M    | 1–3 minutes             |

If the migration log stops moving for >5 minutes, check `lsof` (someone else
opened the file) or `iostat` (your disk may be saturated). Don't kill the
process — let it finish. If you must, every bump is atomic and resumes on
restart.

### 4.5 Validation queries

Once the daemon is up, run these in another shell. They should all return
clean signals:

```bash
# Schema is at the v0.7.0 target.
sqlite3 ~/.local/share/ai-memory/ai-memory.db 'PRAGMA user_version;'
# Expected: 49

# Row counts match your pre-upgrade backup.
sqlite3 ~/.local/share/ai-memory/ai-memory.db.bak.pre-v07 \
  'SELECT COUNT(*) FROM memories;'
sqlite3 ~/.local/share/ai-memory/ai-memory.db \
  'SELECT COUNT(*) FROM memories;'
# Both numbers identical — no data lost.

# Tables you should now have that didn't exist on v0.6.4:
sqlite3 ~/.local/share/ai-memory/ai-memory.db \
  ".tables" | tr ' ' '\n' | grep -E '^(signed_events|memory_transcripts|agent_skills|offloaded_blobs|confidence_shadow_observations|federation_push_dlq)$'
# All six names should print.

# New columns on `memories` are populated with safe defaults.
sqlite3 ~/.local/share/ai-memory/ai-memory.db \
  "SELECT COUNT(*) FROM memories WHERE memory_kind IS NULL;"
# Expected: 0 (the default is 'observation' for every row)
sqlite3 ~/.local/share/ai-memory/ai-memory.db \
  "SELECT memory_kind, COUNT(*) FROM memories GROUP BY memory_kind;"
# Expected: observation | <your row count>  (and possibly some reflections if you used memory_reflect)

# Sanity: pick a memory you know by heart and recall it.
ai-memory recall "the topic you wrote on Monday" --json | jq '.memories[0].title'

# Capability surface advertises v3.
ai-memory mcp call memory_capabilities '{"schema_version":"3"}' | jq '.schema_version'
# Expected: "3"
```

### 4.6 Cleanup

Once you're satisfied (a day of normal use is the operator-recommended
soak time), you can delete the `.bak.pre-v07` file to reclaim disk:

```bash
rm ~/.local/share/ai-memory/ai-memory.db.bak.pre-v07
rm ~/.local/share/ai-memory/ai-memory.db-wal.bak.pre-v07 2>/dev/null || true
rm ~/.local/share/ai-memory/ai-memory.db-shm.bak.pre-v07 2>/dev/null || true
```

**Don't rush this step.** The rollback path in §7 needs that backup. Most
operators wait at least 7 days of clean runtime before deleting.

---

## 5. Step-by-step migration — postgres deployments

If you run ai-memory against PostgreSQL (with or without Apache AGE), the
upgrade path differs because schema bumps land via the `ai-memory schema-init
--upgrade` command rather than via the daemon's first-boot ladder.

**Read [`migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.md) for the
full runbook.** It covers schema-init upgrades, the v15→v28→v49 paths, the
AGE projection prime, and the cutover dance.

### 5.1 Executive summary (do not skip the full doc)

1. **Snapshot the postgres database first.** `pg_dump` of the database
   schema + data:
   ```bash
   pg_dump --format=custom --file=ai-memory.pre-v07.dump \
     postgres://aimemory:PASSWORD@HOST:5432/aimemory
   ```
2. **Stop the daemon.** `systemctl stop ai-memory` or your service manager.
3. **Install the v0.7.0 binary** (per §4.3 above).
4. **Run the in-place upgrade** against the live postgres URL:
   ```bash
   ai-memory schema-init \
     --store-url postgres://aimemory:PASSWORD@HOST:5432/aimemory \
     --upgrade
   ```
   This walks the postgres ladder up to schema v49 idempotently, preserving
   data.
5. **Verify schema parity:**
   ```bash
   psql 'postgres://aimemory:PASSWORD@HOST:5432/aimemory' \
     -tAc "SELECT version FROM _ai_memory_schema_version ORDER BY version DESC LIMIT 1;"
   # → 49
   ```
6. **Restart and validate:**
   ```bash
   sudo systemctl start ai-memory
   curl -s http://localhost:9077/api/v1/capabilities | jq '.store_backend, .kg_backend'
   # → "PostgresStore"
   # → "Age" (if you have AGE installed) or "cte" (recursive-CTE fallback)
   ```

### 5.2 If you want to switch sqlite → postgres at the same time

The v0.7.0 SAL trait makes sqlite ↔ postgres a one-command migration.
Run `ai-memory migrate --from sqlite:///path/to/memory.db --to postgres://...`
per the postgres guide. You can do it before OR after the v0.7.0 upgrade —
the SAL boundary is byte-stable across both backends at schema v49.

---

## 6. What changed — schema field-by-field

This section walks the 11 new columns on the `memories` table and the WHY
behind each. The detailed call-out paragraphs follow the summary table.
Schema-deep readers, see
[`MIGRATION_v0.7.md` §"Per-bump narrative"](MIGRATION_v0.7.md) for the v34 →
v49 ladder.

### Summary table

| # | Column | Type & default | Schema | One-line why |
|---|--------|----------------|--------|--------------|
| 1 | `reflection_depth` | INTEGER NOT NULL DEFAULT 0 | v29 | Bound recursion in `memory_reflect`; filter recall to raw observations. |
| 2 | `memory_kind` | TEXT NOT NULL DEFAULT 'observation' | v30 | 10-variant Batman vocabulary — indexed type lookup vs JSON-extract scan. |
| 3 | `entity_id` | TEXT NULL | v36 | Subject of a Persona artefact; queryable by who-it's-about. |
| 4 | `persona_version` | INTEGER NULL | v36 | Monotonic persona version — old profiles stay queryable for audit. |
| 5 | `citations` | TEXT NOT NULL DEFAULT '[]' | v38 | Hop recall hits back to source PR / doc / conversation. |
| 6 | `source_uri` | TEXT NULL | v38 | First-class URI form; untangles role-label `source` from URL. |
| 7 | `source_span` | TEXT NULL | v38 | Byte-range into the parent doc — reverse-translate atom → source paragraph. |
| 8 | `confidence_source` | TEXT NOT NULL DEFAULT 'caller_provided' | v39 | Caller's gut vs calibrated — provenance of the confidence value. |
| 9 | `confidence_signals` | TEXT NULL | v39 | Reproducibility — replay the derivation three weeks later. |
| 10 | `confidence_decayed_at` | TEXT NULL | v39 | Has freshness decay already aged this value? |
| 11 | `version` | INTEGER NOT NULL DEFAULT 1 | v45 | Optimistic-concurrency counter — surface conflicts instead of silent last-writer-wins. |

Plus three columns added in passing:

- **`mentioned_entity_id`** TEXT NULL (v42, PERF-8) — indexed entity descriptor for auto-persona candidate matching; drops O(namespace_rows × content_bytes) reflection-clustering to O(matching_rows).
- **`atomised_into`** + **`atom_of`** TEXT NULL — pointers between a long-form memory and its atom decomposition.
- **`provenance_version`** TEXT NULL (v39) — Form-4 envelope carry version.

And new tables (opt-in / empty if you never use the feature): `signed_events` (V-4 audit chain), `memory_transcripts` + `memory_transcript_links` (zstd-3 sidechain), `agent_skills` (L1-5 SKILL.md storage), `offloaded_blobs` (QW-3), `confidence_shadow_observations` (Form-5 telemetry), `federation_push_dlq` (Track D), `recall_observations` (recursive-learning Task 4/8), plus governance / quota / hook-subscriber bookkeeping.

### Field details

**6.1 `reflection_depth`** (v29). Depth in the reflection tree. `0` for caller-minted rows (and every pre-v0.7.0 row); positive for reflections synthesised by `memory_reflect` over lower-depth peers. Without this, a reflection that summarises three reflections that summarise nine raw observations is indistinguishable from any other memory — you can't bound runaway recursion or filter recall to "raw observations only".

**6.2 `memory_kind`** (v30, backfilled by `0025_v07_memory_kind.sql`). Ten-variant Batman discriminator. Rows tagged `metadata.type='reflection'` are auto-promoted from `observation` to `reflection`. "Show me decisions, not observations" becomes an indexed lookup instead of a JSON-extract scan.

**6.3 `entity_id`** (v36, QW-2). Subject of a Persona artefact. Populated only when `memory_kind = 'persona'`. Lets you query Persona rows by who-they're-about rather than by full-text search.

**6.4 `persona_version`** (v36). Monotonic per-`(entity_id, namespace)` version. Each `memory_persona_generate` writes `version + 1`; older profiles stay queryable. Personas evolve — yesterday's profile of "Alice the engineer" must not silently destroy today's.

**6.5 `citations`** (v38, Form 4 fact-provenance). JSON array of Citation envelopes — `[{ uri, accessed_at, hash?, span? }, …]`. Without citations every recall result is a he-said-she-said blob; with them, downstream readers can hop straight back to the source PR / doc / conversation.

**6.6 `source_uri`** (v38). First-class URI form — `uri:`, `doc:`, or `file:` schemes. Distinct from the role-label `source` column (`"user"`, `"claude"`, `"api"`). v0.6.4 had operators stuffing both roles and URLs into `source`; v0.7.0 untangles them into a typed pair. Legacy `source` values are untouched.

**6.7 `source_span`** (v38). JSON `{start, end}` byte-range into the parent source. Set by the WT-1-B atomiser per atom — a 50-word fact sentence carries a `{start: 2034, end: 2113}` pointer into its 5000-word parent. Reverse-translating a hit back to the source paragraph becomes a slice op, not a re-search.

**6.8 `confidence_source`** (v39, Form 5). Provenance of the `confidence` value itself: `caller_provided` (default), `auto_derived`, `calibrated`, `decayed`. v0.6.4 took every confidence at face — no way to tell `0.9` from gut vs from calibration. v0.7.0 makes the trust path inspectable.

**6.9 `confidence_signals`** (v39). JSON snapshot of the signals used to compute the confidence — `source_age_days`, `atom_derivation`, `prior_corroboration_count`, `freshness_factor`, `baseline_per_source`. Reproducibility — three weeks later you can still answer "why is this 0.87 confident".

**6.10 `confidence_decayed_at`** (v39). RFC3339 stamp of the last freshness-decay pass. Set when `AI_MEMORY_CONFIDENCE_DECAY=1` or the namespace policy carries `confidence_decay_half_life_days`. A fact at 0.9 captured yesterday is worth more than the same value at 0.9 captured 18 months ago — without a stamp you can't know whether decay has already been applied.

**6.11 `version`** (v45, Provenance Gap 1 / #884). Optimistic-concurrency counter. Bumped on every `memory_update`. Two callers writing against the same `expected_version` race one winner; the loser receives a typed CONFLICT envelope naming the current version. v0.6.4 was last-writer-wins and quietly destroyed concurrent edits.

The bump-by-bump v34 → v49 narrative lives in
[`MIGRATION_v0.7.md` §"Upgrade steps"](MIGRATION_v0.7.md).

---

## 7. Rollback procedure

> **Rollback loses every memory you wrote while on v0.7.0.** The pre-upgrade
> backup is the only readable v0.6.4-shaped database you have; once v0.7.0
> migrates the original, the original is at v49 and v0.6.4 can't open it.
> Plan for this — don't migrate until you have a backup and a stop-the-world
> plan.

### 7.1 Stop the v0.7.0 daemon

```bash
ai-memory stop                                                  # graceful
# or:
sudo systemctl stop ai-memory
lsof ~/.local/share/ai-memory/ai-memory.db                      # confirm nothing's open
```

### 7.2 Move the v0.7.0 database out of the way (don't delete it yet)

You may want this file later if rollback turns out to be unnecessary, or for
forensic comparison. Move it sideways:

```bash
mv ~/.local/share/ai-memory/ai-memory.db ~/.local/share/ai-memory/ai-memory.db.v0.7.0-rollback-quarantine
mv ~/.local/share/ai-memory/ai-memory.db-wal ~/.local/share/ai-memory/ai-memory.db-wal.v0.7.0-rollback-quarantine 2>/dev/null || true
mv ~/.local/share/ai-memory/ai-memory.db-shm ~/.local/share/ai-memory/ai-memory.db-shm.v0.7.0-rollback-quarantine 2>/dev/null || true
```

### 7.3 Restore the v0.6.4 backup

```bash
cp ~/.local/share/ai-memory/ai-memory.db.bak.pre-v07 ~/.local/share/ai-memory/ai-memory.db
cp ~/.local/share/ai-memory/ai-memory.db-wal.bak.pre-v07 ~/.local/share/ai-memory/ai-memory.db-wal 2>/dev/null || true
cp ~/.local/share/ai-memory/ai-memory.db-shm.bak.pre-v07 ~/.local/share/ai-memory/ai-memory.db-shm 2>/dev/null || true
```

### 7.4 Restore the v0.6.4 binary

```bash
# Homebrew users:
brew install ai-memory@0.6.4                                    # if a tap exposes it
# OR: download the v0.6.4 release binary directly:
curl -L -o ai-memory-064.tar.gz \
  https://github.com/alphaonedev/ai-memory-mcp/releases/download/v0.6.4/ai-memory-aarch64-apple-darwin.tar.gz
tar -xzf ai-memory-064.tar.gz
sudo install -m 0755 ai-memory /usr/local/bin/ai-memory
ai-memory --version                                             # confirm 0.6.4
```

### 7.5 Start back up and verify

```bash
ai-memory start
sqlite3 ~/.local/share/ai-memory/ai-memory.db 'PRAGMA user_version;'
# Expected: 15 (your pre-v0.7.0 version)
ai-memory recall "a memory you knew was there pre-upgrade"
```

### 7.6 What you lose

- Any memory stored between the v0.7.0 cutover and the rollback. The v0.7.0
  database is in the `.v0.7.0-rollback-quarantine` file — you can keep it
  for forensic recovery (sqlite3 it open, hand-pick rows of interest,
  re-store them via the v0.6.4 binary) but there's no automatic re-import.
- Any signed-events audit-chain entries from the v0.7.0 window. v0.6.4
  doesn't know about that table.
- Any persona artefacts the v0.7.0 auto-persona hook generated. v0.6.4
  has no concept of `memory_kind = 'persona'`.

If you have a workload where rollback >24h post-cutover is realistic, run
a forward-rsync of the v0.7.0 file daily to a quarantine partition so the
forensic recovery window doesn't have a single point of file-corruption
risk.

---

## 8. Validation — make sure the migration worked

Beyond the smoke checks in §4.5, these are the canonical "your migration
is healthy" probes.

### 8.1 `ai-memory list`

```bash
ai-memory list --limit 10
```

Expected output: ten of your recent memories in plain-text format, each with
a title, namespace, tier, confidence, and last-accessed timestamp. The v0.7.0
list view also surfaces `memory_kind` and (where set) `entity_id`, but legacy
rows just show `observation` for the kind — no row should be missing.

### 8.2 `ai-memory verify-signed-events-chain`

This is the V-4 cross-row hash chain verifier. It walks the `signed_events`
table from beginning to end and confirms every `prev_hash` matches the SHA-256
of the previous row.

```bash
ai-memory verify-signed-events-chain --format json
```

Expected output on a fresh v0.7.0 install with no signed activity yet:

```json
{
  "status": "ok",
  "rows_verified": 0,
  "chain_head": null,
  "chain_tip": null,
  "tampered": false
}
```

After your first signed activity (a `memory_link` write against an agent that
has an Ed25519 keypair under `~/.config/ai-memory/keys/`), the same command
should report `rows_verified > 0` with `tampered: false`.

If you see `tampered: true`, something has rewritten the `signed_events`
table out-of-band. That's a serious finding — file an issue with the JSON
output attached.

### 8.3 Capability surface health

```bash
ai-memory mcp call memory_capabilities '{"schema_version":"3"}' | jq '.schema_version, .summary'
# Expected:
# "3"
# "AI Memory MCP exposes a 7-tool core with N additional families available via runtime expansion."
```

The `summary` and `to_describe_to_user` fields are v3-only — if they're
missing you're either still on v0.6.4 or your client is forcing schema v2.

### 8.4 Recall round-trip

Pick a memory you know existed before the upgrade. Recall it:

```bash
ai-memory recall "<some title or topic you wrote pre-upgrade>" --json | jq '.memories[0] | {id, title, memory_kind, confidence_source, version}'
```

Expected fields populated:

- `id` — same id as before the migration.
- `title` — unchanged.
- `memory_kind` — `"observation"` (the default for any pre-v0.7.0 row).
- `confidence_source` — `"caller_provided"` (the default).
- `version` — `1` (the default for any pre-v45 row).

If `id` differs or the row isn't found, something went wrong — recover from
the backup (§7).

### 8.5 Optional — sqlite integrity check

```bash
sqlite3 ~/.local/share/ai-memory/ai-memory.db 'PRAGMA integrity_check;'
# Expected: ok
```

Failure here means physical-on-disk corruption. Restore from backup
immediately and file an issue with the exact `integrity_check` output.

---

## 9. Troubleshooting — common errors + fixes

### 9.1 "database is locked" on first boot

**Symptom:** First `ai-memory serve` after the upgrade hangs or aborts with
`database is locked`.

**Cause:** Another process is holding the file. Common culprits: a stale
ai-memory daemon, an editor with the DB open in a sqlite viewer, a Claude
Code MCP session that was running when you upgraded.

**Fix:**
```bash
lsof ~/.local/share/ai-memory/ai-memory.db                      # see who's holding it
kill <pid>                                                      # kill the holder
ai-memory serve
```

### 9.2 "no such column: memory_kind" / "no such column: citations"

**Symptom:** A query (often via a third-party tool reading the DB
directly) fails because it expects a v0.7.0 column that isn't there.

**Cause:** The schema migration didn't run. Most likely you copied the
v0.7.0 binary in place but never started it against the DB, OR the
migration aborted partway and the daemon never reached v49.

**Fix:**
```bash
sqlite3 ~/.local/share/ai-memory/ai-memory.db 'PRAGMA user_version;'
# If <49: rerun:
ai-memory serve --foreground 2>&1 | tee ~/.local/share/ai-memory/migrate.log
# Watch the log for migration completion; halt only after schema_version=49.
```

### 9.3 "schema_version=49 but column missing" (very rare)

**Symptom:** `PRAGMA user_version;` reports `49` but a SELECT against one of
the new columns errors out.

**Cause:** A migration crash between the column ADD and the version-bump
INSERT. Should be impossible because the ladder wraps each bump in a
transaction; if you see it, file an issue and attach the output of `.schema
memories` and your migration log.

**Workaround:** Reduce the recorded version to before the failing bump
manually, then restart:
```bash
sqlite3 ~/.local/share/ai-memory/ai-memory.db 'PRAGMA user_version = <last-good-version>;'
ai-memory serve --foreground
```

### 9.4 "permissions.mode = enforce" denies a write that v0.6.4 allowed

**Symptom:** A `memory_store` (or any write) returns a `GOVERNANCE_REFUSED`
error envelope where on v0.6.4 it would have succeeded.

**Cause:** v0.7.0 flips `permissions.mode` from `advisory` (the v0.6.4
default) to `enforce`. Existing governance rules that were "log only" on
v0.6.4 are now real gates.

**Fix:** Either (a) tighten your governance rules so the write is allowed
explicitly, or (b) restore the v0.6.4 advisory posture in `config.toml`:
```toml
[permissions]
mode = "advisory"
```
or via env var:
```bash
export AI_MEMORY_PERMISSIONS_MODE=advisory
```

This is a one-line revert. Operators with custom rule corpora should run
`ai-memory governance migrate-to-permissions --dry-run` to preview the
v0.7.0 shape before flipping back.

### 9.5 "G1 inheritance now blocks a write that used to succeed"

**Symptom:** Writing to `team/alice` errors with an Approve-required
verdict that didn't fire on v0.6.4.

**Cause:** v0.6.3.1 (and forward, including v0.7.0) walks the namespace
chain and consults parent policies. If `team` has an Approve policy and
`team/alice` has none, the parent's policy now blocks the write.

**Fix:** If you upgraded straight from a pre-v0.6.3.1 version, set
`inherit = false` on the child policy to restore pre-v0.6.3.1 behavior:
```sql
UPDATE governance_policies
   SET inherit = false
 WHERE namespace = 'team/alice';
```

### 9.6 "I lost my identity keypair"

**Symptom:** After the upgrade `ai-memory identity list` reports no
keys, but `verify-signed-events-chain` reports rows.

**Cause:** Most likely your `~/.config/ai-memory/keys/` directory was
not migrated alongside the database. Restore from `keys.bak.pre-v07`
(per §2.1) — keys are not regenerable from the database.

**Fix:**
```bash
cp -r ~/.config/ai-memory/keys.bak.pre-v07 ~/.config/ai-memory/keys
chmod 0700 ~/.config/ai-memory/keys
chmod 0400 ~/.config/ai-memory/keys/*.priv 2>/dev/null
chmod 0644 ~/.config/ai-memory/keys/*.pub 2>/dev/null
ai-memory identity list                                         # confirm visible
```

If you have no backup, generate a fresh keypair — but be aware that links
signed by the old key will read as `peer_attested = false` against the new
key. Old signatures remain valid in the audit chain; only new writes are
attributed to the new key.

### 9.7 "verify-signed-events-chain reports tampered: true"

**Symptom:** Post-migration the chain verifier reports tampering.

**Cause (most common, benign):** The v0.7.0 V-4 closeout (schema v34) is the
migration that introduced the `prev_hash + sequence` columns. If your
pre-upgrade `signed_events` table had rows from earlier writes, the v34
backfill (`migrate_v34_backfill_chain` in `storage/migrations.rs`) walks the
existing rows and computes `prev_hash` for each. If the daemon crashed
mid-backfill on a previous attempt and you restored from backup but didn't
re-run the daemon to completion, the chain will read as broken.

**Fix:** Restart the daemon. The v34 backfill is idempotent — it re-walks
and re-stamps. After a clean run, `verify-signed-events-chain` should report
`tampered: false`.

**Cause (rare, serious):** Something genuinely wrote into the table
out-of-band. File an issue with the full JSON verifier output and the
output of:
```sql
SELECT id, sequence, hex(prev_hash) FROM signed_events ORDER BY sequence;
```

### 9.8 Daemon hangs on first boot, log shows "migration v40 source_uri_backfill"

**Symptom:** First boot stalls inside the v40 `source_uri_backfill`
migration. The log shows `migration v40 applied: 0 rows scanned` indefinitely
or it just stops moving.

**Cause:** v40 walks `metadata.source` JSON-extract values for every memory
row. On a large DB (>100k rows) with old corrupt-metadata blobs, this can
take minutes; the log line only writes after the scan finishes.

**Fix:** Wait. If you must abort, `Ctrl-C` is safe — the bump is atomic;
restart resumes from v39. If you suspect a corrupt-metadata blob,
identify it with:
```bash
sqlite3 ~/.local/share/ai-memory/ai-memory.db \
  "SELECT id FROM memories WHERE json_valid(metadata) = 0 LIMIT 10;"
```
and clean up those rows manually (set `metadata = '{}'`) before retrying.

---

## 10. FAQ

### Q1. Do I HAVE to upgrade to v0.7.0?

**No.** v0.6.4 continues to receive security patches in the v0.6.x branch.
That said, every new feature lands on v0.7.x going forward — agent skills,
sidechain transcripts, persona artefacts, the 25-event hook pipeline, the
provider-agnostic LLM substrate (#1067), and the mobile target CI all
require v0.7.0.

### Q2. Is the migration reversible?

**Yes, via file restore.** The schema ladder is idempotent on replay but
not in-place reversible — once you reach `schema_version=49`, the columns
exist and the data has been backfilled. Rollback means restoring the
pre-upgrade `.bak.pre-v07` file (per §7). Don't delete the backup until
you've soaked v0.7.0 for at least a week.

### Q3. Will my existing memories carry over unchanged?

**Yes.** Every v0.6.4 row preserves its `id`, `title`, `content`,
`namespace`, `tier`, `tags`, `priority`, `confidence`, `source`, and
`metadata`. The 11 new columns land with safe defaults: `memory_kind` =
`'observation'`, `version` = `1`, `confidence_source` =
`'caller_provided'`, `citations` = `[]`, everything else NULL.

### Q4. Do I need to re-embed everything?

**No.** Embeddings carry over verbatim. The HuggingFace model & dimension
are stamped on each memory; the HNSW index rebuilds on first boot from
the existing vectors, no re-computation needed.

### Q5. Will my v0.6.4 SDK / client keep working?

**Yes.** Capabilities v3 is additive — v2 fields stay at their existing
paths and shapes. v0.6.4 SDKs continue to read v2 fields and ignore the
new top-level keys. Every v0.6.4 CLI subcommand, MCP tool, and HTTP route
behaves identically against a v0.7.0 server (where v0.7.0 added 28 new
MCP tools, those are net-new; nothing was removed).

### Q6. What's the biggest behavior change?

**`permissions.mode` flips from `advisory` to `enforce`** as the default.
If you relied on the v0.6.4 default-permissive posture, opt back in via
`[permissions] mode = "advisory"` in your `config.toml` (or set
`AI_MEMORY_PERMISSIONS_MODE=advisory`). This is the single most likely
"works on v0.6.4, fails on v0.7.0" symptom — see §9.4.

### Q7. Can I migrate from sqlite to postgres at the same time?

**Yes.** v0.7.0 ships a bidirectional migration tool (`ai-memory migrate
--from sqlite:///… --to postgres://…`). The recommended order is: upgrade
the sqlite-backed daemon to v0.7.0 first (so both sides converge on schema
v49), then run the cross-backend migration. The postgres guide has the
full runbook: [`migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.md).

### Q8. The first boot is taking forever. Is it stuck?

**Probably not.** Schema migration time scales with DB size — a 1M-memory
corpus can take 1–3 minutes. The QW-2 `auto_persona_entity_id` backfill
(v42) and the Form-4 `source_uri_backfill` (v40) are the two slowest
bumps because they scan content. Tail the log
(`journalctl -u ai-memory -f` or `tail -f migrate.log`); if you see
`migration vNN applied` lines marching forward, you're fine. If the log
is silent for >5 minutes, check `iostat` (disk saturation) and `lsof`
(another process holding the file). When in doubt, let it finish — every
bump is atomic.

---

## See also

- [`MIGRATION_v0.7.md`](MIGRATION_v0.7.md) — the deep technical migration
  guide (per-form notes, every env var, the v34→v49 ladder narrative).
- [`migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.md) — the
  sqlite → postgres + Apache AGE runbook.
- [`v0.7.0/release-notes.md`](v0.7.0/release-notes.md) — full release notes
  by area (capabilities v3, Batman forms 1–6 + 7th-form foundation,
  recursive-learning primitive, Agent Skills, federation hardening,
  provider-agnostic LLM, mobile target CI).
- [`internal/v070-feature-inventory.md`](internal/v070-feature-inventory.md)
  — canonical feature-by-feature inventory of every net-new surface in
  v0.7.0 vs v0.6.4 (453 commits, 545 files, +233,589 / −23,541 lines).
- [`CHANGELOG.md`](../CHANGELOG.md) — the full v0.7.0 changelog entry.
- [`signed-events-v4.md`](signed-events-v4.md) — the V-4 cross-row
  audit-chain spec, in case §9.7 sent you here.
- [`governance.md`](governance.md) — the permissions / governance system,
  in case §9.4 / §9.5 sent you here.
