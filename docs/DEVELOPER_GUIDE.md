# Developer Guide

## Architecture Overview

`claude-memory` is a single Rust binary that serves two roles:

1. **CLI tool** -- direct SQLite operations for store, recall, search, list, etc.
2. **HTTP daemon** -- an Axum web server exposing the same operations as a REST API

Both interfaces share the same database layer (`db.rs`). The daemon adds automatic garbage collection (every 30 minutes) and graceful shutdown with WAL checkpointing.

```
main.rs          -- CLI parsing (clap), daemon setup (axum), command dispatch
models.rs        -- Data structures: Memory, MemoryLink, query types, constants
handlers.rs      -- HTTP request handlers (Axum extractors + JSON responses)
db.rs            -- All SQLite operations: CRUD, FTS5, recall scoring, GC, migration
```

## Code Structure

### `src/main.rs`

- `Cli` struct with `clap` derive -- defines all CLI commands and global flags
- `Command` enum -- `Serve`, `Store`, `Update`, `Recall`, `Search`, `Get`, `List`, `Delete`, `Promote`, `Forget`, `Link`, `Consolidate`, `Gc`, `Stats`, `Namespaces`, `Export`, `Import`, `Completions`
- `auto_namespace()` -- detects namespace from git remote URL or directory name
- `serve()` -- starts the Axum server with all routes, spawns GC task, handles graceful shutdown
- `cmd_*()` functions -- one per CLI command, each opens the DB directly

### `src/models.rs`

- `Tier` enum (`Short`, `Mid`, `Long`) with TTL defaults: 6h, 7d, none
- `Memory` struct -- the core data type with 14 fields
- `MemoryLink` struct -- typed directional links between memories
- Request types: `CreateMemory`, `UpdateMemory`, `SearchQuery`, `ListQuery`, `RecallQuery`, `RecallBody`, `LinkBody`, `ForgetQuery`, `ConsolidateBody`
- Response types: `Stats`, `TierCount`, `NamespaceCount`
- Constants: `MAX_CONTENT_SIZE` (65536), `PROMOTION_THRESHOLD` (5), `SHORT_TTL_EXTEND_SECS` (3600), `MID_TTL_EXTEND_SECS` (86400)

### `src/handlers.rs`

All HTTP handlers. State is `Arc<Mutex<(Connection, PathBuf)>>`. Each handler acquires the lock, performs DB operations, returns JSON.

### `src/db.rs`

The database layer. Key functions:

| Function | Description |
|----------|-------------|
| `open()` | Opens DB, sets WAL mode, creates schema, runs migrations |
| `insert()` | Upsert on `(title, namespace)` -- never downgrades tier |
| `get()` | Fetch by ID |
| `touch()` | Bump access count, extend TTL, auto-promote mid->long at 5 accesses |
| `update()` | Partial update of any fields |
| `delete()` | Delete by ID |
| `forget()` | Bulk delete by namespace + FTS pattern + tier |
| `list()` | List with filters: namespace, tier, priority, date range, tags |
| `search()` | FTS5 AND search with composite scoring |
| `recall()` | FTS5 OR search + touch + auto-promote + TTL extension |
| `find_contradictions()` | Find memories in same namespace with similar titles |
| `consolidate()` | Merge multiple memories, delete originals, keep max priority and all tags |
| `create_link()` / `get_links()` / `delete_link()` | Memory linking |
| `gc()` | Delete expired memories |
| `stats()` | Aggregate statistics |
| `export_all()` / `export_links()` | Full data export |
| `checkpoint()` | WAL checkpoint for clean shutdown |
| `health_check()` | Verifies DB accessibility and FTS integrity |

## Database Schema

### `memories` table

```sql
CREATE TABLE memories (
    id               TEXT PRIMARY KEY,
    tier             TEXT NOT NULL,           -- 'short', 'mid', 'long'
    namespace        TEXT NOT NULL DEFAULT 'global',
    title            TEXT NOT NULL,
    content          TEXT NOT NULL,
    tags             TEXT NOT NULL DEFAULT '[]',  -- JSON array
    priority         INTEGER NOT NULL DEFAULT 5,  -- 1-10
    confidence       REAL NOT NULL DEFAULT 1.0,   -- 0.0-1.0
    source           TEXT NOT NULL DEFAULT 'api', -- 'user', 'claude', 'hook', 'api', 'cli'
    access_count     INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,           -- ISO 8601
    updated_at       TEXT NOT NULL,
    last_accessed_at TEXT,
    expires_at       TEXT                     -- NULL for long-term
);

-- Unique constraint enables upsert behavior
CREATE UNIQUE INDEX idx_memories_title_ns ON memories(title, namespace);
```

### `memories_fts` virtual table

```sql
CREATE VIRTUAL TABLE memories_fts USING fts5(
    title, content, tags,
    content=memories, content_rowid=rowid
);
```

Kept in sync via `AFTER INSERT`, `AFTER DELETE`, and `AFTER UPDATE` triggers on `memories`.

### `memory_links` table

```sql
CREATE TABLE memory_links (
    source_id   TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
    target_id   TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
    relation    TEXT NOT NULL DEFAULT 'related_to',
    created_at  TEXT NOT NULL,
    PRIMARY KEY (source_id, target_id, relation)
);
```

Relation types: `related_to`, `supersedes`, `contradicts`, `derived_from`.

### `schema_version` table

Tracks migration state. Current version: 2.

## Recall Scoring Formula

The recall function uses a composite score to rank results:

```
score = (fts_rank * -1)         -- FTS5 relevance (negated because lower = better in SQLite)
      + (priority * 0.5)        -- Priority weight (1-10 -> 0.5-5.0)
      + (access_count * 0.1)    -- Frequency bonus
      + (confidence * 2.0)      -- Certainty weight (0.0-1.0 -> 0.0-2.0)
      + tier_boost              -- long=3.0, mid=1.0, short=0.0
```

The `search` function uses the same formula minus the tier boost.

## API Reference

Base URL: `http://127.0.0.1:9077/api/v1`

All responses are JSON. Error responses include `{"error": "message"}`.

### Health Check

```
GET /health
```

Response: `{"status": "ok", "service": "claude-memory"}`

### Create Memory

```
POST /memories
Content-Type: application/json

{
  "title": "Project uses Axum",
  "content": "The HTTP server is built with Axum 0.8.",
  "tier": "mid",
  "namespace": "claude-memory",
  "tags": ["rust", "web"],
  "priority": 6,
  "confidence": 1.0,
  "source": "api"
}
```

Response (201):
```json
{
  "id": "a1b2c3d4-...",
  "tier": "mid",
  "namespace": "claude-memory",
  "title": "Project uses Axum"
}
```

If potential contradictions are detected, the response includes `"potential_contradictions": ["id1", "id2"]`.

Defaults: `tier=mid`, `namespace=global`, `priority=5`, `confidence=1.0`, `source=api`.

Optional fields: `expires_at` (ISO 8601), `ttl_secs` (overrides tier default).

### Bulk Create

```
POST /memories/bulk
Content-Type: application/json

[
  {"title": "Memory 1", "content": "..."},
  {"title": "Memory 2", "content": "..."}
]
```

Response: `{"created": 2, "errors": []}`

### Get Memory

```
GET /memories/{id}
```

Response:
```json
{
  "memory": { ... },
  "links": [ ... ]
}
```

### Update Memory

```
PUT /memories/{id}
Content-Type: application/json

{
  "content": "Updated content",
  "priority": 8
}
```

All fields are optional. Only provided fields are updated.

### Delete Memory

```
DELETE /memories/{id}
```

Response: `{"deleted": true}`

### List Memories

```
GET /memories?namespace=my-app&tier=long&limit=20&offset=0&min_priority=5&since=2025-01-01T00:00:00Z&until=2025-12-31T23:59:59Z&tags=rust
```

All query parameters are optional. Max limit is 200.

Response:
```json
{
  "memories": [ ... ],
  "count": 5
}
```

### Search (AND semantics)

```
GET /search?q=database+migration&namespace=my-app&tier=mid&limit=10
```

Response:
```json
{
  "results": [ ... ],
  "count": 3,
  "query": "database migration"
}
```

### Recall (OR semantics + touch)

```
GET /recall?context=auth+flow+jwt&namespace=my-app&limit=10&tags=auth&since=2025-01-01T00:00:00Z
```

Or via POST:

```
POST /recall
Content-Type: application/json

{
  "context": "auth flow jwt",
  "namespace": "my-app",
  "limit": 10
}
```

Response:
```json
{
  "memories": [ ... ],
  "count": 5
}
```

Recall automatically: bumps `access_count`, extends TTL, and auto-promotes mid-tier memories with 5+ accesses to long-term.

### Forget (Bulk Delete)

```
POST /forget
Content-Type: application/json

{
  "namespace": "my-app",
  "pattern": "deprecated API",
  "tier": "short"
}
```

At least one field is required. Response: `{"deleted": 3}`

### Consolidate

```
POST /consolidate
Content-Type: application/json

{
  "ids": ["id1", "id2", "id3"],
  "title": "Auth system summary",
  "summary": "JWT with refresh tokens, RBAC middleware, Redis sessions.",
  "namespace": "my-app",
  "tier": "long"
}
```

Requires at least 2 IDs. Deletes source memories. Response: `{"id": "new-id", "consolidated": 3}`

### Links

Create a link:
```
POST /links
Content-Type: application/json

{
  "source_id": "id1",
  "target_id": "id2",
  "relation": "related_to"
}
```

Get links for a memory:
```
GET /links/{id}
```

Response: `{"links": [{"source_id": "...", "target_id": "...", "relation": "...", "created_at": "..."}]}`

### Namespaces

```
GET /namespaces
```

Response: `{"namespaces": [{"namespace": "my-app", "count": 42}]}`

### Stats

```
GET /stats
```

Response:
```json
{
  "total": 150,
  "by_tier": [{"tier": "long", "count": 80}, ...],
  "by_namespace": [{"namespace": "my-app", "count": 42}, ...],
  "expiring_soon": 5,
  "links_count": 12,
  "db_size_bytes": 524288
}
```

### Garbage Collection

```
POST /gc
```

Response: `{"expired_deleted": 3}`

### Export

```
GET /export
```

Response: full JSON dump of all memories and links.

### Import

```
POST /import
Content-Type: application/json

{
  "memories": [ ... ],
  "links": [ ... ]
}
```

Response: `{"imported": 50, "errors": []}`

## CLI Reference

Global flags:
- `--db <path>` -- database path (default: `claude-memory.db`, env: `CLAUDE_MEMORY_DB`)
- `--json` -- output as machine-parseable JSON

### `serve`

Start the HTTP daemon.

```bash
claude-memory serve --host 127.0.0.1 --port 9077
```

### `store`

```bash
claude-memory store \
  -T "Title" \
  -c "Content" \
  --tier mid \
  --namespace my-app \
  --tags "tag1,tag2" \
  --priority 7 \
  --confidence 0.9 \
  --source claude
```

Use `-c -` to read content from stdin.

### `update`

```bash
claude-memory update <id> -T "New title" -c "New content" --priority 8
```

### `recall`

```bash
claude-memory recall "search context" --namespace my-app --limit 10 --tags auth --since 2025-01-01T00:00:00Z
```

### `search`

```bash
claude-memory search "exact terms" --namespace my-app --tier long --limit 20 --since 2025-01-01 --until 2025-12-31 --tags rust
```

### `get`

```bash
claude-memory get <id>
```

### `list`

```bash
claude-memory list --namespace my-app --tier mid --limit 50 --tags devops
```

### `delete`

```bash
claude-memory delete <id>
```

### `promote`

```bash
claude-memory promote <id>
```

Promotes to long-term and clears expiry.

### `forget`

```bash
claude-memory forget --namespace my-app --pattern "old stuff" --tier short
```

At least one filter is required.

### `link`

```bash
claude-memory link <source-id> <target-id> --relation supersedes
```

Relation types: `related_to` (default), `supersedes`, `contradicts`, `derived_from`.

### `consolidate`

```bash
claude-memory consolidate "id1,id2,id3" -T "Summary title" -s "Consolidated content" --namespace my-app
```

### `gc`

```bash
claude-memory gc
```

### `stats`

```bash
claude-memory stats
```

### `namespaces`

```bash
claude-memory namespaces
```

### `export` / `import`

```bash
claude-memory export > backup.json
claude-memory import < backup.json
```

### `completions`

```bash
claude-memory completions bash
claude-memory completions zsh
claude-memory completions fish
```

## Adding New Features

1. **Add the model** in `models.rs` -- new struct or new fields on existing structs
2. **Add the DB function** in `db.rs` -- SQL operations
3. **Add the HTTP handler** in `handlers.rs` -- Axum handler function
4. **Add the route** in `main.rs` inside the `Router::new()` chain
5. **Add the CLI command** in `main.rs` -- new variant in `Command` enum, new `Args` struct, new `cmd_*()` function
6. **Add tests** in `tests/integration.rs`

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run a specific test
cargo test test_name
```

Integration tests are in `tests/integration.rs`.

## Building from Source

```bash
git clone https://github.com/alphaonedev/claude-memory.git
cd claude-memory

# Debug build
cargo build

# Release build (optimized, stripped)
cargo build --release

# The binary is at target/release/claude-memory
```

Release profile settings (from `Cargo.toml`):
- `opt-level = 2`
- `strip = true` (removes debug symbols)
- `lto = "thin"` (link-time optimization)
