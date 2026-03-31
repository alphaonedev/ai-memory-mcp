# Admin Guide

## Deployment Options

### Standalone (Development)

Run directly in the foreground:

```bash
claude-memory --db /path/to/claude-memory.db serve
```

The daemon listens on `127.0.0.1:9077` by default.

### Systemd (Production)

```bash
sudo tee /etc/systemd/system/claude-memory.service > /dev/null << 'EOF'
[Unit]
Description=Claude Memory Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/claude-memory --db /var/lib/claude-memory/claude-memory.db serve
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=claude_memory=info,tower_http=info

[Install]
WantedBy=multi-user.target
EOF

sudo mkdir -p /var/lib/claude-memory
sudo systemctl daemon-reload
sudo systemctl enable --now claude-memory
```

Check status:

```bash
sudo systemctl status claude-memory
sudo journalctl -u claude-memory -f
```

### Docker

Example Dockerfile:

```dockerfile
FROM rust:1.75-slim AS builder
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /src/target/release/claude-memory /usr/local/bin/
VOLUME /data
EXPOSE 9077
CMD ["claude-memory", "--db", "/data/claude-memory.db", "serve"]
```

Build and run:

```bash
docker build -t claude-memory .
docker run -d -p 127.0.0.1:9077:9077 -v claude-memory-data:/data claude-memory
```

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--db <path>` | `claude-memory.db` | Path to SQLite database |
| `--host <addr>` | `127.0.0.1` | Bind address (serve only) |
| `--port <port>` | `9077` | Bind port (serve only) |
| `--json` | `false` | JSON output for CLI commands |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAUDE_MEMORY_DB` | `claude-memory.db` | Database path (overridden by `--db`) |
| `RUST_LOG` | (none) | Logging filter (e.g., `claude_memory=info,tower_http=debug`) |

### Compile-Time Constants

These are set in the source code and require recompilation to change:

| Constant | Value | Location |
|----------|-------|----------|
| `DEFAULT_PORT` | 9077 | `main.rs` |
| `GC_INTERVAL_SECS` | 1800 (30 min) | `main.rs` |
| `MAX_CONTENT_SIZE` | 65536 (64 KB) | `models.rs` |
| `PROMOTION_THRESHOLD` | 5 accesses | `models.rs` |
| `SHORT_TTL_EXTEND_SECS` | 3600 (1 hour) | `models.rs` |
| `MID_TTL_EXTEND_SECS` | 86400 (1 day) | `models.rs` |

## Database Management

### SQLite Settings

The database uses these pragmas (set automatically on open):

- **WAL mode** -- write-ahead logging for concurrent reads
- **busy_timeout = 5000** -- 5 second wait on lock contention
- **synchronous = NORMAL** -- balanced durability/performance
- **foreign_keys = ON** -- enforced referential integrity

### Backup

**Live backup (while daemon is running):**

```bash
sqlite3 /path/to/claude-memory.db ".backup /path/to/backup.db"
```

**JSON export:**

```bash
claude-memory --db /path/to/claude-memory.db export > backup.json
```

**File copy (daemon must be stopped or use WAL checkpoint first):**

```bash
systemctl stop claude-memory
cp /path/to/claude-memory.db /path/to/backup.db
cp /path/to/claude-memory.db-wal /path/to/backup.db-wal 2>/dev/null
systemctl start claude-memory
```

### Restore

**From JSON:**

```bash
claude-memory --db /path/to/new.db import < backup.json
```

**From SQLite backup:**

```bash
systemctl stop claude-memory
cp /path/to/backup.db /var/lib/claude-memory/claude-memory.db
systemctl start claude-memory
```

### Migration

The schema is auto-migrated on startup. The `schema_version` table tracks the current version (currently 2). Migrations are forward-only and non-destructive.

### Database Maintenance

Manually trigger garbage collection:

```bash
# Via CLI
claude-memory gc

# Via API
curl -X POST http://127.0.0.1:9077/api/v1/gc
```

Compact the database (reduces file size after many deletions):

```bash
sqlite3 /path/to/claude-memory.db "VACUUM"
```

Rebuild the FTS index (if it becomes corrupt):

```bash
sqlite3 /path/to/claude-memory.db "INSERT INTO memories_fts(memories_fts) VALUES('rebuild')"
```

## Monitoring

### Health Endpoint

```bash
curl http://127.0.0.1:9077/api/v1/health
```

Returns `200 OK` with `{"status": "ok", "service": "claude-memory"}` if healthy.

Returns `503 Service Unavailable` if the database is inaccessible or FTS integrity check fails.

The health check verifies:
1. Database is readable (runs `SELECT COUNT(*) FROM memories`)
2. FTS index integrity (`INSERT INTO memories_fts(memories_fts) VALUES('integrity-check')`)

### Stats Endpoint

```bash
curl http://127.0.0.1:9077/api/v1/stats
```

Returns:
- Total memory count
- Breakdown by tier
- Breakdown by namespace
- Memories expiring within 1 hour
- Total link count
- Database file size in bytes

### Logs

The daemon logs via `tracing` with configurable levels:

```bash
# Info level (default recommended)
RUST_LOG=claude_memory=info,tower_http=info claude-memory serve

# Debug level (verbose, includes all HTTP requests)
RUST_LOG=claude_memory=debug,tower_http=debug claude-memory serve

# Trace level (extremely verbose)
RUST_LOG=claude_memory=trace claude-memory serve
```

With systemd, logs go to the journal:

```bash
sudo journalctl -u claude-memory -f
sudo journalctl -u claude-memory --since "1 hour ago"
```

### Monitoring Script Example

```bash
#!/bin/bash
HEALTH=$(curl -sf http://127.0.0.1:9077/api/v1/health | jq -r '.status')
if [ "$HEALTH" != "ok" ]; then
    echo "claude-memory health check failed"
    systemctl restart claude-memory
fi
```

## Scaling Considerations

`claude-memory` is designed for single-machine use. It is not a distributed system.

- **Concurrency**: The daemon uses `Arc<Mutex<Connection>>` -- one write at a time, but this is fine for a single-user tool. SQLite WAL mode allows concurrent reads.
- **Database size**: SQLite handles databases up to 281 TB. Practically, performance stays excellent up to millions of rows.
- **Memory usage**: Minimal. The daemon holds only the connection and a path in memory. All data is on disk.
- **Multiple instances**: You can run multiple daemons on different ports with different databases. Do not point two daemons at the same database file.

## Troubleshooting

### Daemon won't start

**Port already in use:**
```bash
ss -tlnp | grep 9077
# Kill the existing process or use a different port
claude-memory serve --port 9078
```

**Database locked:**
```bash
# Remove stale WAL files (only if daemon is not running)
rm -f claude-memory.db-wal claude-memory.db-shm
```

**Permission denied:**
```bash
# Check file permissions
ls -la /path/to/claude-memory.db
# Ensure the user running the daemon has read/write access
```

### Slow queries

If recall or search is slow:

```bash
# Rebuild the FTS index
sqlite3 /path/to/claude-memory.db "INSERT INTO memories_fts(memories_fts) VALUES('rebuild')"

# Compact the database
sqlite3 /path/to/claude-memory.db "VACUUM"
```

### FTS index corruption

Symptoms: search returns no results or errors.

```bash
# Check integrity
sqlite3 /path/to/claude-memory.db "INSERT INTO memories_fts(memories_fts) VALUES('integrity-check')"

# Rebuild if corrupt
sqlite3 /path/to/claude-memory.db "INSERT INTO memories_fts(memories_fts) VALUES('rebuild')"
```

### Database is growing too large

```bash
# Check what's taking space
claude-memory stats

# Delete expired memories
claude-memory gc

# Delete all short-term memories in a namespace
claude-memory forget --tier short --namespace my-app

# Compact after deletion
sqlite3 /path/to/claude-memory.db "VACUUM"
```

## Security

### Localhost Binding

By default, the daemon binds to `127.0.0.1` only. It is **not accessible from the network**. This is intentional -- `claude-memory` is a local-machine tool.

If you need to bind to a different address (not recommended):

```bash
claude-memory serve --host 0.0.0.0 --port 9077
```

### No Authentication

There is no authentication mechanism. This is by design -- the daemon is intended for localhost access only. If you expose it to a network, you are responsible for adding a reverse proxy with authentication.

### Data at Rest

The SQLite database is stored as a regular file. It is not encrypted. If you need encryption at rest, use filesystem-level encryption (LUKS, FileVault, BitLocker).

### WAL Files

SQLite WAL mode creates two additional files alongside the database:
- `claude-memory.db-wal` -- write-ahead log
- `claude-memory.db-shm` -- shared memory file

Both are cleaned up on graceful shutdown (the daemon runs `PRAGMA wal_checkpoint(TRUNCATE)` on SIGINT). If the daemon crashes, these files persist but are automatically recovered on next open.
