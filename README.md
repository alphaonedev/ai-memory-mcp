```
      _                 _
  ___| | __ _ _   _  __| | ___       _ __ ___   ___ _ __ ___   ___  _ __ _   _
 / __| |/ _` | | | |/ _` |/ _ \___  | '_ ` _ \ / _ \ '_ ` _ \ / _ \| '__| | | |
| (__| | (_| | |_| | (_| |  __/___| | | | | | |  __/ | | | | | (_) | |  | |_| |
 \___|_|\__,_|\__,_|\__,_|\___|     |_| |_| |_|\___|_| |_| |_|\___/|_|   \__, |
                                                                          |___/
```

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![SQLite](https://img.shields.io/badge/sqlite-FTS5-003B57?logo=sqlite)](https://www.sqlite.org/)

**Persistent memory for Claude Code** -- short, mid, and long-term recall backed by SQLite + FTS5.

---

## What Is This?

`claude-memory` is a Rust daemon that gives Claude Code a real memory system. It stores knowledge in three tiers (short/mid/long), ranks recall by relevance + priority + access frequency, and auto-promotes frequently accessed memories to permanent storage. It exposes both an HTTP API and a CLI.

## Features

- **Three-tier memory** -- short (6h TTL), mid (7d TTL), long (permanent)
- **Full-text search** -- SQLite FTS5 with ranked retrieval
- **Smart recall** -- composite scoring: FTS relevance + priority + access frequency + confidence + tier boost
- **Auto-promotion** -- memories accessed 5+ times automatically promote from mid to long
- **TTL extension** -- each access extends expiry (1h for short, 1d for mid)
- **Contradiction detection** -- warns when storing memories that conflict with existing ones
- **Namespaces** -- isolate memories per project (auto-detected from git remote)
- **Memory linking** -- connect related memories with typed relations
- **Consolidation** -- merge multiple memories into a single long-term summary
- **Import/Export** -- full JSON backup and restore
- **Garbage collection** -- automatic background expiry every 30 minutes
- **Dual interface** -- HTTP API (port 9077) and CLI with identical capabilities
- **Zero config** -- works out of the box, single binary, no external dependencies

## Architecture

```
                        +---------------------+
                        |    Claude Code       |
                        |  (or any client)     |
                        +----------+----------+
                                   |
                    +--------------+--------------+
                    |                              |
              +-----v-----+              +--------v--------+
              |    CLI     |              |   HTTP API      |
              | claude-    |              |  127.0.0.1:9077 |
              | memory     |              |  /api/v1/*      |
              +-----+------+              +--------+--------+
                    |                              |
                    +--------------+---------------+
                                   |
                         +---------v---------+
                         |   SQLite + FTS5   |
                         |   WAL mode        |
                         +---+-----+-----+---+
                             |     |     |
                        +----+  +--+--+  +----+
                        |short| | mid | | long|
                        |6h   | | 7d  | | inf |
                        +-----+ +-----+ +-----+
                             |     ^
                             |     | auto-promote
                             +-----+ (5+ accesses)
```

## Quick Start

```bash
# 1. Build and install
cargo install --path .

# 2. Start the daemon
claude-memory serve &

# 3. Store your first memory
claude-memory store -T "Project uses Rust 2021 edition" \
  -c "The claude-memory project targets Rust edition 2021 with Axum for HTTP." \
  --tier long --priority 7
```

## Recall Scoring Formula

```
score = (fts_relevance * -1)
      + (priority * 0.5)
      + (access_count * 0.1)
      + (confidence * 2.0)
      + tier_boost          -- long=3.0, mid=1.0, short=0.0
```

## Documentation

| Guide | Audience |
|-------|----------|
| [Installation Guide](docs/INSTALL.md) | Getting it running |
| [User Guide](docs/USER_GUIDE.md) | Claude Code users who want memory to work |
| [Developer Guide](docs/DEVELOPER_GUIDE.md) | Building on or contributing to claude-memory |
| [Admin Guide](docs/ADMIN_GUIDE.md) | Deploying, monitoring, and troubleshooting |
| [GitHub Pages](https://alphaonedev.github.io/claude-memory/) | Visual overview with animated diagrams |

## License

MIT
