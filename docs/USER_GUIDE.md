# User Guide

## What Is This and Why Do I Need It?

`claude-memory` gives Claude Code persistent memory across sessions. Without it, every conversation starts from zero. With it, Claude can:

- Remember your project architecture, preferences, and past decisions
- Recall debugging context from yesterday
- Build up institutional knowledge over time
- Never repeat the same mistakes twice

Think of it as a brain for your AI assistant -- short-term for what you're doing right now, mid-term for this week's work, and long-term for things that should never be forgotten.

## Getting Started

### Store Your First Memory

```bash
claude-memory store \
  -T "Project uses PostgreSQL 15" \
  -c "The main database is PostgreSQL 15 with pgvector for embeddings." \
  --tier long \
  --priority 7
```

That's it. The memory is now stored permanently (long tier) with priority 7/10.

### Recall Memories

```bash
claude-memory recall "database setup"
```

This performs a fuzzy OR search across all your memories and returns the most relevant ones, ranked by a composite score of text relevance, priority, access frequency, confidence, and tier.

### Search for Exact Matches

```bash
claude-memory search "PostgreSQL"
```

Search uses AND semantics -- all terms must match. Use this when you know exactly what you're looking for.

## Memory Tiers Explained

| Tier | TTL | Use Case | Example |
|------|-----|----------|---------|
| **short** | 6 hours | What you're doing right now | "Currently debugging auth flow in login.rs" |
| **mid** | 7 days | This week's working knowledge | "Sprint goal: migrate to new API v2" |
| **long** | Forever | Permanent knowledge | "User prefers tabs over spaces" |

### Automatic Behaviors

- **TTL extension**: Every time a memory is recalled, its expiry extends (1 hour for short, 1 day for mid)
- **Auto-promotion**: A mid-tier memory recalled 5+ times automatically becomes long-term
- **Priority reinforcement**: Every 10 accesses, a memory's priority increases by 1 (max 10)
- **Garbage collection**: Expired memories are cleaned up every 30 minutes

## Namespaces

Namespaces isolate memories per project. If you omit `--namespace`, it auto-detects from the git remote URL or the current directory name.

```bash
# These are equivalent when run inside a git repo named "my-app":
claude-memory store -T "API uses REST" -c "..." --namespace my-app
claude-memory store -T "API uses REST" -c "..."  # auto-detects "my-app"
```

List all namespaces:

```bash
claude-memory namespaces
```

Filter recall or search to a specific namespace:

```bash
claude-memory recall "auth flow" --namespace my-app
```

## Common Workflows

### Start of Session

Recall context relevant to what you're about to work on:

```bash
claude-memory recall "auth module refactor" --namespace my-app --limit 5
```

### Learning Something New

When you discover something important during a session:

```bash
claude-memory store \
  -T "Rate limiter uses token bucket" \
  -c "The rate limiter in middleware.rs uses a token bucket algorithm with 100 req/min default." \
  --tier mid --priority 6
```

### User Correction

When the user corrects you, store it as high-priority long-term:

```bash
claude-memory store \
  -T "User correction: always use snake_case for API fields" \
  -c "The user prefers snake_case for all JSON API response fields, not camelCase." \
  --tier long --priority 9 --source user
```

### Consolidating Knowledge

After a week of scattered mid-term memories about a topic, consolidate them:

```bash
claude-memory consolidate "id1,id2,id3" \
  -T "Auth system architecture" \
  -s "JWT tokens with refresh rotation, RBAC via middleware, sessions in Redis."
```

### Promoting a Memory

If a mid-tier memory turns out to be permanently valuable:

```bash
claude-memory promote <memory-id>
```

### Bulk Cleanup

Delete all short-term memories in a namespace:

```bash
claude-memory forget --namespace my-app --tier short
```

Delete memories matching a pattern:

```bash
claude-memory forget --pattern "deprecated API"
```

### Export and Backup

```bash
claude-memory export > memories-backup.json
```

Restore:

```bash
claude-memory import < memories-backup.json
```

## Priority Guide

| Priority | When to Use |
|----------|-------------|
| 1-3 | Low-value context, temporary notes |
| 4-6 | Standard working knowledge (default is 5) |
| 7-8 | Important architecture decisions, user preferences |
| 9-10 | Critical corrections, hard-won lessons, "never forget this" |

## Confidence

Confidence (0.0 to 1.0) indicates how certain a memory is. Default is 1.0. Lower confidence for things that might change:

```bash
claude-memory store \
  -T "API might switch to GraphQL" \
  -c "Team is evaluating GraphQL migration." \
  --confidence 0.5
```

Confidence is factored into recall scoring -- higher confidence memories rank higher.

## Tags

Tag memories for filtered retrieval:

```bash
claude-memory store -T "Deploy process" -c "..." --tags "devops,ci,deploy"
claude-memory recall "deployment" --tags "devops"
```

## FAQ

**Q: Where is the database stored?**
A: By default, `claude-memory.db` in the current directory. Override with `--db /path/to/db` or the `CLAUDE_MEMORY_DB` environment variable.

**Q: Do I need to run the daemon?**
A: No. The CLI commands work directly against the SQLite database. The daemon is for HTTP API access and automatic background garbage collection.

**Q: What happens if I store a memory with a title that already exists in the same namespace?**
A: It upserts -- the content is updated, the priority takes the higher value, and the tier never downgrades (a long memory stays long).

**Q: How big can a memory be?**
A: Content is limited to 65,536 bytes (64 KB).

**Q: Can I use this with tools other than Claude Code?**
A: Yes. The HTTP API at `http://127.0.0.1:9077/api/v1/` is language-agnostic. Any tool that can make HTTP requests can store and recall memories.
