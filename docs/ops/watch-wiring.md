---
layout: doc
---

# Watch line-file daemon — operator wiring (#3587 U6 PREP)

Templates for running `ai-memory watch --daemon` against swarm
**line files** (inbox + outbox). This page does **not** activate the
daemons. Substitution, install, and enable stay with the Conductor.

Capture contract (path safety, per-file dedup, `observed_actor`,
tags): [`anti-drift.md`](../anti-drift.html). Flag table:
[`CLI_REFERENCE.md`](../CLI_REFERENCE.html) § `watch`.

| Host | Unit | Install path (after substitution) |
|---|---|---|
| Linux (f2) | [`ai-memory-watch.service`](ai-memory-watch.service) (systemd **user** unit) | `~/.config/systemd/user/ai-memory-watch.service` |
| macOS (f1) | [`co.alphaone.ai-memory-watch.plist`](co.alphaone.ai-memory-watch.plist) (launchd agent) | `~/Library/LaunchAgents/co.alphaone.ai-memory-watch.plist` |

These are **not** the distro system units under `packaging/systemd/`.
They are session-scoped swarm-capture templates.

## Placeholders

Every angle-bracket token must be substituted before the file is
installed. Tracked copies keep the tokens. Never paste real host
paths, principal ids, or store URLs into the repository.

| Token | Meaning |
|---|---|
| `<binary>` | Absolute path to the `ai-memory` executable |
| `<principal>` | Hardened agent id for this process |
| `<db-path>` | Sqlite file the CLI `--db` flag names |
| `<db-dir>` | Directory of that sqlite file (systemd `ReadWritePaths` only) |
| `<inbox>` | Absolute path of the inbox line file |
| `<outbox>` | Absolute path of the outbox line file |
| `<home>` | Launching user's home (launchd log paths only) |
| `<store-url-file>` | Optional `0600` file whose contents are the store URL (postgres hive) |

Both hosts use the same argv shape:

```bash
<binary> --agent-id <principal> --db <db-path> watch --daemon \
  --host file:<inbox> --host file:<outbox>
```

`--agent-id` is the global CLI flag (also accepted after `watch`).
`AI_MEMORY_AGENT_ID=<principal>` is the env twin; keep them equal.

## Two stores, two truth sets

Capture is per database. The two hosts do **not** share a corpus:

- **f2** (Conductor) — line-file watch plus the Conductor MCP server
  write into the f2 store. Conductor rulings live here.
- **f1** (deputies) — line-file watch into the f1 hive. Deputy
  READY / STATUS / BLOCKER / ACK / NOTE lines live here.

A line captured on one store does not supersede a ruling on the
other. Supersession, when it lands, is per store. Wiring both
daemons to the same file set does not merge the truth sets.

f1 postgres hive: use a binary built with `--features sal` (and
`sal-postgres` when the store is postgres) and set
`AI_MEMORY_STORE_URL_FILE=<store-url-file>` (mode `0600`). Never put a
DSN on argv (`--store-url` is world-readable in `ps`). Default
(non-`sal`) builds `refuse_pg_store` and fail closed.

## Conductor MCP server — `AI_MEMORY_AGENT_ID`

The watch daemon's `--agent-id` / `AI_MEMORY_AGENT_ID` stamps
`metadata.agent_id` on **captured lines**. It does not stamp the
Conductor's own `memory_store` calls.

Set `AI_MEMORY_AGENT_ID=<principal>` on the Conductor MCP **server
entry** (the process that serves `memory_store`) so those writes
carry a hardened principal. Use the same `<principal>` the f2 watch
unit uses. File bytes never become the owner — a line that says
`MASTER → …` is untrusted `observed_actor` only.

This PREP documents that env; it does not edit the MCP server
config.

## WAL and bounded retry

`watch --daemon` is a poll loop (default 5 s, clamped `[1, 3600]`).
Sqlite opens in WAL mode. Per-source in-memory `(dev, ino, len, offset)`
is the change detector only; idempotency is `transcript_line_dedup`
(restart / rotation / truncation safe).

A tick that returns embedded per-turn errors is retried on the same
delta up to `WATCH_RECOVERY_MAX_RETRIES` (3) times, then the watermark
advances so a poison line cannot busy-loop. `--dry-run` never arms
retry state and writes nothing.

`--features fs-notify`: each line-file watches its **parent
directory**; poll is the fallback when that directory is unwatchable.

## Logs to watch

Human `--once` report fields (also on the JSON `WatchReport`):

- `changes_detected`
- `memories_captured`
- `errors_total` in the human report; the JSON `WatchReport` field is `errors` (includes recover errors embedded in an otherwise-Ok tick)

systemd user unit: `journalctl --user -u ai-memory-watch.service -f`

launchd: `<home>/Library/Logs/ai-memory-watch.out` and
`<home>/Library/Logs/ai-memory-watch.err`

## Verification checklist (before enable)

Do this on a substituted copy, **before** `enable --now` / `bootstrap`.

1. Confirm every `<…>` token in the unit/plist is gone.
2. Confirm `<inbox>` and `<outbox>` are regular files, same uid as
   the watch process, no symlink component (U2 path safety).
3. Dry-run one tick — **no writes, no retry arm**:

   ```bash
   <binary> --agent-id <principal> --db <db-path> \
     watch --once --dry-run \
     --host file:<inbox> --host file:<outbox>
   ```

   Expect `ticks: 1`, `memories_captured: 0`, `errors_total: 0` (or
   an explained per-host error). A missing file is not an error
   (`Ok(None)` so the daemon can start before the outbox exists).
4. Optional: repeat `--once` without `--dry-run` against a throwaway
   `<db-path>`, never against a live operator store.
5. Only then install and enable (below).

## Install / enable / disable

### Linux — systemd user unit (f2)

```bash
mkdir -p ~/.config/systemd/user
# copy the substituted unit onto:
#   ~/.config/systemd/user/ai-memory-watch.service
systemctl --user daemon-reload
systemctl --user enable --now ai-memory-watch.service
systemctl --user status ai-memory-watch.service
```

Headless reboot survival: `loginctl enable-linger` for that user so
the user systemd instance runs without a login session.

Disable:

```bash
systemctl --user disable --now ai-memory-watch.service
```

Hardening in the template (do not drop on substitution):
`Restart=on-failure`, `NoNewPrivileges=yes`, `ProtectSystem=strict`,
`ReadWritePaths=<db-dir>` only, `PrivateTmp=yes`, `UMask=0077`.

### macOS — launchd agent (f1)

```bash
mkdir -p ~/Library/LaunchAgents ~/Library/Logs
# copy the substituted plist onto:
#   ~/Library/LaunchAgents/co.alphaone.ai-memory-watch.plist
launchctl bootstrap "gui/$(id -u)" \
  ~/Library/LaunchAgents/co.alphaone.ai-memory-watch.plist
launchctl print "gui/$(id -u)/co.alphaone.ai-memory-watch" \
  | grep -E '(state|pid) ='
```

`KeepAlive` is crash-restart (`Crashed=true`, `SuccessfulExit=false`)
so a clean `bootout` does not loop. `Umask` is `63` (octal `077`).
Stdout/stderr go under `<home>/Library/Logs/`.

Disable:

```bash
launchctl bootout "gui/$(id -u)/co.alphaone.ai-memory-watch"
```

## Out of scope (not this PREP)

- Enabling the units on a live host
- `install claude-code --hook capture` (U4)
- `watch --host claude-code` transcript capture
- Curator `--stale-rulings` (U3)
- Store supersession / `ruling_key` (U1)
- Distro `packaging/systemd/` system units
