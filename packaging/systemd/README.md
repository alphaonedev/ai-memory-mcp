# ai-memory systemd units

Drop-in systemd units for operators running ai-memory as a hardened
single-node deployment. The Debian (.deb), release RPM and Fedora COPR
recipes are binary-only: install the users, state directories and units
manually using the steps below before enabling services. The AUR package
ships `ai-memory.service` and the sysusers fragment only (PKGBUILD:58-70); the
other units are installed manually from this directory. These units also work standalone
on any systemd distro.

## Units

| File | Purpose | Type |
|------|---------|------|
| `ai-memory.service` | Main daemon (HTTP + MCP) | `simple` |
| `ai-memory-sync.service` | Peer-mesh sync daemon (optional) | `simple` |
| `ai-memory-curator.service` | Autonomous curator daemon (optional) | `simple` |
| `ai-memory-backup.service` | One-shot snapshot via `VACUUM INTO` | `oneshot` |
| `ai-memory-backup.timer` | Hourly backup trigger | `timer` |
| `ai-memory-wake-hub.service` | Content-free wake plane (`User=ai-memory-hub`) | `simple` |
| `ai-memory-wake-hub-refresh.service` | Derive+install the hub allowlist snapshot | `oneshot` |
| `ai-memory-wake-hub-refresh.timer` | 30 s refresh of that snapshot | `timer` |
| `ai-memory.sysusers.conf` | Creates `ai-memory` + `ai-memory-hub` via systemd-sysusers | `sysusers` |

## Install — manual

```sh
# 1. System users + state dir. Required for binary-only deb/rpm installs.
#    The AUR PKGBUILD installs /usr/lib/sysusers.d/ai-memory.conf; for
#    manual installation, create both service users from the source fragment:
sudo systemd-sysusers packaging/systemd/ai-memory.sysusers.conf
# Fallback if systemd-sysusers is unavailable:
# sudo useradd --system --home /var/lib/ai-memory --shell /usr/sbin/nologin ai-memory
# sudo useradd --system --home /run/ai-memory-hub --shell /usr/sbin/nologin ai-memory-hub
sudo install -d -o ai-memory -g ai-memory -m 0750 /var/lib/ai-memory
sudo install -d -o ai-memory -g ai-memory -m 0750 /var/lib/ai-memory/backups

# 2. Units into /etc/systemd/system. The .deb and .rpm packages ship no units.
sudo install -m 0644 packaging/systemd/*.service /etc/systemd/system/
sudo install -m 0644 packaging/systemd/*.timer   /etc/systemd/system/

# 3. Reload + enable.
sudo systemctl daemon-reload
sudo systemctl enable --now ai-memory.service
sudo systemctl enable --now ai-memory-backup.timer
```

## Sync daemon — optional

The `ai-memory-sync.service` is disabled by default. Configure peers via
`/etc/ai-memory/sync.env`:

```sh
PEERS=https://peer-a.example:9077,https://peer-b.example:9077
# For mTLS, add --client-cert / --client-key / --mtls-allowlist:
EXTRA_ARGS=--client-cert /etc/ai-memory/tls/client.pem --client-key /etc/ai-memory/tls/client.key
```

Then:

```sh
sudo systemctl enable --now ai-memory-sync.service
```

## Hardening

All units ship with maximally restrictive systemd sandboxing:

- No new privileges
- Strict filesystem — read-only system, only `/var/lib/ai-memory` writable
- No access to `/home`, `/tmp` (private), `/dev` (private)
- No kernel tunables, modules, logs, cgroups
- Address families restricted to `AF_UNIX AF_INET AF_INET6`
- `SystemCallFilter=@system-service` with `@mount @swap @reboot @obsolete` denied
- Capability bounding set empty
- Memory Deny Write Execute (no JIT)

Review `systemd-analyze security ai-memory.service` to verify exposure level.
Ship-default target: "OK" or better (score <5.0).

## Resource caps

Default caps are tuned for a single-node operator running a modest
load. Override via a drop-in at
`/etc/systemd/system/ai-memory.service.d/override.conf`:

```ini
[Service]
MemoryMax=8G
TasksMax=2048
LimitNOFILE=131072
```

Do not weaken hardening directives without understanding the tradeoff —
if an exploit lands in a crate deep in the dep tree, these are the walls
that keep it from pivoting.

## Upgrading the binary

The deb / rpm / COPR packages and `install.sh` replace `/usr/bin/ai-memory`
in place and restart nothing. The running daemon keeps executing the OLD
binary. `ai-memory-curator.service` and `ai-memory-sync.service` open the
live database through the migrating opener, so a companion that restarted
before the primary (a crash, an OOM-kill, a `systemctl restart` of that unit
alone) would run the NEW binary's migration ladder on the live database
under the still-running OLDER daemon — the schema-ahead state the daemon
refuses (#2445; this route is #4326). The backup job is immune: it opens the
database through the unmigrated egress funnel and never migrates (#4207).

Both companion units carry `PartOf=ai-memory.service`, so restarting the
primary restarts them with it. After replacing the binary, restart the
primary FIRST and nothing else:

```sh
sudo systemctl restart ai-memory.service      # PartOf= restarts curator + sync too
systemctl status ai-memory ai-memory-curator ai-memory-sync
```

Do not restart `ai-memory-curator.service` or `ai-memory-sync.service` on
their own while the primary still runs the previous binary.

## Troubleshooting

```sh
# Runtime status
systemctl status ai-memory
journalctl -u ai-memory -n 200 -f

# Sandboxing review
systemd-analyze security ai-memory.service
systemd-analyze verify /etc/systemd/system/ai-memory.service

# Backup verification
ls -la /var/lib/ai-memory/backups
sudo -u ai-memory /usr/bin/ai-memory backup list --to /var/lib/ai-memory/backups
```

## License

Apache-2.0. See `../../LICENSE`.
