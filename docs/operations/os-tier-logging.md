---
layout: doc
---
# OS-tier logging (journald / unified log / Event Log)

> **Issue #1463 — Tier 1.** ai-memory's operational logs can be emitted as
> structured lines on **stdout** so the host's init system captures, rotates,
> retains, and forwards them with its *own* facilities. This is the
> highest-leverage, lowest-risk way to "log to an OS-tier system file" — zero
> extra dependencies, zero hot-path cost. **Tier 2** (#1765) adds an
> OS-agnostic, dependency-free native **remote `syslog`** sink (RFC 5424 over
> TCP, optional TLS) for shipping straight to a SIEM — see [Tier 2](#tier-2--native-remote-syslog-sink---features-syslog)
> below. (The Linux-only `journald` protocol sink was deliberately dropped as
> non-OS-agnostic; on Linux use Tier 1 `stdout` → `StandardOutput=journal`.)

## TL;DR

```toml
# ~/.config/ai-memory/config.toml
[logging]
enabled    = true       # master switch (default false)
sink       = "stdout"   # "file" (default) | "stdout"
structured = true       # JSON lines — recommended for OS/SIEM ingestion
level      = "info"
```

or, equivalently, by environment (highest precedence):

```bash
AI_MEMORY_LOG_SINK=stdout   # env > [logging].sink > compiled default "file"
```

When `sink = "stdout"`, ai-memory writes through the **same non-blocking
background worker** the file appender uses, so the `write(2)` to stdout never
happens on a `memory_store` / recall call site. The `[logging].path`,
`rotation`, `max_files`, `retention_days`, and `filename_prefix` knobs are
file-sink-only and are ignored under `stdout` — rotation/retention is now the
init system's job (below).

`enabled = false` (the default) silences operational logging entirely
regardless of `sink`. An unrecognized `sink` value falls back to `file` with a
one-shot WARN.

## Why this satisfies "use the pre-existing OS facilities"

Every major init system already captures a service's stdout and applies its own
structured-log storage, rotation, retention, and forwarding:

| OS | Captures service stdout into | Rotation / retention | Forwarding |
|----|------------------------------|----------------------|------------|
| Linux (systemd) | **systemd-journald** | `journald.conf` (`SystemMaxUse`, `MaxRetentionSec`) | `systemd-journal-upload`, rsyslog → SIEM |
| Linux (syslog) | rsyslog/syslog-ng via stdout→journal→syslog | `/etc/logrotate.d` | rsyslog `omfwd` (RFC 5424, TCP+TLS) |
| macOS (launchd) | **unified logging** / `StandardOutPath` | `log` subsystem retention | `log collect`, MDM log pipelines |
| Windows (service) | **Windows Event Log** (service stdout) / NSSM | Event Log retention policy | Windows Event Forwarding (WEF) |

ai-memory does not reimplement any of that — it just emits clean structured
lines and lets the platform own the lifecycle.

## Linux — systemd unit

`/etc/systemd/system/ai-memory.service`:

```ini
[Unit]
Description=ai-memory server
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ai-memory serve
Environment=AI_MEMORY_LOG_SINK=stdout
# Route stdout/stderr into the journal with structured fields:
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ai-memory
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now ai-memory
journalctl -u ai-memory -f                 # follow
journalctl -u ai-memory -o json-pretty     # structured fields
```

Rotation/retention is configured once, globally, in `journald.conf`
(`SystemMaxUse=`, `MaxRetentionSec=`) — not per-service.

### Syslog / SIEM forwarding

With logs in the journal, forward to a remote RFC 5424 collector via rsyslog's
`imjournal` + `omfwd` (TCP + TLS), e.g. `/etc/rsyslog.d/10-ai-memory.conf`:

```rsyslog
module(load="imjournal")
action(type="omfwd" target="siem.example" port="6514"
       protocol="tcp" StreamDriver="gtls" StreamDriverMode="1")
```

## macOS — launchd plist

`~/Library/LaunchAgents/co.alphaone.ai-memory.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>co.alphaone.ai-memory</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/ai-memory</string>
    <string>serve</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>AI_MEMORY_LOG_SINK</key><string>stdout</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <!-- launchd captures stdout into the unified log; or pin a file: -->
  <key>StandardOutPath</key><string>/usr/local/var/log/ai-memory.out.log</string>
  <key>StandardErrorPath</key><string>/usr/local/var/log/ai-memory.err.log</string>
</dict>
</plist>
```

```bash
launchctl load ~/Library/LaunchAgents/co.alphaone.ai-memory.plist
log stream --predicate 'process == "ai-memory"' --style json   # unified log
```

## Windows — service stdout → Event Log

Windows services don't capture stdout by default; use a service shim such as
**NSSM** (or `sc.exe` with a wrapper) to redirect ai-memory's stdout into the
Event Log / a managed file that Windows Event Forwarding can collect.

```powershell
nssm install ai-memory "C:\Program Files\ai-memory\ai-memory.exe" serve
nssm set ai-memory AppEnvironmentExtra AI_MEMORY_LOG_SINK=stdout
# Route captured stdout to a rotating file NSSM manages, or to the Event Log:
nssm set ai-memory AppStdout C:\ProgramData\ai-memory\logs\ai-memory.log
nssm set ai-memory AppStdoutCreationDisposition 4   # rotate
nssm start ai-memory
```

Configure **Windows Event Forwarding (WEF)** with a subscription to ship these
events to a central collector.

## Tier 2 — native remote `syslog` sink (`--features syslog`)

> **Issue #1765 — Tier 2.** When you'd rather ship logs **directly** to a remote
> RFC 5424 collector / SIEM than route them through the host init system (Tier 1
> above), build with `--features syslog` and select `sink = "syslog"`. This sink
> is **OS-agnostic** — pure network I/O (RFC 5424 over TCP, optional rustls TLS
> per RFC 5425), so it behaves identically on Linux, macOS, Windows, and mobile —
> and **dependency-free** (it reuses the rustls + chrono deps already in the
> tree). The Linux-only `journald` protocol sink was intentionally **not** added;
> it cannot be OS-agnostic, and Linux operators already reach journald via Tier 1
> (`stdout` → `StandardOutput=journal`).

```toml
[logging]
enabled            = true
sink               = "syslog"
structured         = true                              # JSON in the RFC 5424 MSG
level              = "info"
syslog_address     = "logs.example.com:6514"           # host:port (REQUIRED)
syslog_transport   = "tls"                             # "tls" (default) | "tcp"
syslog_tls_ca_file = "/etc/ai-memory/collector-ca.pem" # PEM CA (REQUIRED for tls)
# syslog_app_name  = "ai-memory"                        # RFC 5424 APP-NAME (default)
```

Environment equivalents (highest precedence): `AI_MEMORY_LOG_SINK=syslog`,
`AI_MEMORY_LOG_SYSLOG_ADDRESS`, `AI_MEMORY_LOG_SYSLOG_TRANSPORT`,
`AI_MEMORY_LOG_SYSLOG_TLS_CA_FILE`.

**Wire format.** Each event becomes one RFC 5424 record —
`<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID - - <BOM>MSG` — framed with RFC 6587
octet-counting (`MSG-LEN SP RECORD`) so newlines embedded in the MSG cannot
corrupt the stream. `PRI` is `local0` (16) × 8 + severity, and severity is mapped
**per event** from the tracing level (ERROR→3, WARN→4, INFO→6, DEBUG/TRACE→7) so
a collector can route/alert on syslog severity. With `structured = true` the MSG
body is a JSON object.

**Transport & TLS.** `tls` (the default; RFC 5425, conventionally port 6514) is
the norm for any routable collector: the server certificate is verified against
the operator-supplied CA in `syslog_tls_ca_file` (the trust anchor — no
public-roots dependency and no certificate-verification bypass). `tcp` is
plaintext and is intended **only** for a trusted loopback / sidecar forwarder
(e.g. a local rsyslog / Vector / Fluent Bit agent) — there is no silent plaintext
path to a remote host, because `tls` requires the CA file.

**Failure posture.**

- *Configured but not compiled:* selecting `sink = "syslog"` in a binary built
  **without** `--features syslog` **fails closed at boot** (a clear "requires
  `--features syslog`" error) — unlike Tier 1's warn-and-fallback for an
  unrecognized value, because the operator explicitly opted into off-host
  shipping and a silent fallback to a local file would be a confidentiality
  surprise.
- *Collector unreachable at runtime:* **lossy, never blocking** — the sink shares
  the file/stdout non-blocking worker, connects with a bounded timeout, and on
  failure drops the record and reconnects on the next event. A down / slow /
  attacker-reachable collector can never stall a `memory_store` / recall path or
  daemon shutdown.
- *Zero-cost when off:* the entire syslog writer is `#[cfg(feature = "syslog")]`,
  so default / mobile / `sal` builds are byte-identical to a build without it.

**vs Tier 1 (`stdout` → init system).** Tier 1 is zero-config, zero-dep, and lets
each OS own rotation / retention / forwarding. Reach for Tier 2 when you want
ai-memory to ship structured records straight to a central SIEM without an
intermediary agent — on any OS, including platforms with no syslog daemon (e.g.
Windows).

## Logging policy & archival guidance

- **Pick one owner of the log lifecycle.** With `sink = "stdout"`, the init
  system owns rotation/retention/forwarding — do **not** also enable the file
  sink for the same process. With `sink = "file"` (default), ai-memory's
  rolling appender owns it (`rotation`, `max_files`, `retention_days`).
- **Operational logs are not the audit trail.** The tamper-evident signed
  audit chain (`[audit]`, `AI_MEMORY_AUDIT_DIR`) remains the source of truth for
  security/forensic events; OS-tier sinks carry *operational* info/warn/error
  only. See [`docs/security/audit-trail.md`](../security/audit-trail.md).
- **Use `structured = true` for any OS/SIEM ingestion** so fields are parsed,
  not regex-scraped.
- **Performance:** the stdout sink shares the file sink's non-blocking,
  lossy-by-default worker — a slow/full journald or collector can never stall a
  write path, and with `sink` left at `file` (or `enabled = false`) the stdout
  path is never constructed (zero allocation, zero syscall, zero added hot-path
  branch).
