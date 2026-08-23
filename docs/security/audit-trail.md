---
layout: doc
---
# ai-memory enterprise audit trail

PR-5 of issue [#487](https://github.com/alphaonedev/ai-memory-mcp/issues/487).
A turnkey, enterprise-class security audit trail and operational
logging facility for AI memory activity across every AI agent that
talks to ai-memory.

This is the **operator** doc: how to turn it on, what it does, how to
ship the lines into your SIEM, and how the regulatory mappings line
up. The **developer** schema reference lives in
[`audit-schema.md`](./audit-schema.html).

---

## At a glance

| Subsystem | Default | Purpose |
|---|---|---|
| Operational logs (`tracing::*` → file) | OFF | Capture every `tracing::info!` / `tracing::warn!` / `tracing::error!` to a rotating on-disk file. Suitable for Splunk / Datadog / Elastic / Loki ingestion. |
| Security audit trail | OFF | One hash-chained, tamper-evident JSON line per memory mutation. SIEM-grade evidence for SOC2 / HIPAA / GDPR / FedRAMP. |

Both are **default-OFF for privacy.** No log lines hit the disk
without a deliberate config opt-in.

---

## Quickstart

```toml
# ~/.config/ai-memory/config.toml

[logging]
enabled = true
path = "~/.local/state/ai-memory/logs/"
max_files = 30
retention_days = 90
structured = true                 # JSON lines for SIEM ingest
level = "info"

[audit]
enabled = true
path = "~/.local/state/ai-memory/audit/"
schema_version = 1
redact_content = true
hash_chain = true                 # mandatory; an explicit `false` REFUSES boot
attestation_cadence_minutes = 60  # RESERVED — parsed, resolved, drives nothing
append_only = true

[audit.compliance.soc2]
applied = true
retention_days = 730
attestation_cadence_minutes = 60  # RESERVED — see below
```

> **`attestation_cadence_minutes` is RESERVED, not implemented.** The knob
> parses and resolves (including the compliance-preset overrides), but the
> periodic `CHECKPOINT.sig` attestation marker it would drive **does not
> exist**: `src/audit.rs` states it "is **NOT** yet implemented: no emission
> code exists and `effective_attestation_cadence_minutes` … has no production
> consumer." An audit-enabled daemon emits a one-shot operator WARN
> (`target: audit.attestation`) saying exactly that. Do not cite this knob as
> an anti-truncation or continuous-monitoring control. `retention_days` **is**
> live (`AuditConfig::effective_retention_days`, consumed by
> `ai-memory logs purge`).
>
> `hash_chain = false` is refused outright at init rather than silently
> ignored — the cross-row chain is mandatory and cannot be disabled.

Restart the daemon (or any new CLI invocation picks up the new
config). Verify:

```bash
ai-memory audit path                    # prints resolved log path
ai-memory store --title 'hello' --content 'world'
ai-memory audit tail --lines 5          # shows the store event
ai-memory audit verify                  # exits 0 on intact chain
```

---

## What gets audited

The wire `action` vocabulary is the `AuditAction` enum in `src/audit.rs` —
**14 values**, exactly these strings and no others. A SIEM parser should be
built against this set:

| Wire value | Meaning | Emitted today? |
|---|---|---|
| `store` | new memory written | yes |
| `update` | existing memory modified | yes |
| `delete` | memory deleted / tombstoned | yes |
| `recall` | read access — **one event per query**, target `"*"` for list-style ops | yes |
| `link` | typed link written | yes |
| `promote` | tier promotion | yes |
| `forget` | explicit forget | yes |
| `consolidate` | consolidation | yes |
| `export` | bulk export | **no producer at v1.0.0 — reserved** |
| `import` | bulk import | **no producer at v1.0.0 — reserved** |
| `approve` | governance approval | yes |
| `reject` | governance rejection | yes |
| `session_boot` | `ai-memory boot` invocation (an agent's first turn) | yes |
| `capture_lag` | L1 capture-nag: an agent crossed the consecutive-non-capture-tool-call threshold without a write (#1389 / #1398). Informational, `outcome = allow` | yes |

Three corrections a SIEM integrator needs, stated plainly:

- **There is no `search`, `list`, or `get` action.** The `memory_search`,
  `memory_list`, `memory_get`, `memory_recall` and `memory_session_start` MCP
  tools all emit `recall`. A parser keyed on `search` / `list` / `get` will
  match nothing.
- **`capture_lag` is on the wire and was previously undocumented.** A parser
  built against the older 13-value list meets it and fails to classify it.
- **`export` and `import` are enum variants with no production emission site
  at v1.0.0.** They are reserved; a bulk export or import produces no audit
  line today.

**Emission surfaces, honestly.** Read-access (`recall`) events come from the
**MCP stdio dispatch layer only** (`src/mcp/mod.rs`) — the HTTP read routes
(`GET /api/v1/memories`, `/memories/search`, `/recall`, `GET /memories/{id}`)
emit **no** line to this file. HTTP emits `store`, `delete`, `link`,
`approve`, `reject` (and the federation receive path emits `store`); the CLI
emits `store`, `update`, `delete`, and `session_boot`. The in-DB `signed_events`
chain has its own, differently-scoped read coverage and its own honest gap
statement — see [`audit-trail-coverage.md`](./audit-trail-coverage.html).

Each event captures:

- **Who.** Resolved NHI agent_id + synthesis source (`mcp_client_info`, `http_header`, `host_fallback`, …) so a SIEM can trace claims back to the transport.
- **What.** Action + outcome (`allow | deny | error | pending`).
- **Where.** Memory id (or `*`), namespace, title (advisory label only — **never content**), tier, scope.
- **How.** Auth context for HTTP-originated events (peer IP, mTLS fingerprint, hashed API key id). Stdio (CLI / MCP) emissions omit auth entirely.
- **When.** RFC3339 UTC timestamp + per-process monotonic sequence number.
- **Tamper-evidence.** `prev_hash` + `self_hash` form a sha256 chain; verify with `ai-memory audit verify`.

## What is NEVER audited

- `memory.content` (the secret payload). The schema has no content
  field. `redact_content = true` is the only supported v1 mode.
- Raw API keys, raw mTLS private keys, raw passwords.
- Free-form caller-supplied strings outside the documented fields.

---

## Threat model

| Adversary | Defense |
|---|---|
| Local attacker edits one line | `self_hash` recomputation fails on `audit verify`; precise line number surfaces |
| Local attacker inserts a forged line | The next line's `prev_hash` no longer matches the inserted line's `self_hash` |
| Local attacker deletes one line | The line after the deletion has a `prev_hash` from a now-gone source line |
| Local attacker truncates the tail of `audit.log` | **Not detected by this file's chain.** Truncation leaves the surviving prefix internally consistent, so `audit verify` reports OK. There is no `CHECKPOINT.sig` marker: it is **RESERVED and not implemented** (`src/audit.rs` — "no emission code exists"), and the daemon says so in a one-shot WARN. The control for this threat is **real-time off-host shipping** to an immutable SIEM (row below); the SIEM's copy is what bounds how much tail can be silently discarded. The substrate's separate in-DB `signed_events` chain has its own, implemented anti-truncation anchor — next two rows. |
| Root attacker rewrites the entire file | **Not defended.** Ship the lines off-host to an immutable SIEM in real time. The on-host chain still cross-checks the SIEM record. |
| Attacker truncates the tail of the in-DB `signed_events` chain | **Detected** (#1850). `ai-memory verify-audit-trail` compares the surviving `MAX(sequence)` against the head sequence recorded in the off-table forensic watermark; an in-DB head below the anchored head is `TruncationCheck::Detected` (dirty, non-zero exit). With no anchor enrolled the verdict **withholds** (`Unknown`) rather than emitting a false all-clear. |
| Attacker rewrites the whole `signed_events` suffix at the **same length** (recomputed `prev_hash`, equal row count — the chain walk and the sequence-only checks read clean) | **Detected** (#1873 / #2202). The verifier recomputes `SHA-256(canonical_chain_bytes(row))` of the surviving row **at the anchored sequence** and compares it against the watermark's `head_canonical_hash` / the K1-pinned, signature-verified witness dual-head hash whenever `anchored_seq <= db_head` → `HeadHashCheck::Mismatch` (dirty). **Residual, by design:** `canonical_chain_bytes` deliberately excludes `prev_hash`, so the anchor binds only the **anchored row** — an interior / mid-suffix rewrite **below** it that leaves that row's own columns intact, and a rewrite of the up-to-63 (`WATERMARK_INTERVAL` − 1) un-anchored rows **above** the last watermark, are **NOT** caught by the in-DB verdicts. `AI_MEMORY_LOG_SINK=syslog` off-host shipping (or a future rolling/accumulator hash committing the whole prefix) is the residual-closing control. |
| Process crashes mid-write | A short or interrupted write can leave a malformed final JSONL record; `audit verify` reports the malformed/broken chain. `O_APPEND` prevents file-offset races but does not make an arbitrarily sized JSON line atomic. Use one writer process per audit file; separate processes are not chain-serialized. |
| Attacker rolls back the whole DB **file** to an earlier snapshot | **[#1946 A1, v1.0.0]** Detected at the next `db::open` by the OPEN-TIME rollback-evidence head check: the surviving `signed_events` head is compared against the witness-signed OFF-TABLE `head-anchor.log` high-water on the `AI_MEMORY_WITNESS_KEY_DIR` mount (an on-host sibling the DB rollback does not touch). A head below the K1-pinned anchor high-water, with no operator sanction, is a `RollbackCheck::Evidence` verdict (loud WARN + signed `audit.rollback_evidence` row; refuses the open under `AI_MEMORY_REQUIRE_ROLLBACK_CHECK`). A legitimate DR restore is distinguished from an attack ONLY by an operator-signed `audit restore-attest --sign` sanction. ⚠️ **tamper-EVIDENCE, not tamper-PROOF** — see the honest-limit note below. |

> **⚠️ Honest limit of the rollback-evidence anchor (#1946 A1, ESTIMABLE not
> ATTESTABLE).** In the OSS build the off-table head-anchor lives on the same
> host as the DB. An **imaged-disk attacker** who snapshots the whole host —
> DB file *and* the sibling `head-anchor.log` together — rolls both back in
> lockstep and defeats the check with zero evidence. The control is
> tamper-**evidence** against a DB-file-only rollback (a naive
> `DELETE`/restore-just-the-`.db`), **not** tamper-**proof** against a
> whole-host snapshot. Genuine whole-host resistance requires a hardware
> monotonic counter (TPM2 NV — the `tpm2-nv` rollback-counter source is
> reserved-when-present in the wire format, format only in OSS) or an
> **off-host** anchor. Every verdict degrades to `Unknown` (WITHHOLD) rather
> than ever emitting a false all-clear, and the default posture emits evidence
> and continues (no self-DOS on a legitimate DR restore).

The append-only OS flag (`chflags +UF_APPEND` on BSD/macOS,
`FS_IOC_SETFLAGS +FS_APPEND_FL` on Linux) is **best-effort defense in
depth**. The hash chain is the load-bearing tamper-evidence.

---

## Log directory resolution

End users can set the operational-log directory **and** the audit-log
directory at every layer of the configuration stack. This is a
**user-mandated** addendum to PR-5 — operators always retain control
over where logs land regardless of how `ai-memory` was installed or
launched.

### Precedence (highest wins)

| Priority | Layer | Operational logs | Audit log |
|---:|---|---|---|
| 1 | **CLI flag** | `ai-memory logs --log-dir <PATH> …` | `ai-memory audit --audit-dir <PATH> …` |
| 2 | **Environment variable** | `AI_MEMORY_LOG_DIR` | `AI_MEMORY_AUDIT_DIR` |
| 3 | **`config.toml`** | `[logging] path = "…"` | `[audit] path = "…"` |
| 4 | **Platform default** | per-OS table below | per-OS table below |

The resolver also recognises an `INVOCATION_ID` environment variable
(set by `systemd` for unit-managed processes). When present *and*
`/var/log/ai-memory/` is writable, the platform-default branch picks
`/var/log/ai-memory/` instead of the per-user XDG path. This lets a
`systemd` service with `LogsDirectory=ai-memory` write logs to the
canonical system path without any extra configuration.

`AI_MEMORY_LOG_DIR` and `AI_MEMORY_AUDIT_DIR` are read with
`std::env::var_os`, so non-UTF-8 paths on Windows pass through to
`PathBuf` unchanged.

### Platform defaults

| OS | Operational logs | Audit log |
|---|---|---|
| **Linux** (and BSD / illumos / other Unix) | `${XDG_STATE_HOME:-$HOME/.local/state}/ai-memory/logs/` | `${XDG_STATE_HOME:-$HOME/.local/state}/ai-memory/audit/` |
| **macOS** | `~/Library/Logs/ai-memory/` | `~/Library/Logs/ai-memory/audit/` |
| **systemd-managed daemon** (any OS, `INVOCATION_ID` set, `/var/log/ai-memory/` writable) | `/var/log/ai-memory/logs/` | `/var/log/ai-memory/audit/` |

### Worked examples

**Laptop dev (no config — accept the default).**

```bash
$ ai-memory audit path
/Users/alice/Library/Logs/ai-memory/audit/audit.log

$ ai-memory logs tail --lines 5
# tails ~/Library/Logs/ai-memory/ai-memory.log.YYYY-MM-DD
```

**Docker container with a host-mounted log volume.** Mount the host
directory into a stable container path, then point `ai-memory` at it
with `AI_MEMORY_LOG_DIR` so the env-injected path wins over any
baked-in `config.toml`:

```bash
docker run -d \
  -v /var/log/ai-memory-host:/var/log/ai-memory \
  -e AI_MEMORY_LOG_DIR=/var/log/ai-memory/logs \
  -e AI_MEMORY_AUDIT_DIR=/var/log/ai-memory/audit \
  ghcr.io/alphaonedev/ai-memory:0.10.0
```

**Kubernetes pod with `emptyDir` volume.** Project the volume into
`/var/log/ai-memory/` and point both env vars at the matching
subdirectories. Use a sidecar log shipper (Promtail, Filebeat,
Fluentbit) to forward both streams off-pod before termination.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ai-memory
spec:
  containers:
    - name: ai-memory
      image: ghcr.io/alphaonedev/ai-memory:0.10.0
      env:
        - name: AI_MEMORY_LOG_DIR
          value: /var/log/ai-memory/logs
        - name: AI_MEMORY_AUDIT_DIR
          value: /var/log/ai-memory/audit
      volumeMounts:
        - name: ai-memory-logs
          mountPath: /var/log/ai-memory
  volumes:
    - name: ai-memory-logs
      emptyDir: {}
```

**systemd unit with `LogsDirectory=`.** systemd creates and chowns the
directory to the unit's `User=`; `ai-memory` auto-detects via
`INVOCATION_ID` and lands logs in `/var/log/ai-memory/`:

```ini
[Service]
ExecStart=/usr/local/bin/ai-memory serve
User=ai-memory
LogsDirectory=ai-memory
LogsDirectoryMode=0700
```

No env vars or `config.toml` paths required — the platform-default
branch picks `/var/log/ai-memory/` because `INVOCATION_ID` is set and
the directory is writable.

**Override at the CLI for a one-off run** (debugging, audit forensics):

```bash
ai-memory audit --audit-dir /tmp/ai-memory-forensics verify
ai-memory logs --log-dir /tmp/ai-memory-debug tail --follow
```

### Security guard: no world-writable directories

The resolver **refuses** to write to a directory whose Unix permissions
include the world-writable bit (`mode & 0o002 != 0`). World-writable
log destinations are a pivot target — any local user could append
forged events, truncate the chain, or replace files atomically. The
error message names the resolution layer that landed there so the
operator can fix the right config:

```
Error: log directory /tmp/foo is world-writable (mode 0777); refusing
for security. Resolved via: CLI flag (--log-dir / --audit-dir).
Pick a non-world-writable directory and re-run.
```

When `ai-memory` creates the directory itself, it applies mode `0700`
on Unix. On Windows the default ACL (Authenticated Users only) is
sufficient.

---

## Operator CLI

### `ai-memory audit verify`

Walks the audit log, recomputes every line's `self_hash`, and asserts
each `prev_hash` matches the prior line's `self_hash`. Exits:

- `0` — chain intact
- `2` — chain broken (precise line + failure kind printed)
- non-zero with anyhow context — I/O error

```bash
$ ai-memory audit verify
audit verify OK: 1428 line(s) verified at /home/op/.local/state/ai-memory/audit/audit.log

$ ai-memory audit verify --json
{"status":"ok","total_lines":1428,"path":"…/audit.log"}

$ ai-memory audit verify   # after a tamper
audit verify FAIL at line 203: SelfHash — self_hash mismatch: stored=ab…, recomputed=cd…
```

### `ai-memory audit tail`

Print recent events, optionally filtered:

```bash
ai-memory audit tail --lines 100 --action store
ai-memory audit tail --namespace finance --format json | jq .
ai-memory audit tail --actor 'ai:claude-code@laptop'
```

### `ai-memory audit path`

Prints the resolved audit log path. Convenient for SIEM ingestion
configuration scripts. Honours the same `--audit-dir <PATH>` override
as every other `ai-memory audit` subcommand, so you can point at an
ad-hoc location for one-off inspection:

```bash
ai-memory audit --audit-dir /var/lib/forensics/2026-04-30 path
```

### `ai-memory audit restore-attest [--sign]`

**[#1946 A1, v1.0.0]** The **sanctioned-restore ceremony**. After a
legitimate disaster-recovery restore of the DB from an earlier snapshot,
the surviving `signed_events` head is BELOW the witness-signed off-table
`head-anchor.log` high-water — byte-identical to an attack rollback, so
the open-time rollback check would flag `RollbackCheck::Evidence`. This
command records ONE **operator-signed** `audit.restore_sanctioned` event
committing `{old_head, new_head, gap, timestamp}` to the off-table
sanction log on the `AI_MEMORY_WITNESS_KEY_DIR` mount. The open-time
check treats a matching, operator-signature-verified sanction as
**clearing** the evidence for that DR window. The operator signature
(custody-separate from the daemon and witness keys, never on
DB-writable disk) is the **only** discriminator between a sanctioned DR
restore and an attack.

```bash
# Dry-run: preview the {old_head, new_head, gap} it WOULD attest.
ai-memory audit restore-attest

# Emit the operator-signed sanction (loads the operator key from
# --key-dir / AI_MEMORY_KEY_DIR).
ai-memory audit restore-attest --sign
```

### `ai-memory audit re-anchor [--json]`

**[#2004, v1.0.0]** The **crypto-agility re-anchor ceremony** for
**sqlite-endpoint chains**. Per-record post-quantum signatures are
forbidden (spec §2.4 — arithmetically incompatible with endpoint
budgets), so PQ strength binds at **checkpoint granularity**: this
command countersigns the CURRENT `signed_events` chain head — "the
new-suite key has seen prior head `H` at sequence `N`" — under the
enrolled suite (the FROZEN `re-anchor/v1` format), and persists it as a
signed `re_anchor` checkpoint. Enabling a stronger / PQ suite on a live
corpus later then causes **zero** write failures and **zero** record
rewrites, and every pre-break record stays attributable across the suite
boundary.

> **Backend scope (honest):** the verb operates on the **local sqlite**
> database it opens (`chain sqlite:signed_events` — the db path + chain
> are printed on every disposition). A **postgres**-backed deployment
> maintains its own `signed_events` chain, and that chain has **no
> re-anchor twin yet** — running this verb on a pg deployment anchors
> only the local sqlite file, NOT the pg chain. The pg ceremony twin is
> tracked as [#2217](https://github.com/alphaonedev/ai-memory-mcp/issues/2217).

The countersignature is produced by the **distinct off-daemon
audit-witness custody key** (the same K1-pinnable custody as the #1822
witness anchor), so the ceremony is opt-in: with no witness custody
enrolled (`AI_MEMORY_WITNESS_KEY_DIR`) it is an explicit `skipped`
no-op — but an **enrolled key that fails to load** (corrupt /
half-enrolled / public-only custody) is a ceremony **failure** (exit 1,
reason `witness_key_unloadable`), never a silent skip. The persisted
anchor is **reloaded from the database** and self-verified via the
read-back path (K1-pinned to `AI_MEMORY_WITNESS_PUBKEY`) so the operator
sees the true persisted round-trip, not just a write. A universal
per-signed-class `suite_tag` is deferred to v1.x; today the only
enrolled suite is Ed25519-SHA256 (no suite rotation is operationally
possible yet — see the claims discipline: "crypto-agile" remains a
banned public claim until R75 completes).

```bash
# Countersign + anchor the current head (loads the witness key from
# AI_MEMORY_WITNESS_KEY_DIR; verifies against AI_MEMORY_WITNESS_PUBKEY).
ai-memory audit re-anchor
```

### `ai-memory logs tail [--follow]`

Tail and (optionally) stream operational logs. Accepts the global
`--log-dir <PATH>` override. See the **Log directory resolution**
section above for the full precedence ladder.

### `ai-memory logs archive`

zstd-compresses rotated log files past the configured
`retention_days`. Idempotent.

### `ai-memory logs purge --before <date>`

Delete archived logs older than `<date>`. Surfaces a
**audit-gap warning** when the cutoff date overlaps the configured
audit retention horizon — deleting audit logs creates a compliance
hole the next `audit verify` (or external attestation) will surface.

---

## SIEM ingestion guide

The audit and operational log lines are plain UTF-8 JSON. Any SIEM
that ingests JSON ingests this. Recipes for the four most common:

### Splunk Universal Forwarder

`inputs.conf`:

```conf
[monitor:///home/op/.local/state/ai-memory/audit/audit.log]
sourcetype = ai-memory:audit
index = security_audit
disabled = 0

[monitor:///home/op/.local/state/ai-memory/logs/ai-memory.log.*]
sourcetype = ai-memory:ops
index = ai_ops
disabled = 0
```

`props.conf`:

```conf
[ai-memory:audit]
INDEXED_EXTRACTIONS = json
TIMESTAMP_FIELDS = timestamp
KV_MODE = none
```

### Datadog Agent

`/etc/datadog-agent/conf.d/ai_memory.d/conf.yaml`:

```yaml
logs:
  - type: file
    path: /home/op/.local/state/ai-memory/audit/audit.log
    service: ai-memory
    source: ai-memory-audit
    log_processing_rules:
      - type: include_at_match
        name: keep_all
        pattern: ".*"
  - type: file
    path: /home/op/.local/state/ai-memory/logs/ai-memory.log*
    service: ai-memory
    source: ai-memory-ops
```

Pair with the [JSON parser]([https://docs.datadoghq.com/logs/log_configuration/parsing/](https://docs.datadoghq.com/logs/log_configuration/parsing/))
for the audit pipeline.

### Elastic Filebeat

`filebeat.yml`:

```yaml
filebeat.inputs:
  - type: filestream
    id: ai-memory-audit
    paths:
      - /home/op/.local/state/ai-memory/audit/audit.log
    parsers:
      - ndjson:
          target: ai_memory_audit
          add_error_key: true
    fields:
      service: ai-memory
      stream: audit
  - type: filestream
    id: ai-memory-ops
    paths:
      - /home/op/.local/state/ai-memory/logs/ai-memory.log*
    fields:
      service: ai-memory
      stream: operational
```

### Loki / Promtail

`promtail.yaml`:

```yaml
scrape_configs:
  - job_name: ai-memory-audit
    static_configs:
      - targets: [localhost]
        labels:
          service: ai-memory
          stream: audit
          __path__: /home/op/.local/state/ai-memory/audit/audit.log
    pipeline_stages:
      - json:
          expressions:
            timestamp: timestamp
            action: action
            actor: actor.agent_id
            namespace: target.namespace
            outcome: outcome
      - timestamp:
          source: timestamp
          format: RFC3339
      - labels:
          action:
          outcome:

  - job_name: ai-memory-ops
    static_configs:
      - targets: [localhost]
        labels:
          service: ai-memory
          stream: operational
          __path__: /home/op/.local/state/ai-memory/logs/ai-memory.log*
```

---

## Regulatory mapping

The compliance presets propagate a well-known **retention** value into the
effective config. Set `applied = true` for the relevant preset; ai-memory
picks the longest retention when multiple presets are active.

| Preset | Citation (retention) | Retention | Notes |
|---|---|---|---|
| `soc2` | TSC CC7.2 | 2 years | Retention only — see the attestation-cadence note below. |
| `hipaa` | 45 CFR §164.316(b)(2) | 6 years | Pair with `--features sqlcipher` for required at-rest crypto. |
| `gdpr` | Art. 30 + Art. 5(1)(e) | 3 years | `pseudonymize_actors` is reserved — no implementation. |
| `fedramp` | NIST SP 800-53 AU-11 | 3 years | Retention high-water mark for federal civilian / DoD IL2-IL5. |

**Attestation cadence is not mapped, deliberately.** Earlier revisions of this
table published a per-preset attestation cadence (SOC2 60 min, FedRAMP 30 min)
against TSC CC7.2 and NIST SP 800-53 AU-12. That mapping is withdrawn: the
cadence resolver exists, but nothing consumes its value — the
`CHECKPOINT.sig` marker it would drive is RESERVED and unimplemented (see the
Quickstart note). A named control citation that resolves to a value no code
acts on is worse than no mapping, so there is no cadence column. It returns
when the emission does.

What the presets do map is **retention** (`AuditConfig::effective_retention_days`,
enforced by `ai-memory logs purge`, which warns when a purge cutoff overlaps
the configured audit-retention horizon).

The presets are configuration only. Compliance certification still
requires the broader control environment (access reviews, change
management, incident response). The audit trail is one piece of the
evidence package, not the whole thing.

---

## Operational runbook

### Rotation

The rolling appender writes one file per `rotation` cadence (default
daily). `max_files` retained on disk; older files are removed by the
appender. `ai-memory logs archive` zstd-compresses files past
`retention_days` for cold-storage handoff to the SIEM.

### Verification cadence

Run `ai-memory audit verify` from a SIEM-monitored cron / systemd
timer at least daily. A failure is a P0 — somebody touched the file.

```service
# /etc/systemd/system/ai-memory-audit-verify.service
[Unit]
Description=Verify ai-memory audit chain

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ai-memory audit verify --json
SyslogIdentifier=ai-memory-audit-verify
```

```service
# /etc/systemd/system/ai-memory-audit-verify.timer
[Unit]
Description=Hourly ai-memory audit chain verification
[Timer]
OnCalendar=hourly
[Install]
WantedBy=timers.target
```

### Off-host attestation

Ship every line to an immutable off-host store (SIEM, S3 Object Lock,
WORM appliance) in real time. The on-host hash chain serves as a
cross-check for the off-host record.

### Incident response

A failed `audit verify` means the audit log has been tampered with.
The chain itself tells you where (precise line number + failure kind).
Cross-reference the timestamp with:

1. The off-host SIEM ingest stream (the immutable copy the on-host
   chain cross-checks against).
2. Operating-system audit (auditd / OSSEC / EndPoint EDR) for
   unauthorized writes to the log path.
3. `ai-memory doctor` for related runtime anomalies.
