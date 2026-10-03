#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#4577 / #4600 / #4603 / #4604 / #4609 / #4617 - no-credentials-on-argv gate.

A database password on a command line is readable from ``/proc/<pid>/cmdline``
and ``ps auxww`` by every local UID, and a secret rendered into a world-readable
script is readable by every local UID at rest. The product has non-argv
channels (``AI_MEMORY_STORE_URL_FILE`` first, then ``AI_MEMORY_STORE_URL``;
``src/store_url.rs`` ``resolve_store_url``), used by ``serve``, ``curator`` and
(#4600) ``schema-init``, so a tracked doc, unit, template or script must not use
the argv form. Rules (a hit in any is a failure):

  store-url-literal  a ``--store-url`` argument whose value carries an inline
                     userinfo password (``scheme://user:pass@``), unless the
                     password is a redaction token (an ellipsis, asterisks,
                     ``REDACTED``) (#4577; the schema-init allowance of #4600 is
                     gone: ``schema-init`` resolves the file/env channels).
  store-url-expansion  ``--store-url`` followed by an ``AI_MEMORY_STORE_URL``
                     expansion (``$VAR``, ``${VAR}``, or the escaped forms a
                     heredoc unit uses): the shell or systemd expands the
                     secret onto argv at run time (#4603).
  psql-password-argv  a ``psql`` command line that carries ``-c`` /
                     ``--command`` with ``PASSWORD '<value>'`` in the SQL text
                     (#4604). Feed the statement from a 0600 file on stdin.
  cloud-init-readable-secret  a cloud-init ``write_files`` entry whose
                     ``permissions`` leave a group/world bit set (or are
                     absent, default 0644) and whose content interpolates a
                     ``${..password|secret|token|key|cred..}`` template
                     variable (#4604: the rendered ``provision.sh`` was 0755).

  env-password-argv  ``docker run/exec -e PGPASSWORD=$X`` /
                     ``-e POSTGRES_PASSWORD=$X`` or ``psql -v pw=$X``: a
                     runtime-expanded password on argv (#4617). ``-e NAME``
                     with no value and ``--env-file`` are the sanctioned forms.
  xtrace-secret      a line that expands a password-named variable while
                     xtrace (``set -x`` / ``set -euxo``) is on and not switched
                     off by ``set +x`` (#4609: the trace lands in the log).

``store-url-expansion`` also matches a DSN/URL-named variable after the flag
(``--store-url "$DSN"``, #4603). A ``_FILE`` variable is the sanctioned channel
and is not flagged. The ``--self-test`` also runs the #4609 runtime probe: it
executes the credential-handling lines of the do-hive ``provision.sh`` with a
dummy password and proves the provision log never contains it and is mode 0600
(and that a regressed copy of the script does leak, so the probe is not vacuous).

Usage:
  scripts/check-docs-no-argv-secrets.py             exit 0 clean, 1 on a hit,
                                                    2 on a scanner fault
  scripts/check-docs-no-argv-secrets.py --self-test prove every rule is red on
                                                    probes and green on
                                                    near-misses
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Redaction tokens that are not a credential.
REDACTION_TOKENS = ("...", "…", "***", "redacted", "<redacted>", "xxxx")

# Files that quote the pattern on purpose: this gate and its own docs.
SELF_EXEMPT = {"scripts/check-docs-no-argv-secrets.py"}

# Historical or machine-generated trees where quoted old commands are a record,
# not a recommendation: the changelog fragments and the per-PR review evidence.
SKIP_PREFIXES = ("changelog.d/", "docs/reviews/", "docs/handoff/")
SKIP_FILES = {"CHANGELOG.md"}

# `--store-url`, optional `=` or whitespace / backslash-newline continuation,
# optional opening quote, then scheme://user:PASSWORD@ (userinfo cannot contain
# `/`, `@`, whitespace or a quote; a percent-encoded password is still literal).
ARG_RE = re.compile(
    r"--store-url(?:=|(?:\s|\\)+)"
    r"[\"']?"
    r"[A-Za-z][A-Za-z0-9+.\-]*://"
    r"[^\s/@\"':]+"  # user
    r":(?P<pw>[^\s/@\"']+)"  # password (non-empty)
    r"@"
)

TEXT_SUFFIXES = {
    ".md", ".html", ".yaml", ".yml", ".tpl", ".sh", ".py", ".toml", ".txt",
    ".service", ".conf", ".ini", ".tf", ".tfvars", ".json", ".env", ".rs",
    ".csv", ".cfg", "",
}
MAX_BYTES = 4 * 1024 * 1024


def is_redaction(pw: str) -> bool:
    low = pw.lower()
    return any(tok in low for tok in REDACTION_TOKENS)


# A runtime expansion of the store-URL env var, or of any variable named like a
# DSN / URL (verify.sh's `"$DSN"`), straight after `--store-url`. A `_FILE`
# variable is the sanctioned channel and is not matched (the lookahead rejects
# a name that continues past DSN/URL).
EXPANSION_RE = re.compile(
    r"--store-url(?:=|(?:\s|\\)+)"
    r"[\"']?"
    r"\\*\$\{?[A-Za-z0-9_]*(?:DSN|URL)(?![A-Za-z0-9_])",
    re.IGNORECASE,
)

# #4609: xtrace (`set -x`, `set -euxo pipefail`) echoes every expanded command,
# so a credential-bearing line must sit between `set +x` and `set -x`.
XTRACE_ON_RE = re.compile(r"^\s*set\s+-[a-z]*x")
XTRACE_OFF_RE = re.compile(r"^\s*set\s+\+[a-z]*x")
TRACED_SECRET_RE = re.compile(
    r"\$\{?(?:[A-Za-z0-9_]*(?:password|passwd|secret|token|_pw)|pw)(?![A-Za-z0-9])",
    re.IGNORECASE,
)

PSQL_ARGV_RE = re.compile(
    r"\bpsql\b[^\n]*?\s(?:-c|--command)(?:=|\s)\s*[\"'][^\n]*?\bPASSWORD\s+\\?'(?P<pw>[^'\s]+)",
    re.IGNORECASE,
)

# #4617: `docker run/exec -e PGPASSWORD=<value>`, `-e POSTGRES_PASSWORD=<value>`
# and `psql -v pw=<value>` put a runtime-expanded password ($VAR) in argv;
# constant throwaway CI values are not secrets and are not matched. `-e NAME` with no value
# (inherits the caller's environment) and `--env-file` are the sanctioned forms.
ENV_ARGV_RE = re.compile(
    r"(?:\s-e|\s--env)(?:=|\s)\s*[\"']?(?:PGPASSWORD|POSTGRES_PASSWORD)=[\"']?(?P<pw>\$[^\s\"']+)"
    r"|\spsql\b[^\n]*?\s-v\s+(?:pw|password|passwd)=[\"']?(?P<pw2>\$[^\s\"']+)",
    re.IGNORECASE,
)

SECRET_VAR_RE = re.compile(
    r"\$\{[A-Za-z0-9_]*(?:password|passwd|secret|token|key|cred)[A-Za-z0-9_]*\}",
    re.IGNORECASE,
)
ENTRY_RE = re.compile(r"^(?P<indent>\s*)- path:\s*(?P<path>\S+)")
PERM_RE = re.compile(r"^\s*permissions:\s*[\"']?(?P<mode>[0-7]{3,4})[\"']?")


def _line_of(text: str, pos: int) -> tuple[int, str]:
    line = text.count("\n", 0, pos) + 1
    snippet = text.splitlines()[line - 1].strip() if text else ""
    return line, snippet[:140]


def scan_write_files(rel: str, text: str) -> list[tuple[str, int, str]]:
    """cloud-init write_files entries that interpolate a secret into a file
    left group/world readable (#4604)."""
    hits: list[tuple[str, int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = ENTRY_RE.match(lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group("indent"))
        j = i + 1
        mode = 0o644  # cloud-init default when permissions is absent
        body: list[tuple[int, str]] = []
        while j < len(lines):
            ln = lines[j]
            stripped = ln.strip()
            cur = len(ln) - len(ln.lstrip())
            if stripped and cur <= indent and not stripped.startswith("#"):
                break
            pm = PERM_RE.match(ln)
            if pm and cur == indent + 2:
                mode = int(pm.group("mode"), 8)
            body.append((j + 1, ln))
            j += 1
        if mode & 0o077:
            for lineno, ln in body:
                if SECRET_VAR_RE.search(ln):
                    hits.append((rel, lineno, "[cloud-init-readable-secret %o %s] %s"
                                 % (mode, m.group("path"), ln.strip()[:100])))
                    break
        i = j
    return hits


def scan_xtrace(rel: str, text: str) -> list[tuple[str, int, str]]:
    """Credential-bearing lines executed while xtrace is on (#4609)."""
    hits: list[tuple[str, int, str]] = []
    traced = False
    for n, ln in enumerate(text.splitlines(), 1):
        if ln.lstrip().startswith("#"):
            continue
        if XTRACE_OFF_RE.match(ln):
            traced = False
            continue
        if XTRACE_ON_RE.match(ln):
            traced = True
            continue
        if traced and TRACED_SECRET_RE.search(ln):
            hits.append((rel, n, "[xtrace-secret] " + ln.strip()[:120]))
    return hits


def scan_text(rel: str, text: str) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    if rel in SELF_EXEMPT:
        return hits
    for m in ARG_RE.finditer(text):
        if is_redaction(m.group("pw")):
            continue
        line, snippet = _line_of(text, m.start())
        hits.append((rel, line, "[store-url-literal] " + snippet))
    for m in EXPANSION_RE.finditer(text):
        line, snippet = _line_of(text, m.start())
        hits.append((rel, line, "[store-url-expansion] " + snippet))
    for m in PSQL_ARGV_RE.finditer(text):
        if is_redaction(m.group("pw")):
            continue
        line, snippet = _line_of(text, m.start())
        hits.append((rel, line, "[psql-password-argv] " + snippet))
    for m in ENV_ARGV_RE.finditer(text):
        if is_redaction(m.group("pw") or m.group("pw2") or ""):
            continue
        line, snippet = _line_of(text, m.start())
        hits.append((rel, line, "[env-password-argv] " + snippet))
    if rel.endswith((".tpl", ".yaml", ".yml")):
        hits.extend(scan_write_files(rel, text))
    if rel.endswith((".sh", ".tpl", ".yaml", ".yml")):
        hits.extend(scan_xtrace(rel, text))
    return hits


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            check=True, capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("git ls-files failed: %s" % exc) from exc
    files = [f for f in out.decode("utf-8", "replace").split("\0") if f]
    if not files:
        raise RuntimeError("git ls-files returned no files; refusing to pass on an empty scan")
    return files


def scan_paths(root: Path, files: list[str]) -> tuple[list[tuple[str, int, str]], int]:
    hits: list[tuple[str, int, str]] = []
    scanned = 0
    for rel in files:
        if rel in SKIP_FILES or rel.startswith(SKIP_PREFIXES):
            continue
        p = root / rel
        if p.suffix.lower() not in TEXT_SUFFIXES or not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        hits.extend(scan_text(rel, text))
    return hits, scanned


def run() -> int:
    try:
        files = tracked_files()
        hits, scanned = scan_paths(ROOT, files)
    except (RuntimeError, OSError) as exc:
        print("FAIL: check-docs-no-argv-secrets: scanner fault: %s" % exc, file=sys.stderr)
        return 2
    if scanned == 0:
        print("FAIL: check-docs-no-argv-secrets: scanned 0 files; refusing to pass", file=sys.stderr)
        return 2
    if hits:
        for rel, line, snippet in hits:
            print("HIT %s:%d: %s" % (rel, line, snippet), file=sys.stderr)
        print(
            "FAIL: check-docs-no-argv-secrets: %d tracked line(s) put a credential on argv or in a "
            "readable file (#4577/#4603/#4604). Use AI_MEMORY_STORE_URL_FILE (a 0600 file) and feed "
            "psql from a 0600 file on stdin; see docs/CLI_REFERENCE.md."
            % len(hits),
            file=sys.stderr,
        )
        return 1
    print("PASS: check-docs-no-argv-secrets: %d files scanned, 0 argv credentials" % scanned)
    return 0


RED_PROBES = {
    "inline": "ai-memory serve --store-url postgres://u:hunter2@h:5432/d",
    "equals": "ai-memory serve --store-url=postgres://u:hunter2@h/d",
    "quoted": 'ExecStart=/bin/ai-memory serve --store-url "postgres://u:${db_password}@h/d"',
    "single-quoted": "x serve --store-url 'postgresql://u:p%40ss@h/d?sslmode=require'",
    "shell-var": "ssh h \"ai-memory serve --store-url 'postgres://u:$PG_PW@h/d'\"",
    "continuation": "ai-memory serve \\\n  --store-url \\\n  postgres://u:hunter2@h/d",
    "other-verb": "ai-memory curator --store-url postgres://u:hunter2@h/d",
    "schema-init": "ai-memory schema-init --store-url postgres://u:hunter2@h/d",
    "schema-init-continued": "ai-memory schema-init \\\n  --store-url postgres://u:hunter2@h/d",
    # #4603: a runtime expansion of the env var onto the --store-url argv.
    "expansion-systemd": "ExecStart=/bin/ai-memory serve --store-url ${AI_MEMORY_STORE_URL} --port 1",
    "expansion-heredoc-escaped": "ExecStart=$BIN curator --daemon --store-url \\\\\\${AI_MEMORY_STORE_URL} --x 1",
    "expansion-shell-quoted": 'exec ai-memory serve --store-url "$AI_MEMORY_STORE_URL" \\',
    "expansion-continued": "serve \\\n  --store-url \\\n  $AI_MEMORY_STORE_URL",
    # #4603: verify.sh's shape, a DSN variable on --store-url.
    "expansion-dsn-var": 'AI_MEMORY_NO_CONFIG=1 "$BIN" verify-audit-trail --store-url "$DSN" >out 2>&1',
    "expansion-pooled-url": '"$BIN" schema-init --store-url "$POOLED_URL"',
    # #4617: password on a docker -e / psql -v argv word.
    "docker-exec-pgpassword": "ssh h \"docker exec -e PGPASSWORD='$SU_PW' c psql -U postgres\"",
    "docker-run-postgres-password": "docker run -d -e POSTGRES_PASSWORD=\"$PGPW\" img",
    "psql-v-pw": "docker exec -i c psql -v ON_ERROR_STOP=1 -v pw='$PG_PW' -f -",
    # #4609: xtrace on while the password is handled.
    "xtrace-secret": "set -euxo pipefail\nprintf '%s' ${db_password} > /etc/x\n",
    "xtrace-secret-after-restore": "set -x\nset +x\nset -x\necho $PG_PW\n",
    # #4604: the role password in a psql -c statement, and a readable script.
    "psql-create-user": "sudo -u postgres psql -c \"CREATE USER aimemory WITH PASSWORD '${db_password}';\"",
    "psql-alter-role": "psql -h h -d d --command=\"ALTER ROLE a WITH PASSWORD 'hunter2'\"",
    "cloud-init-0755": "write_files:\n  - path: /opt/p.sh\n    permissions: '0755'\n    content: |\n      x '${db_password}'\n",
    "cloud-init-no-perms": "write_files:\n  - path: /opt/p.sh\n    content: |\n      x ${api_token}\n",
}
GREEN_PROBES = {
    "file-form": "AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url ai-memory serve",
    "no-password": "ai-memory serve --store-url postgres://u@h/d",
    "no-userinfo": "ai-memory serve --store-url postgres://h:5432/d",
    "file-env-expansion": 'ai-memory keys --store-url "$AI_MEMORY_STORE_URL_FILE" prune',
    "ellipsis": "ai-memory serve --store-url postgres://aimemory:...@10.0.0.4:5432/db",
    "redacted": "ai-memory serve --store-url postgres://aimemory:REDACTED@h/db",
    "ellipsis-char": "ai-memory serve --store-url postgres://user:…@h/db",
    "lookalike-flag": "wake_abab.sh --store-url-src postgres://u:p@h/d",
    "prose-mention": "the `serve --store-url` connection URL (e.g. postgres://user:pass@host/db)",
    "schema-init-file-form": "AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url ai-memory schema-init",
    "expansion-of-other-var": 'ai-memory keys --store-url "$SQLITE_PATH" prune',
    "docker-e-inherit": 'PGPASSWORD="$PW" docker exec -e PGPASSWORD c psql -U u',
    "docker-env-file": "docker run -d --env-file /run/s/su.env img",
    "psql-v-no-secret": "psql -v ON_ERROR_STOP=1 -f -",
    "xtrace-off-around-secret": "set -euxo pipefail\nset +x\nprintf '%s' ${db_password} > /etc/x\nset -x\n",
    "xtrace-no-secret": "set -x\necho ${node_index}\n",
    "no-xtrace-secret": "set -euo pipefail\nprintf '%s' ${db_password} > /etc/x\n",
    "xtrace-comment-only": "set -x\n# ${db_password} is handled below\n",
    "env-var-not-after-flag": "export AI_MEMORY_STORE_URL=postgres://u@h/d; ai-memory serve",
    "psql-stdin-file": "sudo -u postgres psql -f - < /etc/ai-memory/create-role.sql",
    "psql-select": 'sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname=\'a\'"',
    "psql-redacted": "psql -c \"CREATE USER a WITH PASSWORD '...'\"",
    "sql-file-not-psql": "CREATE USER aimemory WITH PASSWORD 'x';",
    "cloud-init-0600": "write_files:\n  - path: /etc/s\n    permissions: '0600'\n    content: |\n      pw ${db_password}\n",
    "cloud-init-0700": "write_files:\n  - path: /opt/p.sh\n    permissions: '0700'\n    content: |\n      x '${db_password}'\n",
    "cloud-init-readable-no-secret": "write_files:\n  - path: /opt/p.sh\n    permissions: '0755'\n    content: |\n      echo ${node_index}\n",
}


DUMMY_PW = "DUMMY-pw-4609-must-not-leak"
PROVISION_TPL = "infra/do-hive/cloud-init-memory.yaml.tpl"


def _provision_body(tpl: str) -> list[str]:
    """The de-indented provision.sh body from the cloud-init template."""
    lines = tpl.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "- path: /opt/ai-memory/provision.sh")
    cont = next(i for i in range(start, len(lines)) if lines[i].strip() == "content: |")
    body = []
    for ln in lines[cont + 1:]:
        if ln.strip() and not ln.startswith("      "):
            break
        body.append(ln[6:] if ln.startswith("      ") else "")
    return body


def _credential_harness(body: list[str], scratch: Path) -> str:
    """Preamble + role block + userlist block of provision.sh, paths pointed
    at ``scratch`` (no /etc, /root or /var/log writes)."""
    pre_end = next(i for i, ln in enumerate(body) if ln.startswith('echo "=== ai-memory'))
    role_start = next(i for i, ln in enumerate(body) if "db + role + extensions" in ln)
    role_end = next(i for i in range(role_start, len(body)) if "CREATE DATABASE" in body[i])
    ul = next(i for i, ln in enumerate(body) if "userlist.txt" in ln and "printf" in ln)
    ul_start = ul - 1 if body[ul - 1].lstrip().startswith("set +x") else ul
    ul_end = next(i for i in range(ul, len(body)) if "chmod 0600 /etc/pgbouncer/userlist.txt" in body[i])
    picked = body[:pre_end + 1] + body[role_start:role_end + 1] + body[ul_start:ul_end + 1]
    text = "\n".join(picked) + "\n"
    for real, fake in (("/var/log/ai-memory-provision.log", str(scratch / "provision.log")),
                       ("/root/.aimemory-role.sql", str(scratch / "role.sql")),
                       ("/etc/pgbouncer/userlist.txt", str(scratch / "userlist.txt")),
                       ("/etc/pgbouncer/pgbouncer.ini", str(scratch / "pgbouncer.ini"))):
        text = text.replace(real, fake)
    return text.replace("${db_password}", DUMMY_PW)


def _run_provision_probe(tpl: str) -> tuple[str, int, str]:
    """Run the harness under bash with stubbed sudo/chown. Returns
    (log text, log mode, stderr)."""
    scratch_parent = ROOT / ".local-runs"
    scratch_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(scratch_parent)) as td:
        scratch = Path(td)
        stubs = scratch / "bin"
        stubs.mkdir()
        for name in ("sudo", "chown"):
            stub = stubs / name
            stub.write_text("#!/bin/sh\ncat >/dev/null 2>&1 </dev/null || true\nexit 0\n", encoding="utf-8")
            stub.chmod(0o755)
        script = scratch / "harness.sh"
        script.write_text(_credential_harness(_provision_body(tpl), scratch), encoding="utf-8")
        proc = subprocess.run(
            ["bash", str(script)], capture_output=True, text=True, timeout=60, check=False,
            env={"PATH": "%s:/usr/bin:/bin" % stubs, "HOME": str(scratch)},
        )
        import time
        time.sleep(0.5)  # let the `tee` process substitution flush the log
        log = scratch / "provision.log"
        mode = (log.stat().st_mode & 0o777) if log.exists() else -1
        leaked = log.read_text(encoding="utf-8") if log.exists() else ""
        if proc.returncode != 0:
            leaked += "\n[harness rc=%d] %s" % (proc.returncode, proc.stderr[-300:])
        return leaked, mode, proc.stderr


def runtime_probe() -> int:
    """#4609 red-then-green: dummy password, real bash, real xtrace + tee."""
    tpl_path = ROOT / PROVISION_TPL
    if not tpl_path.exists():
        print("SELF-TEST FAIL: %s missing" % PROVISION_TPL, file=sys.stderr)
        return 1
    tpl = tpl_path.read_text(encoding="utf-8")
    bad = 0
    log, mode, _ = _run_provision_probe(tpl)
    if DUMMY_PW in log or "harness rc=" in log:
        print("SELF-TEST FAIL: provision.sh leaks the dummy password (or the harness failed) in its log", file=sys.stderr)
        bad += 1
    if mode != 0o600:
        print("SELF-TEST FAIL: provision log mode is %s, want 0600" % oct(mode), file=sys.stderr)
        bad += 1
    # Red: remove the protections from a copy; the same probe must now leak.
    regressed = "\n".join(
        ln for ln in tpl.splitlines()
        if ln.strip() not in ("set +x", "set +x   # #4609: no xtrace of the userlist credential line")
        and "chmod 0600 /var/log/ai-memory-provision.log" not in ln
        and ": >> /var/log/ai-memory-provision.log" not in ln
    ) + "\n"
    rlog, rmode, _ = _run_provision_probe(regressed)
    if DUMMY_PW not in rlog:
        print("SELF-TEST FAIL: regressed provision.sh did not leak the dummy password; the probe is vacuous", file=sys.stderr)
        bad += 1
    return bad


def self_test() -> int:
    bad = 0
    bad += runtime_probe()
    for name, text in RED_PROBES.items():
        if not scan_text("probe.yaml.tpl", text):
            print("SELF-TEST FAIL: red probe %r was not flagged" % name, file=sys.stderr)
            bad += 1
    for name, text in GREEN_PROBES.items():
        got = scan_text("probe.yaml.tpl", text)
        if got:
            print("SELF-TEST FAIL: green probe %r was flagged: %r" % (name, got), file=sys.stderr)
            bad += 1
    if scan_text("scripts/check-docs-no-argv-secrets.py", RED_PROBES["inline"]):
        print("SELF-TEST FAIL: self-exempt path was flagged", file=sys.stderr)
        bad += 1
    # End to end through the file walker, in a scratch dir inside the repo.
    scratch_parent = ROOT / ".local-runs"
    scratch_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(scratch_parent)) as td:
        root = Path(td)
        (root / "bad.md").write_text(RED_PROBES["inline"] + "\n", encoding="utf-8")
        (root / "ok.md").write_text(GREEN_PROBES["file-form"] + "\n", encoding="utf-8")
        hits, scanned = scan_paths(root, ["bad.md", "ok.md"])
        if scanned != 2 or [h[0] for h in hits] != ["bad.md"]:
            print("SELF-TEST FAIL: file walk gave hits=%r scanned=%d" % (hits, scanned), file=sys.stderr)
            bad += 1
        hits, scanned = scan_paths(root, [])
        if scanned != 0:
            print("SELF-TEST FAIL: empty file list scanned something", file=sys.stderr)
            bad += 1
    if bad:
        return 2
    print("PASS: check-docs-no-argv-secrets self-test: %d red probes flagged, %d green probes clean"
          % (len(RED_PROBES), len(GREEN_PROBES)))
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    return run()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
