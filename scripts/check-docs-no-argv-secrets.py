#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#4577 - no credential on a process argv in a tracked file.

Threat model. A process argv is world-readable: ``/proc/<pid>/cmdline`` and
``ps auxww`` show it to every local UID, and a systemd unit (``ExecStart=``,
``Environment=``) is shown to every user by ``systemctl show``. The product
has non-argv channels for the store URL (``AI_MEMORY_STORE_URL_FILE`` first,
then ``AI_MEMORY_STORE_URL``; ``src/store_url.rs`` ``resolve_store_url``), and
libpq clients read ``PGPASSWORD`` / ``PGPASSFILE`` from the environment. So a
tracked doc, unit, template or script must not put a credential on an argv.

What the gate refuses (exit 1):

  * Every text file: a ``--store-url`` argument (the flag name may be split by
    shell quotes, #4693) whose URL carries a credential: a userinfo password
    (``scheme://user:pass@``) or a query key that percent-decodes to
    ``password`` (#4663, #4691).
  * Shell-like files (.sh .bash .tpl .yaml .yml .service .conf): each logical
    line (backslash continuations joined) is split into words with shell
    quoting removed (shlex) and cut into commands at ``; | & ( ) < >``. In
    every command whose words reach a process argv:
      - a postgres URL with a credential in any word, at the word start, after
        ``=`` (``--dbname=<dsn>``, #4690) or inside a ``-c`` script string;
      - a keyword conninfo ``password=<value>`` (``host=h password=x``, #4692);
      - ``-e`` / ``--env`` ``NAME=<value>`` on a docker, podman or nerdctl argv
        where NAME names a password, secret, token or key, or is a ``PW``
        part (``PG_PW``) (#4694);
      - a ``NAME=<value>`` word (also ``--opt=NAME=<value>``) after a wrapper
        that keeps its argv while the child runs or stores it (sudo, doas,
        runuser, timeout, systemd-run, kubectl, oc) where NAME names a
        password, secret, token or API key. ``env NAME=v cmd`` execs in place
        and is treated like an env prefix.
    A systemd ``Environment=`` line carrying a credential URL is refused
    whatever the key spelling (#4689).

Known defects that the rules find in tracked files are listed in PENDING
with their tracking issue: reported, not approved, and a PENDING entry that
matches no hit fails the gate as stale.

Not an argv, so not refused: a variable assignment before the command word
(``PGPASSWORD=x psql``) or after ``export``/``local``/``readonly``/``declare``;
a comment; a line that is only a URL (a file line the script writes); a YAML
``key: value`` mapping line; echo/printf (shell builtins); a redaction token
(an ellipsis, asterisks, ``REDACTED``, ``<redacted>``); a value with no
credential (``"$DSN"``); the argv-only verb ``schema-init`` (#4600).

What the gate does NOT claim:

  * It reads text, not a running shell. A credential assembled at runtime
    (a flag built from variables, ``eval``, a wrapper written over a binary)
    is not seen here. For the two cloud-init templates that class is closed
    by scripts/check-cloud-init-serve-flags.py, which approves every sensitive
    template line from an exact allowlist.
  * A password in a SQL literal inside a ``psql -c`` argument
    (``PASSWORD '...'``) is not modelled here; the cloud-init gate refuses it
    in the templates and lists the do-hive instance as pending #4671.
  * Prose (.md) is checked for ``--store-url`` only; a heredoc body is read as
    commands (stricter, not looser); .tf, .py and .rs sources are checked for
    ``--store-url`` only.
  * changelog.d/, docs/reviews/, docs/handoff/ and CHANGELOG.md are records,
    not recommendations, and are skipped.

Usage:
  scripts/check-docs-no-argv-secrets.py             exit 0 clean, 1 on a hit,
                                                    2 on a scanner fault
  scripts/check-docs-no-argv-secrets.py --self-test prove the rules are red on
                                                    probes and green on
                                                    near-misses
"""
from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent

Hit = Tuple[str, int, str]

# Verbs that offer no non-argv channel. verb -> tracking issue.
ARGV_ONLY_VERBS = {"schema-init": "#4600"}

# Redaction tokens that are not a credential.
REDACTION_TOKENS = ("...", "…", "***", "redacted", "<redacted>", "xxxx")

# Files that quote the patterns on purpose: this gate.
SELF_EXEMPT = {"scripts/check-docs-no-argv-secrets.py"}

# Historical or machine-generated trees where quoted old commands are a record,
# not a recommendation: the changelog fragments and the per-PR review evidence.
SKIP_PREFIXES = ("changelog.d/", "docs/reviews/", "docs/handoff/")
SKIP_FILES = {"CHANGELOG.md"}

# Known defects listed, not approved: (path, text on the hit's logical line,
# tracking issue[, expected hit count, default 1]). An entry claims at most its
# count of hits, so a second matching line is a new failing hit (#4791). A listed hit is reported as PENDING and does not fail the
# gate; an entry that matches no hit is stale and fails it, so the entry must
# go when the defect is fixed.
PENDING = (
    ("deploy/hive-1461/provision/20_pg_age.sh", "-e POSTGRES_PASSWORD='$SU_PW'", "#4762"),
    ("deploy/hive-1461/provision/20_pg_age.sh", "docker exec -i -e PGPASSWORD='$SU_PW'", "#4762"),
    ("deploy/hive-1461/provision/20_pg_age.sh", "exts=\"$(ssh_node \"$ip\" \"docker exec -e PGPASSWORD='$SU_PW'", "#4762"),
)

TEXT_SUFFIXES = {
    ".md", ".html", ".yaml", ".yml", ".tpl", ".sh", ".bash", ".py", ".toml",
    ".txt", ".service", ".conf", ".ini", ".tf", ".tfvars", ".json", ".env",
    ".rs", ".csv", ".cfg", "",
}
SHELL_SUFFIXES = {".sh", ".bash", ".tpl", ".yaml", ".yml", ".service", ".conf"}
MAX_BYTES = 4 * 1024 * 1024

SCHEME = r"[A-Za-z][A-Za-z0-9+.\-]*://"
DSN_SCHEMES = ("postgres://", "postgresql://")

# The serve flag, tolerating shell quotes split into the name (#4693):
# --store-url, --"store-url", --store-'url', --store_url.
FLAG = r"--[\"']*store[\"']*[-_][\"']*url[\"']*"
# A --store-url argument (=, whitespace or backslash-newline), optional quote,
# then the URL up to whitespace or a quote.
ARG_RE = re.compile(FLAG + r"(?:=|(?:\s|\\)+)[\"']?(?P<url>" + SCHEME + r"[^\s\"']+)")

# A postgres URL inside a word: at the word start, after = (an option value or
# a conninfo dbname), or after a separator inside a -c script string.
WORD_URL_RE = re.compile(r"(?:^|[\s=,\[{(\"'])(?P<url>(?:postgres|postgresql)://[^\s,\]\"')]+)", re.I)
# Keyword conninfo password (libpq: password = value, whitespace allowed).
CONNINFO_PW_RE = re.compile(r"(?:^|[\s-])password\s*=\s*(?P<pw>'[^']*'|\S+)", re.I)
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
UNIT_EXEC_RE = re.compile(r"^(?:Exec[A-Za-z]*)=[-@+!:]*")
UNIT_ENV_RE = re.compile(r"^\s*Environment\s*=", re.I)
SECRET_NAME_RE = re.compile(r"pass|secret|token|key|cred|(?:^|_)pw(?:_|$)|pwd|auth", re.I)
# Wrappers whose NAME=value words are their own argv, not a shell env prefix.
# A name that holds a location, not the secret itself (AI_MEMORY_KEY_DIR).
LOCATOR_NAME_RE = re.compile(r"_(?:DIR|FILE|PATH|ID)$", re.I)
ENV_WRAPPERS = {"env", "sudo", "doas", "runuser", "su"}
# A NAME=value word on the argv of a wrapper that stays resident while its child
# runs (sudo/doas/runuser/timeout keep their argv; systemd-run and kubectl store
# it in a unit or pod spec): sudo PGPASSWORD=v psql, kubectl run --env=NAME=v.
RESIDENT_WRAPPERS = {"sudo", "doas", "runuser", "timeout", "systemd-run", "kubectl", "oc"}
ARGV_ASSIGN_RE = re.compile(r"^(?:--?[A-Za-z][\w-]*=)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.+)$")
ARGV_SECRET_NAME_RE = re.compile(r"passw|passwd|(?:^|_)pg?pass(?:$|_)|secret|token|api_?key|(?:^|_)pw(?:$|_)", re.I)

DECLARE_BUILTINS = {"export", "local", "readonly", "declare", "typeset"}
BUILTIN_PRINTERS = {"echo", "printf"}
CONTAINER_CLIS = {"docker", "podman", "nerdctl"}
SEPARATORS = set(";|&()<>")


def is_redaction(value: str) -> bool:
    low = value.lower()
    return any(tok in low for tok in REDACTION_TOKENS)


def url_credential(url: str) -> str:
    """The credential a URL carries: the userinfo password, or the value of a
    query key that percent-decodes (case-insensitively) to ``password``
    (libpq and sqlx both decode keys, #4691). '' when there is none or it is
    a redaction token."""
    rest = url.split("://", 1)[1] if "://" in url else url
    authority = re.split(r"[/?#]", rest, 1)[0]
    if "@" in authority:
        userinfo = authority.rsplit("@", 1)[0]
        if ":" in userinfo:
            pw = userinfo.split(":", 1)[1]
            if pw and not is_redaction(pw):
                return pw
    if "?" in rest:
        query = rest.split("?", 1)[1].split("#", 1)[0]
        for pair in query.split("&"):
            key, _, value = pair.partition("=")
            if unquote(key).strip().lower() == "password" and value and not is_redaction(value):
                return value
    return ""


def redact(text: str) -> str:
    """Hide credentials in a reported snippet: never print a secret."""
    text = re.sub(r"(://[^\s/@:\"']*:)[^\s/@\"']+@", r"\1***@", text)
    text = re.sub(r"(?i)((?:password|%70assword|pass\w*|secret\w*|token\w*)\s*=\s*)[^\s&\"']+", r"\1***", text)
    return text[:140]


def verb_allowed(words: List[str]) -> str:
    joined = " ".join(words)
    for verb, ref in ARGV_ONLY_VERBS.items():
        if re.search(r"(?<![\w-])" + re.escape(verb) + r"(?![\w-])", joined):
            return ref
    return ""


def window_verb_allowed(text: str, start: int) -> str:
    """For prose: the verb owning a --store-url is the text since the last
    blank line (or 400 characters), so a continuation line still sees it."""
    window = text[max(0, start - 400):start].rsplit("\n\n", 1)[-1]
    for verb, ref in ARGV_ONLY_VERBS.items():
        if re.search(r"(?<![\w-])" + re.escape(verb) + r"(?![\w-])", window):
            return ref
    return ""


def logical_lines(text: str) -> List[Tuple[int, str]]:
    """Join backslash-newline continuations; keep each start line number."""
    out: List[Tuple[int, str]] = []
    buf: List[str] = []
    start = 0
    for no, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start = no
        stripped = raw.rstrip()
        if stripped.endswith("\\") and not stripped.endswith("\\\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(raw)
        out.append((start, " ".join(buf)))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def split_words(line: str) -> List[str]:
    """Shell words with quoting removed, separators as their own words. An
    unbalanced line (a YAML scalar, a fragment) falls back to whitespace words
    with quote characters stripped, so it is still scanned (fail closed)."""
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        words: List[str] = []
        for w in line.split():
            if w.startswith("#"):
                break
            words.append(w.replace('"', "").replace("'", ""))
        return words


def commands(words: List[str]) -> List[List[str]]:
    out: List[List[str]] = []
    cur: List[str] = []
    for w in words:
        if w and all(c in SEPARATORS for c in w):
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(w)
    if cur:
        out.append(cur)
    return out


def argv_words(cmd: List[str]) -> List[str]:
    """The words of one command that reach a process argv, or [] when none do
    (a declaration builtin, echo/printf, a bare assignment, a YAML key line,
    a line that is only a URL)."""
    i = 0
    while i < len(cmd) and cmd[i] == "-":  # a YAML list item marker
        i += 1
    if i < len(cmd) and UNIT_EXEC_RE.match(cmd[i]):
        first = UNIT_EXEC_RE.sub("", cmd[i])
        cmd = ([first] if first else []) + cmd[i + 1:]
        i = 0
    while i < len(cmd) and ASSIGN_RE.match(cmd[i]):
        i += 1  # env prefix of the command: environment, not argv
    rest = cmd[i:]
    if not rest:
        return []
    head = rest[0]
    if head.endswith(":") or head.lower().startswith(DSN_SCHEMES):
        return []  # a YAML mapping key, or a URL line the script writes
    if head in DECLARE_BUILTINS or head in BUILTIN_PRINTERS:
        return []
    return rest


def container_env_hits(words: List[str]) -> List[str]:
    """#4694: -e/--env NAME=<value> on a container CLI argv."""
    found: List[str] = []
    in_cli = False
    i = 0
    while i < len(words):
        w = words[i]
        if Path(w).name in CONTAINER_CLIS:
            in_cli = True
        elif in_cli:
            val: Optional[str] = None
            if w in ("-e", "--env") and i + 1 < len(words):
                val = words[i + 1]
                i += 1
            elif w.startswith("--env="):
                val = w[len("--env="):]
            elif w.startswith("-e") and len(w) > 2 and not w.startswith("--"):
                val = w[2:]
            if val is not None and "=" in val:
                name, _, value = val.partition("=")
                if (SECRET_NAME_RE.search(name) or ARGV_SECRET_NAME_RE.search(name)) and value and not is_redaction(value):
                    found.append(name)
        i += 1
    return found


def word_hits(words: List[str], depth: int = 0) -> List[str]:
    reasons: List[str] = []
    if depth < 3:
        # A word that is itself a command string (sh -c "...", ssh host "...")
        # is scanned as commands too.
        for w in words[1:]:
            if any(c.isspace() for c in w):
                for cmd in commands(split_words(w)):
                    reasons.extend(command_hits(cmd, depth + 1))
    for w in words:
        for m in WORD_URL_RE.finditer(w):
            if url_credential(m.group("url")):
                reasons.append("credential URL")
        for m in CONNINFO_PW_RE.finditer(w):
            pw = m.group("pw").strip("'")
            if pw and not is_redaction(pw) and not pw.startswith(("://",)):
                reasons.append("conninfo password")
    reasons.extend("container env %s" % n for n in container_env_hits(words))
    reasons.extend("wrapper env %s" % n for n in wrapper_env_hits(words))
    resident = False
    for w in words:
        if Path(w).name in RESIDENT_WRAPPERS:
            resident = True
            continue
        m = ARGV_ASSIGN_RE.match(w) if resident else None
        if m and ARGV_SECRET_NAME_RE.search(m.group("name")) and not is_redaction(m.group("value")):
            reasons.append("NAME=value on a resident wrapper argv %s" % m.group("name"))
    return reasons


def wrapper_env_hits(words: List[str]) -> List[str]:
    """env/sudo NAME=<value>: the assignment is an argv word of the wrapper,
    so /proc/<pid>/cmdline of env or sudo shows it to every local UID."""
    found: List[str] = []
    in_wrapper = False
    for w in words:
        if Path(w).name in ENV_WRAPPERS:
            in_wrapper = True
            continue
        if in_wrapper and ASSIGN_RE.match(w):
            name, _, value = w.partition("=")
            if (SECRET_NAME_RE.search(name) and not LOCATOR_NAME_RE.search(name)
                    and value and not is_redaction(value)):
                found.append(name)
    return found


def command_hits(cmd: List[str], depth: int = 0) -> List[str]:
    """Reasons one command puts a credential on an argv. A command
    substitution in an assignment value (X="$(docker exec -e ...)") runs a
    command, so the value is scanned as commands too."""
    reasons: List[str] = []
    if depth < 3:
        for k, w in enumerate(cmd):
            if not ASSIGN_RE.match(w):
                break
            value = w.split("=", 1)[1]
            if "$(" in value or "`" in value:
                # Quote removal may have glued the substitution to the words
                # after it; the substitution text runs to the end of the command.
                text = " ".join([value] + cmd[k + 1:]).replace("`", " ")
                for inner in commands(split_words(text)):
                    reasons.extend(command_hits(inner, depth + 1))
    words = argv_words(cmd)
    if words and not verb_allowed(words):
        reasons.extend(word_hits(words, depth))
    return reasons


def shell_hits(rel: str, text: str) -> List[Hit]:
    hits: List[Hit] = []
    raw_lines = text.splitlines()
    for no, line in logical_lines(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if UNIT_ENV_RE.match(stripped):
            body = UNIT_ENV_RE.sub("", stripped, 1)
            if any(url_credential(m.group("url")) for m in WORD_URL_RE.finditer(" " + body)):
                hits.append((rel, no, redact(raw_lines[no - 1].strip())))
            continue
        if any(command_hits(cmd) for cmd in commands(split_words(line))):
            hits.append((rel, no, redact(raw_lines[no - 1].strip())))
    return hits


def flag_hits(rel: str, text: str) -> List[Hit]:
    hits: List[Hit] = []
    lines = text.splitlines()
    for m in ARG_RE.finditer(text):
        if not url_credential(m.group("url")) or window_verb_allowed(text, m.start()):
            continue
        line = text.count("\n", 0, m.start()) + 1
        hits.append((rel, line, redact(lines[line - 1].strip()) if lines else ""))
    return hits


def scan_text(rel: str, text: str) -> List[Hit]:
    if rel in SELF_EXEMPT:
        return []
    hits = flag_hits(rel, text)
    if Path(rel).suffix.lower() in SHELL_SUFFIXES:
        seen = {h[:2] for h in hits}
        hits.extend(h for h in shell_hits(rel, text) if h[:2] not in seen)
    return hits


def tracked_files() -> List[str]:
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


def scan_paths(root: Path, files: List[str]) -> Tuple[List[Hit], int]:
    hits: List[Hit] = []
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


def split_pending(root: Path, hits: List[Hit], pending=PENDING) -> Tuple[List[Hit], List[str], List[str]]:
    """(failing hits, pending report lines, stale entry lines). An entry
    claims the hits whose logical line in that file contains its text."""
    texts = {}
    claimed = set()
    listed: List[str] = []
    stale: List[str] = []
    for entry in pending:
        rel, needle, issue = entry[0], entry[1], entry[2]
        count = entry[3] if len(entry) > 3 else 1
        if rel not in texts:
            p = root / rel
            texts[rel] = dict(logical_lines(p.read_text(encoding="utf-8"))) if p.is_file() else {}
        matched = [h for h in hits if h[0] == rel and needle in texts[rel].get(h[1], "")]
        if not matched:
            stale.append("%s %s: %s" % (rel, issue, redact(needle)))
        for h in matched[:count]:
            claimed.add(h)
            listed.append("%s:%d %s" % (h[0], h[1], issue))
    return [h for h in hits if h not in claimed], listed, stale


def run() -> int:
    try:
        files = tracked_files()
        hits, scanned = scan_paths(ROOT, files)
        hits, listed, stale = split_pending(ROOT, hits)
    except (RuntimeError, OSError, UnicodeDecodeError) as exc:
        print("FAIL: check-docs-no-argv-secrets: scanner fault: %s" % exc, file=sys.stderr)
        return 2
    if scanned == 0:
        print("FAIL: check-docs-no-argv-secrets: scanned 0 files; refusing to pass", file=sys.stderr)
        return 2
    for item in listed:
        print("PENDING %s" % item)
    for item in stale:
        print("STALE pending entry (matches no hit; remove it): %s" % item, file=sys.stderr)
    if stale and not hits:
        print("FAIL: check-docs-no-argv-secrets: %d stale pending entr(ies)" % len(stale), file=sys.stderr)
        return 1
    if hits:
        for rel, line, snippet in hits:
            print("HIT %s:%d: %s" % (rel, line, snippet), file=sys.stderr)
        print(
            "FAIL: check-docs-no-argv-secrets: %d tracked line(s) put a credential on a process "
            "argv (#4577). Use AI_MEMORY_STORE_URL_FILE (a 0600 file) or the PGPASSWORD "
            "environment; see docs/CLI_REFERENCE.md." % len(hits),
            file=sys.stderr,
        )
        return 1
    print("PASS: check-docs-no-argv-secrets: %d files scanned, 0 argv credentials, %d pending (listed, not approved)"
          % (scanned, len(listed)))
    return 0


# Probe strings avoid a literal flag-plus-DSN in this file: the flag is built.
SU = "--store-" + "url"
PW = "ProbePlaceholder1"

RED_PROBES = {
    "inline": "ai-memory serve %s postgres://u:%s@h:5432/d" % (SU, PW),
    "equals": "ai-memory serve %s=postgres://u:%s@h/d" % (SU, PW),
    "quoted": 'ExecStart=/bin/ai-memory serve %s "postgres://u:${db_password}@h/d"' % SU,
    "single-quoted": "x serve %s 'postgresql://u:p%%40ss@h/d?sslmode=require'" % SU,
    "shell-var": "ssh h \"ai-memory serve %s 'postgres://u:$PG_PW@h/d'\"" % SU,
    "continuation": "ai-memory serve \\\n  %s \\\n  postgres://u:%s@h/d" % (SU, PW),
    "other-verb": "ai-memory curator %s postgres://u:%s@h/d" % (SU, PW),
    "4663 password= query parameter": 'ai-memory serve %s "postgres://u@h/d?sslmode=verify-full&password=%s"' % (SU, PW),
    "4663 password= query parameter, = form": "ai-memory serve %s=postgres://u@h/d?password=%s" % (SU, PW),
    "4691 percent-encoded password key": "ai-memory serve %s 'postgres://u@h/d?%%70assword=%s'" % (SU, PW),
    "4691 upper-case encoded key": "ai-memory serve %s 'postgres://u@h/d?PASS%%57ORD=%s'" % (SU, PW),
    "4693 quote-split flag name": "ai-memory serve --store-\"url\" postgres://u:%s@h/d" % PW,
    "4693 single-quote-split flag name": "ai-memory serve --'store'-url postgres://u:%s@h/d" % PW,
}
# Shell-like files (probe.sh): a credential on another program's argv.
RED_SHELL_PROBES = {
    "r3 env NAME=value: env's own argv holds the value (security A11, #4792; the code verdict's A18 expected green, the stricter result wins)": "env PGPASSWORD=\"$PW\" psql -h h",
    "r3 sudo NAME=value keeps the password on the sudo argv": "sudo PGPASSWORD=%s psql -h h -U u d" % PW,
    "r3 runuser -- env NAME=value": "runuser -u postgres -- env PGPASSWORD=%s psql -h h" % PW,
    "r3 kubectl run --env=NAME=value": "kubectl run t --image=i --env=PGPASSWORD=%s" % PW,
    "r3 docker -e abbreviated PG_PW name": "docker run --rm -e PG_PW=%s img" % PW,
    "4663 psql with a ${VAR} password": 'psql "postgres://aimemory:$DB_PASS@localhost/aimemory" -c "select 1"',
    "4663 psql with a literal password": "psql postgres://u:%s@h/d -c x" % PW,
    "4663 psql with a password= query parameter": 'psql "postgres://u@h/d?sslmode=verify-full&password=%s"' % PW,
    "4663 psql inside a docker exec line": 'docker exec c psql "postgres://u:${PW}@pgbouncer:6432/db" -tA',
    "4663 pg_dump continued onto the next line": 'pg_dump \\\n  "postgres://u:$PW@h/d"',
    "4690 pg_dump --dbname= form": "pg_dump --dbname=postgres://u:%s@h/d -f out" % PW,
    "4690 pg_isready -d= quoted": "pg_isready \"-d=postgresql://u:$PW@h/d\"",
    "4691 psql percent-encoded password key": "psql 'postgres://u@h/d?%%70assword=%s'" % PW,
    "4692 keyword conninfo": "psql \"host=h user=u password=$DB_PASS dbname=d\" -c x",
    "4692 keyword conninfo with spaces around =": "pg_dump 'host=h password = %s dbname=d'" % PW,
    "4692 conninfo inside sh -c": "sudo -u x sh -c \"psql 'host=h password=%s'\"" % PW,
    "4694 docker exec -e PGPASSWORD=value": 'docker exec -e PGPASSWORD="$PW" c psql -c x',
    "4694 docker run --env=NAME=value": "docker run --env=POSTGRES_PASSWORD=%s img" % PW,
    "4694 podman -eNAME=value": "sudo podman run -eDB_SECRET=%s img" % PW,
    "4693 env wrapper puts the DSN on argv": "env AI_MEMORY_STORE_URL=postgres://u:%s@h/d ai-memory serve" % PW,
    "4693 nohup launch with a quote-split flag": "nohup ai-memory serve --store-\"url\" \"postgres://u:$PW@h/d\" &",
    "4689 unit Environment= with a space before =": "Environment=AI_MEMORY_STORE_URL =postgres://u:%s@h/d" % PW,
    "4689 unit Environment= quoted": "Environment=\"AI_MEMORY_STORE_URL=postgres://u@h/d?password=%s\"" % PW,
    "command substitution in an assignment": "exts=\"$(ssh h \"docker exec -e PGPASSWORD='$X' c psql\")\"",
    "unit ExecStartPre psql": "ExecStartPre=-/usr/bin/psql postgres://u:%s@h/d -c x" % PW,
    "yaml runcmd list item": "  - psql postgres://u:%s@h/d -c x" % PW,
}
GREEN_SHELL_PROBES = {
    "r3 sudo with a non-secret NAME=value": "sudo AI_MEMORY_KEY_DIR=/k ai-memory serve",
    "4663 assignment": 'PGURL="postgres://u:$PW@h/d"',
    "4663 exported assignment": "export PGURL=postgres://u:$PW@h/d",
    "env prefix of a command": "PGPASSWORD=\"$PW\" psql postgres://u@h/d -c x",
    "4663 yaml content block line": "      postgres://aimemory:CHANGEME@localhost/aimemory?sslmode=verify-full",
    "4663 yaml mapping value": '      AI_MEMORY_STORE_URL: "postgres://u:p@h/d"',
    "4663 redaction token": "psql postgres://u:REDACTED@h/d",
    "4663 no password": "psql postgres://u@h/d",
    "4663 regex that begins with the scheme": "sed -n 's#^postgres://aimemory:\\([^@]*\\)@.*#\\1#p' /etc/ai-memory/store-url",
    "4663 printf builtin writes a file": "printf 'postgres://u:%s@h/d\\n' \"$PW\" > f",
    "4663 comment": "# psql postgres://u:%s@h/d" % PW,
    "4694 docker -e NAME with no value": "docker exec -e PGPASSWORD c psql -c x",
    "4694 docker -e of a non-secret name": "docker run -e PGHOST=db img",
    "4692 passfile is not a password": "psql 'host=h passfile=/etc/pgpass dbname=d'",
    "4691 a key that only contains password": "psql 'postgres://u@h/d?xpassword=1'",
    "4689 Environment= without a credential": "Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url",
    "argv-only verb": "ai-memory schema-init %s postgres://u:%s@h/d" % (SU, PW),
}
RED_SHELL_PROBES.update({
    # round 3, security reviewer A-series (#4792): wrapper and abbreviated-name forms
    "r3-S docker run --env NAME=val": "docker run --env POSTGRES_PASSWORD=%s img" % PW,
    "r3-S psql with a URL password": "psql \"postgres://u:%s@h/db\" -c 'select 1'" % PW,
    "r3-S ssh host runs psql with a URL password": "ssh host \"psql postgres://u:%s@h/d -c 'select 1'\"" % PW,
    "r3-S mysql --password=": "mysql -u root --password=%s db" % PW,
    "r3-S docker -e DB_PW=": "docker run -e DB_PW=%s img" % PW,
    "r3-S sudo -u postgres PGPASSWORD=x psql": "sudo -u postgres PGPASSWORD=%s psql -h h" % PW,
    "r3-S kubectl --from-literal=password=": "kubectl create secret generic s --from-literal=password=%s" % PW,
    "r3-S conninfo in an ssh string": "ssh h \"psql 'host=h user=u password=%s'\"" % PW,
    "r3-S docker run -e via $(...) assignment": "X=$(docker run -e POSTGRES_PASSWORD=%s img)" % PW,
    "r3-S podman --env=TOKEN": "podman run --env=API_TOKEN=%s img" % PW,
    "r3-S xargs-fed docker": "echo img | xargs docker run -e POSTGRES_PASSWORD=%s" % PW,
    # round 3, code reviewer A-series
    "r3-C psql DSN double-quoted": 'psql "postgresql://u:%s@h/d" -c "SELECT 1"' % PW,
    "r3-C psql DSN with a split scheme": "psql 'postgres''ql://u:%s@h/d'" % PW,
    "r3-C store flag split by quotes, = form": "ai-memory serve --'store'-url=postgres://u:%s@h/d" % PW,
    "r3-C docker run -e K=V": "docker run --rm -e PGPASSWORD=%s img" % PW,
    "r3-C docker run --env=K=V": "docker run --rm --env=DB_PASSWORD=%s img" % PW,
    "r3-C docker run -eK=V glued": "docker run --rm -eAPI_TOKEN=%s img" % PW,
    "r3-C docker -e STORE_URL=DSN": 'docker run -e "AI_MEMORY_STORE_URL=postgres://u:%s@h/d" img' % PW,
    "r3-C psql keyword conninfo": 'psql "host=h dbname=d user=u password=%s"' % PW,
    "r3-C psql query password key, encoded": 'psql "postgresql://u@h/d?pass%%77ord=%s"' % PW,
    "r3-C ssh remote command string with a DSN": 'ssh host "psql postgresql://u:%s@h/d -c \'SELECT 1\'"' % PW,
    "r3-C ssh unquoted remote docker -e": "ssh host docker exec -e PGPASSWORD=%s c psql" % PW,
    "r3-C bash -c wrapping docker -e": 'bash -c "docker run -e PGPASSWORD=%s img"' % PW,
    "r3-C substitution in an assignment runs docker -e": 'OUT="$(docker exec -e PGPASSWORD=%s c psql)"' % PW,
    "r3-C a variable password is still a credential on argv": 'psql "postgresql://u:$PW@h/d"',
    "r3-C backslash continuation splitting docker -e": "docker run --rm \\\n  -e PGPASSWORD=%s \\\n  img" % PW,
    "r3-C YAML list item with an ExecStart DSN": "  - ExecStart=/usr/bin/x %s postgres://u:%s@h/d" % (SU, PW),
})
GREEN_SHELL_PROBES.update({
    "r3-S docker run --env-file": "docker run --env-file ./pg.env img",
    "r3-S PGPASSWORD=x psql (environment, not argv)": "PGPASSWORD=%s psql -h h -U u" % PW,
    "r3-S docker exec -e PGPASSWORD (bare name)": "docker exec -e PGPASSWORD c psql -U u",
    "r3-C here-string carries a DSN on stdin": 'psql -f - <<< "postgresql://u:%s@h/d"' % PW,
    "r3-C docker run -e bare name": "docker run --rm -e PGPASSWORD img",
    "r3-C redaction token ***": 'psql "postgresql://u:***@h/d"',
    "r3-C echo of a DSN (builtin, no argv)": 'echo "postgresql://u:%s@h/d" > f' % PW,
})
GREEN_PROBES = {
    "file-form": "AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url ai-memory serve",
    "no-password": "ai-memory serve %s postgres://u@h/d" % SU,
    "no-userinfo": "ai-memory serve %s postgres://h:5432/d" % SU,
    "shell-expansion": 'ai-memory keys %s "$AI_MEMORY_STORE_URL" prune' % SU,
    "ellipsis": "ai-memory serve %s postgres://aimemory:...@10.0.0.4:5432/db" % SU,
    "redacted": "ai-memory serve %s postgres://aimemory:REDACTED@h/db" % SU,
    "ellipsis-char": "ai-memory serve %s postgres://user:…@h/db" % SU,
    "lookalike-flag": "wake_abab.sh %s-src postgres://u:p@h/d" % SU,
    "prose-mention": "the `serve %s` connection URL (e.g. postgres://user:pass@host/db)" % SU,
    "argv-only-verb": "ai-memory schema-init %s postgres://u:%s@h/d" % (SU, PW),
    "argv-only-verb-continued": "ai-memory schema-init \\\n  %s postgres://u:%s@h/d" % (SU, PW),
}


def self_test() -> int:
    bad = 0
    red = green = 0
    for name, text in RED_PROBES.items():
        red += 1
        if not scan_text("probe.md", text):
            print("SELF-TEST FAIL: red probe %r was not flagged" % name, file=sys.stderr)
            bad += 1
    for name, text in GREEN_PROBES.items():
        green += 1
        if scan_text("probe.md", text):
            print("SELF-TEST FAIL: green probe %r was flagged" % name, file=sys.stderr)
            bad += 1
    for suffix in (".sh", ".tpl", ".service"):
        for name, text in RED_SHELL_PROBES.items():
            red += 1
            if not scan_text("probe" + suffix, text):
                print("SELF-TEST FAIL: red shell probe %r (%s) was not flagged" % (name, suffix), file=sys.stderr)
                bad += 1
        for name, text in GREEN_SHELL_PROBES.items():
            green += 1
            if scan_text("probe" + suffix, text):
                print("SELF-TEST FAIL: green shell probe %r (%s) was flagged" % (name, suffix), file=sys.stderr)
                bad += 1
    red += 1
    if scan_text("probe.md", RED_SHELL_PROBES["4663 psql with a literal password"]):
        print("SELF-TEST FAIL: a prose file (.md) was read as a shell file", file=sys.stderr)
        bad += 1
    red += 1
    if scan_text("scripts/check-docs-no-argv-secrets.py", RED_PROBES["inline"]):
        print("SELF-TEST FAIL: self-exempt path was flagged", file=sys.stderr)
        bad += 1
    # A reported snippet never carries the placeholder secret.
    red += 1
    reported = scan_text("probe.sh", RED_SHELL_PROBES["4692 keyword conninfo with spaces around ="])
    reported += scan_text("probe.md", RED_PROBES["inline"])
    reported += scan_text("probe.sh", RED_SHELL_PROBES["4694 docker run --env=NAME=value"])
    if len(reported) != 3 or any(PW in h[2] for h in reported):
        print("SELF-TEST FAIL: a hit snippet is missing or prints the secret: %r" % reported, file=sys.stderr)
        bad += 1
    # End to end through the file walker, in a scratch dir inside the repo.
    scratch_parent = ROOT / ".local-runs"
    scratch_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(scratch_parent)) as td:
        root = Path(td)
        (root / "bad.md").write_text(RED_PROBES["inline"] + "\n", encoding="utf-8")
        (root / "ok.md").write_text(GREEN_PROBES["file-form"] + "\n", encoding="utf-8")
        (root / "bad.sh").write_text(RED_SHELL_PROBES["4690 pg_dump --dbname= form"] + "\n", encoding="utf-8")
        hits, scanned = scan_paths(root, ["bad.md", "ok.md", "bad.sh"])
        red += 1
        if scanned != 3 or sorted(h[0] for h in hits) != ["bad.md", "bad.sh"]:
            print("SELF-TEST FAIL: file walk gave hits=%r scanned=%d" % (hits, scanned), file=sys.stderr)
            bad += 1
        # A pending entry claims its hit; an entry with no hit is stale.
        sh_hits, _ = scan_paths(root, ["bad.sh"])
        left, listed, stale = split_pending(root, sh_hits, (("bad.sh", "pg_dump --dbname=", "#0"),))
        red += 1
        if left or len(listed) != 1 or stale:
            print("SELF-TEST FAIL: pending entry did not claim its hit", file=sys.stderr)
            bad += 1
        left, listed, stale = split_pending(root, [], (("bad.sh", "pg_dump --dbname=", "#0"),))
        red += 1
        if len(stale) != 1:
            print("SELF-TEST FAIL: stale pending entry was not reported", file=sys.stderr)
            bad += 1
        # #4791: an entry claims its expected count of hits, not every matching line.
        (root / "two.sh").write_text(
            RED_SHELL_PROBES["4690 pg_dump --dbname= form"] + "\n" + RED_SHELL_PROBES["4690 pg_dump --dbname= form"] + "\n",
            encoding="utf-8")
        two_hits, _ = scan_paths(root, ["two.sh"])
        left, listed, stale = split_pending(root, two_hits, (("two.sh", "pg_dump --dbname=", "#0"),))
        red += 1
        if len(two_hits) != 2 or len(left) != 1 or len(listed) != 1 or stale:
            print("SELF-TEST FAIL: a pending entry claimed more hits than its count (#4791)", file=sys.stderr)
            bad += 1
        left, listed, stale = split_pending(root, two_hits, (("two.sh", "pg_dump --dbname=", "#0", 2),))
        green += 1
        if left or len(listed) != 2 or stale:
            print("SELF-TEST FAIL: a pending entry with count 2 did not claim both hits (#4791)", file=sys.stderr)
            bad += 1
        _, scanned = scan_paths(root, [])
        red += 1
        if scanned != 0:
            print("SELF-TEST FAIL: empty file list scanned something", file=sys.stderr)
            bad += 1
    if bad:
        print("SELF-TEST FAIL: %d case(s) wrong" % bad, file=sys.stderr)
        return 2
    print("PASS: check-docs-no-argv-secrets self-test: %d red cases flagged, %d green cases clean"
          % (red, green))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Refuse a credential on a process argv in a tracked file (#4577).")
    parser.add_argument("--self-test", action="store_true",
                        help="run the red/green probe set instead of the repository scan")
    return parser


def main(argv: List[str]) -> int:
    try:
        args = build_parser().parse_args(argv[1:])
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.self_test:
        return self_test()
    return run()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
