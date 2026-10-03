#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#4577 / #4600 / #4603 / #4604 / #4609 / #4617 / #4689-#4694 - no credential on a
process argv, and no secret in a readable file, in a tracked file.

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

List-form argv (#4614): a compose ``command:`` array, a Kubernetes ``args:`` list
or a JSON argv array puts the flag and its value in separate items
(``"--store-url", "postgres://u:pw@h/d"``); the flag-to-value separator accepts
quotes, commas, newlines and a YAML ``- `` marker, so those are refused too.
``migrate --from`` / ``--to`` take URLs on argv (#4600): a credential URL after
either flag is refused (fail closed: whatever command owns it, a credential on an
argv is exposed). The sanctioned forms are ``--from-url-file`` / ``--to-url-file``.

Argv secret forms (#4813-#4819), on every text file: a literal secret on the argv
of ``curl -u user:literal`` (#4813), ``mysql``/``mysqldump``/``mariadb`` ``-pLITERAL`` or
``--password=LITERAL`` (#4814), ``sshpass -p LITERAL`` (#4815), ``redis-cli -a LITERAL``
or ``--pass LITERAL`` (#4816), ``psql -v pw=LITERAL`` for a password-named variable
(#4817), a ``curl -H 'Authorization: Bearer LITERAL'`` header (#4818) and
``docker login -p LITERAL`` / ``--password LITERAL`` (#4819). A placeholder is not
a secret and stays clean: a shell variable reference or command substitution
(``$PW``, ``${PW}``, ``$(cat f)``), an angle-bracket or brace placeholder, a redaction
token, or an obviously fake word (CHANGEME, PASSWORD, xxxx, YOUR_PASSWORD). The
sanctioned forms are stdin / file channels (``curl --netrc-file``, ``MYSQL_PWD``,
``sshpass -f``, ``REDISCLI_AUTH``, ``docker login --password-stdin``). A hit never
prints the secret: it reports the form, and the file and line locate it. These seven
rules extend the gate by the existing pattern (one rule plus red and green probes
per form), so no crossroads vote applies.

Rules from the #4600 line of work (text rules, also run on every shell-like or
template file):

  store-url-expansion  ``--store-url`` followed by an ``AI_MEMORY_STORE_URL`` or
                     DSN/URL-named variable expansion: the shell or systemd
                     expands the secret onto argv at run time (#4603). A
                     ``_FILE`` variable is the sanctioned channel.
  psql-password-argv  a ``psql`` line with ``-c`` / ``--command`` whose SQL text
                     carries ``PASSWORD '<value>'`` (#4604). Feed the statement
                     from a 0600 file on stdin.
  env-password-argv  ``docker run/exec -e PGPASSWORD=$X`` / ``-e
                     POSTGRES_PASSWORD=$X`` or ``psql -v pw=$X`` (#4617).
                     ``-e NAME`` with no value and ``--env-file`` are the
                     sanctioned forms.
  cloud-init-readable-secret  a cloud-init ``write_files`` entry left group or
                     world readable (or with no ``permissions``) whose content
                     interpolates a ``${..password|secret|token|key|cred..}``
                     template variable (#4604).
  xtrace-secret      a line that expands a password-named variable while xtrace
                     is on and not switched off by ``set +x`` (#4609). The
                     ``--self-test`` also runs the #4609 runtime probe: it
                     executes the credential-handling lines of the do-hive
                     ``provision.sh`` with a dummy password and proves the
                     provision log never contains it and is mode 0600.

``schema-init`` is no longer an argv-only verb: it resolves
``AI_MEMORY_STORE_URL_FILE`` then ``AI_MEMORY_STORE_URL`` (#4600), so an inline
credential on its ``--store-url`` is refused like any other verb's.

Known defects that the rules find in tracked files are listed in PENDING
with their tracking issue: reported, not approved, and a PENDING entry that
matches no hit fails the gate as stale.

Not an argv, so not refused: a variable assignment before the command word
(``PGPASSWORD=x psql``) or after ``export``/``local``/``readonly``/``declare``;
a comment; a line that is only a URL (a file line the script writes); a YAML
``key: value`` mapping line; echo/printf (shell builtins); a redaction token
(an ellipsis, asterisks, ``REDACTED``, ``<redacted>``); a value with no
credential (``"$DSN"``).

What the gate does NOT claim:

  * It reads text, not a running shell. A credential assembled at runtime
    (a flag built from variables, ``eval``, a wrapper written over a binary)
    is not seen here. For the two cloud-init templates that class is closed
    by scripts/check-cloud-init-serve-flags.py, which approves every sensitive
    template line from an exact allowlist.
  * Prose (.md) is checked for ``--store-url`` only; a heredoc body is read as
    commands (stricter, not looser); .tf, .py and .rs sources are checked for
    ``--store-url`` only.
  * Nothing is skipped by path: changelog.d/, docs/reviews/, docs/handoff/ and
    CHANGELOG.md are scanned like every other tracked file (#4615), because a
    credential is no less exposed for sitting in a record. A text file over
    MAX_BYTES or not valid UTF-8 cannot be read here; the PASS line counts those
    so the skip is visible.

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

# Redaction tokens that are not a credential.
REDACTION_TOKENS = ("...", "…", "***", "redacted", "<redacted>", "xxxx")
# A whole value made of one filler character ("xxxx", "****", "......").
FILLER_RE = re.compile(r"(?:x{3,}|\*{3,}|\.{3,}|…+|_{3,}|-{3,})", re.I)

# Files that quote the patterns on purpose: this gate.
SELF_EXEMPT = {"scripts/check-docs-no-argv-secrets.py"}

# No path is skipped (#4615). If a historical file ever needs an exemption, add a
# path entry here that names its tracking issue and is proven load-bearing by the
# self-test.

# Known defects listed, not approved: (path, text on the hit's logical line,
# tracking issue[, expected hit count, default 1]). An entry claims at most its
# count of hits, so a second matching line is a new failing hit (#4791). A listed hit is reported as PENDING and does not fail the
# gate; an entry that matches no hit is stale and fails it, so the entry must
# go when the defect is fixed.
PENDING = ()

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
# Flag-to-value separator: =, whitespace, backslash-newline, and the list-form
# glue (a closing quote, a comma, a newline, a YAML "- " item marker, #4614).
SEP = r"(?:[=\s,\\])+(?:-\s+)?"
# A --store-url argument, optional quote, then the URL up to whitespace or a quote.
ARG_RE = re.compile(FLAG + SEP + r"[\"']?(?P<url>" + SCHEME + r"[^\s\"']+)")
# migrate --from / --to take a URL on argv (#4600, #4614). --from-url-file and
# --to-url-file are the sanctioned forms and do not match.
MIGRATE_ARG_RE = re.compile(
    r"--(?:from|to)(?![\w-])[\"']?" + SEP + r"[\"']?(?P<url>" + SCHEME + r"[^\s\"']+)")

# #4603: a runtime expansion of the store-URL env var, or of any variable named
# like a DSN / URL, straight after the flag. A `_FILE` variable is the
# sanctioned channel and is not matched.
EXPANSION_RE = re.compile(
    FLAG + SEP + r"[\"']?\\*\$\{?[A-Za-z0-9_]*(?:DSN|URL)(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
# #4609: xtrace echoes every expanded command, so a credential-bearing line
# must sit between `set +x` and `set -x`.
XTRACE_ON_RE = re.compile(r"^\s*set\s+-[a-z]*x")
XTRACE_OFF_RE = re.compile(r"^\s*set\s+\+[a-z]*x")
TRACED_SECRET_RE = re.compile(
    r"\$\{?(?:[A-Za-z0-9_]*(?:password|passwd|secret|token|_pw)|pw)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
# #4604: a password literal in a psql -c / --command SQL string.
PSQL_ARGV_RE = re.compile(
    r"\bpsql\b[^\n]*?\s(?:-c|--command)(?:=|\s)\s*[\"'][^\n]*?\bPASSWORD\s+\\?'(?P<pw>[^'\s]+)",
    re.IGNORECASE,
)
# #4617: a runtime-expanded password on a docker -e / psql -v argv word.
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
    """True when the WHOLE value is a redaction token (#4612). A real password
    that merely contains "..." or "***" is a credential, not a redaction."""
    low = value.strip().strip("'\"").lower()
    return low in REDACTION_TOKENS or bool(FILLER_RE.fullmatch(low))


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
            if unquote(key).strip().lower() in ("password", "sslpassword") and value and not is_redaction(value):
                return value
    return ""


def redact(text: str) -> str:
    """Hide credentials in a reported snippet: never print a secret."""
    text = re.sub(r"(://[^\s/@:\"']*:)[^\s/@\"']+@", r"\1***@", text)
    text = re.sub(r"(?i)((?:password|%70assword|pass\w*|secret\w*|token\w*)\s*=\s*)[^\s&\"']+", r"\1***", text)
    return text[:140]


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
    if words:
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
        if not url_credential(m.group("url")):
            continue
        line = text.count("\n", 0, m.start()) + 1
        hits.append((rel, line, redact(lines[line - 1].strip()) if lines else ""))
    for m in MIGRATE_ARG_RE.finditer(text):
        if not url_credential(m.group("url")):
            continue
        line = text.count("\n", 0, m.start()) + 1
        hits.append((rel, line, "[migrate-argv-url] " + (redact(lines[line - 1].strip()) if lines else "")))
    return hits


def _line_of(text: str, pos: int) -> Tuple[int, str]:
    line = text.count("\n", 0, pos) + 1
    snippet = text.splitlines()[line - 1].strip() if text else ""
    return line, redact(snippet)


def scan_write_files(rel: str, text: str) -> List[Hit]:
    """cloud-init write_files entries that interpolate a secret into a file
    left group/world readable (#4604)."""
    hits: List[Hit] = []
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
        body: List[Tuple[int, str]] = []
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


def scan_xtrace(rel: str, text: str) -> List[Hit]:
    """Credential-bearing lines executed while xtrace is on (#4609)."""
    hits: List[Hit] = []
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


# --- #4813-#4819: a literal secret on the argv of a well-known client ----------
# A placeholder is not a secret: a variable reference or substitution, an
# angle-bracket or brace placeholder, a redaction token, or an obviously fake word.
FAKE_WORD_RE = re.compile(
    r"(?:(?:your|my)[-_ ]?)?(?:password|passwd|pw)(?:[-_ ]?here)?|change[-_]?me|placeholder|dummy|fake|example",
    re.I)
PLACEHOLDER_SHAPE_RE = re.compile(r"<[^<>]*>|\{\{.*\}\}|\[[^\]]*\]")
MYSQL_CLIS = {"mysql", "mysqldump", "mysqladmin", "mysqlimport", "mysqlcheck", "mysqlshow", "mariadb",
              "mariadb-dump", "mariadb-admin"}
FORM_VERB_RE = re.compile(r"\b(?:curl|mysql\w*|mariadb[\w-]*|sshpass|redis-cli|psql|docker|podman|nerdctl)\b")
AUTH_HEADER_RE = re.compile(
    r"^\s*(?:proxy-)?authorization\s*:\s*(?:(?:bearer|basic|token|digest|negotiate)\s+)?(?P<tok>.*)$", re.I)
PSQL_SECRET_VAR_RE = re.compile(r"passw|(?:^|_)(?:pw|pwd|pass|secret|token)(?:$|_)", re.I)


def is_placeholder(value: str) -> bool:
    """True when ``value`` is not a literal secret: empty, a variable reference
    or substitution, a bracketed placeholder, a redaction token, a fake word."""
    v = value.strip().strip("'\"")
    if not v or "$" in v or "`" in v:
        return True
    return bool(PLACEHOLDER_SHAPE_RE.fullmatch(v) or FAKE_WORD_RE.fullmatch(v) or is_redaction(v))


def _literal(value: str) -> bool:
    return not is_placeholder(value)


def _after(words: List[str], j: int) -> str:
    return words[j + 1] if j + 1 < len(words) else ""


def _curl_forms(rest: List[str]) -> List[str]:
    found: List[str] = []
    for j, w in enumerate(rest):
        user: Optional[str] = None
        if w in ("-u", "--user", "-U", "--proxy-user") or re.fullmatch(r"-[A-Za-z]+[uU]", w):
            user = _after(rest, j)
        elif w.startswith(("--user=", "--proxy-user=")):
            user = w.split("=", 1)[1]
        elif re.match(r"-[uU][^-]", w) and ":" in w:
            user = w[2:]
        if user is not None and ":" in user and _literal(user.split(":", 1)[1]):
            found.append("curl -u / --user value carries a literal password (#4813)")
        header: Optional[str] = None
        if w in ("-H", "--header"):
            header = _after(rest, j)
        elif w.startswith("--header="):
            header = w.split("=", 1)[1]
        elif w.startswith("-H") and len(w) > 2 and not w.startswith("--"):
            header = w[2:]
        if header is not None:
            m = AUTH_HEADER_RE.match(header)
            if m and _literal(m.group("tok")):
                found.append("curl Authorization header carries a literal token (#4818)")
    return found


def _mysql_forms(rest: List[str]) -> List[str]:
    found: List[str] = []
    for w in rest:
        val: Optional[str] = None
        if w.startswith("--password="):
            val = w.split("=", 1)[1]
        elif w.startswith("-p") and len(w) > 2 and not w.startswith("--"):
            val = w[2:]
        if val is not None and _literal(val):
            found.append("mysql client -p / --password carries a literal password (#4814)")
    return found


def _sshpass_forms(rest: List[str]) -> List[str]:
    found: List[str] = []
    for j, w in enumerate(rest):
        val: Optional[str] = None
        if w == "-p":
            val = _after(rest, j)
        elif w.startswith("-p") and len(w) > 2:
            val = w[2:]
        if val is not None and _literal(val):
            found.append("sshpass -p carries a literal password (#4815)")
    return found


def _redis_forms(rest: List[str]) -> List[str]:
    found: List[str] = []
    for j, w in enumerate(rest):
        val: Optional[str] = None
        if w in ("-a", "--pass"):
            val = _after(rest, j)
        elif w.startswith("--pass="):
            val = w.split("=", 1)[1]
        if val is not None and _literal(val):
            found.append("redis-cli -a / --pass carries a literal password (#4816)")
    return found


def _psql_forms(rest: List[str]) -> List[str]:
    found: List[str] = []
    for j, w in enumerate(rest):
        pair: Optional[str] = None
        if w in ("-v", "--set"):
            pair = _after(rest, j)
        elif w.startswith("--set="):
            pair = w.split("=", 1)[1]
        elif w.startswith("-v") and len(w) > 2 and not w.startswith("--"):
            pair = w[2:]
        if pair and "=" in pair:
            name, _, value = pair.partition("=")
            if PSQL_SECRET_VAR_RE.search(name) and _literal(value):
                found.append("psql -v password-named variable carries a literal value (#4817)")
    return found


def _login_forms(rest: List[str]) -> List[str]:
    found: List[str] = []
    if "login" not in rest:
        return found
    tail = rest[rest.index("login") + 1:]
    for j, w in enumerate(tail):
        val: Optional[str] = None
        if w in ("-p", "--password"):
            val = _after(tail, j)
        elif w.startswith("--password="):
            val = w.split("=", 1)[1]
        elif w.startswith("-p") and len(w) > 2 and not w.startswith("--"):
            val = w[2:]
        if val is not None and _literal(val):
            found.append("docker login -p / --password carries a literal password (#4819)")
    return found


def form_command_hits(cmd: List[str], depth: int = 0) -> List[str]:
    """Reasons one command carries a literal secret on a client argv (#4813-#4819).
    A word that is itself a command string (sh -c "...", ssh host "...") is read
    as commands too."""
    reasons: List[str] = []
    if depth < 3:
        for w in cmd[1:]:
            if any(c.isspace() for c in w) and FORM_VERB_RE.search(w):
                for inner in commands(split_words(w)):
                    reasons.extend(form_command_hits(inner, depth + 1))
    for i, w in enumerate(cmd):
        base = Path(w).name
        rest = cmd[i + 1:]
        if base == "curl":
            reasons.extend(_curl_forms(rest))
        elif base in MYSQL_CLIS:
            reasons.extend(_mysql_forms(rest))
        elif base == "sshpass":
            reasons.extend(_sshpass_forms(rest))
        elif base == "redis-cli":
            reasons.extend(_redis_forms(rest))
        elif base == "psql":
            reasons.extend(_psql_forms(rest))
        elif base in CONTAINER_CLIS:
            reasons.extend(_login_forms(rest))
    return reasons


def scan_argv_forms(rel: str, text: str) -> List[Hit]:
    """The seven argv-secret forms, line by line. The reported snippet names the
    form and never repeats the line, so a hit cannot print the secret."""
    hits: List[Hit] = []
    for no, line in logical_lines(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or not FORM_VERB_RE.search(line):
            continue
        reasons: List[str] = []
        for cmd in commands(split_words(line)):
            reasons.extend(form_command_hits(cmd))
        if reasons:
            hits.append((rel, no, "[argv-secret-form] " + reasons[0]))
    return hits


def text_rule_hits(rel: str, text: str) -> List[Hit]:
    """The #4600-line text rules: expansion, psql -c password, docker -e / psql
    -v runtime-expanded password, readable cloud-init secret, traced secret."""
    hits: List[Hit] = []
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
    hits.extend(scan_argv_forms(rel, text))
    return hits


def scan_text(rel: str, text: str) -> List[Hit]:
    if rel in SELF_EXEMPT:
        return []
    hits = flag_hits(rel, text)
    if Path(rel).suffix.lower() in SHELL_SUFFIXES:
        seen = {h[:2] for h in hits}
        hits.extend(h for h in shell_hits(rel, text) if h[:2] not in seen)
    seen = {h[:2] for h in hits}
    hits.extend(h for h in text_rule_hits(rel, text) if h[:2] not in seen)
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


def scan_paths(root: Path, files: List[str], max_bytes: int = MAX_BYTES) -> Tuple[List[Hit], int, int]:
    """(hits, files scanned, files skipped). A skipped file is a text-suffix file
    that is over ``max_bytes`` or not valid UTF-8 (#4615): counted, never silent."""
    hits: List[Hit] = []
    scanned = 0
    skipped = 0
    for rel in files:
        p = root / rel
        if p.suffix.lower() not in TEXT_SUFFIXES or not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > max_bytes:
                skipped += 1
                continue
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        scanned += 1
        hits.extend(scan_text(rel, text))
    return hits, scanned, skipped


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
        hits, scanned, skipped = scan_paths(ROOT, files)
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
    print("PASS: check-docs-no-argv-secrets: %d files scanned, %d skipped (over %d bytes or not UTF-8), "
          "0 argv credentials, %d pending (listed, not approved)" % (scanned, skipped, MAX_BYTES, len(listed)))
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
    # #4600: schema-init resolves the file/env channels now, so an inline
    # credential on its flag is refused like any other verb's (these three were
    # green probes while the verb was argv-only). The expansion of the store-URL
    # variable puts the credential on argv at run time (#4603), so the former
    # green probe "shell-expansion" is red.
    "4600 schema-init inline": "ai-memory schema-init %s postgres://u:%s@h/d" % (SU, PW),
    "4600 schema-init continued": "ai-memory schema-init \\\n  %s postgres://u:%s@h/d" % (SU, PW),
    "4600 schema-init quote-split": "ai-memory schema-init --store-\"url\" postgres://u:%s@h/d" % PW,
    "4603 shell-expansion of the store URL": 'ai-memory keys %s "$AI_MEMORY_STORE_URL" prune' % SU,
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
    "ellipsis": "ai-memory serve %s postgres://aimemory:...@10.0.0.4:5432/db" % SU,
    "redacted": "ai-memory serve %s postgres://aimemory:REDACTED@h/db" % SU,
    "ellipsis-char": "ai-memory serve %s postgres://user:…@h/db" % SU,
    "lookalike-flag": "wake_abab.sh %s-src postgres://u:p@h/d" % SU,
    "prose-mention": "the `serve %s` connection URL (e.g. postgres://user:pass@host/db)" % SU,
}


RED_PROBES_4600 = {
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
GREEN_PROBES_4600 = {
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



# --- #4612 / #4614 / #4813-#4819 probes (a literal secret is the placeholder PW) ---
RED_FORM_PROBES = {
    # #4612: evasion classes of the original gate
    "4612 serve in the same block as a schema-init line":
        "ai-memory schema-init --store-url postgres://u@h/d\nai-memory serve %s postgres://u:%s@h/d" % (SU, PW),
    "4612 empty user, password only": "ai-memory serve %s postgres://:%s@h/d" % (SU, PW),
    "4612 sslpassword query key": "ai-memory serve %s 'postgres://u@h/d?sslpassword=%s'" % (SU, PW),
    "4612 password that contains an ellipsis": "ai-memory serve %s postgres://u:ab...cd@h/d" % SU,
    "4612 password that contains asterisks": "ai-memory serve %s postgres://u:p***w@h/d" % SU,
    "4612 password that contains xxxx": "ai-memory serve %s postgres://u:pxxxxq@h/d" % SU,
    # #4614: list-form argv and migrate --from / --to
    "4614 YAML list": "command:\n  - serve\n  - %s\n  - postgres://u:%s@h/d" % (SU, PW),
    "4614 compose array": 'command: ["serve", "%s", "postgres://u:%s@h/d"]' % (SU, PW),
    "4614 JSON args array": '{"args": ["serve", "%s", "postgres://u:%s@h/d"]}' % (SU, PW),
    "4614 list-form expansion of a DSN variable": 'command: ["serve", "%s", "${AI_MEMORY_STORE_URL}"]' % SU,
    "4614 migrate --to": "ai-memory migrate --from sqlite:///a.db --to postgres://u:%s@h/d" % PW,
    "4614 migrate --from=": "ai-memory migrate --from=postgres://u:%s@h/d --to sqlite:///a.db" % PW,
    "4614 migrate YAML list": "args:\n  - migrate\n  - --to\n  - postgres://u:%s@h/d" % PW,
    "4614 migrate JSON array": '["migrate", "--to", "postgres://u:%s@h/d"]' % PW,
    # #4813-#4819: one literal-secret form each
    "4813 curl -u user:literal": "curl -u admin:%s https://h/p" % PW,
    "4813 curl --user user:literal": "curl --user admin:%s https://h/p" % PW,
    "4813 curl -su cluster": "curl -su admin:%s https://h/p" % PW,
    "4813 curl --user= form": "curl --user=admin:%s https://h/p" % PW,
    "4814 mysql -pLITERAL": "mysql -u root -p%s db" % PW,
    "4814 mysqldump --password=LITERAL": "mysqldump --password=%s db" % PW,
    "4815 sshpass -p LITERAL": "sshpass -p %s ssh h" % PW,
    "4815 sshpass -pLITERAL": "sshpass -p%s ssh h" % PW,
    "4816 redis-cli -a LITERAL": "redis-cli -a %s ping" % PW,
    "4816 redis-cli --pass LITERAL": "redis-cli --pass %s ping" % PW,
    "4817 psql -v pw=LITERAL": "psql -v pw=%s -c 'select 1'" % PW,
    "4817 psql --set password=LITERAL": "psql --set password=%s -f x.sql" % PW,
    "4818 curl Authorization Bearer LITERAL": "curl -H 'Authorization: Bearer %s' https://h" % PW,
    "4818 curl --header Authorization Basic LITERAL": 'curl --header "Authorization: Basic %s" https://h' % PW,
    "4819 docker login -p LITERAL": "docker login -u u -p %s registry" % PW,
    "4819 docker login --password LITERAL": "docker login --password %s registry" % PW,
    "4813 curl inside ssh": 'ssh h "curl -u admin:%s https://h/p"' % PW,
    "4819 podman login": "podman login -u u --password=%s registry" % PW,
}
GREEN_FORM_PROBES = {
    # #4612 / #4614 near-misses
    "4612 schema-init alone with a file channel": "AI_MEMORY_STORE_URL_FILE=/etc/s ai-memory schema-init",
    "4612 empty user and no password": "ai-memory serve %s postgres://@h/d" % SU,
    "4612 whole-token redaction": "ai-memory serve %s postgres://u:****@h/d" % SU,
    "4614 list-form file channel": 'command: ["serve", "%s", "${AI_MEMORY_STORE_URL_FILE}"]' % SU,
    "4614 list-form URL without a password": 'command: ["serve", "%s", "postgres://u@h/d"]' % SU,
    "4614 migrate with file flags": "ai-memory migrate --from-url-file /s/from --to-url-file /s/to",
    "4614 migrate with credential-free URLs": "ai-memory migrate --from sqlite:///a.db --to postgres://h/d",
    "4614 migrate YAML list of file flags": "args:\n  - migrate\n  - --to-url-file\n  - /s/to",
    # #4813-#4819 placeholders and sanctioned forms
    "4813 curl -u user with no password": "curl -u admin https://h/p",
    "4813 curl -u variable password": 'curl -u "admin:$API_PW" https://h/p',
    "4813 curl -u brace variable": "curl -u admin:${API_PW} https://h/p",
    "4813 curl -u substitution": "curl -u admin:$(cat /run/s/pw) https://h/p",
    "4813 curl -u angle placeholder": "curl -u admin:<password> https://h/p",
    "4813 curl -u CHANGEME": "curl -u admin:CHANGEME https://h/p",
    "4813 curl --netrc-file": "curl --netrc-file /run/s/netrc https://h/p",
    "4814 mysql -p prompts": "mysql -u root -p db",
    "4814 mysql variable": 'mysql -u root -p"$DB_PW" db',
    "4814 mysql PASSWORD word": "mysql -u root -pPASSWORD db",
    "4814 mysql port flag": "mysql -h h -P 3306 --protocol=tcp db",
    "4815 sshpass -f file": "sshpass -f /run/s/pw ssh h",
    "4815 sshpass variable": 'sshpass -p "$SSH_PW" ssh h',
    "4816 redis-cli REDISCLI_AUTH": "REDISCLI_AUTH=\"$(cat /run/s/r)\" redis-cli ping",
    "4816 redis-cli variable": "redis-cli -a $REDIS_PW ping",
    "4816 redis-cli xxxx": "redis-cli -a xxxx ping",
    "4817 psql -v non-secret name": "psql -v ON_ERROR_STOP=1 -v dbname=app -f x.sql",
    "4817 psql -v empty": "psql -v pw= -f x.sql",
    "4818 curl Authorization variable": 'curl -H "Authorization: Bearer $API_TOKEN" https://h',
    "4818 curl Authorization brace variable": "curl -H 'Authorization: Bearer ${API_TOKEN}' https://h",
    "4818 curl Authorization placeholder": "curl -H 'Authorization: Bearer <token>' https://h",
    "4818 curl Authorization redacted": "curl -H 'Authorization: Bearer REDACTED' https://h",
    "4818 curl non-auth header": "curl -H 'Accept: application/json' https://h",
    "4818 curl header from file": "curl -H @/run/s/hdr https://h",
    "4819 docker login --password-stdin": "docker login -u u --password-stdin registry < /run/s/pw",
    "4819 docker login variable": 'docker login -u u -p "$REG_PW" registry',
    "4819 docker run -p publishes a port": "docker run -p 8080:80 img",
    "4819 docker login without a password": "docker login registry",
}


PROVISION_TPL = "infra/do-hive/cloud-init-memory.yaml.tpl"
PROVISION_PATH = "/usr/local/sbin/ai-memory-provision.sh"
PLACEHOLDER_URL = "postgres://aimemory:CHANGEME@127.0.0.1:5432/aimemory?sslmode=verify-full\n"


def _provision_body(tpl: str) -> List[str]:
    """The de-indented provision script body from the cloud-init template."""
    lines = tpl.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "- path: " + PROVISION_PATH)
    cont = next(i for i in range(start, len(lines)) if lines[i].strip() == "content: |")
    body = []
    for ln in lines[cont + 1:]:
        if ln.strip() and not ln.startswith("      "):
            break
        body.append(ln[6:] if ln.startswith("      ") else "")
    return body


def _credential_harness(body: List[str], scratch: Path) -> str:
    """Preamble (shebang, set flags, log setup) plus the block that mints the role
    password on the node, with the log and the store-url file pointed at
    ``scratch`` (no /etc or /var/log writes)."""
    pre_end = next(i for i, ln in enumerate(body) if ln.startswith('echo "=== ai-memory'))
    mint = [i for i, ln in enumerate(body) if "grep -q CHANGEME /etc/ai-memory/store-url" in ln]
    if len(mint) < 2:
        raise RuntimeError("provision script no longer has the mint + fail-closed CHANGEME blocks")
    end = next(i for i in range(mint[1], len(body)) if body[i].strip() == "fi")
    text = "\n".join(body[:pre_end + 1] + body[mint[0]:end + 1]) + "\n"
    for real, fake in (("/var/log/ai-memory-provision.log", str(scratch / "provision.log")),
                       ("/etc/ai-memory/store-url", str(scratch / "store-url"))):
        text = text.replace(real, fake)
    return text


def _run_provision_probe(tpl: str) -> Tuple[str, int, str, int]:
    """Run the harness under bash against a placeholder store-url file. Returns
    (log text, log mode, minted secret, exit code)."""
    scratch_parent = ROOT / ".local-runs"
    scratch_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(scratch_parent)) as td:
        scratch = Path(td)
        (scratch / "store-url").write_text(PLACEHOLDER_URL, encoding="utf-8")
        script = scratch / "harness.sh"
        script.write_text(_credential_harness(_provision_body(tpl), scratch), encoding="utf-8")
        proc = subprocess.run(
            ["bash", str(script)], capture_output=True, text=True, timeout=60, check=False,
            env={"PATH": "/usr/bin:/bin", "HOME": str(scratch)},
        )
        log = scratch / "provision.log"
        mode = (log.stat().st_mode & 0o777) if log.exists() else -1
        leaked = log.read_text(encoding="utf-8") if log.exists() else ""
        url = (scratch / "store-url").read_text(encoding="utf-8").strip()
        minted = url.split("://", 1)[1].split("@", 1)[0].split(":", 1)[1] if "@" in url else ""
        return leaked, mode, minted, proc.returncode


def runtime_probe() -> int:
    """#4609 red-then-green: real bash against the real credential-handling lines
    of the provision script. The role password is minted on the node, so the probe
    reads it back from the store-url file and proves it never reaches the log, and
    that the log is mode 0600. The red copy puts xtrace back and drops the log
    protection; the same probe must then see the secret."""
    tpl_path = ROOT / PROVISION_TPL
    if not tpl_path.exists():
        print("SELF-TEST FAIL: %s missing" % PROVISION_TPL, file=sys.stderr)
        return 1
    tpl = tpl_path.read_text(encoding="utf-8")
    bad = 0
    log, mode, minted, rc = _run_provision_probe(tpl)
    if rc != 0 or len(minted) < 16 or "CHANGEME" in minted:
        print("SELF-TEST FAIL: provision harness did not mint a secret (rc=%d)" % rc, file=sys.stderr)
        bad += 1
    elif minted in log:
        print("SELF-TEST FAIL: provision script writes the minted role password to its log", file=sys.stderr)
        bad += 1
    if mode != 0o600:
        print("SELF-TEST FAIL: provision log mode is %s, want 0600" % oct(mode), file=sys.stderr)
        bad += 1
    regressed = "\n".join(
        ln.replace("set -euo pipefail", "set -euxo pipefail")
        for ln in tpl.splitlines()
        if "( umask 077; : >> /var/log/ai-memory-provision.log )" not in ln
    ) + "\n"
    rlog, rmode, rminted, _ = _run_provision_probe(regressed)
    if not rminted or rminted not in rlog:
        print("SELF-TEST FAIL: regressed provision script did not leak the secret; the probe is vacuous",
              file=sys.stderr)
        bad += 1
    return bad


def self_test() -> int:
    bad = 0
    red = green = 0
    bad += runtime_probe()
    for name, text in RED_PROBES_4600.items():
        red += 1
        if not scan_text("probe.yaml.tpl", text):
            print("SELF-TEST FAIL: red probe (#4600 set) %r was not flagged" % name, file=sys.stderr)
            bad += 1
    for name, text in GREEN_PROBES_4600.items():
        green += 1
        # A credential URL after a look-alike flag, or in prose, is clean in a
        # prose file (the same probes are in GREEN_PROBES) but on a script line it
        # is a credential on another command's argv, which the shell reader
        # refuses: decided by whether a credential reaches argv (#4762 merge).
        suffix = "probe.md" if name in ("lookalike-flag", "prose-mention") else "probe.yaml.tpl"
        got = scan_text(suffix, text)
        if got:
            print("SELF-TEST FAIL: green probe (#4600 set) %r was flagged: %r" % (name, got), file=sys.stderr)
            bad += 1
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
    for suffix in (".md", ".sh"):
        for name, text in RED_FORM_PROBES.items():
            red += 1
            if not scan_text("probe" + suffix, text):
                print("SELF-TEST FAIL: red form probe %r (%s) was not flagged" % (name, suffix), file=sys.stderr)
                bad += 1
        for name, text in GREEN_FORM_PROBES.items():
            green += 1
            got = scan_text("probe" + suffix, text)
            if got:
                print("SELF-TEST FAIL: green form probe %r (%s) was flagged: %r" % (name, suffix, got), file=sys.stderr)
                bad += 1
    # A form hit reports the form, never the secret (#4813-#4819).
    red += 1
    form_hits = [h for t in RED_FORM_PROBES.values() for h in scan_text("probe.md", t)]
    if any(PW in h[2] for h in form_hits):
        print("SELF-TEST FAIL: a form hit prints the secret", file=sys.stderr)
        bad += 1
    # #4615: nothing is skipped by path; skipped files are counted.
    red += 1
    if "SKIP_PREFIXES" in globals() or "SKIP_FILES" in globals():
        print("SELF-TEST FAIL: a path skip list is back (#4615)", file=sys.stderr)
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
        hits, scanned, _ = scan_paths(root, ["bad.md", "ok.md", "bad.sh"])
        red += 1
        if scanned != 3 or sorted(h[0] for h in hits) != ["bad.md", "bad.sh"]:
            print("SELF-TEST FAIL: file walk gave hits=%r scanned=%d" % (hits, scanned), file=sys.stderr)
            bad += 1
        # A pending entry claims its hit; an entry with no hit is stale.
        sh_hits, _, _ = scan_paths(root, ["bad.sh"])
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
        two_hits, _, _ = scan_paths(root, ["two.sh"])
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
        # #4615: a changelog.d/ and a docs/handoff/ fixture are scanned, not skipped.
        for sub in ("changelog.d", "docs/handoff", "docs/reviews"):
            (root / sub).mkdir(parents=True, exist_ok=True)
            (root / sub / "n.md").write_text(RED_PROBES["inline"] + "\n", encoding="utf-8")
        (root / "CHANGELOG.md").write_text(RED_PROBES["inline"] + "\n", encoding="utf-8")
        rels = ["changelog.d/n.md", "docs/handoff/n.md", "docs/reviews/n.md", "CHANGELOG.md"]
        hits, scanned, skipped = scan_paths(root, rels)
        red += 1
        if scanned != 4 or skipped != 0 or sorted(h[0] for h in hits) != sorted(rels):
            print("SELF-TEST FAIL: a record tree was skipped (#4615): hits=%r scanned=%d" % (hits, scanned),
                  file=sys.stderr)
            bad += 1
        # #4615: size and encoding skips are counted.
        (root / "big.md").write_text("x" * 200 + "\n", encoding="utf-8")
        (root / "bin.md").write_bytes(b"\xff\xfe\x00bad\n")
        _, scanned, skipped = scan_paths(root, ["big.md", "bin.md", "ok.md"], max_bytes=100)
        red += 1
        if scanned != 1 or skipped != 2:
            print("SELF-TEST FAIL: skipped files not counted: scanned=%d skipped=%d" % (scanned, skipped),
                  file=sys.stderr)
            bad += 1
        _, scanned, _ = scan_paths(root, [])
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
