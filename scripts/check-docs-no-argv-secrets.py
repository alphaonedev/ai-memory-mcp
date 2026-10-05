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
        password, secret, token or API key. ``env NAME=v cmd`` is flagged too:
        the value is on env's own argv until it execs, and an execve audit
        (auditd, strace) records it (#4792).
    A systemd ``Environment=`` line carrying a credential URL is refused
    whatever the key spelling (#4689).

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
# A --store-url argument (=, whitespace or backslash-newline), optional quote,
# then the URL up to whitespace or a quote.
ARG_RE = re.compile(FLAG + r"(?:=|(?:\s|\\)+)[\"']?(?P<url>" + SCHEME + r"[^\s\"']+)")

# #4603: a runtime expansion of the store-URL env var, or of any variable named
# like a DSN / URL / URI / CONN (#4808, #4802), or a command substitution
# (#4802), straight after the flag. A `_FILE` variable is the sanctioned
# channel and is not matched.
EXPANSION_RE = re.compile(
    FLAG + r"(?:=|(?:\s|\\)+)[\"']?"
    r"(?:\\*\$\{?[A-Za-z0-9_]*(?:DSN|URL|URI|CONN)(?![A-Za-z0-9_])|\$\(|`)",
    re.IGNORECASE,
)
# #4609: xtrace echoes every expanded command, so a credential-bearing line
# must sit between `set +x` and `set -x`.
# #4802: also `set -o xtrace` / `set +o xtrace`, a `#!/bin/bash -x` shebang,
# and names ending in pw / pass ($PGPW, $DB_PASS).
XTRACE_ON_RE = re.compile(r"^\s*set\s+(?:-[a-z]*x|-o\s+xtrace\b)")
SHEBANG_X_RE = re.compile(r"^#!\S+(?:\s+\S+)?\s+-[a-z]*x")
XTRACE_OFF_RE = re.compile(r"^\s*set\s+(?:\+[a-z]*x|\+o\s+xtrace\b)")
TRACED_SECRET_RE = re.compile(
    r"\$\{?[A-Za-z0-9_]*(?:password|passwd|pass|secret|token|pw)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
# #4604: a password literal in a psql -c / --command SQL string.
# #4802: combined short flags (-tAc) and E'...' strings; #4808: $$...$$ and
# $tag$...$tag$ dollar quoting.
PSQL_ARGV_RE = re.compile(
    r"\bpsql\b[^\n]*?\s(?:-[A-Za-z]*c|--command)(?:=|\s)\s*[\"'][^\n]*?\bPASSWORD\s+"
    r"(?:[Ee]?\\?'(?P<pw>[^'\s]+)|\\?\$(?P<tag>[A-Za-z_][A-Za-z0-9_]*)?\$(?P<pwd>[^\s$]+))",
    re.IGNORECASE,
)
# #4617: a runtime-expanded password on a docker -e / psql -v argv word.
# #4859 (subsumes #4817, #4808): psql at a line start, by absolute path, after
# $( ` ; | & or a quote; -v, joined -vNAME=, --set and --variable; a literal or
# expanded value. #4802: a glued -eNAME=, AI_MEMORY_STORE_URL, and sh -c.
ENV_ARGV_RE = re.compile(
    r"(?:\s-e|\s--env)(?:=|\s)?\s*[\"']?(?:PGPASSWORD|POSTGRES_PASSWORD|AI_MEMORY_STORE_URL)=[\"']?(?P<pw>\$[^\s\"']+)"
    r"|\b(?:ba)?sh\s+-c\s+[\"'][^\"'\n]*\bPGPASSWORD=(?P<pw3>\$[^\s\"']+)",
    re.IGNORECASE | re.MULTILINE,
)
# #4859 R2 (PR 4810 security re-review): psql -v / --set / --variable NAME=value
# for ANY secret NAME (secret_name(): pw, db_password, new_pw, secret, token),
# combined short flags (-qv, -Xqv), getopt_long abbreviations (--se, --va..),
# psql reached through a variable ($PSQL, ${PSQL_BIN}) and a backslash-newline
# continuation. Every option after the psql word is checked, not the first.
# #5448: _ and - also precede psql (run_psql, my-psql: a wrapper still runs psql).
PSQL_HEAD_RE = re.compile(r"(?:^|[\s;|&(`/\"'${_-])(?P<word>psql[A-Za-z0-9_]*)\b", re.IGNORECASE | re.MULTILINE)
# #5482 (round-6 F2): the shell strips backslashes and quotes inside a word, so
# \psql, p\sql, ps''ql and "ps"ql all run psql. This matches a psql word spelled with
# those characters; normalise_psql_heads() rewrites it to a plain psql word of the
# SAME length (padding with spaces) so every offset, and so every reported line,
# stays valid for both psql rules.
PSQL_SPLIT_HEAD_RE = re.compile(
    r"(?<![A-Za-z0-9\\'\"])[\\'\"]*p[\\'\"]*s[\\'\"]*q[\\'\"]*l[\\'\"]*(?P<tail>[A-Za-z0-9_]*)",
    re.IGNORECASE,
)
PSQL_VAR_OPT_RE = re.compile(
    r"\s(?:-[A-Za-z0-9]*v\s*|--(?:set?|va[a-z]*)(?:=|\s+))"
    r"(?P<operand>[^\s]+)",
    re.IGNORECASE,
)
# #5399 (PR 4810 round-4 security re-review): the shell removes quotes and
# backslashes before psql sees its argv, so the psql -v scan reads the segment with
# both removed (-v 'pw'=, -v p"w"=, pw\=, "-vpw=...", '--set=pw='"$X" are all the
# same argv as -v pw=...). For a psql -v value the NAME rule is a plain substring
# (pw2, pwnew, admin_pw1 are secrets), and neither the locator exemption (pw_id)
# nor a redaction-token suffix (${PW}xxxx) clears a value: a variable whose name
# says it is a credential is flagged whatever its value looks like.
# #5448 (round-5 review F1): psql accepts digits anywhere and any high-bit byte in a
# variable name, so the name is everything before the first = (not an ASCII
# identifier) and a -v operand a text gate cannot decide (a shell expansion or
# substitution in the name part, or an operand that is only an expansion) is
# flagged, never skipped.
# #5481-#5483 round-6 (F1, F2, F3): -v clusters may carry digits before v (-1v, -0v, -Xq1v);
# a psql word spelled with backslashes or quotes (\psql, p\sql, ps''ql, "ps"ql) is
# normalised to psql before BOTH psql rules run; a non-ASCII -v name is flagged
# whatever it spells; a -v VALUE that expands a secret-named variable ($PGPASSWORD,
# ${PG_PW}, $(cat<no space>pw)) is flagged under any name.
# STATED LIMITS (a text gate cannot decide these; each is recorded in its issue):
#   * options that reach psql through an array or another variable
#     (args=(-v pw=$X); psql "${args[@]}") are not after the psql word and a text gate
#     cannot follow them; that form is tracked by its own open issue, #5398.
#   * a secret held in a variable whose own NAME is neutral and passed to psql -v
#     under a neutral name (x=$A where A=$PGPASSWORD was assigned on another line),
#     and a secret written as a literal under a neutral name (-v x=hunter2), carry no
#     secret-like token on the psql line; the gate decides by the names on the line.
#   * the -v operand is one shell word, so a command substitution value with a space
#     (x=$(cat /run/pw)) is read only up to its first space.
PSQL_SECRET_VAR_NAME_RE = re.compile(r"pass|secret|token|key|cred|pw|auth", re.IGNORECASE)
SECRET_VAR_RE = re.compile(
    r"\$\{[A-Za-z0-9_]*(?:(?:password|passwd|secret|token|key|cred)[A-Za-z0-9_]*|pw|pass)\}",
    re.IGNORECASE,
)
# #4802: a psql / pg_* connection URI carrying a password, in any tracked file
# (the migration guides, #4804). Stops at a backtick, ; | & or a < redirect
# (a here-string is stdin, not argv); a comment line is not run.
PSQL_URL_RE = re.compile(
    r"^(?![ \t]*#)[^\n]*?\b(?:psql|pg_dump|pg_dumpall|pg_restore|pg_isready)\b[^\n`;|&<]*?"
    r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s/@\"':]*:(?P<pw>[^\s/@\"']+)@",
    re.MULTILINE,
)
# #4808: a DSN-named container env var carrying scheme://user:PASSWORD@.
DOCKER_ENV_DSN_RE = re.compile(
    r"(?:\s-e|\s--env)(?:=|\s)?\s*[\"']?[A-Za-z0-9_]*(?:URL|DSN|URI|CONN)[A-Za-z0-9_]*="
    r"[\"']?[A-Za-z][A-Za-z0-9+.\-]*://[^\s/@\"':]*:(?P<pw>[^\s/@\"']+)@",
    re.IGNORECASE,
)
# #4808: the quoted remote command of ssh is an ssh argv word, so a URL with a
# password anywhere inside it is on the local process list.
SSH_REMOTE_URL_RE = re.compile(
    r"\bssh\b[^\n]*?\s[\"'][^\n]*?[A-Za-z][A-Za-z0-9+.\-]*://[^\s/@\"':]*:(?P<pw>[^\s/@\"']+)@"
)
# #4808: a literal container password. The shell reader refuses every literal
# (the stricter rule wins); in prose only the named CI fixture constants pass.
FIXTURE_PASSWORDS = {"ai_memory_test", "ci_verify"}
DOCKER_ENV_LITERAL_RE = re.compile(
    r"(?:\s-e|\s--env)(?:=|\s)?\s*[\"']?(?:PGPASSWORD|POSTGRES_PASSWORD)=[\"']?(?P<pw>[^\s\"'$][^\s\"']*)",
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
SECRET_NAME_RE = re.compile(r"pass|secret|token|key|cred|pw(?:_|$)|pwd|auth", re.I)
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
            if w in ("-e", "--env", "--build-arg") and i + 1 < len(words):
                val = words[i + 1]
                i += 1
            elif w.startswith(("--env=", "--build-arg=")):
                val = w.split("=", 1)[1]
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
        if m and secret_name(m.group("name")) and not is_redaction(m.group("value")):
            reasons.append("NAME=value on a resident wrapper argv %s" % m.group("name"))
    return reasons


def secret_name(name: str) -> bool:
    """A NAME that holds a credential: either name rule, and not a locator."""
    return bool((SECRET_NAME_RE.search(name) or ARGV_SECRET_NAME_RE.search(name))
                and not LOCATOR_NAME_RE.search(name))


# Programs that take a command string as one argv word and keep it on their
# argv while it runs (ssh, docker exec, sh -c under sudo/runuser).
STRING_RUNNERS = {"ssh", "sh", "bash", "dash", "zsh", "ksh", "su", "sudo", "doas", "runuser",
                  "docker", "podman", "nerdctl", "kubectl", "oc", "systemd-run", "timeout", "env"}


def string_env_prefix_hits(line: str) -> List[str]:
    """ssh h "PGPASSWORD=$PW psql": the env prefix inside a command string is
    part of the runner's argv. In a single-quoted string a $-value is literal
    text (expanded later, inside the child), so only a literal value counts."""
    try:
        lex = shlex.shlex(line, posix=False, punctuation_chars=True)
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        return []
    if not any(Path(t).name in STRING_RUNNERS for t in toks):
        return []
    found: List[str] = []
    for t in toks:
        if len(t) < 2 or t[0] not in "\"'" or t[-1] != t[0] or not any(c.isspace() for c in t):
            continue
        single = t[0] == "'"
        for cmd in commands(split_words(t[1:-1])):
            for a in cmd:
                if not ASSIGN_RE.match(a):
                    break
                name, _, value = a.partition("=")
                if single and ("$" in value or "`" in value):
                    continue
                if secret_name(name) and value and not is_redaction(value):
                    found.append(name)
    return found


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
        if any(command_hits(cmd) for cmd in commands(split_words(line))) or string_env_prefix_hits(line):
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
        if n == 1 and SHEBANG_X_RE.match(ln):
            traced = True
            continue
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


def normalise_psql_heads(text: str) -> str:
    """Rewrite every shell-split psql word (\\psql, p\\sql, ps''ql, "ps"ql) to a plain
    psql word of the same length, so the head rule and the psql -c rule see what the
    shell runs (#5482). Offsets are preserved: removed characters become spaces."""
    def plain(m: "re.Match[str]") -> str:
        word = m.group(0)
        tail = m.group("tail")
        if len(word) == 4 + len(tail) and word[: 4].lower() == "psql":
            return word
        return "psql" + tail + " " * (len(word) - 4 - len(tail))
    return PSQL_SPLIT_HEAD_RE.sub(plain, text)


def psql_var_operand_flagged(operand: str) -> bool:
    """A psql -v operand is flagged when its name is secret-like, non-ASCII or
    undecidable (#5448), or when its VALUE expands a secret-named variable (#5483)."""
    name, _, value = operand.partition("=")
    if PSQL_SECRET_VAR_NAME_RE.search(name):
        return True
    if any(ch in name for ch in "$`(){}"):
        return True
    # #5483 (round-6 F3): a name psql takes as high-bit bytes can spell a secret name
    # with a look-alike letter (a Cyrillic p), so any non-ASCII name is flagged.
    if not name.isascii():
        return True
    # #5483: a neutral name does not hide a value that expands a secret-named variable
    # ($PGPASSWORD, ${PG_PW}); the operand is one word, so the value is read to its first space.
    if "$" in value and PSQL_SECRET_VAR_NAME_RE.search(value[value.index("$"):]):
        return True
    return False


def text_rule_hits(rel: str, text: str) -> List[Hit]:
    """The #4600-line text rules: expansion, psql -c password, docker -e / psql
    -v runtime-expanded password, readable cloud-init secret, traced secret."""
    hits: List[Hit] = []
    for m in EXPANSION_RE.finditer(text):
        line, snippet = _line_of(text, m.start())
        hits.append((rel, line, "[store-url-expansion] " + snippet))
    for m in PSQL_ARGV_RE.finditer(normalise_psql_heads(text)):
        if is_redaction(m.group("pw") or m.group("pwd") or ""):
            continue
        line, snippet = _line_of(text, m.start())
        hits.append((rel, line, "[psql-password-argv] " + snippet))
    for m in ENV_ARGV_RE.finditer(text):
        if is_redaction(m.group("pw") or m.group("pw3") or ""):
            continue
        line, snippet = _line_of(text, m.start())
        hits.append((rel, line, "[env-password-argv] " + snippet))
    # A backslash-newline is two characters; two spaces keep every offset, so
    # _line_of on the original text still names the right line.
    joined = normalise_psql_heads(text.replace("\\\n", "  "))
    for head in PSQL_HEAD_RE.finditer(joined):
        eol = joined.find("\n", head.end())
        segment = joined[head.end():eol if eol >= 0 else len(joined)]
        shell_view = segment.replace("\\", "").replace('"', "").replace("'", "")
        if any(psql_var_operand_flagged(m.group("operand"))
               for m in PSQL_VAR_OPT_RE.finditer(shell_view)):
            # head.start() is the PREFIX character, a newline when psql opens a line, which
            # reported the previous line; the word itself names the line (#5485).
            line, snippet = _line_of(text, head.start("word"))
            hits.append((rel, line, "[env-password-argv] " + snippet))
    for rule, tag in ((PSQL_URL_RE, "psql-url-password"), (DOCKER_ENV_DSN_RE, "env-dsn-argv"),
                      (SSH_REMOTE_URL_RE, "ssh-remote-url-password")):
        for m in rule.finditer(text):
            if is_redaction(m.group("pw")):
                continue
            line, snippet = _line_of(text, m.start())
            hits.append((rel, line, "[%s] %s" % (tag, snippet)))
    for m in DOCKER_ENV_LITERAL_RE.finditer(text):
        if m.group("pw") in FIXTURE_PASSWORDS or is_redaction(m.group("pw")):
            continue
        line, snippet = _line_of(text, m.start())
        hits.append((rel, line, "[env-password-literal] " + snippet))
    if rel.endswith((".tpl", ".yaml", ".yml")):
        hits.extend(scan_write_files(rel, text))
    if rel.endswith((".sh", ".tpl", ".yaml", ".yml")):
        hits.extend(scan_xtrace(rel, text))
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
RED_SHELL_PROBES.update({
    # round 4, security reviewer B-series (#4826, #4827, #4808, #4792)
    "r4 B01 env -i NAME=v": "env -i PGPASSWORD=%s psql -h h" % PW,
    "r4 B02 /usr/bin/env NAME=v": "/usr/bin/env PGPASSWORD=%s psql" % PW,
    "r4 B03 env -S 'NAME=v cmd'": "env -S 'PGPASSWORD=%s psql -h h'" % PW,
    "r4 B04 nohup env NAME=v": "nohup env PGPASSWORD=%s psql &" % PW,
    "r4 B05 exec env NAME=v": "exec env PGPASSWORD=%s psql" % PW,
    "r4 B06 env -u X NAME=v": "env -u HOME DB_PASSWORD=%s app" % PW,
    "r4 B07 systemd-run --setenv=..._KEY=": "systemd-run --setenv=AI_MEMORY_DB_KEY=%s ai-memory serve" % PW,
    "r4 B08 systemd-run -E DB_PASSPHRASE=": "systemd-run -E DB_PASSPHRASE=%s app" % PW,
    "r4 B09 kubectl run --env=SQLCIPHER_KEY=": "kubectl run t --image=i --env=SQLCIPHER_KEY=%s" % PW,
    "r4 B10 timeout 5 NAME_KEY= (needs env)": "timeout 5 env AI_MEMORY_DB_KEY=%s ai-memory list" % PW,
    "r4 B11 kubectl set env PRIVATE_KEY=": "kubectl set env deploy/x PRIVATE_KEY=%s" % PW,
    "r4 B12 oc set env CREDENTIALS=": "oc set env dc/x DB_CREDENTIALS=%s" % PW,
    "r4 B13 kubectl --env=AUTH=": "kubectl run t --image=i --env=AUTH=%s" % PW,
    "r4 B14 sudo -u pg bash -c 'NAME=v psql'": "sudo -u postgres bash -c \"PGPASSWORD=%s psql -h h\"" % PW,
    "r4 B15 runuser -- sh -c 'NAME=v psql'": "runuser -u postgres -- sh -c 'PGPASSWORD=%s psql'" % PW,
    "r4 B16 ssh host 'NAME=v psql'": "ssh host \"PGPASSWORD=%s psql -h h\"" % PW,
    "r4 B17 docker exec c sh -c 'NAME=v psql'": "docker exec c sh -c 'PGPASSWORD=%s psql'" % PW,
    "r4 B18 su -c 'NAME=v psql'": "su postgres -c 'PGPASSWORD=%s psql'" % PW,
    "r4 B19 sudo DBPW=": "sudo DBPW=%s app" % PW,
    "r4 B20 sudo PGPASS=": "sudo PGPASS=%s psql" % PW,
    "r4 B21 sudo MYSQL_PWD=": "sudo MYSQL_PWD=%s mysql" % PW,
    "r4 B22 docker -e DBPW=": "docker run -e DBPW=%s img" % PW,
    "r4 B23 sudo PW=": "sudo PW=%s app" % PW,
    "r4 B24 docker build --build-arg PASSWORD=": "docker build --build-arg DB_PASSWORD=%s ." % PW,
})
GREEN_SHELL_PROBES.update({
    "r4 G01 env with locator name": "env AI_MEMORY_KEY_FILE=/k ai-memory serve",
    "r4 G02 sudo -E (value from env)": "sudo -E psql -h h",
    "r4 G03 env NAME=$(cat file) is still a value": "env -i HOME=/root psql",
    "r4 G04 systemd-run --setenv=NAME (no value)": "systemd-run --setenv=PGPASSWORD psql",
    "r4 kubectl --env locator name": "kubectl run t --image=i --env=AI_MEMORY_KEY_FILE=/k",
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
    # #4808: in prose only the named CI fixture constants pass as a literal
    # container password (the shell reader refuses every literal).
    "4808 docker -e fixture password": "docker run -e POSTGRES_PASSWORD=ci_verify postgres:16",
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
    "psql-v-pw-line-start": "psql -v ON_ERROR_STOP=1 -v pw='$PG_PW' -U postgres -f -",
    "psql-v-pw-abs-path": '/usr/bin/psql -v pw="$PG_PW" -f x.sql',
    "psql-v-pw-substitution": 'out=$(psql -v pw="$PG_PW" -f x.sql)',
    "psql-v-pw-after-semicolon": 'true;psql -v pw="$PG_PW" -f x.sql',
    "psql-set-pw": 'psql --set pw="$PG_PW" -f x.sql',
    "psql-variable-pw": 'psql --variable=pw="$PG_PW" -f x.sql',
    "psql-v-pw-joined": 'psql -vpw="$PG_PW" -f x.sql',
    "psql-v-pw-literal": "psql -v pw=litsecret9 -f x.sql",
    # #4859 R2 (PR 4810 security re-review): any secret variable NAME, other spellings.
    "4859-psql-v-db-password": 'psql -v db_password="$PG_PW" -f x.sql',
    "4859-psql-v-new-pw": 'psql -v new_pw="$PG_PW" -f x.sql',
    "4859-psql-v-aimemory-pw": 'psql -v aimemory_pw="$PG_PW" -f x.sql',
    "4859-psql-v-secret": 'psql -v secret="$S" -f x.sql',
    "4859-psql-continuation": 'psql -U postgres \\\n  -v pw="$PG_PW" \\\n  -f x.sql',
    "4859-psql-combined-qv": 'psql -qv pw="$PG_PW" -f x.sql',
    "4859-psql-abbrev-vari": 'psql --vari=pw="$PG_PW" -f x.sql',
    "4859-psql-via-variable": '"$PSQL" -v pw="$PG_PW" -f x.sql',
    # #5399 (PR 4810 round-4 security re-review): spellings 1-11 that passed.
    "5399-01-quoted-name-single": "psql -v 'pw'=\"$PG_PW\" -f x.sql",
    "5399-02-quoted-name-double": 'psql -v "pw"="$PG_PW" -f x.sql',
    "5399-03-quote-inside-name": 'psql -v p"w"="$PG_PW" -f x.sql',
    "5399-04-escaped-equals": 'psql -v pw\\="$PG_PW" -f x.sql',
    "5399-05-quoted-option-word": 'psql "-vpw=$PG_PW" -f x.sql',
    "5399-06-quoted-long-option": "psql '--set=pw='\"$PG_PW\" -f x.sql",
    "5399-07-pw-digit": 'psql -v pw2="$PG_PW" -f x.sql',
    "5399-08-pw-letters": 'psql -v pwnew="$PG_PW" -f x.sql',
    "5399-09-pw-name-digit": 'psql -v admin_pw1="$PG_PW" -f x.sql',
    "5399-10-locator-suffix": 'psql -v pw_id="$PG_PW" -f x.sql',
    "5399-11-redaction-suffixed-value": "psql -v pw=${PG_PW}xxxx -f x.sql",
    "5399-12-auth-name": 'psql -v auth="$DB_SECRET_VALUE" -f x.sql',
    "5399-13-leading-underscore-name": 'psql -v _pw="$PG_PW" -f x.sql',
    # #5448 (PR 4810 round-5 cloud review F1): names psql accepts that the old
    # ASCII-identifier name group could not match, and -v forms undecidable by text.
    "5448-01-leading-digit-name": 'psql -v 1pw="$PG_PW" -f x.sql',
    "5448-02-non-ascii-tail": 'psql -v pw\u00e9="$PG_PW" -f x.sql',
    "5448-03-non-ascii-head": 'psql -v \u00e9pw="$PG_PW" -f x.sql',
    "5448-04-ansi-c-quoted-name": "psql -v $'pw'=\"$PG_PW\" -f x.sql",
    "5448-05-expansion-in-name": 'psql -v p${E}w="$PG_PW" -f x.sql',
    "5448-06-wrapper-function-head": 'run_psql -v pw="$PG_PW" -f x.sql',
    "5448-07-name-from-variable": 'psql -v "$VARSPEC" -f x.sql',
    "5448-08-name-from-substitution": 'psql -v "$(printf pw)=$PG_PW" -f x.sql',
    "5448-09-long-option-leading-digit": 'psql --set 1pw="$PG_PW" -f x.sql',
    "5448-10-wrapper-hyphen-head": 'my-psql -v pw="$PG_PW" -f x.sql',
    "5448-11-uppercase-name": 'psql -v PGPW="$PG_PW" -f x.sql',
    "5448-12-backtick-name": 'psql -v `n`="$PG_PW" -f x.sql',
    "5448-13-brace-expansion-name": 'psql -v p{w,x}="$PG_PW" -f x.sql',
    "5448-14-extglob-paren-name": 'psql -v p@(w)="$PG_PW" -f x.sql',
    # #5481 (PR 4810 round-6 F1): a digit in the short-flag cluster ahead of v (-1 single
    # transaction, -0 record separator take no argument, so psql still reads the -v).
    "5481-01-cluster-digit-before-v": 'psql -1v pw="$PG_PW" -f x.sql',
    "5481-02-cluster-zero-before-v": 'psql -0v pw="$PG_PW" -f x.sql',
    "5481-03-cluster-letters-digit-v": 'psql -Xq1v pw="$PG_PW" -f x.sql',
    "5481-04-cluster-digit-v-joined": 'psql -1vpw="$PG_PW" -f x.sql',
    # #5482 (PR 4810 round-6 F2): the shell strips backslashes and quotes inside a word, so
    # these all run psql; a backslash inside the -v name pins the shell-view step (M11).
    "5482-01-leading-backslash-head": '\\psql -v pw="$PG_PW" -f x.sql',
    "5482-02-backslash-inside-head": 'p\\sql -v pw="$PG_PW" -f x.sql',
    "5482-03-empty-quotes-inside-head": "ps''ql -v pw=\"$PG_PW\" -f x.sql",
    "5482-04-quoted-head-prefix": '"ps"ql -v pw="$PG_PW" -f x.sql',
    "5482-05-backslash-inside-v-name": 'psql -v p\\w="$PG_PW" -f x.sql',
    "5482-06-split-head-c-password": "p\\sql -c \"ALTER USER a PASSWORD 'hunter2x'\"",
    "5482-07-quoted-wrapper-head": '"run_ps"ql -v pw="$PG_PW" -f x.sql',
    "5482-08-split-head-after-semicolon": 'true;\\psql -v pw="$PG_PW" -f x.sql',
    "5482-09-uppercase-split-head": 'P\\SQL -v pw="$PG_PW" -f x.sql',
    "5482-10-backslash-before-last-letter": 'psq\\l -v pw="$PG_PW" -f x.sql',
    # #5483 (PR 4810 round-6 F3): a neutral variable name does not hide a value that expands
    # a secret-named variable, and a non-ASCII name can spell a secret with a look-alike letter.
    "5483-01-neutral-name-pgpassword": 'psql -v x="$PGPASSWORD" -f x.sql',
    "5483-02-neutral-name-braced-pw": 'psql -v x="${PG_PW}" -f x.sql',
    "5483-03-neutral-name-unquoted-pw": 'psql -v x=$PG_PW -f x.sql',
    "5483-04-homoglyph-name": 'psql -v \u0440w="$PG_PW" -f x.sql',
    "5483-05-neutral-name-set-long": 'psql --set x="$DB_SECRET" -f x.sql',
    "5483-06-neutral-name-literal-prefix": 'psql -v x=pre-${TOKEN_VALUE} -f x.sql',
    "5483-07-neutral-name-joined-cluster": 'psql -qvx="$PGPASSWORD" -f x.sql',
    "5483-08-neutral-name-key-value": 'psql --variable=x=$API_KEY -f x.sql',
    "5483-09-non-ascii-name-only": 'psql -v \u0440=1 -f x.sql',
    # #4808: the forms the #4782 gate missed.
    "4808-docker-e-dsn-literal": "docker run -e DATABASE_URL=postgres://u:hunter2@h/d img",
    "4808-psql-set-equals-pw": 'psql --set=pw="$PG_PW" -f bootstrap.sql',
    "4808-psql-variable-space-pw": 'psql --variable pw="$PG_PW" -f bootstrap.sql',
    "4808-expansion-conn-var": 'ai-memory serve --store-url "$PG_CONN"',
    "4808-ssh-remote-env-dsn": "ssh root@h \"AI_MEMORY_STORE_URL='postgres://a:$PG_PW@127.0.0.1/a' ai-memory serve\"",
    "4808-docker-e-literal-password": "docker run -e POSTGRES_PASSWORD=Sup3rS3cret postgres:16",
    "4808-psql-dollar-quoted": "psql -c \"ALTER ROLE u PASSWORD $$hunter2$$\"",
    "4808-psql-dollar-tag-quoted": "psql -c \"ALTER ROLE u PASSWORD $pw$hunter2$pw$\"",
    # #4802: the 13 untracked forms of the #4782 code review.
    "4802-psql-uri-password": 'psql "postgres://u:hunter2@h:5432/d" -c "select 1"',
    "4802-psql-combined-c": "psql -U postgres -tAc \"ALTER ROLE u PASSWORD '$x'\"",
    "4802-psql-e-string": "psql -c \"ALTER ROLE u PASSWORD E'hunter2'\"",
    "4802-expansion-substitution": 'ai-memory serve --store-url "$(cat f)"',
    "4802-expansion-backtick": "ai-memory serve --store-url `cat f`",
    "4802-expansion-uri-var": 'ai-memory serve --store-url "$PG_URI"',
    "4802-docker-e-store-url": 'docker run -e AI_MEMORY_STORE_URL="$DSN" img serve',
    "4802-docker-e-glued": 'docker run -ePOSTGRES_PASSWORD="$PG_PW" postgres:16',
    "4802-sh-c-pgpassword": 'sh -c "PGPASSWORD=$X psql -h h"',
    "4802-set-o-xtrace": "set -o xtrace\nprintf '%s' \"$DB_PASS\" | x\n",
    "4802-shebang-x": "#!/bin/bash -x\nprintf '%s' \"$PGPW\" | x\n",
    "4802-traced-pw-suffix": "set -x\nprintf '%s' \"$PGPW\" | x\n",
    "4802-cloud-init-pw-var": "write_files:\n  - path: /opt/p.sh\n    permissions: '0755'\n    content: |\n      x '${pg_pw}'\n",
    # #4609: xtrace on while the password is handled.
    "xtrace-secret": "set -euxo pipefail\nprintf '%s' ${db_password} > /etc/x\n",
    "xtrace-secret-after-restore": "set -x\nset +x\nset -x\necho $PG_PW\n",
    # #4604: the role password in a psql -c statement, and a readable script.
    "psql-create-user": "sudo -u postgres psql -c \"CREATE USER aimemory WITH PASSWORD '${db_password}';\"",
    "psql-alter-role": "psql -h h -d d --command=\"ALTER ROLE a WITH PASSWORD 'hunter2'\"",
    "cloud-init-0755": "write_files:\n  - path: /opt/p.sh\n    permissions: '0755'\n    content: |\n      x '${db_password}'\n",
    "cloud-init-no-perms": "write_files:\n  - path: /opt/p.sh\n    content: |\n      x ${api_token}\n",
}
RED_PROBES.update({
    # #4802 / #4804: a psql URI password in a prose file (the migration guides).
    "4804 psql URI password in prose": "psql 'postgres://aimemory:%s@HOST:5432/aimemory' -c x" % PW,
    "4808 docker -e literal password in prose": "docker run -e POSTGRES_PASSWORD=%s postgres:16" % PW,
    "4859 psql --set password in prose": 'psql --set=pw="$PG_PW" -f bootstrap.sql',
})
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
    "4859-psql-v-non-secret-name": "psql -v ON_ERROR_STOP=1 -v role=aimemory -f x.sql",
    "5448-psql-v-digit-non-secret-name": "psql -v 1x=1 -f x.sql",
    "5448-psql-v-bare-name": "psql -v ON_ERROR_STOP -f x.sql",
    "5448-psql-v-value-holds-equals-and-pw": "psql -v role=pw=x -f x.sql",
    "5448-psql-v-substituted-value-only": 'psql -v role="$ROLE_NAME" -f x.sql',
    "5482-split-word-not-psql": 'p\\sqlx -v role=aimemory -f x.sql',
    "5482-quoted-psql-no-secret": 'echo "psql" -v role=aimemory -f x.sql',
    "5483-psql-v-neutral-value-expansion": 'psql -v x="$DB_NAME" -f x.sql',
    "5483-psql-v-neutral-value-dollar-only": 'psql -v n=$ROWS -f x.sql',
    "5483-psql-v-ascii-name-literal-value": 'psql -v role=aimemory -v n=3 -f x.sql',
    "5481-psql-cluster-digit-non-secret-name": "psql -1v role=aimemory -f x.sql",
    "4808-docker-e-dsn-inherit": "docker run -e DATABASE_URL img",
    "4808-docker-e-dsn-no-password": "docker run -e DATABASE_URL=postgres://u@h/d img",
    "4808-psql-set-no-secret": "psql --set=ON_ERROR_STOP=1 -f bootstrap.sql",
    "4808-expansion-conn-file": 'ai-memory serve --store-url "$PG_CONN_FILE"',
    "4808-ssh-remote-stdin-url": "ssh root@h \"IFS= read -r AI_MEMORY_STORE_URL; ai-memory serve\" < url",
    "4808-psql-dollar-redacted": "psql -c \"ALTER ROLE u PASSWORD $$...$$\"",
    "4802-set-plus-o-xtrace": "set -o xtrace\nset +o xtrace\nprintf '%s' \"$DB_PASS\" | x\nset -x\n",
    "4804-psql-pgpass-uri": "psql 'postgres://aimemory@HOST:5432/aimemory' -c x",
    "4802-psql-uri-comment": "# psql postgres://u:hunter2@h/d",
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


def _provision_body(tpl: str) -> List[str]:
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


def _credential_harness(body: List[str], scratch: Path) -> str:
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


def _run_provision_probe(tpl: str) -> Tuple[str, int, str]:
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
    red += 1
    # A psql URI password is a text rule now (#4802), so the prose-file check
    # uses a form only the shell reader refuses (a NAME=value on a sudo argv).
    if scan_text("probe.md", RED_SHELL_PROBES["r3 sudo NAME=value keeps the password on the sudo argv"]):
        print("SELF-TEST FAIL: a prose file (.md) was read as a shell file", file=sys.stderr)
        bad += 1
    red += 1
    if scan_text("scripts/check-docs-no-argv-secrets.py", RED_PROBES["inline"]):
        print("SELF-TEST FAIL: self-exempt path was flagged", file=sys.stderr)
        bad += 1
    # #5482: the split-head rewrite keeps every offset, so a hit that follows split
    # heads with tails is still reported on its own line (line 4 here).
    red += 1
    pad = "psql_" + "x" * 30 + " -X -f a.sql\n"
    pinned = [h for h in scan_text("probe.sh", pad * 3 + 'psql -v pw="$PG_PW" -f x.sql\n')
              if h[2].startswith("[env-password-argv]")]
    if [h[1] for h in pinned] != [4]:
        print("SELF-TEST FAIL: a psql -v hit after split heads is not reported on line 4: %r" % pinned, file=sys.stderr)
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
