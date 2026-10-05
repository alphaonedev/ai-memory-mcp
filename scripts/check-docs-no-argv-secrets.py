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

# Redaction tokens that are not a credential: a closed list of whole values, shared by every
# rule that asks whether a password is a placeholder (is_redaction).
REDACTION_TOKENS = frozenset({"...", "…", "***", "redacted", "<redacted>", "xxxx"})

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
# #5597: the spellings are read by a parser (xtrace_effect), not by a pattern: every option
# cluster of set, shopt -o and the shebang is walked, and an option word the gate cannot read
# (an expansion) counts as xtrace on.
XTRACE_PREFIX_WORDS = frozenset({"-", "!", "{", "}", "if", "then", "else", "elif", "do",
                                 "while", "until", "time", "builtin", "command", "exec"})
XTRACE_UNREAD = ("$", "`")
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
# #5482 / #5512 (round-6): the shell strips backslashes and quotes inside a word and
# builds it from ANSI-C segments and empty substitutions, so \psql, p\sql, ps''ql,
# "ps"ql, ps$'q'l, $'ps\x71l' and ps$()ql all run psql. psql_head_view() resolves each
# shell word (the resolver below) and rewrites a psql word to the plain psql word of
# the SAME length (padding with spaces) so every offset, and so every reported line,
# stays valid for both psql rules; a word that still holds an expansion, substitution,
# glob or brace and could spell psql is refused as undecidable.
PSQL_VAR_OPT_RE = re.compile(
    r"\s(?:-[A-Za-z0-9]*v\s*|--(?:set?|va(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)(?:=|\s+))"
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
# ${PG_PW}, $(cat<no space>pw), `cat<no space>pw`) is flagged under any name.
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
    """#4612 item 3: a placeholder is the WHOLE password (case-insensitive), never a part of
    it: hunterREDACTEDx and a***b are credentials."""
    return value.lower() in REDACTION_TOKENS


def is_url_redaction(value: str) -> bool:
    """#5620: a URL password is percent-decoded by libpq and sqlx before use, so the WHOLE
    decoded value is compared with the same closed list (%2A%2A%2A is ***). Other paths
    (an env value, an SQL literal) are not decoded and use is_redaction."""
    return is_redaction(unquote(value))


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
            if pw and not is_url_redaction(pw):
                return pw
    if "?" in rest:
        query = rest.split("?", 1)[1].split("#", 1)[0]
        for pair in query.split("&"):
            key, _, value = pair.partition("=")
            if unquote(key).strip().lower() == "password" and value and not is_url_redaction(value):
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


def set_xtrace(args: List[str]) -> Optional[bool]:
    """#5597: the xtrace state after the set builtin's arguments, or None when they do not
    touch it. Every cluster is walked (set -e -x, set -u -o xtrace); each o takes the next
    word as an option name; set - turns tracing off; -- or a first operand ends the options;
    an expansion where an option or an option name can stand counts as on (fail closed)."""
    state: Optional[bool] = None
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            break
        if arg == "-":
            return False
        if any(c in arg for c in XTRACE_UNREAD):
            return True
        if len(arg) < 2 or arg[0] not in "-+":
            break
        on = arg[0] == "-"
        for ch in arg[1:]:
            if ch == "x":
                state = on
            elif ch == "o" and i < len(args):
                name = args[i]
                i += 1
                if any(c in name for c in XTRACE_UNREAD):
                    return True
                if name == "xtrace":
                    state = on
    return state


def shopt_xtrace(args: List[str]) -> Optional[bool]:
    """#5597: shopt -so xtrace / shopt -s -o xtrace turn tracing on, -uo turns it off; an
    expansion in a flag or a name under -o counts as on."""
    flags = ""
    names: List[str] = []
    for arg in args:
        if any(c in arg for c in XTRACE_UNREAD):
            return True
        if arg.startswith("-") and len(arg) > 1 and not names:
            flags += arg[1:]
        else:
            names.append(arg)
    if "o" not in flags or "xtrace" not in names:
        return None
    if "s" in flags:
        return True
    return False if "u" in flags else None


def xtrace_effect(line: str, depth: int = 0) -> Optional[bool]:
    """#5597: the xtrace state a script line leaves (True on, False off, None unchanged).
    Every simple command is read; a quoted word holding a command string (eval, trap, sh -c)
    is read as a line of its own, so a nested set -x is never missed (a nested one in a
    subshell or child shell is counted too: fail closed)."""
    state: Optional[bool] = None
    for cmd in commands(split_words(line)):
        i = 0
        while i < len(cmd) and cmd[i].lstrip("\\") in XTRACE_PREFIX_WORDS:
            i += 1
        head = cmd[i].lstrip("\\") if i < len(cmd) else ""
        effect: Optional[bool] = None
        if head == "set":
            effect = set_xtrace(cmd[i + 1:])
        elif head == "shopt":
            effect = shopt_xtrace(cmd[i + 1:])
        if effect is not None:
            state = effect
        if depth < 3:
            for w in cmd[i:]:
                if any(c.isspace() for c in w):
                    nested = xtrace_effect(w, depth + 1)
                    if nested is not None:
                        state = nested
    return state


def shebang_xtrace(line: str) -> bool:
    """#5597: a shebang whose interpreter options turn xtrace on: an x in any - cluster or
    an o cluster followed by xtrace, after any number of words, env -S split strings
    included (#!/usr/bin/env -S bash -x, #!/bin/bash -o xtrace, #!/bin/bash -e -x)."""
    words: List[str] = []
    for w in line[2:].split():
        if w.startswith("-S") and len(w) > 2:
            words.extend(["-S", w[2:]])
        elif w.startswith("--split-string="):
            words.extend(["-S", w.split("=", 1)[1]])
        else:
            words.append(w)
    for k, w in enumerate(words[1:], 1):
        if w.startswith("-") and not w.startswith("--"):
            if "x" in w[1:]:
                return True
            if "o" in w[1:] and k + 1 < len(words) and words[k + 1] == "xtrace":
                return True
    return False


def scan_xtrace(rel: str, text: str) -> List[Hit]:
    """Credential-bearing lines executed while xtrace is on (#4609)."""
    hits: List[Hit] = []
    traced = False
    for n, ln in enumerate(text.splitlines(), 1):
        if n == 1 and ln.startswith("#!"):
            traced = shebang_xtrace(ln)
            continue
        if ln.lstrip().startswith("#"):
            continue
        effect = xtrace_effect(ln)
        if effect is not None:
            traced = effect
            continue
        if traced and TRACED_SECRET_RE.search(ln):
            hits.append((rel, n, "[xtrace-secret] " + ln.strip()[:120]))
    return hits


# --- #5512 / #5513 (PR 4810 round-6 F1, F2): a shell word resolver ----------------
# The shell builds the word psql (and the option -v) from quotes, backslashes, a
# backslash-newline, an ANSI-C segment ($'ps\x71l'), an empty substitution ($(), ``),
# and, undecidably, a non-empty substitution, an expansion, a glob or a brace. Naming
# the spellings one at a time is an open-ended denylist; this follows the closed-world
# fail-closed shape of #4869: every word is resolved to a plain literal when it can be,
# and a word that still holds an expansion and could spell psql is refused.
# A piece is ("l", text) for a literal, or ("h", (start, end)) for an expansion the gate
# cannot decide; a word is (start, end, pieces) and offsets index the scanned text.
WordPiece = Tuple[str, object]
Word = Tuple[int, int, List[WordPiece]]
WORD_DELIMS = " \t\r\n;|&<>()"
SCAN_LIMIT = 4000
# A word made only of these characters resolves to itself: the resolver skips it.
PLAIN_WORD_RE = re.compile(r"[A-Za-z0-9_./:=@%+,#~^!-]+")
MAX_NEST = 6
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ANSI_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r",
               "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def ansi_c_decode(body: str) -> Optional[str]:
    """Decode the inside of $'...' as bash does (\\xHH, octal, \\uHHHH, \\cX and the
    single-letter escapes). None when the result holds a NUL (bash cuts the word there,
    so the gate calls it undecidable)."""
    out: List[str] = []
    i = 0
    while i < len(body):
        c = body[i]
        if c != "\\" or i + 1 >= len(body):
            out.append(c)
            i += 1
            continue
        d = body[i + 1]
        if d in ANSI_SIMPLE:
            out.append(ANSI_SIMPLE[d])
            i += 2
            continue
        num = re.match(r"x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}", body[i + 1:])
        if num:
            tok = num.group(0)
            value = int(tok[1:], 16) if tok[0] in "xuU" else int(tok, 8) & 0xFF
            try:
                out.append(chr(value))
            except (ValueError, OverflowError):
                return None
            i += 1 + len(tok)
        elif d == "c" and i + 2 < len(body):
            out.append(chr(ord(body[i + 2]) & 0x1F))
            i += 3
        else:
            out.append("\\" + d)
            i += 2
    decoded = "".join(out)
    return None if "\x00" in decoded else decoded


def match_close(text: str, i: int, hi: int, open_c: str, close_c: str) -> int:
    """Index of the bracket closing text[i], or -1 (naive nesting, quotes skipped)."""
    depth = 0
    k = i
    stop = min(hi, i + SCAN_LIMIT)
    while k < stop:
        c = text[k]
        if c == "\\":
            k += 2
            continue
        if c in "'\"":
            end = text.find(c, k + 1, stop)
            k = (end if end >= 0 else k) + 1
            continue
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return k
        k += 1
    return -1


def consume_dollar(text: str, j: int, hi: int, in_dq: bool) -> Tuple[int, WordPiece, Optional[Tuple[int, int]]]:
    """One expansion starting at text[j] == "$": (end, piece, inner span to rescan)."""
    nxt = text[j + 1:j + 2] if j + 1 < hi else ""
    if nxt in ("(", "{"):
        k = match_close(text, j + 1, hi, nxt, ")" if nxt == "(" else "}")
        if k < 0:
            eol = text.find("\n", j, hi)
            return (hi if eol < 0 else eol), ("h", (j, hi if eol < 0 else eol)), None
        if nxt == "(" and not text[j + 2:k].strip():
            return k + 1, ("l", ""), None
        return k + 1, ("h", (j, k + 1)), ((j + 2, k) if nxt == "(" else None)
    if nxt == "'" and not in_dq:
        k = j + 2
        while k < hi and text[k] != "\n":
            if text[k] == "\\":
                k += 2
                continue
            if text[k] == "'":
                decoded = ansi_c_decode(text[j + 2:k])
                piece: WordPiece = ("l", decoded) if decoded is not None else ("h", (j, k + 1))
                return k + 1, piece, None
            k += 1
        return j + 1, ("l", "$"), None
    if nxt == '"' and not in_dq:
        return j + 1, ("l", ""), None
    m = NAME_RE.match(text, j + 1)
    if m and m.end() <= hi:
        return m.end(), ("h", (j, m.end())), None
    if nxt and nxt in "0123456789?$!#@*-":
        return j + 2, ("h", (j, j + 2)), None
    return j + 1, ("l", "$"), None


def backtick_close(text: str, j: int, hi: int) -> int:
    """Index of the backtick closing the one at text[j] on the SAME line, else -1: prose
    pairs backticks across lines (`a` ... `b`), so a span is never allowed to cross a newline."""
    k = j + 1
    stop = min(hi, j + SCAN_LIMIT)
    while k < stop:
        if text[k] == "\\":
            k += 2
            continue
        if text[k] == "\n":
            return -1
        if text[k] == "`":
            return k
        k += 1
    return -1


def parse_dq(text: str, j: int, hi: int, subs: List[Tuple[int, int]]) -> Optional[Tuple[int, List[WordPiece]]]:
    """A double-quoted string on ONE line starting at text[j]; None when it is not closed
    on this line (the quote is then read as a literal, never as a span that could swallow
    later commands)."""
    pieces: List[WordPiece] = []
    buf: List[str] = []
    local: List[Tuple[int, int]] = []
    k = j + 1
    while k < hi:
        c = text[k]
        if c == "\\":
            d = text[k + 1:k + 2]
            if d == "\n":
                k += 2
            elif d in ("$", "`", '"', "\\"):
                buf.append(d)
                k += 2
            else:
                buf.append("\\")
                k += 1
            continue
        if c == "\n":
            return None
        if c == '"':
            if buf:
                pieces.append(("l", "".join(buf)))
            subs.extend(local)
            subs.append((j + 1, k))
            return k + 1, pieces
        if c in "$`":
            if buf:
                pieces.append(("l", "".join(buf)))
                buf = []
            if c == "$":
                k, piece, inner = consume_dollar(text, k, hi, True)
            else:
                close = backtick_close(text, k, hi)
                if close < 0:
                    buf.append("`")
                    k += 1
                    continue
                inner = (k + 1, close) if text[k + 1:close].strip() else None
                piece = ("h", (k, close + 1)) if inner else ("l", "")
                k = close + 1
            pieces.append(piece)
            if inner:
                local.append(inner)
            continue
        buf.append(c)
        k += 1
    return None


def parse_word(text: str, i: int, hi: int, subs: List[Tuple[int, int]]) -> Tuple[int, List[WordPiece]]:
    """One shell word from text[i]; spans to scan again (substitutions and quoted
    strings, where another command may start) are appended to subs."""
    pieces: List[WordPiece] = []
    j = i
    while j < hi:
        c = text[j]
        if c in WORD_DELIMS:
            break
        if c == "\\":
            if text.startswith("\n", j + 1):
                j += 2
            elif text.startswith("\r\n", j + 1):
                j += 3
            elif j + 1 < hi:
                pieces.append(("l", text[j + 1]))
                j += 2
            else:
                pieces.append(("l", "\\"))
                j += 1
        elif c == "'":
            k = text.find("'", j + 1, hi)
            eol = text.find("\n", j + 1, hi)
            if k >= 0 and (eol < 0 or k < eol):
                pieces.append(("l", text[j + 1:k]))
                subs.append((j + 1, k))
                j = k + 1
            else:
                pieces.append(("l", "'"))
                j += 1
        elif c == '"':
            parsed = parse_dq(text, j, hi, subs)
            if parsed is None:
                pieces.append(("l", '"'))
                j += 1
            else:
                j = parsed[0]
                pieces.extend(parsed[1])
        elif c == "$":
            j, piece, inner = consume_dollar(text, j, hi, False)
            pieces.append(piece)
            if inner:
                subs.append(inner)
        elif c == "`":
            close = backtick_close(text, j, hi)
            if close < 0:
                pieces.append(("l", "`"))
                j += 1
            else:
                inner = (j + 1, close) if text[j + 1:close].strip() else None
                pieces.append(("h", (j, close + 1)) if inner else ("l", ""))
                if inner:
                    subs.append(inner)
                j = close + 1
        elif c in "*?":
            pieces.append(("h", (j, j + 1)))
            j += 1
        elif c in "[{":
            close_c = "]" if c == "[" else "}"
            k = text.find(close_c, j + 1, hi)
            body = text[j + 1:k] if k >= 0 else ""
            if k >= 0 and body and not re.search(r"[\s;|&<>()]", body) and (c == "[" or "," in body or ".." in body):
                pieces.append(("h", (j, k + 1)))
                j = k + 1
            else:
                pieces.append(("l", c))
                j += 1
        else:
            pieces.append(("l", c))
            j += 1
    return j, pieces


def scan_words(text: str, lo: int = 0, hi: Optional[int] = None, nested: bool = True,
               depth: int = 0) -> List[Word]:
    """Every shell word of text[lo:hi]; with nested, also the words inside quoted strings
    and command substitutions (offsets always index text)."""
    hi = len(text) if hi is None else hi
    out: List[Word] = []
    i = lo
    while i < hi:
        if text[i] in WORD_DELIMS:
            i += 1
            continue
        plain = PLAIN_WORD_RE.match(text, i, hi)
        if plain and (plain.end() >= hi or text[plain.end()] in WORD_DELIMS):
            i = plain.end()
            continue
        subs: List[Tuple[int, int]] = []
        j, pieces = parse_word(text, i, hi, subs)
        if j <= i:
            i += 1
            continue
        if pieces:
            out.append((i, j, pieces))
        if nested and depth < MAX_NEST:
            for a, b in subs:
                if b > a:
                    out.extend(scan_words(text, a, b, True, depth + 1))
        i = j
    return out


def word_literal(pieces: List[WordPiece]) -> Optional[str]:
    """The plain string a word resolves to, or None when any piece is undecidable."""
    if any(kind == "h" for kind, _ in pieces):
        return None
    return "".join(str(value) for _, value in pieces)


def word_view(text: str, pieces: List[WordPiece]) -> str:
    """The word as the shell passes it where that is known: literals resolved, each
    undecidable expansion kept as written."""
    # An expansion is ONE word to the shell whatever spaces it holds, so its whitespace is
    # masked (the -v operand rule reads an operand to its first space).
    return "".join(str(v) if k == "l" else re.sub(r"\s", "\x01", text[v[0]:v[1]])  # type: ignore[index]
                   for k, v in pieces)


def glob_class_admits(raw: str, ch: str) -> bool:
    """Whether the bracket expression raw ([abc], [a-z]) can match ch; a negated or POSIX
    class is treated as matching anything (undecidable stays refused)."""
    body = raw[1:-1]
    if not body or body[0] in "!^" or "[:" in body:
        return True
    pos = 0
    while pos < len(body):
        if pos + 2 < len(body) and body[pos + 1] == "-":
            if body[pos].lower() <= ch <= body[pos + 2].lower():
                return True
            pos += 3
        else:
            if body[pos].lower() == ch:
                return True
            pos += 1
    return False


def psql_word_possible(text: str, pieces: List[WordPiece]) -> bool:
    """True when a word that holds an undecidable piece could still spell psql (or a
    wrapper such as run_psql): some expansion of every hole makes it psql[A-Za-z0-9_]*
    with at least two literals standing for letters of the fixed four (one alone is prose such as **loss**). A ? or [..] glob
    stands for exactly one character, anything else for any string."""
    chars: List[Tuple[str, str]] = []
    for kind, value in pieces:
        if kind == "l":
            chars.extend(("L", ch) for ch in str(value))
        else:
            raw = text[value[0]:value[1]]  # type: ignore[index]
            chars.append(("1", raw) if raw[:1] in ("?", "[") else ("W", raw))
    starts = [0] + [k + 1 for k, (kind, ch) in enumerate(chars) if kind == "L" and ch in "/_-"]
    target = "psql"
    seen: dict = {}

    def fits(pos: int, tp: int, used: int) -> bool:
        """Can chars[pos:] finish a psql word, given tp of its 4 fixed letters are placed
        and `used` (capped at 2) counts the literals that stood for them?"""
        key = (pos, tp, used)
        if key not in seen:
            seen[key] = False
            if pos == len(chars):
                seen[key] = tp >= 4 and used >= 2
            elif chars[pos][0] == "W":
                takes = range(0, max(0, 4 - tp) + 1)
                seen[key] = any(fits(pos + 1, tp + take, used) for take in takes)
            elif chars[pos][0] == "1":
                raw = chars[pos][1]
                ok = tp >= 4 or raw[0] == "?" or glob_class_admits(raw, target[tp])
                seen[key] = ok and fits(pos + 1, min(tp + 1, 4), used)
            else:
                ch = chars[pos][1]
                if tp < 4:
                    seen[key] = ch.lower() == target[tp] and fits(pos + 1, tp + 1, min(used + 1, 2))
                else:
                    seen[key] = ch.isascii() and (ch.isalnum() or ch == "_") and fits(pos + 1, tp, used)
        return seen[key]

    for s in starts:
        if any(kind != "L" for kind, _ in chars[s:]) and fits(s, 0, 0):
            return True
    return False


def psql_head_view(text: str, strict: bool = True) -> Tuple[str, List[int]]:
    """The text with every shell-spelled psql word rewritten to the plain word, same
    length (removed characters become spaces), so every offset and line stays valid for
    the psql rules; and the offsets of psql-looking words the gate cannot decide.
    Words are resolved with scan_words, replacing the single-spelling regex of #5482.
    strict is False for a prose or source file (not a shell script), where a word that
    opens with a glob (**sqlite**, *SQL_NAME) is emphasis or a dereference, not a command."""
    chars = list(text)
    undecidable: List[int] = []
    for start, end, pieces in scan_words(text):
        literal = word_literal(pieces)
        if literal is None:
            opens_glob = pieces[0][0] == "h" and text[start] in "*?["
            if (strict or not opens_glob) and psql_word_possible(text, pieces):
                undecidable.append(start)
            continue
        if (literal != text[start:end] and len(literal) <= end - start and not re.search(r"\s", literal)
                and PSQL_HEAD_RE.search(" " + literal)):
            chars[start:end] = list(literal.ljust(end - start))
    return "".join(chars), undecidable


def normalise_psql_heads(text: str) -> str:
    """Rewrite every shell-spelled psql word (\\psql, p\\sql, ps''ql, "ps"ql, ps$'q'l,
    $'ps\\x71l', ps$()ql) to a plain psql word of the same length (#5482, #5512)."""
    return psql_head_view(text)[0]


PSQL_FLAG_LETTERS = frozenset("AabEeHlnqstVWwXxz0123456789")


def option_word_undecidable(pieces: List[WordPiece]) -> bool:
    """True for a word that opens like a psql option and then holds an expansion, so the
    shell may build -v or --set from it at run time (-$o, -X$o, --$o, --s$x): the
    literal prefix is dashes plus only argument-less flag letters, or is a prefix of
    set or variable."""
    prefix = ""
    for kind, value in pieces:
        if kind != "l":
            break
        prefix += str(value)
    else:
        return False
    if not prefix.startswith("-"):
        return False
    if prefix.startswith("--"):
        tail = prefix[2:].lower()
        return "set".startswith(tail) or "variable".startswith(tail)
    return all(ch in PSQL_FLAG_LETTERS for ch in prefix[1:])


def segment_view(segment: str) -> Tuple[str, List[int]]:
    """The text a psql head passes on its argv as far as it can be known: each word is
    resolved (quotes, backslashes, ANSI-C and empty substitutions removed, so $'-v' and
    -v read the same), an expansion stays as written; and the offsets of option words
    that hold an expansion after an option-like prefix (an undecidable option)."""
    out: List[str] = []
    undecided: List[int] = []
    last = 0
    for start, end, pieces in scan_words(segment, nested=False):
        out.append(segment[last:start])
        out.append(word_view(segment, pieces))
        last = end
        if word_literal(pieces) is None and option_word_undecidable(pieces):
            undecided.append(start)
    out.append(segment[last:])
    return "".join(out), undecided


def psql_segment_end(joined: str, head_end: int) -> int:
    """Offset where the command that owns the psql word ends (#5516): the newline, an
    unquoted ; | or & (not a redirection such as 2>&1 or &>) at the nesting level of the
    word, or the close of the quote, parenthesis or backtick that holds it. Quote, $( ),
    ( ) and backtick nesting is tracked from the line start so a separator inside a
    string or a substitution does not end the segment. A quote that holds only the word
    ("$PSQL", "psql") is part of the word, not an enclosing string, so its close does
    not end the segment."""
    n = len(joined)
    i = joined.rfind("\n", 0, head_end) + 1
    stack: List[str] = []
    opens: List[int] = []
    base = -1
    base_top = ""
    word_quote = False

    def push(ch: str, at: int) -> None:
        stack.append(ch)
        opens.append(at)

    def pop() -> None:
        stack.pop()
        opens.pop()

    while i < n:
        if base < 0 and i >= head_end:
            base, base_top = len(stack), (stack[-1] if stack else "")
            if base_top in ('"', "'"):
                close = joined.find(base_top, head_end)
                inside = joined[opens[-1] + 1:close if close >= 0 else n]
                word_quote = close >= 0 and not re.search(r"\s", inside)
        c = joined[i]
        if c == "\n":
            return i
        top = stack[-1] if stack else ""
        if c == "\\" and top != "'":
            i += 2
            continue
        if top == "'":
            if c == "'":
                pop()
        elif top == '"':
            if c == '"':
                pop()
            elif c == "`":
                push("`", i)
            elif c == "$" and joined[i + 1:i + 2] == "(":
                push("(", i)
                i += 1
        elif c in "'\"":
            push(c, i)
        elif c == "`":
            if top == "`":
                pop()
            else:
                push("`", i)
        elif c == "(":
            push("(", i)
        elif c == ")":
            if top == "(":
                pop()
            elif base >= 0:
                return i
        elif c in ";|&" and base >= 0 and len(stack) == base and top == base_top:
            redirect = c == "&" and (joined[i - 1:i] in ("<", ">") or joined[i + 1:i + 2] == ">")
            if not redirect:
                return i
        if base >= 0 and len(stack) < base:
            if not word_quote:
                return i
            word_quote = False
            base = len(stack)
            base_top = stack[-1] if stack else ""
        i += 1
    return n


# #5556 #5557 #5558 (round 8) and round 9 (the unresolved-head class, B-operand shape):
# the proof obligation is inverted. A credential-shaped -v / --set / --variable operand is
# CLEAN only when the command it belongs to provably has a fully literal head that is not
# psql. Every other command (a non-literal head, a psql head, a head behind a wrapper,
# keyword, option or redirection form the model below does not know) is undecidable, and an
# undecidable command with a credential operand is flagged. There is no word-count cap: the
# walk is bounded by the command, and the command comes from a tokenisation of the text.
#
# Command starts (shell_commands): the text start, a newline, an unquoted ; & | ( and ) (so
# &&, ||, |&, ;; and a case-arm close paren), and the inside of every $( ), backtick span,
# <( ), >( ), ${ } body, and every whole-word quoted string that holds a space (read as a
# command string). The reserved words !, {, }, then, do, else, elif, if, while, until, fi,
# done and esac stand before a command and are skipped; coproc is modelled; case, for,
# select and function are not, so a command that opens with them is undecidable.
# A redirection ([n]<, [n]>, >>, <<, <<-, <<<, <>, >|, <&, >&, &>, &>>, {name}>) and its
# target are removed from the argv wherever they stand. A word with an unclosed quote is
# undecidable (the quoting of the rest of the line is unknown).
#
# Transparent wrappers (TRANSPARENT_WRAPPERS) are followed with their exact grammar: the
# options with no argument, the options that take one argument (attached, separate, or
# --long=value), the count of positional operands before the command, and where a command
# string stands. An option the table does not list, a long-option abbreviation, a
# non-literal word where an option or the command may stand, and a word in an argument or
# positional slot that may expand to other than one field (an unquoted expansion) make the
# command undecidable. KNOWN_RUNNERS run their arguments with a grammar that is not
# modelled (ssh, docker, kubectl, xargs, su, nsenter, ...) and are undecidable.
#
# B (round 9): the operand is psql's NAME=VALUE. Under a head that is not proven to be psql,
# an operand whose first literal colon stands before any literal = (a docker or compose
# mount SRC:DST, /run/secrets/pgpass:/s:ro, "$SECRET_DIR:/s") is not that shape: psql
# rejects a variable name that holds a colon, and an = that only an expansion could add is
# the #5398 indirection limit. A literal psql head keeps the full operand rule.
#
# STATED LIMITS: a fully literal head that is neither psql, a known runner nor a modelled
# wrapper is a different program and its arguments are not read (a site-specific script that
# itself runs "$@" is not followed); a word in prose that the tokeniser reads as a
# redirection target (an HTML tag such as <code>) is not a command word.
Grammar = Tuple[frozenset, frozenset, int, frozenset, frozenset, bool]
# name -> (flags, options with one argument, positional operands, command-string options,
#          long options with an optional =argument, obsolete -NUM accepted)
TRANSPARENT_WRAPPERS = {
    "env": (frozenset({"-", "-i", "-0", "-v", "--ignore-environment", "--null", "--debug"}),
            frozenset({"-u", "--unset", "-C", "--chdir"}), 0, frozenset(), frozenset(), False),
    "nice": (frozenset(), frozenset({"-n", "--adjustment"}), 0, frozenset(), frozenset(), True),
    "nohup": (frozenset(), frozenset(), 0, frozenset(), frozenset(), False),
    "timeout": (frozenset({"-v", "--verbose", "--foreground", "--preserve-status"}),
                frozenset({"-k", "--kill-after", "-s", "--signal"}), 1, frozenset(), frozenset(), False),
    "stdbuf": (frozenset(), frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}), 0,
               frozenset(), frozenset(), False),
    "setsid": (frozenset({"-c", "-f", "-w", "--ctty", "--fork", "--wait"}), frozenset(), 0,
               frozenset(), frozenset(), False),
    "taskset": (frozenset({"-a", "-c", "--all-tasks", "--cpu-list"}), frozenset(), 1, frozenset(),
                frozenset(), False),
    "ionice": (frozenset({"-t", "--ignore"}), frozenset({"-c", "-n", "--class", "--classdata"}), 0,
               frozenset(), frozenset(), False),
    "chrt": (frozenset({"-a", "-b", "-d", "-f", "-i", "-o", "-r", "-R", "-v", "--all-tasks", "--batch",
                        "--deadline", "--fifo", "--idle", "--other", "--rr", "--reset-on-fork",
                        "--verbose"}),
             frozenset({"-T", "-P", "-D", "--sched-runtime", "--sched-period", "--sched-deadline"}), 1,
             frozenset(), frozenset(), False),
    "flock": (frozenset({"-s", "-x", "-e", "-u", "-n", "-o", "-F", "--shared", "--exclusive", "--unlock",
                         "--nonblock", "--nb", "--close", "--no-fork", "--verbose"}),
              frozenset({"-w", "-E", "--timeout", "--wait", "--conflict-exit-code"}), 1,
              frozenset({"-c", "--command"}), frozenset(), False),
    "chroot": (frozenset({"--skip-chdir"}), frozenset({"--userspec", "--groups"}), 1, frozenset(),
               frozenset(), False),
    "sudo": (frozenset({"-A", "-B", "-b", "-E", "-H", "-i", "-k", "-n", "-P", "-S", "-s", "--askpass",
                        "--bell", "--background", "--preserve-env", "--set-home", "--login",
                        "--reset-timestamp", "--non-interactive", "--preserve-groups", "--stdin",
                        "--shell"}),
             frozenset({"-C", "-D", "-g", "-p", "-R", "-r", "-T", "-t", "-U", "-u", "--close-from",
                        "--chdir", "--group", "--prompt", "--chroot", "--role", "--command-timeout",
                        "--type", "--other-user", "--user"}), 0, frozenset(),
             frozenset({"--preserve-env"}), False),
    "doas": (frozenset({"-n", "-s"}), frozenset({"-u", "-C"}), 0, frozenset(), frozenset(), False),
    "exec": (frozenset({"-c", "-l"}), frozenset({"-a"}), 0, frozenset(), frozenset(), False),
    "command": (frozenset({"-p"}), frozenset(), 0, frozenset(), frozenset(), False),
    "builtin": (frozenset(), frozenset(), 0, frozenset(), frozenset(), False),
    "time": (frozenset({"-p"}), frozenset(), 0, frozenset(), frozenset(), False),
}
# A shell takes -c and a command string, or a script path; the words after either are $0, $1...
SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "yash", "posh"})
SHELL_OPTION_LETTERS = frozenset("abcefhiklmnprstuvxBCEHPT")
SHELL_LONG_FLAGS = frozenset({"--login", "--norc", "--noprofile", "--posix", "--noediting",
                              "--restricted", "--verbose"})
KNOWN_RUNNERS = frozenset({
    "eval", "xargs", "nsenter", "unshare", "systemd-run", "systemd-nspawn", "su", "runuser", "ssh",
    "sshpass", "autossh", "mosh", "docker", "podman", "nerdctl", "kubectl", "oc", "machinectl",
    "lxc-attach", "lxc", "incus", "watch", "unbuffer", "strace", "ltrace", "valgrind", "gdb",
    "script", "firejail", "bwrap", "proot", "fakeroot", "faketime", "numactl", "cgexec", "schroot",
    "setpriv", "sg", "newgrp", "pkexec", "parallel", "find", "entr", "tini", "dumb-init", "gosu",
    "su-exec", "chpst", "daemonize", "start-stop-daemon", "prlimit", "cpulimit", "trickle",
    "torsocks", "proxychains", "proxychains4", "catchsegv", "chronic", "sem", "rlwrap", "ip",
    "trap", "expect", "screen", "tmux", "busybox", "toybox", "aws-vault", "op", "doppler", "direnv",
    "dotenv", "nix-shell", "bundle", "poetry", "pipenv", "uv", "uvx", "npx", "pipx",
})
UNMODELLED_KEYWORDS = frozenset({"case", "for", "select", "function", "in"})
SKIPPED_KEYWORDS = frozenset({"!", "{", "}", "then", "do", "else", "elif", "if", "while", "until",
                              "fi", "done", "esac"})
# Document markers that stand before a command in prose and configuration: a list bullet, a
# shell prompt, a Dockerfile instruction; a word that ends with a colon is a label or a key
# whose value may be a command (YAML run:, "Note:").
DOC_MARKERS = frozenset({"-", "+", "$", "#", "%", "RUN", "CMD", "ENTRYPOINT"})
LIST_NUMBER_RE = re.compile(r"\d+\.")
REDIR_OP_RE = re.compile(r"&>>?|<<<|<<-?|<>|<&|>&|>>|>\||<|>")
FD_PREFIX_RE = re.compile(r"\d+|\{[A-Za-z_][A-Za-z0-9_]*\}")
NEST_LIMIT = 8
CLEAN, UNDECIDED, PSQL, STRING_HIT, RUNNER = "clean", "undecidable", "psql", "string-hit", "runner"
Command = Tuple[List[Word], bool]


def unclosed_quote(raw: str) -> bool:
    """True when a word holds a quote or backtick the parser took as a literal because it does
    not close on its line: the quoting of the rest of the line is then unknown."""
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c == "\\":
            i += 2
            continue
        if c in "'`":
            k = raw.find(c, i + 1)
            if k < 0:
                return True
            i = k + 1
            continue
        if c == '"':
            k = i + 1
            while k < n and raw[k] != '"':
                k += 2 if raw[k] == "\\" else 1
            if k >= n:
                return True
            i = k + 1
            continue
        i += 1
    return False


def shell_commands(text: str, lo: int = 0, hi: Optional[int] = None, depth: int = 0,
                   out: Optional[List[Command]] = None) -> List[Command]:
    """Every simple command of text[lo:hi] and of every nested context, as (argv words,
    forced): redirections and their targets are dropped; forced marks a command found past
    the nesting limit, which is never proven clean."""
    hi = len(text) if hi is None else hi
    out = [] if out is None else out
    forced = depth >= NEST_LIMIT
    cmd: List[Word] = []

    def flush() -> None:
        if cmd:
            out.append((list(cmd), forced))
            cmd.clear()

    def nest(a: int, b: int) -> None:
        if b > a:
            shell_commands(text, a, b, depth + 1, out)

    i = lo
    while i < hi:
        c = text[i]
        if c in " \t\r":
            i += 1
            continue
        if c in "<>" and text[i + 1:i + 2] == "(":
            k = match_close(text, i + 1, hi, "(", ")")
            end = k if k >= 0 else (text.find("\n", i, hi) if "\n" in text[i:hi] else hi)
            nest(i + 2, end)
            cmd.append((i, min(hi, end + 1), [("h", (i, min(hi, end + 1)))]))
            i = min(hi, end + 1)
            continue
        if c in "<>" or (c == "&" and text[i + 1:i + 2] == ">"):
            m = REDIR_OP_RE.match(text, i)
            j = m.end() if m else i + 1
            if cmd and cmd[-1][1] == i and FD_PREFIX_RE.fullmatch(text[cmd[-1][0]:i]):
                cmd.pop()
            while j < hi and text[j] in " \t":
                j += 1
            if j < hi and text[j] not in WORD_DELIMS:
                subs: List[Tuple[int, int]] = []
                j, _pieces = parse_word(text, j, hi, subs)
                for a, b in subs:
                    nest(a, b)
            i = max(j, i + 1)
            continue
        if c in "\n;|&()":
            flush()
            i += 1
            continue
        subs = []
        j, pieces = parse_word(text, i, hi, subs)
        if j <= i:
            i += 1
            continue
        cmd.append((i, j, pieces))
        for a, b in subs:
            quote = text[a - 1:a]
            if quote in ("'", '"') and text[b:b + 1] == quote:
                # A quoted string is a command string only when it is the whole word and holds a space.
                if a - 1 == i and b + 1 == j and re.search(r"\s", text[a:b]):
                    nest(a, b)
            else:
                nest(a, b)
        for kind, value in pieces:
            if kind != "h":
                continue
            a, b = value  # type: ignore[misc]
            if text.startswith("${", a):
                nest(a + 2, b - 1)
            elif text.startswith("$(", a) and text[b - 1:b] != ")":
                nest(a + 2, b)  # an unclosed $( runs to the line end
        i = j
    flush()
    return out


def one_field(text: str, word: Word) -> bool:
    """A word the shell passes as exactly one argv word: fully literal, or one double-quoted
    string that holds no "$@" or array [@] expansion."""
    start, end, pieces = word
    raw = text[start:end]
    if unclosed_quote(raw):
        return False
    if word_literal(pieces) is not None:
        return True
    if not raw.startswith('"'):
        return False
    parsed = parse_dq(text, start, end, [])
    if parsed is None or parsed[0] != end:
        return False
    return "$@" not in raw and "${@" not in raw and "[@]" not in raw


def plain_literal(text: str, word: Word) -> Optional[str]:
    """The literal a word resolves to, or None when it holds an expansion or an unclosed quote."""
    if unclosed_quote(text[word[0]:word[1]]):
        return None
    return word_literal(word[2])


def string_verdict(value: Optional[str], depth: int) -> str:
    """A command string the wrapper runs: CLEAN when every command in it is proven clean or
    carries no credential operand, STRING_HIT when one is flagged, UNDECIDED when it is not
    a literal."""
    if value is None:
        return UNDECIDED
    if depth >= NEST_LIMIT:
        return UNDECIDED
    return STRING_HIT if unproven_operand_commands(value, depth + 1) else CLEAN


def walk_wrapper(text: str, words: List[Word], i: int, grammar: Grammar, depth: int) -> Tuple[str, int]:
    """Follow one transparent wrapper from words[i]: (CLEAN or "next", index of the word that
    may be the command) or (UNDECIDED / STRING_HIT, index)."""
    flags, args, positionals, strings, optargs, numeric = grammar
    n = len(words)
    j = i + 1

    def slot(k: int) -> Optional[bool]:
        """None when the slot is past the end, else whether it is one field."""
        return None if k >= n else one_field(text, words[k])

    while j < n:
        lit = plain_literal(text, words[j])
        if lit is None:
            return UNDECIDED, j
        if lit == "--":
            j += 1
            break
        if lit == "-" and "-" in flags:
            j += 1
            continue
        if lit.startswith("--"):
            name, eq, value = lit.partition("=")
            if eq:
                if name in args or name in optargs:
                    j += 1
                    continue
                if name in strings:
                    return string_verdict(value, depth), j
                return UNDECIDED, j
            if name in flags:
                j += 1
                continue
            if name in args:
                ok = slot(j + 1)
                if ok is None:
                    return CLEAN, j
                if not ok:
                    return UNDECIDED, j + 1
                j += 2
                continue
            if name in strings:
                return string_verdict(plain_literal(text, words[j + 1]) if j + 1 < n else "", depth), j
            return UNDECIDED, j
        if lit.startswith("-") and len(lit) > 1:
            if numeric and lit[1:].isdigit():
                j += 1
                continue
            k = 1
            step = 1
            while k < len(lit):
                opt = "-" + lit[k]
                if opt in flags:
                    k += 1
                    continue
                if opt in args or opt in strings:
                    rest = lit[k + 1:]
                    if opt in strings:
                        value = rest if rest else (plain_literal(text, words[j + 1]) if j + 1 < n else "")
                        return string_verdict(value, depth), j
                    if not rest:
                        ok = slot(j + 1)
                        if ok is None:
                            return CLEAN, j
                        if not ok:
                            return UNDECIDED, j + 1
                        step = 2
                    break
                return UNDECIDED, j
            j += step
            continue
        break
    for _ in range(positionals):
        ok = slot(j)
        if ok is None:
            return CLEAN, j
        if not ok:
            return UNDECIDED, j
        j += 1
    if strings and j < n and plain_literal(text, words[j]) in strings:
        return string_verdict(plain_literal(text, words[j + 1]) if j + 1 < n else "", depth), j
    return "next", j


def walk_shell(text: str, words: List[Word], i: int, depth: int) -> Tuple[str, int]:
    """sh/bash/...: options, then -c's command string (the words after it are $0, $1, ...
    and never a command) or a script path (a literal path is a proven head)."""
    n = len(words)
    j = i + 1
    string_mode = False
    while j < n:
        lit = plain_literal(text, words[j])
        if lit is None:
            return UNDECIDED, j
        if lit == "--":
            j += 1
            break
        if lit in ("-o", "+o", "-O", "+O"):
            if j + 1 < n and plain_literal(text, words[j + 1]) is None:
                return UNDECIDED, j + 1
            j += 2
            continue
        if lit.startswith("--"):
            if lit not in SHELL_LONG_FLAGS:
                return UNDECIDED, j
            j += 1
            continue
        if lit[:1] in ("-", "+") and len(lit) > 1:
            if not all(ch in SHELL_OPTION_LETTERS for ch in lit[1:]):
                return UNDECIDED, j
            string_mode = string_mode or (lit[0] == "-" and "c" in lit[1:])
            j += 1
            continue
        break
    if j >= n:
        return CLEAN, j
    if string_mode:
        return string_verdict(plain_literal(text, words[j]), depth), j
    return (CLEAN, j) if plain_literal(text, words[j]) is not None else (UNDECIDED, j)


def command_lookup(text: str, words: List[Word], i: int) -> bool:
    """command -v / -V (alone or in a cluster with -p, before any other word) only prints how
    a name resolves and runs nothing, so it carries no psql argv (round 9, B)."""
    j = i + 1
    lookup = False
    while j < len(words):
        lit = plain_literal(text, words[j])
        if lit is None or lit == "--" or not re.fullmatch(r"-[pvV]+", lit):
            break
        lookup = lookup or "v" in lit or "V" in lit
        j += 1
    return lookup


def head_verdict(text: str, words: List[Word], depth: int = 0) -> Tuple[str, int]:
    """(verdict, index of the deciding word). CLEAN only for a proven fully literal head that
    is not psql (or a command with no head at all); PSQL for a literal psql head; UNDECIDED
    for everything the model does not prove; STRING_HIT for a flagged command string."""
    n = len(words)
    i = 0
    while i < n:
        start, end, _pieces = words[i]
        raw = text[start:end]
        unit_exec = UNIT_EXEC_RE.match(raw)
        if ASSIGN_RE.match(raw) and not unit_exec:
            i += 1
            continue
        lit = plain_literal(text, words[i])
        if lit is None:
            return UNDECIDED, i
        if unit_exec:
            # A unit's ExecStart=/usr/bin/x: the value after the key and its prefix flags is the head.
            exec_key = UNIT_EXEC_RE.match(lit)
            lit = lit[exec_key.end():] if exec_key else lit
            if not lit:
                i += 1
                continue
        if lit in SKIPPED_KEYWORDS or lit in DOC_MARKERS or (lit.endswith(":") and len(lit) > 1) \
                or LIST_NUMBER_RE.fullmatch(lit):
            i += 1
            continue
        if re.search(r"psql", lit, re.IGNORECASE):
            return PSQL, i
        base = lit.rstrip("/").rsplit("/", 1)[-1]
        if lit in UNMODELLED_KEYWORDS:
            return UNDECIDED, i
        if base in KNOWN_RUNNERS:
            return RUNNER, i
        if lit == "coproc":
            nxt = plain_literal(text, words[i + 2]) if i + 2 < n else None
            i += 2 if nxt == "{" else 1
            continue
        if base in SHELLS:
            return walk_shell(text, words, i, depth)
        if base == "command" and command_lookup(text, words, i):
            return CLEAN, i
        grammar = TRANSPARENT_WRAPPERS.get(base)
        if grammar is None:
            return CLEAN, i
        verdict, nxt_i = walk_wrapper(text, words, i, grammar, depth)
        if verdict != "next":
            return verdict, nxt_i
        i = nxt_i
    return CLEAN, n


def operand_views(text: str, words: List[Word], mask: bool = True) -> Tuple[str, str]:
    """The command's argv as one string with every word's own whitespace masked (an operand
    is one word), and the same string with each expansion masked, so an operand's literal
    colon and equals sign can be located. Without mask, a quoted word's literal whitespace is
    kept: a runner (eval, ssh, su -c) joins and re-splits its arguments."""
    view: List[str] = []
    lits: List[str] = []
    for _start, _end, pieces in words:
        v: List[str] = []
        lv: List[str] = []
        for kind, value in pieces:
            if kind == "l":
                t = re.sub(r"\s", "\x01", str(value)) if mask else str(value)
                v.append(t)
                lv.append(t)
            else:
                a, b = value  # type: ignore[misc]
                t = re.sub(r"\s", "\x01", text[a:b])
                v.append(t)
                lv.append("\x02" * len(t))
        view.append("".join(v))
        lits.append("".join(lv))
    return " " + " ".join(view), " " + " ".join(lits)


# F1 (round 10): the only expansions a mount source may hold before its first literal colon.
MOUNT_SOURCE_EXPANSION_RE = re.compile(r"\$(?:\{(?P<b>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<n>[A-Za-z_][A-Za-z0-9_]*))")
MOUNT_SOURCE_NAME_RE = re.compile(r"^(?:HOME|PWD)$|_(?:DIR|FILE|PATH)$", re.I)


def mount_shaped(view_operand: str, literal_operand: str) -> bool:
    """B (round 9): SRC:DST with no literal = before the first literal colon is not psql's
    NAME=VALUE (a docker or compose volume mount). F1 (round 10): an expansion before that
    colon can supply the = itself ($PW_ASSIGN:x is pw=...:x), so the source may hold only
    plain $NAME / ${NAME} expansions of a path-named variable (HOME, PWD, *_DIR, *_FILE,
    *_PATH); any other expansion there leaves the operand a credential candidate."""
    colon = literal_operand.find(":")
    equals = literal_operand.find("=")
    if colon < 0 or (0 <= equals < colon):
        return False
    for run in re.finditer("\x02+", literal_operand[:colon]):
        m = MOUNT_SOURCE_EXPANSION_RE.fullmatch(view_operand[run.start():run.end()])
        if not m or not MOUNT_SOURCE_NAME_RE.search(m.group("b") or m.group("n")):
            return False
    return True


def credential_operand(text: str, words: List[Word], narrow: bool, resplit: bool) -> bool:
    for mask in (True, False) if resplit else (True,):
        view, lits = operand_views(text, words, mask)
        for m in PSQL_VAR_OPT_RE.finditer(view):
            a, b = m.span("operand")
            if narrow and mount_shaped(view[a:b], lits[a:b]):
                continue
            if psql_var_operand_flagged(m.group("operand")):
                return True
    return False


def unproven_operand_commands(text: str, depth: int = 0) -> List[Tuple[int, int, int]]:
    """(report offset, start, end) of every command of text that is not proven clean and
    carries a credential-shaped -v / --set / --variable operand."""
    found: List[Tuple[int, int, int]] = []
    seen = set()
    for words, forced in shell_commands(text):
        key = (words[0][0], words[-1][1])
        if key in seen:
            continue
        seen.add(key)
        verdict, at = head_verdict(text, words, depth)
        if forced and verdict == CLEAN:
            verdict = UNDECIDED
        report = words[min(at, len(words) - 1)][0]
        if verdict == STRING_HIT or (verdict in (UNDECIDED, RUNNER, PSQL)
                                     and credential_operand(text, words, verdict != PSQL, verdict == RUNNER)):
            found.append((report, words[0][0], words[-1][1]))
    return found


def psql_command_snippet(text: str, start: int, end: int) -> str:
    """The whole (continued) psql command from its word to the segment end, on one
    line, so a hit shows the offending option (#5516)."""
    one = re.sub(r"\\\r?\n\s*", " ", text[start:end])
    return redact(re.sub(r"\s+", " ", one).strip())


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
    # #5514: a backtick command substitution expands at run time exactly like $(...), so
    # the value is read from the first $ or backtick (a plain pw$ROWS suffix is not scanned
    # from its start, so x=pw$ROWS stays clean).
    marks = [value.index(c) for c in "$`" if c in value]
    if marks and PSQL_SECRET_VAR_NAME_RE.search(value[min(marks):]):
        return True
    return False


def text_rule_hits(rel: str, text: str) -> List[Hit]:
    """The #4600-line text rules: expansion, psql -c password, docker -e / psql
    -v runtime-expanded password, readable cloud-init secret, traced secret."""
    hits: List[Hit] = []
    for m in EXPANSION_RE.finditer(text):
        line, snippet = _line_of(text, m.start())
        hits.append((rel, line, "[store-url-expansion] " + snippet))
    norm, undecidable_words = psql_head_view(text, Path(rel).suffix.lower() in SHELL_SUFFIXES)
    for pos in undecidable_words:
        line, snippet = _line_of(text, pos)
        hits.append((rel, line, "[psql-undecidable-word] " + snippet))
    for m in PSQL_ARGV_RE.finditer(norm):
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
    joined = norm.replace("\\\n", "  ")
    for head in PSQL_HEAD_RE.finditer(joined):
        end = psql_segment_end(joined, head.end())
        shell_view, undecided = segment_view(joined[head.end():end])
        for off in undecided:
            line, snippet = _line_of(text, head.end() + off)
            hits.append((rel, line, "[psql-undecidable-option] " + snippet))
        if any(psql_var_operand_flagged(m.group("operand"))
               for m in PSQL_VAR_OPT_RE.finditer(shell_view)):
            # head.start() is the PREFIX character, a newline when psql opens a line, which
            # reported the previous line; the word itself names the line (#5485).
            line = _line_of(text, head.start("word"))[0]
            hits.append((rel, line, "[env-password-argv] "
                         + psql_command_snippet(text, head.start("word"), end)))
    # #5556 #5557 #5558 and round 9: a credential operand is clean only under a command whose
    # head is proven literal and not psql (unproven_operand_commands); one hit per line.
    argv_lines = {hit[1] for hit in hits if hit[2].startswith("[env-password-argv] ")}
    for report, start, end in unproven_operand_commands(joined):
        line = _line_of(text, report)[0]
        if line in argv_lines:
            continue
        argv_lines.add(line)
        hits.append((rel, line, "[env-password-argv] " + psql_command_snippet(text, start, end)))
    for rule, tag in ((PSQL_URL_RE, "psql-url-password"), (DOCKER_ENV_DSN_RE, "env-dsn-argv"),
                      (SSH_REMOTE_URL_RE, "ssh-remote-url-password")):
        for m in rule.finditer(text):
            if is_url_redaction(m.group("pw")):
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
    # #5512: in a script a leading glob can still expand to the psql word.
    "5512 leading star glob head": "*sql -f x.sql",
    "5512 leading bracket glob head": '[p]sql -v pw="$PG_PW" -f x.sql',
    "5512 leading question glob head": "?sql -f x.sql",
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
    "5512 prose question-mark glob word": "what ?sql means here\n",
    "5512 prose bold sqlite": "the **sqlite** and **SQL NULL** cells\n",
    "5512 prose key-loss emphasis": "| G13 rotation lineage | **SHIPPED** | key-**loss** recovery OPEN |\n",
    "5512 rust deref of an SQL constant": "format!(\"{} FOR UPDATE\", *SQL_SELECT_ROW_BY_ID);\n",
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
    # #5512 (PR 4810 round-6 F1): more spellings of the psql word, and the closed-world
    # refusal of a word that holds an expansion and could still spell psql.
    "5512-01-ansi-c-segment-in-head": 'ps$\'q\'l -v pw="$PG_PW" -f x.sql',
    "5512-02-ansi-c-hex-inside-head": "$'ps\\x71l' -v pw=\"$PG_PW\" -f x.sql",
    "5512-03-ansi-c-hex-first-letter": "$'\\x70sql' -v pw=\"$PG_PW\" -f x.sql",
    "5512-04-backslash-newline-inside-head": 'ps\\\nql -v pw="$PG_PW" -f x.sql',
    "5512-05-empty-backtick-inside-head": 'ps``ql -v pw="$PG_PW" -f x.sql',
    "5512-06-empty-substitution-inside-head": 'ps$()ql -v pw="$PG_PW" -f x.sql',
    "5512-07-ansi-c-head-c-password": "ps$'q'l -c \"ALTER USER a PASSWORD 'hunter2x'\"",
    "5512-08-octal-escape-head": "$'\\160sql' -v pw=\"$PG_PW\" -f x.sql",
    "5512-09-unicode-escape-head": "$'ps\\u0071l' -v pw=\"$PG_PW\" -f x.sql",
    "5512-10-ansi-c-head-after-semicolon": "true; ps$'q'l -v pw=\"$PG_PW\" -f x.sql",
    "5512-11-undecidable-substitution-head": 'ps$(printf q)l -f x.sql',
    "5512-12-undecidable-parameter-head": 'ps${Q}l -f x.sql',
    "5512-13-undecidable-glob-head": 'p[s]ql -f x.sql',
    "5512-14-undecidable-brace-head": 'p{s,s}ql -f x.sql',
    "5512-15-undecidable-star-head": 'ps*l -f x.sql',
    "5512-16-undecidable-backtick-head": 'ps`printf q`l -f x.sql',
    "5512-17-undecidable-wrapper-head": 'run_ps$(printf q)l -f x.sql',
    "5512-18-undecidable-head-inside-string": 'bash -c "ps$(printf q)l -f x.sql"',
    "5512-19-split-head-inside-string": "ssh h 'p\\sql -v pw=\"$PG_PW\"'",
    "5514-01-backtick-redirect-value": 'psql -v x=`<pw_file` -f x.sql',
    "5514-02-backtick-cat-value": 'psql -v x=`cat<pw_file` -f x.sql',
    "5514-03-backtick-after-prefix": 'psql -v x=a`cat /run/pgpassword` -f x.sql',
    "5514-04-backtick-set-long": 'psql --set=x=`cat /run/pg_pw` -f x.sql',
    "5514-05-backtick-in-quotes": 'psql -v "x=`cat /run/pg_pw`" -f x.sql',
    "5514-06-backtick-then-dollar-value": 'psql -v x=`cat /run/pg_pw`$ROWS -f x.sql',
    "5514-07-dollar-then-backtick-value": 'psql -v x=$PG_PW`date` -f x.sql',
    "5513-01-ansi-c-dash-v": "psql $'-v' pw=\"$PG_PW\"",
    "5513-02-ansi-c-hex-dash-v": "psql $'\\x2dv' pw=\"$PG_PW\"",
    "5513-03-ansi-c-octal-dash-v": "psql $'\\055v' pw=\"$PG_PW\"",
    "5513-04-ansi-c-set": "psql $'--set' pw=\"$PG_PW\"",
    "5513-05-dash-then-expansion": 'psql -$o pw="$PG_PW"',
    "5513-06-flag-then-expansion": 'psql -X$o pw="$PG_PW"',
    "5513-07-long-then-expansion": 'psql --$o pw="$PG_PW"',
    "5513-08-set-prefix-expansion": 'psql --s$x pw="$PG_PW"',
    "5513-09-variable-prefix-expansion": 'psql --var$x pw="$PG_PW"',
    "5513-10-ansi-c-cluster": "psql $'-Xv' pw=\"$PG_PW\"",
    "5512-24-negated-class-head": 'p[^x]ql -f x.sql',
    "5512-25-octal-wraps-to-low-byte": "$'\\560sql' -v pw=\"$PG_PW\" -f x.sql",
    "5512-20-path-then-ansi-c-head": "/usr/bin/ps$'q'l -v pw=\"$PG_PW\" -f x.sql",
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
    "5514-neutral-backtick-value": 'psql -v x=`date +%s` -f x.sql',
    "5514-secret-name-after-dollar-not-in-prefix": 'psql -v x=pw$ROWS -f x.sql',
    "5514-secret-looking-prefix-before-backtick": 'psql -v x=pwd`date` -f x.sql',
    "5513-host-flag-then-expansion": 'psql -h"$HOST" -d "$DB" -f x.sql',
    "5513-dbname-expansion": 'psql -d "$DB" -f x.sql',
    "5513-long-host-expansion": 'psql --host="$HOST" --port=5432 -f x.sql',
    "5513-ansi-c-neutral-option": "psql $'-X' -v role=aimemory -f x.sql",
    "5513-user-flag-expansion": 'psql -U"$USER_NAME" -f x.sql',
    "5512-multiline-prose-backticks": "// the `chunks(0)` panics here a\n// `LIMIT 0` scan would return\n",
    "5512-prose-backtick-across-lines": "see `foo\nbar`sql here\n",
    "5512-ansi-c-word-not-psql": "ps$'x'l -c \"ALTER USER a PASSWORD 'hunter2x'\"",
    "5512-hole-word-cannot-be-psql": 'ls$(date)x.txt -f x.sql',
    "5512-glob-word-cannot-be-psql": 'rm ps*.txt',
    "5512-parameter-word-not-psql-shaped": 'foo$BAR -v role=aimemory',
    "5512-plain-parameter-word": '"$BIN" serve --listen 127.0.0.1:9077',
    "5512-command-substitution-word": 'x=$(command -v psql)',
    "5512-empty-substitution-word-not-psql": 'ps$()x -v role=aimemory -f x.sql',
    "5482-split-word-not-psql": 'p\\sqlx -v role=aimemory -f x.sql',
    "5482-quoted-psql-no-secret": 'echo "psql" -v role=aimemory -f x.sql',
    "5482-trailing-backslash-word-not-psql": 'psql\\x -c "ALTER USER a PASSWORD \'hunter2x\'"',
    "5482-prefixed-split-word-not-psql": 'a\\psq\\l -c "ALTER USER a PASSWORD \'hunter2x\'"',
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


# #5516 (PR 4810 round-6 F5): (name, text, expected hit lines, text each snippet shows).
PSQL_SEGMENT_PROBES = (
    ("5516-01-repeated-head-one-hit", 'psql -X; psql -v pw="$PG_PW"', [1], "-v pw="),
    ("5516-02-continued-snippet-shows-v", 'psql \\\n  -X \\\n  -v pw="$PG_PW" \\\n  -f x.sql\n', [1], "-v pw="),
    ("5516-03-two-real-commands-two-hits", 'psql -v pw="$A"; psql -v token="$B"', [1, 1], "-v"),
    ("5516-04-separator-inside-quotes-kept", 'psql -c "select 1;" -v pw="$PG_PW"', [1], "-v pw="),
    ("5516-05-redirect-ampersand-kept", 'psql -X 2>&1 -v pw="$PG_PW"', [1], "-v pw="),
    ("5516-06-ampersand-redirect-kept", 'psql -X &>/dev/null -v pw="$PG_PW"', [1], "-v pw="),
    ("5516-07-separator-inside-substitution-kept", 'psql -X $(true; echo) -v pw="$PG_PW"', [1], "-v pw="),
    ("5516-08-second-line-reports-line-2", 'echo a\npsql -X \\\n  -v pw="$PG_PW"\n', [2], "-v pw="),
    ("5516-09-other-command-after-semicolon", 'psql -X; foo -v pw="$PG_PW"', [], ""),
    ("5516-10-other-command-after-pipe", 'psql -X | foo -v pw="$PG_PW"', [], ""),
    ("5516-11-other-command-after-and", 'psql -X && foo -v pw="$PG_PW"', [], ""),
    ("5516-12-head-in-parenthesis-ends-at-close", '(psql -X) -v pw="$PG_PW"', [], ""),
    ("5516-13-head-in-backticks-ends-at-close", 'x=`psql -X` -v pw="$PG_PW"', [], ""),
    ("5516-14-head-in-dollar-paren-ends-at-close", 'x=$(psql -X) -v pw="$PG_PW"', [], ""),
    ("5516-15-head-in-double-quotes-ends-at-close", 'bash -c "psql -X" -v pw="$PG_PW"', [], ""),
    ("5516-16-or-list", 'psql -X || foo -v pw="$PG_PW"', [], ""),
    ("5516-17-quoted-variable-head-keeps-segment", '"$PSQL" -v pw="$PG_PW" -f x.sql', [1], "-v pw="),
    ("5516-18-quoted-head-word-keeps-segment", '"psql" -v pw="$PG_PW" -f x.sql', [1], "-v pw="),
    ("5516-19-last-char-before-newline-kept", 'psql -v x=$PW\necho a\n', [1], "-v x="),
    ("5516-20-head-in-subshell-keeps-nested-separator", '(psql -X $(true; echo) -v pw="$PG_PW")', [1], "-v pw="),
    ("5516-21-snippet-redacts-the-literal", "psql -v pw=postgres://u:hunter2x@h/d -f x.sql", [1], "-v pw="),
)

# #5556 / #5557 / #5558 (round 8): a command whose first word is not fully literal is read as
# psql whatever it might spell, so a credential -v operand is flagged in every file type.
HEAD_TAIL = ' -v pw="$PG_PW" -f x.sql'
RED_HEAD_PROBES = {
    # #5556: zero and one literal letter beside an expansion
    "5556-01-zero-literal-variable": "$X" + HEAD_TAIL,
    "5556-02-one-literal-then-variable": "p$X" + HEAD_TAIL,
    "5556-03-variable-then-one-literal": "${X}l" + HEAD_TAIL,
    "5556-04-two-variables": "${X}${Y}" + HEAD_TAIL,
    "5556-05-unrelated-letter-then-variable": "s$X" + HEAD_TAIL,
    "5556-06-quoted-variable-head": '"$X"' + HEAD_TAIL,
    "5556-07-one-literal-set-form": 'p$X --set=pw="$PG_PW" -f x.sql',
    "5556-08-one-literal-variable-form": 'p$X --variable pw="$PG_PW" -f x.sql',
    "5556-09-one-literal-secret-value": "p$X -X -v x=$PGPASSWORD -f x.sql",
    "5556-10-array-expansion-head": '"${CMD[@]}"' + HEAD_TAIL,
    "5556-11-assignment-then-head": "FOO=1 $X" + HEAD_TAIL,
    "5556-12-env-prefix": "env -i FOO=1 p$X" + HEAD_TAIL,
    "5556-13-command-prefix": "command $X" + HEAD_TAIL,
    "5556-14-exec-prefix": "exec ${X}l" + HEAD_TAIL,
    "5556-15-sudo-prefix": "sudo -u postgres $X" + HEAD_TAIL,
    "5556-16-time-prefix": "time $X" + HEAD_TAIL,
    "5556-17-eval-word": "eval $X" + HEAD_TAIL,
    "5556-18-eval-string": 'eval "$X' + HEAD_TAIL + '"',
    "5556-19-pipe-before": "cat q.sql | p$X" + HEAD_TAIL,
    "5556-20-here-string-before": '<<< "$IN" $X' + HEAD_TAIL,
    "5556-21-head-on-continued-line": "FOO=1 \\\n  $X" + HEAD_TAIL,
    "5556-22-head-after-continued-options": "env \\\n  -i \\\n  p$X" + HEAD_TAIL,
    "5556-23-bash-c-string": "bash -c '$X" + HEAD_TAIL + "'",
    # #5557: a substitution or backtick span that is itself the head word
    "5557-01-command-v-psql": '"$(command -v psql)"' + HEAD_TAIL,
    "5557-02-command-v-bare": "$(command -v psql)" + HEAD_TAIL,
    "5557-03-which-psql": "$(which psql)" + HEAD_TAIL,
    "5557-04-echo-psql": "$(echo psql)" + HEAD_TAIL,
    "5557-05-backtick-bare": "`echo psql`" + HEAD_TAIL,
    "5557-06-backtick-quoted": '"`which psql`"' + HEAD_TAIL,
    "5557-07-nested-substitution": '"$(echo $(which psql))"' + HEAD_TAIL,
    "5557-08-substitution-inside-prefix": "sudo -u postgres $(which psql)" + HEAD_TAIL,
    "5557-09-substitution-after-pipe": "cat q.sql | $(which psql)" + HEAD_TAIL,
    "5557-10-substitution-after-semicolon": "true; $(which psql)" + HEAD_TAIL,
    "5557-11-substitution-with-set-form": '$(which psql) --set pw="$PG_PW" -f x.sql',
    "5557-12-substitution-continued": "$(which psql) \\\n  -X \\\n  -v pw=\"$PG_PW\" -f x.sql",
    "5557-13-eval-substitution": 'eval "$(which psql)' + HEAD_TAIL + '"',
    "5557-14-substitution-in-subshell": "( $(which psql)" + HEAD_TAIL + " )",
    # #5558: a glob or brace head in prose, fenced, indented and inline text
    "5558-01-bracket-glob-fenced": "```bash\n[p]sql" + HEAD_TAIL + "\n```\n",
    "5558-02-star-glob-fenced": "```sh\n*sql" + HEAD_TAIL + "\n```\n",
    "5558-03-question-glob-fenced": "```\n?sql" + HEAD_TAIL + "\n```\n",
    "5558-04-star-psql-fenced": "```bash\n*psql" + HEAD_TAIL + "\n```\n",
    "5558-05-indented-block": "Run:\n\n    [p]sql" + HEAD_TAIL + "\n",
    "5558-06-inline-prose": "Run `*sql" + HEAD_TAIL + "` to load it.\n",
    "5558-07-brace-head-fenced": "```bash\n{x,y}" + HEAD_TAIL + "\n```\n",
    "5558-08-glob-line-start": "[p]sql" + HEAD_TAIL,
    "5558-09-glob-after-prompt": "$ ?sql" + HEAD_TAIL,
    "5558-10-glob-after-sudo": "sudo *sql" + HEAD_TAIL,
}
# (name, text, lines of the env-password-argv hits the text rule reports)
HEAD_LINE_PROBES = (
    ("5556-l1-head-on-line-two", 'echo a\n$X' + HEAD_TAIL + "\n", [2]),
    ("5557-l2-substitution-head-on-line-three", "echo a\necho b\n$(which psql)" + HEAD_TAIL + "\n", [3]),
    ("5556-l3-continued-head-reports-its-own-line", "echo a \\\n  ; p$X" + HEAD_TAIL + "\n", [2]),
    ("5558-l4-fenced-head-line", "text\n```bash\n[p]sql" + HEAD_TAIL + "\n```\n", [3]),
    ("5556-l5-two-commands-two-lines", "$X" + HEAD_TAIL + "\n$Y" + HEAD_TAIL + "\n", [1, 2]),
)
GREEN_HEAD_PROBES = {
    "5556-g1-no-credential": '$X -h "$HOST" -d "$DB" -f x.sql',
    "5556-g2-neutral-variable": "p$X -v verbose=1 -f x.sql",
    "5556-g4-lookalike-long-option": '"${example_bin}" --variant "${variant}" --report "${report}"',
    "5556-g5-volume-mount-of-other-tool": "$COMPOSE run -v /host:/ct img",
    "5556-g6-literal-other-head": 'echo "$X" -v pw=1',
    "5556-g7-literal-head-keeps-meaning": "docker run -v $KEYS_DIR:/k $IMG",  # #5651: path-named
    "5556-g9-one-word-with-suffix-after-quote": '"$X -v pw=$PG_PW"c',
    "5556-g10-quoted-literal-head-with-space": '"env -i" $X -v pw="$PG_PW"',
    # 5556-g11 (nohup --foo=bar true $X) is red since #5593: nohup takes no option, so the
    # head is undecidable (5593-n45); the clean form is 5593-g19 (env --unset=FOO true $X).
    "5556-g12-command-string-ends-at-its-close": "bash -c 'env -i' $X -v pw=\"$PG_PW\"",
    "5556-g8-prose-quote-no-command": "Set the **loss** value to 3 -v pw is not run here",
}

# #5593 (round 9): a credential operand is clean only under a proven literal non-psql head;
# S1-S8 are the round-8 review's reproducers, n01-n72 the neighbours (wrappers with operands,
# fd redirections, assignment runs, case arms, coproc, function bodies, groups, conditions,
# pipelines, continuations, substitutions). #5594: the operand is psql's NAME=VALUE (a mount
# SRC:DST is not) and command -v is a lookup. Each probe runs as a script, a prose file and a
# fenced block. Green probes carry a neutral -v name whose value expands a secret.
R9_NEUTRAL_TAIL = ' -v x="$PGPASSWORD" -f x.sql'
# 5593 / 5594 red: each must give an [env-password-argv] hit.
R9_RED_PROBES = {
    '5593-S1-timeout-duration': 'timeout 5 $X' + HEAD_TAIL,
    '5593-S2-taskset-mask': 'taskset 0x1 $X' + HEAD_TAIL,
    '5593-S3-seventeen-assignments': 'A0=1 A1=1 A2=1 A3=1 A4=1 A5=1 A6=1 A7=1 A8=1 A9=1 A10=1 A11=1 A12=1 A13=1 A14=1 A15=1 A16=1 $X' + HEAD_TAIL,
    '5593-S4-fd-redirect-first': '2>/dev/null $X' + HEAD_TAIL,
    '5593-S5-exec-fd-redirect': 'exec 3<f $X' + HEAD_TAIL,
    '5593-S6-case-arm': 'case a in a) $X' + HEAD_TAIL + ' ;; esac',
    '5593-S7-coproc': 'coproc $X' + HEAD_TAIL,
    '5593-S8-flock-lockfile': 'flock /run/l.lock $X' + HEAD_TAIL,
    '5593-n01-chrt-priority': 'chrt -f 10 $X' + HEAD_TAIL,
    '5593-n02-nice-n': 'nice -n 10 $X' + HEAD_TAIL,
    '5593-n03-ionice-class': 'ionice -c 3 $X' + HEAD_TAIL,
    '5593-n04-chroot-newroot': 'chroot /srv/root $X' + HEAD_TAIL,
    '5593-n05-nsenter': 'nsenter -t 1 -m $X' + HEAD_TAIL,
    '5593-n06-unshare': 'unshare -n $X' + HEAD_TAIL,
    '5593-n07-systemd-run': 'systemd-run --scope $X' + HEAD_TAIL,
    '5593-n08-stdbuf': 'stdbuf -oL $X' + HEAD_TAIL,
    '5593-n09-setsid': 'setsid -f $X' + HEAD_TAIL,
    '5593-n10-runuser': 'runuser -u postgres -- $X' + HEAD_TAIL,
    '5593-n11-su-c-string': 'su postgres -c "$X -v pw=\'$PG_PW\' -f x.sql"',
    '5593-n12-xargs': 'xargs -0 $X' + HEAD_TAIL,
    '5593-n13-env-split-string': "env -S '$X" + HEAD_TAIL + "'",
    '5593-n14-ssh-host': 'ssh db1 $X' + HEAD_TAIL,
    '5593-n15-docker-exec': 'docker exec db $X' + HEAD_TAIL,
    '5593-n16-kubectl-exec': 'kubectl exec pod -- $X' + HEAD_TAIL,
    '5593-n17-append-stderr-first': '2>>/var/log/x.log $X' + HEAD_TAIL,
    '5593-n18-fd-input-first': '3<f $X' + HEAD_TAIL,
    '5593-n19-and-redirect-first': '&>/dev/null $X' + HEAD_TAIL,
    '5593-n20-dup-to-stderr-first': '>&2 $X' + HEAD_TAIL,
    '5593-n21-fd-here-string-first': '0<<<"$IN" $X' + HEAD_TAIL,
    '5593-n22-process-substitution-input': 'cat <($X' + HEAD_TAIL + ')',
    '5593-n23-process-substitution-output': 'tee >($X' + HEAD_TAIL + ') </dev/null',
    '5593-n24-forty-assignments': 'B0=1 B1=1 B2=1 B3=1 B4=1 B5=1 B6=1 B7=1 B8=1 B9=1 B10=1 B11=1 B12=1 B13=1 B14=1 B15=1 B16=1 B17=1 B18=1 B19=1 B20=1 B21=1 B22=1 B23=1 B24=1 B25=1 B26=1 B27=1 B28=1 B29=1 B30=1 B31=1 B32=1 B33=1 B34=1 B35=1 B36=1 B37=1 B38=1 B39=1 $X' + HEAD_TAIL,
    '5593-n25-assign-redirect-assign': 'A=1 2>/dev/null B=2 $X' + HEAD_TAIL,
    '5593-n26-case-arm-own-line': 'case $1 in\n  a) $X' + HEAD_TAIL + ' ;;\nesac',
    '5593-n27-case-arm-open-paren': 'case a in (a) $X' + HEAD_TAIL + ' ;; esac',
    '5593-n28-coproc-named-group': 'coproc NAME { $X' + HEAD_TAIL + '; }',
    '5593-n29-function-body': 'f() { $X' + HEAD_TAIL + '; }',
    '5593-n30-function-keyword': 'function f { $X' + HEAD_TAIL + '; }',
    '5593-n31-brace-group': '{ $X' + HEAD_TAIL + '; }',
    '5593-n32-if-condition': 'if $X' + HEAD_TAIL + '; then :; fi',
    '5593-n33-while-condition': 'while $X' + HEAD_TAIL + '; do :; done',
    '5593-n34-then-body': 'if true; then $X' + HEAD_TAIL + '; fi',
    '5593-n35-until-body': 'until false; do $X' + HEAD_TAIL + '; done',
    '5593-n36-pipe-stderr': 'true |& $X' + HEAD_TAIL,
    '5593-n37-bang': '! $X' + HEAD_TAIL,
    '5593-n38-time-p': 'time -p $X' + HEAD_TAIL,
    '5593-n39-heredoc-before-pipe': 'cat <<EOF | $X' + HEAD_TAIL + '\nselect 1;\nEOF',
    '5593-n40-continued-wrapper': 'timeout \\\n  5 \\\n  $X' + HEAD_TAIL,
    '5593-n41-backtick-wrapper': '`timeout 5 $X' + HEAD_TAIL + '`',
    '5593-n42-substitution-wrapper': '$(nice $X' + HEAD_TAIL + ')',
    '5593-n43-sudo-then-timeout': 'sudo -u postgres timeout 5 $X' + HEAD_TAIL,
    '5593-n44-env-unset': 'env -u FOO $X' + HEAD_TAIL,
    '5593-n45-nohup-unknown-option': 'nohup --foo=bar true $X' + HEAD_TAIL,
    '5593-n46-exec-two-redirects': 'exec 3<f 4>g $X' + HEAD_TAIL,
    '5593-n47-named-fd-redirect': '{fd}>/dev/null $X' + HEAD_TAIL,
    '5593-n48-unquoted-positional': 'timeout $T echo' + HEAD_TAIL,
    '5593-n49-shell-c-variable-string': 'bash -c "$CMD" x' + HEAD_TAIL,
    '5593-n50-shell-c-ansi-string': "sh -c $'$X -v pw=$PG_PW -f x.sql'",
    '5593-n51-watch': 'watch -n1 $X' + HEAD_TAIL,
    '5593-n52-select-body': 'select x in a; do $X' + HEAD_TAIL + '; done',
    '5593-n53-for-body': 'for x in a; do $X' + HEAD_TAIL + '; done',
    '5593-n54-test-then-and': '[[ -n a ]] && $X' + HEAD_TAIL,
    '5593-n55-unclosed-quote-word': "don't $X" + HEAD_TAIL,
    '5593-n56-elif-condition': 'if false; then :; elif $X' + HEAD_TAIL + '; then :; fi',
    '5593-n57-else-body': 'if false; then :; else $X' + HEAD_TAIL + '; fi',
    '5593-n58-ssh-port': 'ssh -p 22 db1 $X' + HEAD_TAIL,
    '5593-n59-after-semicolon-wrapper': 'echo a; timeout 5 $X' + HEAD_TAIL,
    '5593-n60-default-substitution': 'echo "${Y:-$($X' + HEAD_TAIL + ')}"',
    '5593-n61-yaml-run-key': '- run: $X' + HEAD_TAIL,
    '5593-n62-doas': 'doas -u postgres $X' + HEAD_TAIL,
    '5593-n63-command-p': 'command -p $X' + HEAD_TAIL,
    '5593-n64-nice-obsolete': 'nice -10 $X' + HEAD_TAIL,
    '5593-n65-chrt-pid-mode': 'chrt -p 10 $X' + HEAD_TAIL,
    '5593-n66-pipe-then-wrapper': 'cat q | stdbuf -oL $X' + HEAD_TAIL,
    '5593-n67-taskset-cpu-list': 'taskset -c 0,1 $X' + HEAD_TAIL,
    '5593-n68-bash-c-literal-string': "bash -c '$X -v pw=$PG_PW -f x.sql'",
    '5593-n69-sudo-unknown-option': 'sudo --frobnicate true $X' + HEAD_TAIL,
    '5593-n70-timeout-unquoted-option-arg': 'timeout -s $SIG 5 echo' + HEAD_TAIL,
    '5594-B-r1-equals-before-colon': '$X -v "pw=$A:$B" -f x.sql',
    '5594-B-r2-docker-env-shaped-operand': '"$DOCKER" run -v "pw=$PG_PW" img',
    '5594-B-r3-only-expansion': '$X -v "$SECRET_OPT" -f x.sql',
    '5594-n71-command-p-dashdash': 'command -p -- $X' + HEAD_TAIL,
    '5594-n72-command-v-then-run': 'command -v x; $X' + HEAD_TAIL,
    '5594-B-r4-value-colon-after-equals': '$X -v pw=$PG_PW:x -f x.sql',
    '5593-m01-timeout-quoted-head-after-operands': 'timeout 5 "$X"' + HEAD_TAIL,
    '5593-m02-taskset-quoted-head-after-operands': 'taskset 0x1 "$X"' + HEAD_TAIL,
    '5593-m03-chrt-quoted-head-after-operands': 'chrt -f 10 "$X"' + HEAD_TAIL,
    '5593-m04-flock-quoted-head-after-operands': 'flock /run/l.lock "$X"' + HEAD_TAIL,
    '5593-m05-chroot-quoted-head-after-operands': 'chroot /srv/root "$X"' + HEAD_TAIL,
    '5593-m06-nice-quoted-head-after-operands': 'nice "$X"' + HEAD_TAIL,
    '5593-m07-nohup-quoted-head-after-operands': 'nohup "$X"' + HEAD_TAIL,
    '5593-m08-stdbuf-quoted-head-after-operands': 'stdbuf -oL "$X"' + HEAD_TAIL,
    '5593-m09-setsid-quoted-head-after-operands': 'setsid "$X"' + HEAD_TAIL,
    '5593-m10-ionice-quoted-head-after-operands': 'ionice -c 3 "$X"' + HEAD_TAIL,
    '5593-m11-doas-quoted-head-after-operands': 'doas -u postgres "$X"' + HEAD_TAIL,
    '5593-m12-exec-quoted-head-after-operands': 'exec "$X"' + HEAD_TAIL,
    '5593-m13-command-quoted-head-after-operands': 'command "$X"' + HEAD_TAIL,
    '5593-m14-builtin-quoted-head-after-operands': 'builtin "$X"' + HEAD_TAIL,
    '5593-m15-time-quoted-head-after-operands': 'time "$X"' + HEAD_TAIL,
    '5593-m16-env-quoted-head-after-operands': 'env "$X"' + HEAD_TAIL,
    '5593-m17-sudo-quoted-head-after-operands': 'sudo "$X"' + HEAD_TAIL,
    '5593-m18-timeout-kill-after-argument': 'timeout -k 5 10 $X' + HEAD_TAIL,
    '5593-m19-prose-paren-start': 'see the notes ($X' + HEAD_TAIL + ')',
    '5593-m20-unclosed-substitution': 'x=$($X' + HEAD_TAIL,
    '5593-m21-nice-runner-after-operands': 'nice ssh h echo' + HEAD_TAIL,
    '5593-m22-nohup-runner-after-operands': 'nohup ssh h echo' + HEAD_TAIL,
    '5593-m23-stdbuf-runner-after-operands': 'stdbuf -oL ssh h echo' + HEAD_TAIL,
    '5593-m24-setsid-runner-after-operands': 'setsid ssh h echo' + HEAD_TAIL,
    '5593-m25-ionice-runner-after-operands': 'ionice -c 3 ssh h echo' + HEAD_TAIL,
    '5593-m26-doas-runner-after-operands': 'doas -u postgres ssh h echo' + HEAD_TAIL,
    '5593-m27-exec-runner-after-operands': 'exec ssh h echo' + HEAD_TAIL,
    '5593-m28-command-runner-after-operands': 'command ssh h echo' + HEAD_TAIL,
    '5593-m29-builtin-runner-after-operands': 'builtin ssh h echo' + HEAD_TAIL,
    '5593-m30-time-runner-after-operands': 'time ssh h echo' + HEAD_TAIL,
    '5593-m31-env-runner-after-operands': 'env -i ssh h echo' + HEAD_TAIL,
    '5593-m32-sudo-runner-after-operands': 'sudo -E ssh h echo' + HEAD_TAIL,
    '5593-m33-flock-wait-argument': 'flock -w 5 /run/l.lock $X' + HEAD_TAIL,
    '5593-m34-flock-command-variable': 'flock /run/l.lock -c "$CMD" x' + HEAD_TAIL,
    '5593-m35-shell-dashdash-variable-script': 'bash -- "$SCRIPT"' + HEAD_TAIL,
    '5593-m36-nesting-limit-literal-head': '$(' * 9 + 'echo' + HEAD_TAIL + ')' * 9,
    '5593-m37-psql-inside-unlisted-name': 'mypsqlctl' + HEAD_TAIL,
    '5594-m38-psql-head-keeps-colon-operand': 'mypsqlctl -v "$PW_FILE:x" -f x.sql',
    '5594-m39-expansion-colon-is-not-literal': '$X -v "${PREFIX:-pw}=$PG_PW" -f x.sql',
}
# 5593 / 5594 green: no hit of any kind.
R9_GREEN_PROBES = {
    '5593-g01-timeout-literal': 'timeout 5 echo' + R9_NEUTRAL_TAIL,
    '5593-g02-taskset-literal': 'taskset 0x1 echo' + R9_NEUTRAL_TAIL,
    '5593-g03-nice-literal': 'nice -n 10 echo' + R9_NEUTRAL_TAIL,
    '5593-g04-ionice-literal': 'ionice -c 3 echo' + R9_NEUTRAL_TAIL,
    '5593-g05-chrt-literal': 'chrt -f 10 echo' + R9_NEUTRAL_TAIL,
    '5593-g06-flock-literal': 'flock -w 5 /run/l.lock echo' + R9_NEUTRAL_TAIL,
    '5593-g07-chroot-literal': 'chroot /srv/root echo' + R9_NEUTRAL_TAIL,
    '5593-g08-stdbuf-literal': 'stdbuf -oL echo' + R9_NEUTRAL_TAIL,
    '5593-g09-setsid-literal': 'setsid -f echo' + R9_NEUTRAL_TAIL,
    '5593-g10-env-literal': 'env -i FOO=1 echo' + R9_NEUTRAL_TAIL,
    '5593-g11-sudo-literal': 'sudo -u postgres echo' + R9_NEUTRAL_TAIL,
    '5593-g12-doas-literal': 'doas -u postgres echo' + R9_NEUTRAL_TAIL,
    '5593-g13-exec-redirect-literal': 'exec 3<f echo' + R9_NEUTRAL_TAIL,
    '5593-g14-redirect-first-literal': '2>/dev/null echo' + R9_NEUTRAL_TAIL,
    '5593-g15-time-literal': 'time -p echo' + R9_NEUTRAL_TAIL,
    '5593-g16-nohup-literal': 'nohup echo' + R9_NEUTRAL_TAIL,
    '5593-g17-command-p-literal': 'command -p echo' + R9_NEUTRAL_TAIL,
    '5593-g18-sudo-E-no-argument': 'sudo -E true $X' + R9_NEUTRAL_TAIL,
    '5593-g19-env-unset-equals': 'env --unset=FOO true $X' + R9_NEUTRAL_TAIL,
    '5593-g26-test-v-keyword': '[[ -v PGPASSWORD ]] && echo set',
    '5593-g27-case-literal-arm': 'case a in a) echo' + R9_NEUTRAL_TAIL + ' ;; esac',
    '5593-g28-timeout-signal-literal': 'timeout -s KILL 5 echo' + R9_NEUTRAL_TAIL,
    '5593-g29-bash-c-literal-then-args': "bash -c 'env -i' $X" + R9_NEUTRAL_TAIL,
    '5593-g30-taskset-cpu-list-literal': 'taskset -c 0,1 echo' + R9_NEUTRAL_TAIL,
    '5594-g20-FP1-docker-secret-dir-mount': '"$DOCKER" run -v "$SECRET_DIR:/s" img',
    '5594-g21-docker-secret-path-mount': '$DOCKER run -v /run/secrets/pgpass:/s:ro img',
    '5594-g22-compose-token-mount': '$COMPOSE run -v "$TOKEN_PATH":/t img',
    '5594-g23-psql-non-credential': 'psql -v ON_ERROR_STOP=1 -f x.sql',
    '5594-g24-head-non-credential': '$X -v ON_ERROR_STOP=1 -f x.sql',
    '5594-g25-docker-pw-dir-mount': 'docker run -v "$PW_DIR:/pw" img',
    '5594-g31-command-v-lookup': 'if ! command -v "$BIN" >/dev/null; then exit 1; fi',
    '5594-g32-command-V-cluster': 'command -pV "$TOKEN_TOOL"',
    '5593-g33-shell-o-takes-an-argument': "bash -o pipefail -c 'env -i'" + R9_NEUTRAL_TAIL,
    '5593-g34-unit-exec-literal-head': 'ExecStart=/usr/bin/env -i echo' + R9_NEUTRAL_TAIL,
    '5594-g35-mount-target-holds-equals': '$DOCKER run -v "$SECRET_DIR:/opt/a=b" img',
}
# Round 10 red: some hit of any kind, as a script, a prose file and a fenced block.
R10_RED_PROBES = {
    # #4612 item 3: a placeholder is the WHOLE decoded password, never a substring of it.
    '4612-r01-psql-url-redacted-inside': 'psql postgres://u:hunterREDACTEDx@h/d',
    '4612-r02-psql-url-stars-inside': 'psql "postgresql://app:a***b@db.example/app"',
    '4612-r03-psql-url-dots-inside': 'psql "postgresql://app:pw...1@db.example/app"',
    '4612-r04-psql-url-xxxx-inside': 'psql "postgresql://app:xxxxx@db.example/app"',
    '4612-r05-store-url-redacted-inside': 'ai-memory serve --store-url postgres://u:hunterREDACTEDx@h/d',
    '4612-r06-store-url-angle-redacted-inside': 'ai-memory serve --store-url "postgres://u:<redacted>2@h/d"',
    '4612-r07-store-url-query-redacted-inside': 'ai-memory serve --store-url "postgres://u@h/d?password=hunterREDACTEDx"',
    '4612-r08-psql-c-sql-redacted-inside': 'psql -c "ALTER ROLE x PASSWORD \'hunterREDACTEDx\'"',
    '4612-r09-docker-env-stars-inside': 'docker run -e PGPASSWORD=hunter***x img',
    # #5651: an expansion before the first literal colon can supply psql's = itself.
    '5651-r01-assign-var-before-colon': '"$CLI" -v "$PW_ASSIGN:x"',
    '5651-r02-sudo-braced-var-before-colon': 'sudo -u postgres "$CLI" -v "${CRED}":tail',
    '5651-r03-name-tail-expansion': '"$CLI" -v pw$X:y',
    '5651-r04-command-substitution': '"$CLI" -v "$(printf pw=hunter2):x"',
    '5651-r05-backtick-substitution': '"$CLI" -v "`printf pw=hunter2`:x"',
    '5651-r06-positional': '"$CLI" -v "$1:x"',
    '5651-r07-default-operator': '"$CLI" -v "${A:-pw=x}:y"',
    '5651-r08-path-name-then-other': '"$CLI" -v "$HOME$PW:y"',
    '5651-r09-literal-between': '"$CLI" -v "${HOME}x$CRED:y"',
    '5651-r10-unnamed-var-mount-source': 'docker run -v $KEYS:/k $IMG',
}
# Round 10 green: no hit of any kind.
R10_GREEN_PROBES = {
    # #5651: the real-tree mount shapes stay clean.
    '5651-g01-home-mount': 'docker run -v "$HOME/.ai-memory:/data" img',
    '5651-g02-dir-mount-ro': 'docker run -v "$TLS_DIR:/certs-src:ro" img',
    '5651-g03-pwd-mount': 'docker run -v "$PWD":/work img',
    '5651-g04-braced-path-mount': 'docker run -v "${DATA_PATH}:/d" img',
    # #5620: a URL password is compared after percent-decoding, as libpq and sqlx read it.
    '5620-g01-psql-url-encoded-stars': 'psql "postgresql://app:%2A%2A%2A@db.example/app"',
    '5620-g02-store-url-encoded-stars': 'ai-memory serve --store-url postgres://u:%2a%2a%2a@h/d',
    '5620-g03-store-url-query-encoded-redacted': 'ai-memory serve --store-url "postgres://u@h/d?password=REDACTE%44"',
    '5620-g04-psql-url-encoded-ellipsis': 'psql "postgresql://app:%E2%80%A6@db.example/app"',
}
# #5620: the closed list, pinned per token on the psql URL path and the store URL path. The
# whole token is clean; one extra character before and after is a credential, so the list
# cannot turn back into a substring test. Spellings outside the list stay credentials.
for _i, _tok in enumerate(sorted(REDACTION_TOKENS)):
    R10_GREEN_PROBES['5620-t%d-psql-url-token' % _i] = 'psql "postgresql://app:%s@db.example/app"' % _tok
    R10_GREEN_PROBES['5620-t%d-store-url-token' % _i] = 'ai-memory serve --store-url postgres://u:%s@h/d' % _tok
    R10_RED_PROBES['5620-t%d-psql-url-token-padded' % _i] = 'psql "postgresql://app:q%sq@db.example/app"' % _tok
    R10_RED_PROBES['5620-t%d-store-url-token-padded' % _i] = 'ai-memory serve --store-url postgres://u:q%sq@h/d' % _tok
for _i, _word in enumerate(("CHANGEME", "PASSWORD", "<password>", "&lt;password&gt;", "%2A%2A%2Aq")):
    R10_RED_PROBES['5620-u%d-psql-url-unlisted' % _i] = 'psql "postgresql://app:%s@db.example/app"' % _word
    R10_RED_PROBES['5620-u%d-store-url-unlisted' % _i] = 'ai-memory serve --store-url postgres://u:%s@h/d' % _word
# A docker -e value and a psql -v value are not decoded: an encoded placeholder there is literal.
R10_RED_PROBES['5620-r01-docker-env-encoded-stars'] = 'docker run -e PGPASSWORD=%2A%2A%2A img'
R10_RED_PROBES['5620-r02-psql-v-listed-token'] = 'psql -v pw=REDACTED -f x.sql'

# #5597: xtrace spellings, read in a script (probe.sh and probe.tpl); the line after the
# switch handles a password-named variable, so a red probe is an [xtrace-secret] hit.
XTRACE_SECRET_LINE = 'printf "%s" "$DB_PASS" | x\n'
R10_XTRACE_RED = {
    '5597-x01-set-later-cluster': 'set -e -x\n',
    '5597-x02-set-later-cluster-2': 'set -eu -x\n',
    '5597-x03-set-later-o': 'set -u -o xtrace\n',
    '5597-x04-set-second-o': 'set -o errexit -o xtrace\n',
    '5597-x05-set-o-then-x': 'set -eo pipefail -x\n',
    '5597-x06-shopt-so': 'shopt -so xtrace\n',
    '5597-x07-shopt-s-o': 'shopt -s -o xtrace\n',
    '5597-x08-shopt-os': 'shopt -os xtrace\n',
    '5597-x09-shebang-env-S': '#!/usr/bin/env -S bash -x\n',
    '5597-x10-shebang-env-S-cluster': '#!/usr/bin/env -S bash -eux\n',
    '5597-x11-shebang-env-S-attached': '#!/usr/bin/env -Sbash -x\n',
    '5597-x12-shebang-o-xtrace': '#!/bin/bash -o xtrace\n',
    '5597-x13-shebang-env-split-string': '#!/usr/bin/env --split-string=bash -x\n',
    '5597-x14-and-list': '[ -n "$D" ] && set -x\n',
    '5597-x15-if-then': 'if true; then set -x; fi\n',
    '5597-x16-brace-group': '{ set -x; } 2>/dev/null\n',
    '5597-x17-builtin-set': 'builtin set -x\n',
    '5597-x18-command-set': 'command set -x\n',
    '5597-x19-escaped-set': '\\set -x\n',
    '5597-x20-eval-string': 'eval "set -x"\n',
    '5597-x21-unread-cluster': 'set -$OPTS\n',
    '5597-x22-unread-o-name': 'set -o $OPT\n',
    '5597-x23-unread-shopt-name': 'shopt -so $OPT\n',
    '5597-x24-plus-then-minus': 'set +e -x\n',
    '5597-x25-off-then-on-one-line': 'set +x; set -x\n',
    '5597-x26-unread-operand': 'set $OPTS\n',
}
R10_XTRACE_GREEN = {
    '5597-g01-set-off-later-cluster': 'set -x\nset -e +x\n',
    '5597-g02-set-dash': 'set -x\nset -\n',
    '5597-g03-shopt-uo': 'set -x\nshopt -uo xtrace\n',
    '5597-g04-shopt-u-o': 'set -o xtrace\nshopt -u -o xtrace\n',
    '5597-g05-positional-after-dashdash': 'set -- -x\n',
    '5597-g06-operand-ends-options': 'set -e foo -x\n',
    '5597-g07-shopt-without-o': 'shopt -s xtrace\n',
    '5597-g08-shebang-env-S-no-x': '#!/usr/bin/env -S bash -eu\n',
    '5597-g09-set-o-other': 'set -o pipefail\n',
    '5597-g10-on-then-off-one-line': 'set -x; set +x\n',
    '5597-g11-o-takes-the-x-word': 'set -o xtrace +o xtrace\n',
}


def r9_variants(text: str) -> List[Tuple[str, str, str]]:
    """(label, file name, text): the probe as a script, as prose and inside a fenced block."""
    return [("sh", "probe.sh", text), ("md", "probe.md", text),
            ("fence", "probe.md", "```bash\n" + text + "\n```\n")]


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
    # The #5512, #5513 and #5514 probes are file-type independent: the same spellings in a prose
    # file and a script are read by the same resolver.
    for suffix in ("probe.md", "probe.sh"):
        for name, text in RED_PROBES_4600.items():
            if name.startswith(("5512-", "5513-", "5514-")):
                red += 1
                if not scan_text(suffix, text):
                    print("SELF-TEST FAIL: red probe %r (%s) was not flagged" % (name, suffix), file=sys.stderr)
                    bad += 1
        for name, text in GREEN_PROBES_4600.items():
            if name.startswith(("5512-", "5513-", "5514-")):
                green += 1
                if scan_text(suffix, text):
                    print("SELF-TEST FAIL: green probe %r (%s) was flagged" % (name, suffix), file=sys.stderr)
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
    pad = "p" + "''" * 3 + "s" + "''" * 3 + "ql_" + "x" * 30 + " -X -f a.sql\n"
    pinned = [h for h in scan_text("probe.sh", pad * 3 + 'psql -v pw="$PG_PW" -f x.sql\n')
              if h[2].startswith("[env-password-argv]")]
    if [h[1] for h in pinned] != [4]:
        print("SELF-TEST FAIL: a psql -v hit after split heads is not reported on line 4: %r" % pinned, file=sys.stderr)
        bad += 1
    # #5516: one real command is one hit, on its own line, with a snippet that shows
    # the offending option; a separator ends the psql segment.
    red_before = red
    for name, text, want_lines, must_show in PSQL_SEGMENT_PROBES:
        # A probe with no wanted line asserts that there is NO hit: a clean case, not a red one.
        if want_lines:
            red += 1
        else:
            green += 1
        got = [h for h in scan_text("probe.md", text) if h[2].startswith("[env-password-argv]")]
        if [h[1] for h in got] != want_lines or any(must_show not in h[2] or "\\" in h[2] or "hunter2x" in h[2] for h in got):
            print("SELF-TEST FAIL: psql segment probe %r gave %r (want lines %r showing %r)"
                  % (name, got, want_lines, must_show), file=sys.stderr)
            bad += 1
    # #5559: a probe that wants no hit is counted as a clean case, so the red total is the
    # number of probes that want a hit (the changelog quotes these totals).
    if red - red_before != sum(1 for _n, _t, wanted, _m in PSQL_SEGMENT_PROBES if wanted):
        print("SELF-TEST FAIL: a no-hit segment probe was counted as a red case (#5559)", file=sys.stderr)
        bad += 1
    # #5556-#5558: the undecidable-head rule is file-type independent; each probe is run as a
    # prose file and as a script.
    for suffix in ("probe.md", "probe.sh"):
        for name, text in RED_HEAD_PROBES.items():
            red += 1
            # text_rule_hits, not scan_text: scan_text drops a text hit on a line another
            # layer already reported, which would hide a regression of this rule.
            if not any(h[2].startswith("[env-password-argv]") for h in text_rule_hits(suffix, text)):
                print("SELF-TEST FAIL: red probe %r (%s) was not flagged" % (name, suffix), file=sys.stderr)
                bad += 1
        for name, text in GREEN_HEAD_PROBES.items():
            green += 1
            if scan_text(suffix, text):
                print("SELF-TEST FAIL: green probe %r (%s) was flagged" % (name, suffix), file=sys.stderr)
                bad += 1
    for name, text, want_lines in HEAD_LINE_PROBES:
        red += 1
        got = [h[1] for h in text_rule_hits("probe.md", text) if h[2].startswith("[env-password-argv]")]
        if got != want_lines:
            print("SELF-TEST FAIL: head line probe %r gave lines %r (want %r)" % (name, got, want_lines), file=sys.stderr)
            bad += 1
    # #5593 #5594 (round 9): every probe as a script, a prose file and a fenced block.
    for name, text in R9_RED_PROBES.items():
        for label, suffix, body in r9_variants(text):
            red += 1
            if not any(h[2].startswith("[env-password-argv]") for h in text_rule_hits(suffix, body)):
                print("SELF-TEST FAIL: red probe %r (%s) was not flagged" % (name, label), file=sys.stderr)
                bad += 1
    for name, text in R9_GREEN_PROBES.items():
        for label, suffix, body in r9_variants(text):
            green += 1
            if scan_text(suffix, body):
                print("SELF-TEST FAIL: green probe %r (%s) was flagged" % (name, label), file=sys.stderr)
                bad += 1
    # Round 10: every probe as a script, a prose file and a fenced block.
    for name, text in R10_RED_PROBES.items():
        for label, suffix, body in r9_variants(text):
            red += 1
            if not scan_text(suffix, body):
                print("SELF-TEST FAIL: red probe %r (%s) was not flagged" % (name, label), file=sys.stderr)
                bad += 1
    for name, text in R10_GREEN_PROBES.items():
        for label, suffix, body in r9_variants(text):
            green += 1
            got = scan_text(suffix, body)
            if got:
                print("SELF-TEST FAIL: green probe %r (%s) was flagged: %r" % (name, label, got), file=sys.stderr)
                bad += 1
    for name, text in R10_XTRACE_RED.items():
        for suffix in ("probe.sh", "probe.tpl"):
            red += 1
            got = [h for h in scan_text(suffix, text + XTRACE_SECRET_LINE) if "[xtrace-secret]" in h[2]]
            if not got:
                print("SELF-TEST FAIL: xtrace probe %r (%s) not flagged" % (name, suffix), file=sys.stderr)
                bad += 1
    for name, text in R10_XTRACE_GREEN.items():
        for suffix in ("probe.sh", "probe.tpl"):
            green += 1
            got = [h for h in scan_text(suffix, text + XTRACE_SECRET_LINE) if "[xtrace-secret]" in h[2]]
            if got:
                print("SELF-TEST FAIL: xtrace probe %r (%s) was flagged: %r" % (name, suffix, got), file=sys.stderr)
                bad += 1
    # A glob head with no credential option is emphasis in prose; a script refuses it as undecidable.
    green += 1
    if scan_text("probe.md", "```bash\n[p]sql -f x.sql\n```\n"):
        print("SELF-TEST FAIL: a credential-free glob head in prose was flagged", file=sys.stderr)
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
