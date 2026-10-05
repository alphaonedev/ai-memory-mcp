#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Closed-world gate against secrets on a process argv, for executable files.

Decision: precedent 19497ef6, fail-closed allowlist gate. scripts/check-docs-no-argv-secrets.py
is a denylist of known ways to put a credential on a command line, and every review round
finds a form it misses. The cloud-init gate (scripts/check-cloud-init-serve-flags.py) is
closed-world: every triggered line must match an allowlist entry, and it has held against
every bypass in four review rounds. This gate gives executable files the same form.

Mode 1, executable files (closed world). Files read: .sh and .bash files and shebang scripts
without a suffix; workflow ``run:`` steps (.github/workflows, .github/actions); compose
``command`` / ``entrypoint`` / healthcheck ``test`` (any ``*compose*.yml``); Dockerfile and
Dockerfile.* RUN / CMD / ENTRYPOINT / HEALTHCHECK; ``.service`` Exec lines; Makefile
recipes. Cloud-init ``.tpl`` files stay under the cloud-init gate. A logical line is a
physical line with backslash continuations joined; a bash array that spans lines is one
logical unit. A full-line comment is not executable and is skipped.

A logical line is TRIGGERED when a secret-like name appears in it as an assignment
(``NAME=``), a flag (``--NAME``), an expansion (``$NAME``, ``${NAME``, ``${{ secrets.X }}``),
a header (``Authorization:``, ``x-api-key:``, ``Bearer``), or a secret path (``/run/secrets``,
``api-key``, ``.pw``, ``_PW_FILE``), or when the imported denylist rules of
check-docs-no-argv-secrets.py flag it. The trigger is NOT limited to argument position: a
header variable such as ``keyhdr="-H 'x-api-key: $API_KEY'"`` that is expanded into an ssh or
curl argv later is triggered where it is built. Secret-like names are matched on identifier
segments (``DB_KEY``, ``DBPW``, ``PGPASSWORD``, ``apiKey``, ``PASSPHRASE``, ``AUTH``), so
``passed`` and ``author`` are not secret names.

Every triggered line must match an entry of scripts/qc-allowlists/exec-secret-argv-allow.txt,
keyed by file, normalised logical line text (whitespace runs collapsed) and occurrence
count, never by line number:   <why> | <file> | <count> | <line>
An unknown line is red; an entry whose line or count no longer matches is stale and red.
Lines that are unsafe today are listed in scripts/qc-allowlists/exec-secret-argv-pending.txt
(same form, <why> is ``#<issue>`` or, for a product form whose issue is not yet filed,
``reason: <text>``); the gate prints them and passes, as the cloud-init gate does for its
pending entries. A pending line is never approved and its entry must go when the defect is fixed.

Mode 2, prose (denylist). Markdown code fences and html ``<pre>`` blocks are read with the
imported denylist rules (shell-like rules the denylist script applies to scripts only, such
as a postgres URL with a password on a psql, pg_dump or migrate argv), plus a rule for
``curl -H`` / ``--header`` carrying a key or Authorization header and ``curl -u user:value``,
``openssl ... -hmac``, a container ``-e SECRET_NAME=$expansion`` and a secret-named flag with
an inline value. Prose has no allowlist: a hit is red unless it is listed in the pending file.

Known limits (stated, not hidden):
  * A secret read into a NEUTRALLY NAMED variable (``v=$(cat k); tool --opt "$v"``) is not
    caught by a name trigger, and neither is a literal secret on an unknown tool with no
    secret-like word near it. The literal forms of #4813-#4819 are caught by the imported
    denylist rules; a neutral name on an unknown tool is the residual risk.
  * Arguments assembled at run time, ``eval`` and files written by one script and executed by
    another are read as text only. Cloud-init templates are the cloud-init gate's.
  * Threat model: honest drift. An author who hides a secret AND edits this gate or its
    allowlist is caught by review of the allowlist diff, which regen-exec-secret-argv-allow.py
    makes visible (additions need --accept-new and are printed).

Usage:
  scripts/check-exec-secret-argv.py             exit 0 clean, 1 on a hit, 2 on a scanner fault
  scripts/check-exec-secret-argv.py --self-test red probes, green probes, allow-entry mutations
  scripts/check-exec-secret-argv.py --list      print every triggered line (for review)
"""
import argparse
import contextlib
import difflib
import importlib.util
import io
import os
import re
import subprocess
import sys
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
DENYLIST = "scripts/check-docs-no-argv-secrets.py"
ALLOW_FILE = "scripts/qc-allowlists/exec-secret-argv-allow.txt"
PENDING_FILE = "scripts/qc-allowlists/exec-secret-argv-pending.txt"
MAX_BYTES = 4 * 1024 * 1024
SELF_EXEMPT = {"scripts/check-exec-secret-argv.py", "scripts/regen-exec-secret-argv-allow.py"}

# (first physical line, last physical line, raw text) of one logical unit.
Unit = Tuple[int, int, str]
# One found line: (first physical line, normalised text, reasons).
Found = Tuple[int, str, List[str]]
# One list entry: (why, file, count, text, line number in the list file).
Entry = Tuple[str, str, int, str, int]


def norm(text: str) -> str:
    return " ".join(text.split())


# ---------------------------------------------------------------- denylist import
def load_denylist(root: Path):
    spec = importlib.util.spec_from_file_location("argv_denylist", str(root / DENYLIST))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load " + DENYLIST)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    for need in ("scan_text", "split_words", "commands", "redact", "logical_lines"):
        if not hasattr(mod, need):
            raise RuntimeError("%s no longer exports %s" % (DENYLIST, need))
    return mod


# ---------------------------------------------------------------- secret names
SEGMENT_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
STRONG = ("password", "passwd", "passphrase", "secret", "token", "credential", "bearer", "apikey")
EXACT_SEGMENTS = {"pass", "pw", "pwd", "dbpw", "pgpass", "auth", "oauth", "key", "keys", "cred", "creds",
                  "hmac", "psk", "jwt", "otp", "totp", "hotp", "apikey", "secretid"}
SUFFIXES = ("key", "pass", "pw", "pwd", "auth")


DSN_QUALIFIERS = {"store", "database", "db", "pg", "postgres", "postgresql", "redis", "conn", "connection",
                  "mysql", "mongo", "amqp"}
NOUN_SEGMENTS = {"dir", "dirs", "directory", "id", "ids", "name", "names", "count", "len", "length",
                 "size", "type", "pub", "public", "label", "user", "users", "hash", "num", "max", "min"}


def secret_name(name: str) -> bool:
    """True when an identifier or flag name has a secret-like segment. A name whose last
    segment is a plain noun that cannot hold a secret (KEY_DIR, KEY_ID, TOKEN_COUNT) is not."""
    segs = SEGMENT_RE.findall(name)
    if segs and segs[-1].lower() in NOUN_SEGMENTS and len(segs) > 1:
        # SECRET_ID is the vault approle secret, not an identifier of a secret (#4925)
        if not (segs[-1].lower() == "id" and segs[-2].lower() == "secret"):
            return False
    low = [x.lower() for x in segs]
    for i, s in enumerate(low):
        # a connection string can embed a password (#4808): DSN, or a URL/URI of a data store
        if s == "dsn" or (s in ("url", "uri") and i > 0 and low[i - 1] in DSN_QUALIFIERS):
            return True
    for seg in segs:
        s = seg.lower()
        if s in ("pub", "public", "pubkey", "publickey"):
            return False
        if s in EXACT_SEGMENTS or any(w in s for w in STRONG):
            return True
        if len(s) > 3 and (s.endswith(SUFFIXES) or s.startswith("key")):
            return True
    return False


EXPAND_RE = re.compile(r"\$\{?[!#]?\{?\s*(?:secrets\.|env\.|vars\.)?([A-Za-z_][A-Za-z0-9_]*)")
ASSIGN_RE = re.compile(r"(?<![\w$.\-])([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?\+?=")
BARE_RE = re.compile(r"(?<![\w$.\-/{])([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*)(?![\w=\-/}])")
FLAG_RE = re.compile(r"(?<![\w$./\-])--?([A-Za-z][A-Za-z0-9_\-]*)")
HEADER_RE = re.compile(
    r"\bauthorization\s*:|\bbearer\b|\bx-auth[\w-]*\s*:|\bproxy-authorization|\bapi[-_]?key\b|"
    r"\bpassword\s+['\"$\\]|\bidentified\s+by\b|\$\{\{\s*(?:secrets\.|github\.token|toJSON\(\s*secrets)|"
    r"(?:(?<![\w-])-[A-Za-z]*H|--(?:proxy-)?header)[\s=]*\\?[\"']?[\w-]*(?:token|secret|passw\w*|credential|cookie|"
    r"api[-_]?key)[\w-]*\s*:|"
    r"\bcookie\s*:", re.I)
# A command substitution that reads a secret file or runs a secret-printing command puts the
# value on argv whatever the flag or variable is called (#4924).
SUBST_RE = re.compile(
    r"(?:\$\(|`)\s*(?:"
    r"(?:(?:cat|head|tail|base64|xxd|tr|sed|awk|strings)\b|<)[^)`]*?[\s<]\s*[\"']?[^\s\"')`]*"
    r"(?:\.(?:key|pgpass|netrc|pw|pass|passwd|password|passphrase|token|secret|secrets)|\bid_(?:rsa|ed25519|ecdsa|dsa)"
    r"|/run/secrets/|/secrets?/)(?![\w.\-])"
    r"|gh\s+auth\s+token|vault\s+(?:read|kv\s+get)|[\w-]*get-login-password|[\w-]*get-secret-value|"
    r"pass\s+show|op\s+read|security\s+find-(?:generic|internet)-password|"
    r"[\w\s]*print-(?:access|identity)-token|[\w\s]*get-access-token|kubectl\s+get\s+secret|"
    r"[\w\s]*ssm\s+get-parameter)", re.I)
# A JSON request body carrying a credential literal on a -d/--data/--json argument (#4925).
JSONBODY_RE = re.compile(
    r"(?:\s-d|--data(?:-raw|-binary|-urlencode)?|--json)\b[^|;&]*?"
    r"\\?[\"']\s*(?:password|passwd|secret|token|api[-_]?key|access[-_]?token|client[-_]?secret|private[-_]?key)"
    r"\s*\\?[\"']\s*:", re.I)
MAKEVAR_RE = re.compile(r"\$\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
PATH_RE = re.compile(
    r"/run/secrets|/secrets?/|\.(?:pw|pass|passwd|password|passphrase|token|secret|secrets)\b|"
    r"_pw_?file|\bpw[-_]?file|(?:passw\w*|passphrase|secret|token|credential)[-_.]?(?:file|path)\b", re.I)


def trigger_reasons(text: str, make: bool = False) -> List[str]:
    """Why a logical line is triggered (secret-like name as assignment, flag, expansion,
    header or secret path). Empty when it is not."""
    out: List[str] = []
    for m in ASSIGN_RE.finditer(text):
        if secret_name(m.group(1)):
            out.append("assign:" + m.group(1))
    for m in FLAG_RE.finditer(text):
        if secret_name(m.group(1)):
            out.append("flag:" + m.group(1))
    for m in EXPAND_RE.finditer(text):
        if secret_name(m.group(1)):
            out.append("expand:" + m.group(1))
    for m in BARE_RE.finditer(text):
        if m.group(1) not in ("PASS", "AUTH", "KEY", "KEYS", "HMAC", "JWT", "OTP", "PSK") and secret_name(m.group(1)):
            out.append("word:" + m.group(1))
    if make:
        for m in MAKEVAR_RE.finditer(text):
            if secret_name(m.group(1)):
                out.append("make:" + m.group(1))
    if SUBST_RE.search(text):
        out.append("subst-secret")
    if JSONBODY_RE.search(text):
        out.append("json-secret")
    if HEADER_RE.search(text):
        out.append("header")
    if PATH_RE.search(text):
        out.append("path")
    return out


# ---------------------------------------------------------------- logical units
def _cont_end(raw: str, ch: str = "\\") -> bool:
    s = raw.rstrip()
    return s.endswith(ch) and not s.endswith(ch + ch)


def _backslash_end(raw: str) -> bool:
    return _cont_end(raw, "\\")


_QUOTED_RE = re.compile(r"""'[^']*'|"(?:\\.|[^"\\])*\"""")
_ARRAY_RE = re.compile(r"[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=\(")


ARRAY_JOIN_MAX = 400


def _strip_line(s: str) -> str:
    t = _QUOTED_RE.sub("", re.sub(r"\\.", "", s))
    return re.split(r"(?:^|\s)#", t, 1)[0]


def _array_depth(parts: List[str]) -> int:
    """Open-paren depth of a bash array literal spread over physical lines. Each physical
    line drops its own trailing comment, so a comment cannot hide the closing paren."""
    if not parts or not _ARRAY_RE.search(_strip_line(parts[0])):
        return 0
    return sum(t.count("(") - t.count(")") for t in map(_strip_line, parts))


def _is_comment(raw: str) -> bool:
    return raw.lstrip().startswith("#")


def join_logical(lines: List[Tuple[int, str]], cont: str = "\\", comments_continue: bool = False) -> List[Unit]:
    """Join continuations and a bash array spread over lines into one unit.

    A continuation is removed with no separator (the shell deletes backslash-newline, so a flag
    or header name split across lines is one word, #4926). A whole comment line is never
    continued (#4903); Make is the exception because GNU make continues a comment."""
    def piece(raw: str) -> str:
        return raw.rstrip()[:-1] if _cont_end(raw, cont) else raw

    def continues(raw: str) -> bool:
        return _cont_end(raw, cont) and (comments_continue or not _is_comment(raw))

    out: List[Unit] = []
    i = 0
    n = len(lines)
    while i < n:
        start, raw = lines[i]
        phys = [piece(raw)]
        text = phys[0]
        end = start
        while continues(lines[i][1]) and i + 1 < n:
            i += 1
            end = lines[i][0]
            phys.append(piece(lines[i][1]))
            text += phys[-1]
        depth = _array_depth(phys) if cont == "\\" else 0
        guard = 0
        while depth > 0 and i + 1 < n:
            guard += 1
            if guard > ARRAY_JOIN_MAX:
                raise RuntimeError("array opened at line %d is not closed within %d lines; refusing to "
                                   "approve it as one unit" % (start, ARRAY_JOIN_MAX))
            i += 1
            end = lines[i][0]
            phys.append(piece(lines[i][1]))
            text += " " + phys[-1]
            depth = _array_depth(phys)
        out.append((start, end, text))
        i += 1
    return out


def _numbered(text: str) -> List[Tuple[int, str]]:
    return list(enumerate(text.split("\n"), 1))


def _indent(s: str) -> int:
    return len(s) - len(s.lstrip())


_ANCHOR_RE = re.compile(r"&[A-Za-z_][\w\-]*(?:\s+(.*))?$")
_BLOCK_START = ("|", ">")


def yaml_value_units(text: str, keys: Tuple[str, ...], anchors: bool = True) -> List[Unit]:
    """Values of the given YAML keys, as logical units. Covers `key :` with any spacing, a key
    inside a flow mapping or after `- `, block scalars, plain multi-line scalars (every line
    indented deeper than the key, #4905), and anchor definitions (`&name value`) wherever they
    sit, so an alias cannot carry a command the key-scan never saw (#4927)."""
    lines = text.split("\n")
    key_re = re.compile(r"(?:^|(?<=[\s{,\-]))(?:%s)\s*:(?:\s+(.*))?$" % "|".join(keys))
    out: List[Unit] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") else ""
        m = key_re.search(stripped) if stripped else None
        kind = "key"
        if m is None and anchors and stripped:
            m = _ANCHOR_RE.search(stripped)
            kind = "anchor"
        if m is None:
            i += 1
            continue
        keycol = m.start() if kind == "key" else _indent(raw)
        rest = raw[m.start(1):].strip() if m.group(1) else ""
        block: List[Tuple[int, str]] = []
        if rest and rest[0] not in _BLOCK_START:
            block.append((i + 1, rest))
        j = i + 1
        seq_ok = rest == "" or rest[0] in _BLOCK_START
        while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) > keycol or (
                seq_ok and _indent(lines[j]) == keycol and lines[j].lstrip().startswith("- "))):
            block.append((j + 1, lines[j]))
            j += 1
        out.extend(join_logical(block))
        i = j
    return out


def workflow_units(text: str) -> List[Unit]:
    return yaml_value_units(text, ("run", "options", "args"))


def compose_units(text: str) -> List[Unit]:
    return yaml_value_units(text, ("command", "entrypoint", "test", "args"))


_ESCAPE_RE = re.compile(r"^\s*#\s*escape\s*=\s*(\S)\s*$", re.I)
_HEREDOC_RE = re.compile(r"<<-?\s*[\"']?([A-Za-z_]\w*)[\"']?")
_DOCKER_INSTR_RE = re.compile(r"\s*(?:ONBUILD\s+)?(RUN|CMD|ENTRYPOINT|HEALTHCHECK)\b(.*)$", re.I | re.S)


def dockerfile_units(text: str) -> List[Unit]:
    lines = _numbered(text)
    cont = "\\"
    for _n, raw in lines:
        if not raw.strip():
            continue
        m = _ESCAPE_RE.match(raw)
        if m:
            cont = m.group(1)
            continue
        if not _is_comment(raw):
            break
    out: List[Unit] = []
    # Docker removes a whole comment line (and an empty line) inside a continued instruction
    # before it joins the continuation, so the instruction goes on past it (#4995).
    kept: List[Tuple[int, str]] = []
    joining = False
    for no, raw in lines:
        if joining and (_is_comment(raw) or not raw.strip()):
            continue
        kept.append((no, raw))
        joining = _cont_end(raw, cont) and not _is_comment(raw)
    units = join_logical(kept, cont)
    k = 0
    while k < len(units):
        start, end, t = units[k]
        m = _DOCKER_INSTR_RE.match(t)
        k += 1
        if not m:
            continue
        out.append((start, end, m.group(2)))
        for h in _HEREDOC_RE.finditer(m.group(2)):
            word = h.group(1)
            body: List[Tuple[int, str]] = []
            while k < len(units) and units[k][2].strip() != word:
                body.append((units[k][0], units[k][2]))
                k += 1
            out.extend(join_logical(body))
            k += 1
    return out


def service_units(text: str) -> List[Unit]:
    return [u for u in join_logical(_numbered(text)) if re.match(r"\s*Exec\w*=", u[2])]


_RECIPEPREFIX_RE = re.compile(r"^\s*\.RECIPEPREFIX\s*:?=\s*(\S)?\s*$")


def make_units(text: str) -> List[Unit]:
    prefix = "\t"
    for raw in text.split("\n"):
        m = _RECIPEPREFIX_RE.match(raw)
        if m:
            prefix = m.group(1) or "\t"
            break
    return [u for u in join_logical(_numbered(text), comments_continue=True) if u[2].startswith(prefix)]


_PY_CALL_RE = re.compile(
    r"\b(?:subprocess\.(?:run|Popen|call|check_call|check_output|getoutput|getstatusoutput)|Popen|check_output|"
    r"check_call|os\.(?:system|popen|exec\w*|spawn\w*)|asyncio\.create_subprocess_(?:exec|shell))\s*\(")
_PY_ARGV_RE = re.compile(r"^\s*[A-Za-z_]\w*(?:cmd|argv|args|command|cmdline)\w*\s*(?::[^=]+)?=\s*[\[(]", re.I)
PY_UNIT_MAX = 120


def _bracket_delta(s: str) -> int:
    t = _QUOTED_RE.sub("", re.sub(r"\\.", "", s))
    t = re.split(r"(?:^|\s)#", t, 1)[0]
    return sum(t.count(c) for c in "([{") - sum(t.count(c) for c in ")]}")


def _call_units(text: str, call_re, argv_re) -> List[Unit]:
    lines = text.split("\n")
    out: List[Unit] = []
    for i, raw in enumerate(lines):
        m = call_re.search(raw) or (argv_re.match(raw) if argv_re is not None else None)
        if not m:
            continue
        depth = 0
        buf: List[str] = []
        j = i
        while j < len(lines):
            buf.append(lines[j].strip())
            depth += _bracket_delta(lines[j])
            if depth <= 0:
                break
            j += 1
            if j - i > PY_UNIT_MAX:
                raise RuntimeError("call at line %d is not closed within %d lines (fail closed)" %
                                   (i + 1, PY_UNIT_MAX))
        out.append((i + 1, j + 1, " ".join(buf)))
    return out


def python_units(text: str) -> List[Unit]:
    """Every subprocess/os.system call and every argv-named list assignment, joined to its
    closing bracket, so a credential on a Python argv is read like one on a shell line."""
    return _call_units(text, _PY_CALL_RE, _PY_ARGV_RE)


_JS_CALL_RE = re.compile(r"\b(?:spawn|spawnSync|exec|execSync|execFile|execFileSync|fork)\s*\(")


def node_units(text: str) -> List[Unit]:
    """child_process calls of a JavaScript file, joined to the closing bracket."""
    return _call_units(text, _JS_CALL_RE, None)


# Extensionless tracked files that are data, not scripts. Every other extensionless file is
# read as a shell script, because a script needs no suffix and no shebang to run (#4923).
NONCODE_NAMES = {"LICENSE", "NOTICE", "CODEOWNERS", "changelog", "control", "copyright", "format",
                 "SHA256SUMS", "COPYING", "AUTHORS", "VERSION", "MAINTAINERS", "OWNERS", "Cargo.lock"}

_SYSTEMD_SUFFIXES = (".service", ".socket", ".timer", ".path", ".mount", ".automount", ".swap", ".target",
                     ".service.in", ".socket.in", ".timer.in", ".path.in")
_SH_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh", ".bats", ".sh.in", ".bash.in", ".zsh.in")
_CLOUD_INIT_MEMORY_RE = re.compile(r"^infra/[^/]+/cloud-init-memory[^/]*\.tpl$")


def _systemd_dropin(lowrel: str) -> bool:
    """x.service.d/override.conf: a drop-in directory named after a systemd unit."""
    parent = lowrel.split("/")[-2] if lowrel.count("/") else ""
    return parent.endswith(".d") and parent[:-2].endswith(_SYSTEMD_SUFFIXES)


def file_class(rel: str, head: str) -> Optional[str]:
    base = os.path.basename(rel)
    low = base.lower()
    lowrel = rel.lower()
    # path first: a workflow named compose-*.yml or dockerfile-*.yml is still a workflow (#4907)
    if lowrel.startswith((".github/workflows/", ".github/actions/")) and low.endswith((".yml", ".yaml")):
        return "workflow"
    if low.startswith(("dockerfile", "containerfile")) or low.endswith((".dockerfile", ".containerfile")):
        return "dockerfile"
    if low.endswith((".yml", ".yaml")) and ("compose" in low or low.startswith("stack")):
        return "compose"
    if low.endswith((".yml", ".yaml", ".yml.in", ".yaml.in", ".yml.tpl", ".yaml.tpl")):
        if _CLOUD_INIT_MEMORY_RE.match(rel):
            return None
        return "compose" if not low.endswith(".tpl") else "shell"
    if low.endswith(_SH_SUFFIXES):
        return "shell"
    if low.endswith(_SYSTEMD_SUFFIXES) or (low.endswith(".conf") and _systemd_dropin(lowrel)):
        return "service"
    if base in ("Makefile", "GNUmakefile", "makefile") or low.endswith((".mk", ".mk.in")):
        return "make"
    if low.endswith(".py"):
        return "python"
    if low.endswith((".js", ".mjs", ".cjs")):
        return "node"
    if os.path.splitext(base)[1] == "" and base == "rules" and lowrel.startswith("debian/"):
        return "make"
    if os.path.splitext(base)[1] == "" and not base.startswith(".") and base not in NONCODE_NAMES and not \
            base.startswith(("LICENSE", "README", "CHANGELOG")):
        return "shell"
    if os.path.splitext(base)[1] == "" and head.startswith("#!") and re.search(
            r"\b(?:ba|da|z|k)?sh\b|\bbats\b", head.split("\n", 1)[0]):
        return "shell"
    return None


UNITS = {
    "shell": lambda t: join_logical(_numbered(t)),
    "workflow": workflow_units,
    "compose": compose_units,
    "dockerfile": dockerfile_units,
    "service": service_units,
    "make": make_units,
    "python": python_units,
    "node": node_units,
}


def exec_units(rel: str, text: str) -> Optional[List[Unit]]:
    cls = file_class(rel, text[:200])
    if cls is None:
        return None
    units = UNITS[cls](text)
    return [u for u in units if u[2].strip() and not u[2].strip().startswith("#")]


# ---------------------------------------------------------------- mode 1 scan
def as_shell_name(rel: str) -> str:
    return rel if rel.lower().endswith((".sh", ".bash", ".yml", ".yaml", ".service")) else rel + ".sh"


def deny_lines(dl, rel: str, text: str) -> Dict[int, str]:
    """Physical start line -> the denylist's hit snippet, for one file's text."""
    out: Dict[int, str] = {}
    if rel in SELF_EXEMPT:
        return out
    for _rel, line, snippet in dl.scan_text(as_shell_name(rel), text):
        out.setdefault(line, snippet)
    return out


# mysql family (#4920, #5464, #5502, #5582, #5583, #5630-#5639): a closed world. A head is a word that begins with
# mysql or mariadb in any letter case (mysqldump, mysql_upgrade, mariadb-dump, MySQLDump, mysql.exe ...) after any
# path, at a command position; it is not a head when an assignment, a URL, a user:group pair or a path component
# continues it. The words after the head up to the next pipe, semicolon, ampersand or unmatched parenthesis are
# read by shell word, quotes removed. A word is clean only when it is positively recognised as no credential:
# a word without any expansion, a flag of the measured set, a short cluster read letter by letter, the value of
# a measured value option, an operand that is not led by an expansion, or any operand after --. Everything else
# that carries an expansion is reported: the value of -p or of any prefix of --password (with or without a loose,
# skip, enable or disable prefix, a dash or an underscore), the value of a flag or option the gate does not know,
# the next word of an unknown option, an expansion-led operand before --, and an operand after a password command
# word. Measured on the 5.7.24 clients' --help; the sets are a measured sample, not a client list.
_MY_LONG_VALUE = frozenset("""
auto-generate-sql-execute-number auto-generate-sql-load-type auto-generate-sql-secondary-indexes
auto-generate-sql-unique-query-number auto-generate-sql-unique-write-number auto-generate-sql-write-number
base64-output bind-address binlog-row-event-max-size character-sets-dir columns commit compatible
compress-output concurrency connect-timeout connection-server-id create create-schema database default-auth
default-character-set default-parallelism defaults-extra-file defaults-file defaults-group-suffix delimiter
detach engine exclude-databases exclude-events exclude-gtids exclude-routines exclude-tables exclude-triggers
exclude-users fields-enclosed-by fields-escaped-by fields-optionally-enclosed-by fields-terminated-by host
ignore-error ignore-lines ignore-table include-databases include-events include-gtids include-routines
include-tables include-triggers include-users iterations lines-terminated-by local-load log-error
log-error-file login-path max-allowed-packet max-join-size net-buffer-length number-char-cols number-int-cols
number-of-queries offset open-files-limit parallel-schemas plugin-dir port protocol read-from-remote-master
result-file rewrite-db select-limit server-id server-id-bits server-public-key-path shutdown-timeout
skip-database sleep socket sql-mode ssl-ca ssl-capath ssl-cert ssl-cipher ssl-crl ssl-crlpath ssl-key ssl-mode
start-datetime start-position stop-datetime stop-never-slave-server-id stop-position tab tee tls-version
use-threads user
""".split())
_MY_LONG_FLAG = frozenset("""
add-drop-database add-drop-table add-drop-trigger add-drop-user add-locks all-databases all-in-1
all-tablespaces allow-keywords analyze apply-slave-statements auto-generate-sql
auto-generate-sql-add-autoincrement auto-generate-sql-guid-primary auto-rehash auto-repair
auto-vertical-output batch binary-as-hex binary-mode check check-only-changed check-upgrade column-names
column-type-info comments compact complete-insert compress connect-expired-password count create-options csv
databases debug debug-check debug-info defer-table-indexes delete delete-master-logs disable-keys
disable-log-bin dump-date dump-slave enable-cleartext-plugin events extended extended-insert fast fix-db-names
fix-table-names flush-logs flush-privileges force force-if-open force-read get-server-public-key help hex-blob
hexdump html i-am-a-dummy idempotent ignore ignore-spaces include-master-host-port insert-ignore keys
line-numbers local local-infile lock-all-tables lock-tables low-priority master-data medium-check
named-commands no-auto-rehash no-autocommit no-beep no-create-db no-create-info no-data no-defaults no-drop
no-set-names no-tablespaces one-database only-print opt optimize order-by-primary print-defaults quick
quote-names raw read-from-remote-server reconnect relative repair replace routines safe-updates secure-auth
set-charset set-gtid-purged short-form show-table-type show-warnings sigint-ignore silent single-transaction
skip-column-names skip-definer skip-dump-rows skip-gtids skip-line-numbers skip-opt skip-sys-schema ssl
ssl-verify-server-cert status stop-never syslog table tables to-last-log triggers tz-utc unbuffered
upgrade-system-tables use-frm users verbose verify-binlog-checksum version version-check vertical wait
watch-progress write-binlog xml
""".split())
_MY_NOARG_SHORT = frozenset("1?ABCEGHIKLNQRUVXYabfgkmnstv")
_MY_VALUE_SHORT = frozenset("huPS")
_MY_SENSITIVE = ("password", "password1", "password2", "password3")
_MY_NAME_PREFIXES = ("loose-", "skip-", "enable-", "disable-", "maximum-")
_MY_HEAD_RE = re.compile(
    r"(?<![\w.$-])(?P<dir>(?:[^\s\"'|;&()<>=]*[/\\])?)(?P<name>(?i:mysql|mariadb)[\w-]*(?:(?i:\.exe))?)(?![\w.:/\\=@{}-])")
_MY_NONCMD_PREV = frozenset("""
install reinstall remove purge upgrade update start stop restart reload status enable disable is-active is-enabled
cd ls cat rm mkdir chown chmod chgrp cp mv ln touch test stat du df find tail head echo printf export unset
""".split())
_MY_BIN_DIR_RE = re.compile(r"(?:^|[/\\])(?:s?bin|libexec)[/\\]|^\.{1,2}[/\\]|^~[/\\]|^[\"']?\$")
_MY_REDIRECT_RE = re.compile(r"^(?:\d*|&)(?:<<<|<<-?|<>|>>|>\||>&|<&|<|>)$|^&>>?$")
_MY_REDIRECT_ATTACHED_RE = re.compile(r"^(?:\d*|&)(?:<<<|<<-?|<>|>>|>\||>&|<&|<|>)|^&>>?")


def _my_has_exp(word: str) -> bool:
    return "$" in word or "`" in word


def _my_long_kind(name: str) -> Optional[str]:
    """'flag' or 'value' for a long option name that is positively a measured non-password option (an exact name or
    an abbreviation no password option shares), None for every other spelling (closed world)."""
    base = name.replace("_", "-")
    stripped = True
    while stripped:
        stripped = False
        for pre in _MY_NAME_PREFIXES:
            if base.startswith(pre) and len(base) > len(pre):
                base = base[len(pre):]
                stripped = True
    if not base or base in _MY_SENSITIVE:
        return None
    kinds = set()
    for known, kind in ((_MY_LONG_VALUE, "value"), (_MY_LONG_FLAG, "flag")):
        if base in known:
            return kind
        kinds.update(kind for item in known if item.startswith(base))
    if any(item.startswith(base) for item in _MY_SENSITIVE) or len(kinds) != 1:
        return None
    return next(iter(kinds))


def _my_words(text: str) -> List[str]:
    """The shell words of one command (quotes and backslashes removed), up to its terminator: an unquoted pipe,
    semicolon, ampersand (not the one of a redirection) or unmatched closing parenthesis, a newline, or a quote that
    has no partner (the closing quote of an enclosing sh -c string)."""
    words: List[str] = []
    cur: List[str] = []
    started = False
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = text.find(c, i + 1)
            if j < 0:
                break
            piece = text[i + 1:j]
            cur.append(piece.replace("\\" + c, c) if c == '"' else piece)
            started = True
            i = j + 1
            continue
        if c == "\\" and i + 1 < n:
            if text[i + 1] != "\n":
                cur.append(text[i + 1])
                started = True
            i += 2
            continue
        if c == "$" and text[i + 1:i + 2] == "(":
            depth += 1
            cur.append("$(")
            started = True
            i += 2
            continue
        if c == ")":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and (c in "|;\n" or (c == "&" and not (cur and cur[-1][-1:] in "<>") and text[i + 1:i + 2] != ">")):
            break
        if c.isspace() and depth == 0:
            if started:
                words.append("".join(cur))
                cur, started = [], False
            i += 1
            continue
        cur.append(c)
        started = True
        i += 1
    if started:
        words.append("".join(cur))
    return words


def _my_words_hit(words: Sequence[str]) -> bool:
    """True when a word of one command carries an expansion that the closed world does not clear (see above)."""
    expect = ""
    options_done = False
    after_password_word = False
    skip_next = False
    for w in words:
        if skip_next:
            skip_next = False
            continue
        if _MY_REDIRECT_RE.match(w):
            skip_next = True
            continue
        if _MY_REDIRECT_ATTACHED_RE.match(w):
            continue
        dashed = w.startswith("-") and len(w) > 1 and not options_done
        if expect and not dashed:
            if expect == "unknown" and _my_has_exp(w):
                return True
            expect = ""
            continue
        expect = ""
        if not dashed:
            if _my_has_exp(w) and (after_password_word or (not options_done and w[:1] in "$`")):
                return True
            after_password_word = not _my_has_exp(w) and bool(w) and ("password".startswith(w.lower())
                                                                     or "old-password".startswith(w.lower()))
            continue
        after_password_word = False
        if w == "--":
            options_done = True
        elif w.startswith("--"):
            name, eq, value = w[2:].partition("=")
            if _my_has_exp(name):
                return True
            kind = _my_long_kind(name)
            if eq:
                if kind != "value" and _my_has_exp(value):
                    return True
            elif kind != "flag":
                expect = "safe" if kind == "value" else "unknown"
        else:
            letters = w[1:]
            for idx, ch in enumerate(letters):
                rest = letters[idx + 1:]
                if _my_has_exp(ch):
                    return True
                if ch in _MY_NOARG_SHORT:
                    continue
                if ch in _MY_VALUE_SHORT:
                    expect = "" if rest else "safe"
                elif ch == "p":
                    if _my_has_exp(rest):
                        return True
                elif _my_has_exp(rest):
                    return True
                else:
                    expect = "" if rest else "unknown"
                break
    return False


def _my_head_command(text: str, start: int, directory: str) -> bool:
    """Whether the head matched at text[start:] is a command word: not a word of an echo string, not a package or
    path operand. One rule for every head (#5820): it is a command unless a word before it in its command is a
    verb of _MY_NONCMD_PREV. Its command starts after the last pipe, semicolon, ampersand or parenthesis; for a
    head inside a quote that is the quote's own text when the quote opens a command substitution, and otherwise
    the command around the quote followed by the quote's text, so a wrapper inside a payload (sudo, exec,
    timeout, an assignment) is read like the same wrapper outside it. The first word of a quote is a command."""
    if directory and not _MY_BIN_DIR_RE.search(directory):
        return False
    quote = ""
    opener = -1
    for k in range(start):
        c = text[k]
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote, opener = c, k
    if quote:
        inner = text[opener + 1:start]
        tail = re.split(r"[|;&(`]", inner)[-1]
        if not tail.strip():
            return True
        before = tail if "(" in inner or "`" in inner else re.split(r"[|;&(]", text[:opener])[-1] + " " + tail
    else:
        before = re.split(r"[|;&(]", text[:start])[-1]
    words = before.replace("\"", " ").replace("'", " ").split()
    return not any(w.lower() in _MY_NONCMD_PREV for w in words)


def _my_substitutions(text: str, pos: int) -> List[Tuple[int, int]]:
    """(index of the dollar sign, index of the closing parenthesis or -1) of every $( ... ) around text[pos],
    innermost first. Quotes are transparent (a quoted sh -c payload runs its substitutions); an escaped character
    is skipped, except before a dollar sign, because an escaped \\$( in an ssh or sh -c payload runs on the far side;
    a plain parenthesis nests (#5821)."""
    stack: List[Tuple[int, bool]] = []
    i = 0
    while i < pos:
        c = text[i]
        if c == "\\":
            i += 1 if text[i + 1:i + 2] == "$" else 2
            continue
        if c == "$" and text[i + 1:i + 2] == "(":
            stack.append((i, True))
            i += 2
            continue
        elif c == "(":
            stack.append((i, False))
        elif c == ")" and stack:
            stack.pop()
        i += 1
    out: List[Tuple[int, int]] = []
    depth = 0
    k = pos
    opened = [o for o, sub in stack]
    subs = {o for o, sub in stack if sub}
    while opened and k < len(text):
        c = text[k]
        if c == "(":
            depth += 1
        elif c == ")":
            if depth:
                depth -= 1
            else:
                o = opened.pop()
                if o in subs:
                    out.append((o, k))
        k += 1
    out.extend((o, -1) for o in reversed(opened) if o in subs)
    return out


def _my_substitution_hit(raw: str, pos: int) -> bool:
    """A head inside a command substitution that is itself the command word (#5821): $(command -v mysql),
    "$(which mysqldump)". The substitution prints the command, so the words after it are the client's words and
    are read as such. A substitution glued to a word before it (v=$(mysql ...), x$(...)) is no command word."""
    for opener, close in _my_substitutions(raw, pos):
        if close < 0:
            continue
        word = opener - 1 if opener > 0 and raw[opener - 1] in "\"'\\" else opener
        if word > 0 and not (raw[word - 1].isspace() or raw[word - 1] in "|;&(`"):
            continue
        if not _my_head_command(raw, word, ""):
            continue
        rest = raw[close + 1:]
        if word != opener and rest[:1] == raw[word]:
            rest = rest[1:]
        if _my_words_hit(_my_words(rest)):
            return True
    return False


def mysql_family_hit(raw: str) -> bool:
    """True when a mysql family command of one logical line carries a credential the gate cannot clear."""
    for m in _MY_HEAD_RE.finditer(raw):
        if re.fullmatch(r"[A-Z0-9_]+", m.group("name")):
            continue  # MYSQL_ROOT_PASSWORD, MYSQL_HOST: an environment variable name, not a command
        if not _my_head_command(raw, m.start(), m.group("dir")):
            continue
        rest = raw[m.end():]
        if m.start() > 0 and rest[:1] in ("\"", "'") and raw[m.start() - 1] == rest[:1]:
            rest = rest[1:]  # the head was quoted on its own: "/usr/bin/mysql" --password="$X"
        if _my_words_hit(_my_words(rest)) or _my_substitution_hit(raw, m.start()):
            return True
    return False


# A credential-taking flag of a known tool fed from any expansion: the value is on argv
# whatever the variable is called, so such a line is never allow-able (pending + issue only).
CRED_TOOL_RE = re.compile(
    r"\bsshpass\s+-p\s*[\"']?(?:\$|`)"
    r"|\bredis-cli\b[^|;&]*\s(?:-a|--pass(?![\w-]))[\s=]*[\"']?(?:\$|`)"
    # one shell word after the flag that expands a variable, however its user part is quoted:
    # u:$X, "u:$X", u:"$X", 'u':"$X", "u":"$X" (#5101). A short flag may close a group of
    # combined short flags (-su, -fsSU) (#4993); a long flag is matched whole (not --user-agent).
    # wget has no short credential flag (its -U is the user agent).
    r"|\b(?:curl\b[^|;&]*\s-[A-Za-z]*[uU]|(?:curl|wget)\b[^|;&]*\s(?:--(?:proxy-|http-|ftp-)?"
    r"(?:user|password|pass)|--(?:proxy-)?tlspassword|--oauth2-bearer)(?![\w-]))[\s=]*"
    r"(?:\$'[^']*'|[^\s\"'$]|\"[^\"$]*\"|'[^']*')*(?:\"[^\"$]*)?(?:\$(?!')|`)"
    # curl -E/--cert <file>:<password>: a variable after the colon is the key password; a
    # variable that names the file alone is not (#4891 round 3)
    r"|\bcurl\b[^|;&]*\s(?:-[A-Za-z]*E|--(?:proxy-)?cert(?![\w-]))[\s=]*"
    r"(?:[^\s\"':]|\"[^\":]*\"|'[^':]*')*(?:[\"'][^\"':]*)?:"
    r"(?:[^\s\"'$]|\"[^\"$]*\"|'[^']*')*(?:[\"'][^\"'$]*)?(?:\$|`)"
    # --password-stdin is the safe form and is not matched (#4994)
    r"|\b(?:docker|podman)\s+login\b[^|;&]*\s(?:-p|--password)(?![\w-])"
    # a credential header in any letter case (#4997), after a combined short flag or --header=
    # (#4993), whose value expands a variable inside or after its quotes (#4891 round 3); a backslash
    # before a quote is the ssh, sh -c and CMD-SHELL payload shape (#5294); a command substitution
    # or an ANSI-C quote in a value is one word (#5304)
    r"|(?:(?<![\w-])-[A-Za-z]*H|--(?:proxy-)?header)[\s=]*\\?\$?[\"']?"
    r"(?i:(?:x-)?api-key|authorization|proxy-authorization|x-auth-token)\s*:"
    r"[^\"'$]*(?:[\"'](?:[^\s\"'$]|\"[^\"$]*\"|'[^']*')*(?:\"[^\"$]*)?)?(?:\$|`)")


# wget -e/--execute runs a wgetrc command; getopt takes any unique prefix of the long name, so --exe
# .. --execute all run it (--ex is ambiguous and wget refuses it). wgetrc ignores case, dashes and underscores in a
# command name and allows spaces around "=", so the name is folded and read, not matched (#5293).
WGET_CMD_RE = re.compile(r"\bwget\b[^|;&]*")
WGET_EXEC_OPT_RE = re.compile(r"(?:(?<![\w-])-[A-Za-z]*e|--exe(?:c(?:u(?:te?)?)?)?(?![\w-]))[\s=]*")
WGETRC_PASSWORD_RE = re.compile(r"(?:https?|ftp|proxy)?passw(?:or)?d")


def _shell_word(text: str, pos: int) -> str:
    """The shell word starting at pos, with quotes and backslashes removed. A backslash before a
    quote (an ssh or sh -c payload) is read as that quote."""
    out: List[str] = []
    quote = ""
    i = pos
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt in "\"'":
                ch, i = nxt, i + 1
            else:
                out.append(nxt)
                i += 2
                continue
        if quote:
            if ch == quote:
                quote = ""
            else:
                out.append(ch)
        elif ch in "\"'":
            quote = ch
        elif ch.isspace() or ch in ";|&":
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def wgetrc_credential(raw: str) -> bool:
    """True when a wget -e/--execute value sets a password, or names a setting the gate cannot
    resolve (an expansion in the name): unresolved means flagged (#4869, #5293)."""
    for cmd in WGET_CMD_RE.finditer(raw):
        # every -e and --execute option of the command, not only the first (#5682)
        for m in WGET_EXEC_OPT_RE.finditer(raw, cmd.start(), cmd.end()):
            name = _shell_word(raw, m.end()).split("=", 1)[0]
            if "$" in name or "`" in name:
                return True
            if WGETRC_PASSWORD_RE.fullmatch(re.sub(r"[-_\s]", "", name).lower()):
                return True
    return False


def _wget_password_options() -> str:
    """Every prefix (two letters or more) of the wget long password options and their http, https,
    ftp and proxy forms, as one regex alternation: getopt takes any unique prefix (#5300)."""
    names = set()
    for pre in ("", "http-", "https-", "ftp-", "proxy-"):
        for tail in ("password", "passwd"):
            full = pre + tail
            for n in range(2, len(full) + 1):
                names.add(full[:n])
    return "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))


WGET_PW_LONG_RE = re.compile(
    r"\bwget\b[^|;&]*\s--(?:" + _wget_password_options() + r")(?![\w-])[\s=]*"
    r"(?:[^\s\"'$]|\"[^\"$]*\"|'[^']*')*(?:\"[^\"$]*)?(?:\$|`)")


def scan_exec_file(dl, rel: str, text: str) -> Optional[List[Found]]:
    """Triggered logical lines of one executable file, or None when it is not one."""
    if rel in SELF_EXEMPT:
        return None
    units = exec_units(rel, text)
    if units is None:
        return None
    deny = deny_lines(dl, rel, text)
    found: List[Found] = []
    is_make = file_class(rel, text[:200]) == "make"
    for start, end, raw in units:
        reasons = trigger_reasons(raw, is_make)
        flagged = [deny[k] for k in range(start, end + 1) if k in deny]
        if flagged or CRED_TOOL_RE.search(raw) or mysql_family_hit(raw) or WGET_PW_LONG_RE.search(raw) or wgetrc_credential(raw):
            reasons.append("denylist")
        if reasons:
            found.append((start, norm(raw), reasons))
    return found


# ---------------------------------------------------------------- mode 2 scan
FENCE_LANGS = {"", "bash", "sh", "shell", "console", "zsh", "shell-session", "sh-session", "terminal",
               "dockerfile", "docker", "yaml", "yml", "ini", "systemd", "text", "bash-session", "ps1",
               "powershell", "cmd", "make", "makefile"}
SECRET_HEADER_RE = re.compile(
    r"^\s*(?:(?:x-)?api[-_]?key|authorization|proxy-authorization|x-auth[\w-]*|[\w-]*(?:token|secret)[\w-]*)\s*:", re.I)
PATHISH_RE = re.compile(r"^(?:/|\./|\.\./|~|\$\{?\w*(?:DIR|PATH|HOME|FILE)\b)|\.(?:pem|key|crt|cert|p12|pub|json|txt|env|pw)$")
LOCATOR_FLAG_RE = re.compile(r"(?:file|path|dir|stdin|id|env)$", re.I)


def md_blocks(text: str) -> List[Unit]:
    out: List[Unit] = []
    lines = text.split("\n")
    in_f, fence, lang, buf = False, "", "", []  # type: bool, str, str, List[Tuple[int, str]]
    for n, raw in enumerate(lines, 1):
        m = re.match(r"^\s*(`{3,}|~{3,})\s*([\w+-]*)", raw)
        if not in_f and m:
            in_f, fence, lang, buf = True, m.group(1)[:3], m.group(2).lower(), []
            continue
        if in_f and raw.strip().startswith(fence):
            if lang in FENCE_LANGS:
                out.extend(join_logical(buf))
            in_f = False
            continue
        if in_f:
            buf.append((n, raw))
    return out


def html_blocks(text: str) -> List[Unit]:
    import html as _html
    out: List[Unit] = []
    in_p, buf = False, []  # type: bool, List[Tuple[int, str]]
    for n, raw in enumerate(text.split("\n"), 1):
        r = raw
        if not in_p and "<pre" in r:
            in_p, buf = True, []
            r = re.sub(r".*?<pre[^>]*>", "", r, count=1)
        if in_p:
            end = "</pre>" in r
            body = _html.unescape(re.sub(r"<[^>]+>", "", r.split("</pre>")[0]))
            buf.append((n, body))
            if end:
                out.extend(join_logical(buf))
                in_p = False
    return out


def prose_units(rel: str, text: str) -> Optional[List[Unit]]:
    low = rel.lower()
    if low.endswith(".md"):
        units = md_blocks(text)
    elif low.endswith((".html", ".htm")):
        units = html_blocks(text)
    else:
        return None
    return [(a, b, re.sub(r"^\s*(?:\$|#|>)\s+", "", t)) for a, b, t in units
            if t.strip() and not t.strip().startswith("#")]


def _flatten(cmd: List[str], dl, depth: int = 0) -> Iterable[List[str]]:
    yield cmd
    if depth < 3:
        for w in cmd[1:]:
            if any(c.isspace() for c in w):
                for inner in dl.commands(dl.split_words(w)):
                    for sub in _flatten(inner, dl, depth + 1):
                        yield sub


def _url_is_value(v: str) -> bool:
    """A --store-url value matters when it is a connection URL (scheme://...) or a variable
    expansion: the docs then teach the argv form of a DSN that can embed a password (#4890). The
    flag named with no value, or followed by a bare word, is prose."""
    return bool(re.search(r"://|\$\{?\w", v))


NUMERIC_LIMIT_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_TOKENS=\d+\b")


def prose_rule_hits(dl, line: str) -> List[str]:
    """Rules beyond the imported denylist, applied to one prose logical line."""
    reasons: List[str] = []
    for top in dl.commands(dl.split_words(line)):
        for cmd in _flatten(top, dl):
            words = [w for w in cmd]
            while words and re.match(r"^[A-Za-z_]\w*=", words[0]):
                words = words[1:]
            if not words:
                continue
            head = os.path.basename(words[0])
            rest = words[1:]
            if head == "curl":
                for k, w in enumerate(rest):
                    val = None
                    if w in ("-H", "--header") and k + 1 < len(rest):
                        val = rest[k + 1]
                    elif w.startswith("--header="):
                        val = w[len("--header="):]
                    elif w.startswith("-H") and len(w) > 2:
                        val = w[2:]
                    if val is not None and not val.startswith("@") and SECRET_HEADER_RE.match(val):
                        reasons.append("curl-secret-header")
                    uval = None
                    if w in ("-u", "--user") and k + 1 < len(rest):
                        uval = rest[k + 1]
                    elif w.startswith("--user="):
                        uval = w[len("--user="):]
                    if uval is not None and ":" in uval and uval.split(":", 1)[1].strip():
                        reasons.append("curl-user-password")
            if head == "openssl":
                for k, w in enumerate(rest):
                    if w == "-hmac" and k + 1 < len(rest) and not rest[k + 1].startswith("@"):
                        reasons.append("openssl-hmac-key")
            for k, w in enumerate(rest):
                m = re.match(r"^(?:-e|--env)(?:=|$)(.*)$", w)
                if head in ("docker", "podman", "nerdctl") and m:
                    val = m.group(1) or (rest[k + 1] if k + 1 < len(rest) else "")
                    nm, eq, v = val.partition("=")
                    if eq and secret_name(nm) and "$" in v:
                        reasons.append("container-env-secret-expansion")
                fm = re.match(r"^--([A-Za-z][\w-]*)(?:=(.*))?$", w)
                if fm and secret_name(fm.group(1)) and not LOCATOR_FLAG_RE.search(fm.group(1)) \
                        and not (re.fullmatch(r"store[-_]url", fm.group(1), re.I) and not _url_is_value(
                            fm.group(2) if fm.group(2) is not None else (rest[k + 1] if k + 1 < len(rest) else ""))) \
                        and not re.search(r"(?:^|-)(?:tokens|budget|key|tls)(?:-|$)", fm.group(1)):
                    v = fm.group(2) if fm.group(2) is not None else (rest[k + 1] if k + 1 < len(rest) else "")
                    if v and not v.startswith("-") and not v.isdigit() and not PATHISH_RE.search(v):
                        reasons.append("secret-flag-inline-value")
    return reasons


def scan_prose_file(dl, rel: str, text: str) -> Optional[List[Found]]:
    units = prose_units(rel, text)
    if units is None or rel in SELF_EXEMPT:
        return None
    found: List[Found] = []
    for start, end, raw in units:
        reasons = prose_rule_hits(dl, raw)
        # NAME_TOKENS=<int> is a model token limit, not a credential (#4911)
        if dl.scan_text("fence.sh", NUMERIC_LIMIT_RE.sub("NUMERIC_LIMIT=0", raw)):
            reasons.append("denylist")
        if reasons:
            found.append((start, norm(raw), sorted(set(reasons))))
    return found


# ---------------------------------------------------------------- list files
WHY_RE = re.compile(r"^(?:#\d+|reason: \S[^|]*)$")
PEND_WHY_RE = re.compile(r"^#\d+$")


def parse_entries(text: str, label: str, pending: bool, faults: List[str]) -> List[Entry]:
    out: List[Entry] = []
    seen = set()
    for no, raw in enumerate(text.split("\n"), 1):
        if not raw.strip() or (raw.startswith("#") and not re.match(r"#\d+ \| ", raw)):
            continue
        parts = raw.split(" | ", 3)
        if len(parts) != 4:
            faults.append("%s:%d: malformed entry (want '<why> | <file> | <count> | <line>')" % (label, no))
            continue
        why, rel, cnt, line = parts
        if not (PEND_WHY_RE if pending else WHY_RE).match(why):
            faults.append("%s:%d: bad why %r (want %s)" % (label, no, why[:40],
                          "#<issue>" if pending else "#<issue> or 'reason: <text>'"))
            continue
        if not cnt.isdigit() or int(cnt) < 1:
            faults.append("%s:%d: count %r is not a positive integer" % (label, no, cnt))
            continue
        if line != norm(line) or not line:
            faults.append("%s:%d: line is not whitespace-normalised" % (label, no))
            continue
        if (rel, line) in seen:
            faults.append("%s:%d: duplicate entry for %s" % (label, no, rel))
            continue
        seen.add((rel, line))
        out.append((why, rel, int(cnt), line, no))
    return out


# Every Unicode line terminator but LF (str.splitlines): a list file uses LF only (#5501).
LINE_TERMINATORS = "\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"
TERMINATOR_RE = re.compile("[" + LINE_TERMINATORS + "]")
ISSUE_WHY_RE = re.compile(r"#[0-9]+")


def terminator_faults(text: str, label: str) -> List[str]:
    """A list at the tip carries LF line ends only. A CR (or any other terminator) is read as a line end
    by some readers and as part of the row by others, so the rule rows would differ between them (#5501)."""
    hit = TERMINATOR_RE.search(text)
    if hit is None:
        return []
    return ["%s: line terminator U+%04X in the list (LF only; fail closed, #5501)" % (label, ord(hit.group()))]


def read_list_text(path: Path) -> str:
    """The text of a list file, decoded with no newline translation: a CR stays visible (#5501)."""
    return path.read_bytes().decode("utf-8")


def diff_rows(body: str) -> List[Tuple[str, str]]:
    """(whole row, text) of every pending-shaped row in the body of one diff line. A line terminator or
    blank form of a row is read as the row, and a row behind a terminator inside one line is a row too
    (over-collecting fails closed, #5501)."""
    out: List[Tuple[str, str]] = []
    for frag in TERMINATOR_RE.split(body):
        parts = [norm(p) for p in frag.split("|", 3)]
        if len(parts) == 4 and ISSUE_WHY_RE.fullmatch(parts[0]) and parts[3]:
            out.append((" | ".join(parts), parts[3]))
    return out


def parse_git_list(text: str, label: str, pending: bool) -> List[Entry]:
    """Parse a list read from git (the merge base, HEAD). Every line-terminator and blank form of a row is
    read as the row, so a row cannot be hidden from a rule by its line ending; a row that still does not
    parse is a RuntimeError, never a silent skip (#5501)."""
    lines: List[str] = []
    for ln in text.splitlines():
        ln = ln.strip()
        if ln and not (ln.startswith("#") and not re.match(r"#[0-9]+\s*[|]", ln)):
            cols = re.split(r"\s*[|]\s*", ln, 3)
            if len(cols) == 4:
                cols[3] = norm(cols[3])
                ln = " | ".join(cols)
        lines.append(ln)
    faults: List[str] = []
    out = parse_entries("\n".join(lines) + "\n", label, pending, faults)
    if faults:
        raise RuntimeError("the %s list read from git is malformed (fail closed, #5501): %s" % (label, faults[0]))
    return out


# ---------------------------------------------------------------- judge
def judge(found: Dict[str, List[Found]], allow: List[Entry], pending: List[Entry], dl,
          only: Optional[Iterable[str]] = None) -> Tuple[List[str], List[str], Dict[str, int]]:
    """Compare found lines with the lists. Returns (hits, pending report, stats).
    ``only`` limits the stale check to those files (used by the self-test)."""
    hits: List[str] = []
    report: List[str] = []
    scope = set(only) if only is not None else None
    allow_map = {(e[1], e[3]): e for e in allow}
    pend_map = {(e[1], e[3]): e for e in pending}
    for key in set(allow_map) & set(pend_map):
        hits.append("%s: line is both allowed and pending: %s" % (key[0], key[1][:100]))
    stats = {"triggered": 0, "pending": 0}
    keys = set()
    for rel, lines in sorted(found.items()):
        prose = rel.lower().endswith((".md", ".html", ".htm"))
        by_text: "OrderedDict[str, List[Found]]" = OrderedDict()
        for ln in lines:
            by_text.setdefault(ln[1], []).append(ln)
        for text, occ in by_text.items():
            key = (rel, text)
            keys.add(key)
            stats["triggered"] += len(occ)
            a = allow_map.get(key)
            p = pend_map.get(key)
            if prose and a is not None:
                hits.append("%s: prose line cannot be allowed, only pending: %s" % (rel, text[:100]))
            have = (a[2] if a and not prose else 0) + (p[2] if p else 0)
            if len(occ) > have:
                for ln in occ[have:]:
                    hits.append("%s:%d: %s: %s | %s" % (
                        rel, ln[0],
                        "prose line puts a credential on an argv and is not pending" if prose
                        else "line not in the allowlist",
                        ",".join(ln[2][:3]), dl.redact(text)[:160]))
            elif len(occ) < have:
                pass  # reported as stale below
            if p:
                stats["pending"] += min(len(occ), p[2])
                for ln in occ[:p[2]]:
                    report.append("PENDING %s %s:%d" % (p[0], rel, ln[0]))
    for key, e in list(allow_map.items()) + list(pend_map.items()):
        rel, text = key
        if scope is not None and rel not in scope:
            continue
        occ = len(by_key(found, rel, text))
        a = allow_map.get(key)
        p = pend_map.get(key)
        prose = rel.lower().endswith((".md", ".html", ".htm"))
        have = (a[2] if a and not prose else 0) + (p[2] if p else 0)
        if occ < have:
            hits.append("%s:%d: stale %s entry (file has %d of %d): %s" % (
                "pending" if e in pending else "allow", e[4], "pending" if e in pending else "allow",
                occ, have, text[:80]))
    return hits, sorted(set(report), key=report.index), stats


def by_key(found: Dict[str, List[Found]], rel: str, text: str) -> List[Found]:
    return [ln for ln in found.get(rel, []) if ln[1] == text]


# ---------------------------------------------------------------- repo walk
def tracked_files(root: Path) -> List[str]:
    out = _git_raw(root, "ls-files", "-z")
    files = [f for f in out.decode("utf-8", "replace").split("\0") if f]
    if not files:
        raise RuntimeError("git ls-files returned no files; refusing to pass on an empty scan")
    return files


def tracked_exec_bit(root: Path) -> List[str]:
    """Tracked files carrying the executable bit (git mode 100755)."""
    out = _git_raw(root, "ls-files", "-s", "-z").decode("utf-8", "replace")
    res = []
    for rec in out.split("\0"):
        if rec.startswith("100755 ") and "\t" in rec:
            res.append(rec.split("\t", 1)[1])
    return res


# Executable-bit files the gate has read and found to run no command line of their own.
EXEC_BIT_OK: set = set()


def read_tracked(root: Path, rel: str) -> Optional[str]:
    """Text of one tracked file, or None when it is not a regular file (a directory or
    submodule entry). Anything that cannot be scanned is an error, never a silent skip (#4909):
    a symlink must resolve inside the tree, an exec or prose file may not exceed MAX_BYTES, and
    undecodable bytes are read with replacement so every line is still scanned."""
    p = root / rel
    low = rel.lower()
    if p.is_symlink():
        tgt = p.resolve()
        if root.resolve() not in tgt.parents or not tgt.is_file():
            raise RuntimeError("tracked symlink %s points outside the tree or at no file (fail closed)" % rel)
        p = tgt
    if not p.is_file():
        return None
    raw = p.read_bytes() if p.stat().st_size <= MAX_BYTES else None
    if raw is None:
        head = p.open("rb").read(200).decode("utf-8", errors="replace")
        if low.endswith((".md", ".html", ".htm")) or file_class(rel, head) is not None:
            raise RuntimeError("%s is over %d bytes and was not scanned (fail closed)" % (rel, MAX_BYTES))
        return None
    return raw.decode("utf-8", errors="replace")


def scan_repo(root: Path, dl) -> Tuple[Dict[str, List[Found]], int, int]:
    """(found lines by file, exec files scanned, prose files scanned)."""
    found: Dict[str, List[Found]] = {}
    n_exec = n_prose = 0
    exec_bit = set(tracked_exec_bit(root))
    unclassified: List[str] = []
    for rel in tracked_files(root):
        text = read_tracked(root, rel)
        if text is None:
            continue
        if rel.lower().endswith((".md", ".html", ".htm")):
            res = scan_prose_file(dl, rel, text)
            if res is not None:
                n_prose += 1
        else:
            res = scan_exec_file(dl, rel, text)
            if res is not None:
                n_exec += 1
        if res is None and rel in exec_bit and rel not in EXEC_BIT_OK and rel not in SELF_EXEMPT:
            unclassified.append(rel)
        if res:
            found[rel] = res
    if unclassified:
        raise RuntimeError("executable file(s) with no scan class (fail closed, #4923): " +
                           ", ".join(unclassified[:10]))
    return found, n_exec, n_prose


def load_lists(root: Path) -> Tuple[List[Entry], List[Entry], List[str]]:
    faults: List[str] = []
    allow_text = read_list_text(root / ALLOW_FILE)
    pend_text = read_list_text(root / PENDING_FILE)
    faults.extend(terminator_faults(allow_text, "allow"))
    faults.extend(terminator_faults(pend_text, "pending"))
    allow = parse_entries(allow_text, "allow", False, faults)
    pend = parse_entries(pend_text, "pending", True, faults)
    return allow, pend, faults


def check_allow_vs_denylist(found: Dict[str, List[Found]], allow: List[Entry]) -> List[str]:
    """An allow entry may not approve a line the imported denylist rules flag."""
    bad = []
    flagged = {(rel, ln[1]) for rel, lines in found.items() for ln in lines if "denylist" in ln[2]}
    for e in allow:
        if (e[1], e[3]) in flagged:
            bad.append("allow:%d: entry approves a line the denylist rules flag: %s" % (e[4], e[3][:80]))
    return bad


# The ONE funnel of every git read of the gate (#5581). Closed world: the child gets a short allowlist of the
# parent's environment, so no GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, GIT_OBJECT_DIRECTORY,
# GIT_ALTERNATE_OBJECT_DIRECTORIES, GIT_REPLACE_REF_BASE, GIT_SHALLOW_FILE, GIT_CONFIG_COUNT/KEY_n/VALUE_n or
# GIT_CONFIG_PARAMETERS of the caller reaches it, and the entries below are set by the gate itself.
GIT_ENV_KEEP = ("PATH", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP")
_GIT_PROVEN: set = set()
# the signature verifier programs a repo-local config can name (#5822)
GIT_VERIFIER_KEYS = ("gpg.program", "gpg.openpgp.program", "gpg.x509.program", "gpg.ssh.program")


def _git_child_env() -> Dict[str, str]:
    """The environment of every git child: the allowlist plus the gate's own settings (#5581, #5503). An empty
    GIT_ALLOW_PROTOCOL allows no transport, so a partial clone cannot fetch a missing object through a
    repo-configured program (remote.<name>.uploadpack, core.sshCommand): the read faults closed (#5823)."""
    env = {k: os.environ[k] for k in GIT_ENV_KEEP if k in os.environ}
    env.update({"GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": os.devnull, "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_ALLOW_PROTOCOL": ""})
    return env


def _git_exec(root: Path, args: Sequence[str]) -> "subprocess.CompletedProcess[bytes]":
    """The only subprocess call of git in the gate (the self-test checks this by reading this file)."""
    # repo-local config that runs a command is pinned off for every read (#5633): core.fsmonitor runs its value
    # from ls-files and status, core.hooksPath would point git at hooks; log.showSignature would make every log
    # read run the signature verifier of each signed commit, so it is off and every verifier program (gpg,
    # openpgp, x509, ssh) is the null device as well (#5822); the history log and the blob reads also
    # pass --no-ext-diff and --no-textconv themselves
    argv =["git", "-C", str(root), "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
            "-c", "log.showSignature=false"]
    for key in GIT_VERIFIER_KEYS:
        argv += ["-c", key + "=" + os.devnull]
    return subprocess.run(argv + list(args), check=True, capture_output=True, env=_git_child_env())


def _git_prove(root: Path) -> None:
    """Prove once per repository that no global or system config is in reach of the funnel; git that cannot
    show config scopes, or a scope that is still reachable, is a FAULT, not a hope (#5581)."""
    key = str(root)
    if key in _GIT_PROVEN:
        return
    try:
        rows = _git_exec(root, ["config", "--list", "--show-scope"]).stdout.decode("utf-8", "replace")
    except (subprocess.CalledProcessError, OSError) as exc:
        raise RuntimeError("cannot prove the git reads are isolated from global config (%s): %s"
                           % (str(exc)[:100], HISTORY_REMEDY))
    leaks = sorted({ln.split("\t", 1)[0] for ln in rows.split("\n") if ln.split("\t", 1)[0] in ("system", "global")})
    if leaks:
        raise RuntimeError("git reads are not isolated: %s config is in reach of the gate (fail closed)"
                           % "/".join(leaks))
    _GIT_PROVEN.add(key)


def _git_raw(root: Path, *args: str) -> bytes:
    """git stdout as bytes, through the funnel."""
    _git_prove(root)
    return _git_exec(root, args).stdout


def _git(root: Path, *args: str) -> str:
    return _git_raw(root, *args).decode("utf-8", "replace")


def allow_from_pending(allow: List[Entry], base_pending: List[Entry], renames: Dict[str, str]) -> List[str]:
    """#4919: an allow entry may not approve a (file, line) that was PENDING at the merge base.
    A code fix changes the line text and so the key; an edit elsewhere in the file does not make
    the same line safe (#4996). A renamed file keeps its pending lines under the new path."""
    base = {(renames.get(e[1], e[1]), e[3]) for e in base_pending}
    return ["allow:%d: entry approves a line that was pending at the merge base (change the line, "
            "not the list): %s: %s" % (e[4], e[1], e[3][:80]) for e in allow if (e[1], e[3]) in base]


# A new allow entry this close to a pending line that left the pending list in the same change
# is that line with a cosmetic edit, not a fix: it stays pending (#4891 round-2 security).
EDITED_PENDING_RATIO = 0.8


def allow_like_vanished_pending(allow: List[Entry], base_allow: List[Entry], base_pending: List[Entry],
                                head_pending: List[Entry]) -> List[str]:
    """An allow entry that is new since the merge base may not approve a line, or a lightly edited
    copy of a line, that was pending at the merge base and is no longer pending (any file, so a
    rename is covered; an edit elsewhere in the file does not exempt it).
    A real fix that takes the secret off the argv is no longer triggered and needs no entry; a
    fixed line that is still triggered stays pending until its issue closes."""
    # Counted by text, not keyed by (file, text): a renamed file keeps its counts unchanged, and a
    # line pending in several files still counts as gone when one of its rows leaves the list.
    old_allow = Counter(e[3] for e in base_allow)
    still = Counter(e[3] for e in head_pending)
    gone = []
    for e in base_pending:
        if still[e[3]] > 0:
            still[e[3]] -= 1
        else:
            gone.append(e)
    out: List[str] = []
    for e in allow:
        if old_allow[e[3]] > 0:
            old_allow[e[3]] -= 1
            continue
        for v in gone:
            if difflib.SequenceMatcher(None, e[3], v[3], autojunk=False).ratio() >= EDITED_PENDING_RATIO:
                out.append("allow:%d: new entry approves an edited copy of a line that was pending at the merge "
                           "base (%s %s); keep it pending: %s" % (e[4], v[0], v[1], e[3][:80]))
                break
    return out


def _show_or_absent(root: Path, mb: str, path: str) -> str:
    """The text of path at the merge base. Empty only when the base proves the path does not exist
    there; a git failure of any kind (corrupt or missing object, partial clone, permission) is an
    error, never an empty list: unresolved means red (#5297)."""
    spec = "%s:%s" % (mb, path)
    try:
        return _git(root, "show", "--no-textconv", spec)
    except subprocess.CalledProcessError:
        pass
    # show failed: it is "absent" only if the base tree has no such path (a failing ls-tree raises)
    if _git(root, "ls-tree", "--name-only", mb, "--", path).strip():
        raise RuntimeError("cannot read %s although the merge base lists it (fail closed)" % spec)
    return ""


def allow_text_pending_elsewhere(allow: List[Entry], base_allow: List[Entry], base_pending: List[Entry],
                                 head_pending: List[Entry], renames: Dict[str, str]) -> List[str]:
    """An allow entry that is new or changed since the merge base may not approve a line whose text
    is pending in ANY file, at the base or at head. A line copied into a file that allows it, then
    moved there, would otherwise be approved in two green steps (#5295). The regen tool refuses the
    same across files; an entry that is unchanged since the base is not judged again."""
    old = {(renames.get(e[1], e[1]), e[3], e[2]) for e in base_allow}
    pending = {e[3] for e in base_pending} | {e[3] for e in head_pending}
    return ["allow:%d: new entry approves a line whose text is pending in a file (change the line, not "
            "the list): %s: %s" % (e[4], e[1], e[3][:80])
            for e in allow if (e[1], e[3], e[2]) not in old and e[3] in pending]


def in_ci() -> bool:
    """True on a CI runner (GitHub Actions sets both variables)."""
    return (os.environ.get("GITHUB_ACTIONS", "").strip().lower() == "true"
            or os.environ.get("CI", "").strip().lower() in ("true", "1"))


def allow_added_in_pending_file(allow: List[Entry], base_allow: List[Entry], base_pending: List[Entry],
                                renames: Dict[str, str]) -> List[str]:
    """#5298 (5-agent vote 4d3ea1c5, decision B): no allow entry may be added or raised in a file that
    had a pending row at the merge base. A respelling of a pending line that stays under the
    similarity floor is approved by no spelling rule, so the refusal is keyed on the file: while a file
    holds a pending row, new approvals there come only from #4929 Part 1 (values, not spellings).
    An entry that is unchanged or lowered is not an approval and is not judged. The pending row may be
    removed in the same change: the freeze reads the base, not the head."""
    frozen = {renames.get(e[1], e[1]) for e in base_pending}
    had = {(renames.get(e[1], e[1]), e[3]): e[2] for e in base_allow}
    return ["allow:%d: the file had a pending row at the merge base, so no allow entry may be added or "
            "raised in it (#5298; fix the line or keep it pending): %s: %s" % (e[4], e[1], e[3][:80])
            for e in allow if e[1] in frozen and e[2] > had.get((e[1], e[3]), 0)]


HISTORY_REMEDY = ("fetch full history (git fetch --unshallow, or actions/checkout with fetch-depth: 0) "
                  "and run the gate again (#5299)")


# A pending row is "#<issue> | <file> | <count> | <text>". The history scan matches that shape in every file
# at every path (#5299, #5466): the list may have been renamed and rewritten in one commit, where a log
# limited to the path of the list goes blind to the old path. The pickaxe is not anchored to the start of the
# line and allows blanks before the bar: a row behind a CR inside one line, or with blanks, is a row (#5501).
PENDING_ROW_PICKAXE = r"#[0-9]+[[:space:]]*[|]"


def removed_pending_rows(root: Path) -> Dict[str, str]:
    """text -> short sha of a commit that removed a pending row with that text. Fail closed (#5299,
    #5463, #5466; 5-agent vote 4d3ea1c5, decision memory bf29bdb2): the whole history is read with no
    path limit and with no rename detection (--no-renames: a rename onto the allow list path hid a
    removal, #5500), so a list renamed and rewritten in one commit is followed (the deleted old file
    shows its rows as removed: over-collecting fails closed; a row moved unchanged under the pending
    list path by the same diff is netted, so a pure rename of the list names nothing), every merge is diffed against each of its
    parents (-m: a merge, an evil merge and an octopus merge included), and replace refs and grafts are
    ignored. A shallow clone, a git failure, a list that exists but has no history, or a committed row
    that no scanned commit ever added (history this scan cannot follow) is a RuntimeError, never an
    empty answer. The allow list is skipped: an allow row may carry a #<issue> reason."""
    if _git(root, "rev-parse", "--is-shallow-repository").strip() != "false":
        raise RuntimeError("the history of %s is incomplete (shallow clone): %s" % (PENDING_FILE, HISTORY_REMEDY))
    try:
        log = _git(root, "-c", "core.quotepath=false", "log", "-m", "--no-ext-diff", "--no-textconv", "--text",
                   "--encoding=UTF-8", "--no-renames", "-p", "-U0", "--no-color", "--format=commit %h",
                   "-G" + PENDING_ROW_PICKAXE)
        listed = _git(root, "log", "-1", "--format=%h", "--full-history", "--", PENDING_FILE).strip()
        at_head = _show_or_absent(root, "HEAD", PENDING_FILE)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("cannot read the history of %s (%s): %s" % (
            PENDING_FILE, exc.stderr.decode("utf-8", "replace").strip()[:120], HISTORY_REMEDY))
    gone: Dict[str, str] = {}
    added = set()
    sha = path = ""
    in_hunk = False
    removed: List[Tuple[str, str]] = []  # (whole row, text) removed by the diff being read
    readded: Counter = Counter()  # whole rows added back under the pending list path by the same diff

    def flush() -> None:
        # a row removed from one path and added unchanged under the pending list path by the same
        # diff is a move of the list, not a removal: git rename detection is not used (it hid a
        # removal behind a rename onto the allow list path, #5500), so the move is netted here
        for whole, text in removed:
            if readded[whole] > 0:
                readded[whole] -= 1
            else:
                gone.setdefault(text, sha)
        removed.clear()
        readded.clear()

    for raw in log.split("\n"):
        if raw.startswith("commit "):
            flush()
            sha, path, in_hunk = raw[7:].strip(), "", False
        elif raw.startswith("diff --git "):
            path, in_hunk = "", False
        elif raw.startswith("@@"):
            in_hunk = True
        elif not in_hunk and (raw.startswith("--- ") or raw.startswith("+++ ")):
            path = raw[6:] if raw[4:6] in ("a/", "b/") else path
        elif in_hunk and raw[:1] in ("-", "+") and path != ALLOW_FILE:
            for whole, text in diff_rows(raw[1:]):
                if raw[0] == "-":
                    removed.append((whole, text))
                else:
                    added.add(text)
                    if path == PENDING_FILE:
                        readded[whole] += 1
    flush()
    if not listed and (root / PENDING_FILE).is_file():
        raise RuntimeError("the history of %s is empty although the file exists: %s" % (PENDING_FILE, HISTORY_REMEDY))
    unseen = sorted(r[3] for r in parse_git_list(at_head, "head-pending", True) if r[3] not in added)
    if unseen:
        raise RuntimeError("the history of %s cannot be followed: no commit added the row %r: %s" % (
            PENDING_FILE, unseen[0][:60], HISTORY_REMEDY))
    return gone


def allow_text_once_pending(allow: List[Entry], base_allow: List[Entry], renames: Dict[str, str],
                            gone: Dict[str, str]) -> List[str]:
    """#5299 (5-agent vote 4d3ea1c5): a new or raised allow entry may not carry the exact text of a
    pending row that an earlier change removed. The merge base is a real ancestor that no longer has
    the row, so only the history can see it. A respelling is not caught here: #4929 Part 1."""
    had = {(renames.get(e[1], e[1]), e[3]): e[2] for e in base_allow}
    return ["allow:%d: entry carries the text of a pending row removed in commit %s (change the line, not "
            "the list; #5299): %s: %s" % (e[4], gone[e[3]], e[1], e[3][:80])
            for e in allow if e[3] in gone and e[2] > had.get((e[1], e[3]), 0)]


def base_ref() -> str:
    """The base named by EXEC_SECRET_ARGV_BASE (any ref) or GITHUB_BASE_REF (a pull request); empty
    when none is named."""
    ref = os.environ.get("EXEC_SECRET_ARGV_BASE", "").strip()
    if not ref and os.environ.get("GITHUB_BASE_REF", "").strip():
        ref = "origin/" + os.environ["GITHUB_BASE_REF"].strip()
    return ref


def base_state(root: Path, ref: str) -> Tuple[str, Dict[str, str], List[Entry], List[Entry]]:
    """(merge base, renames since it, base pending rows, base allow rows). Any git failure is a
    RuntimeError: unresolved means red."""
    try:
        mb = _git(root, "merge-base", "HEAD", ref).strip()
        renames: Dict[str, str] = {}
        for row in _git(root, "diff", "-M", "--name-status", mb, "HEAD").split("\n"):
            cols = row.split("\t")
            if len(cols) == 3 and cols[0].startswith("R"):
                renames[cols[1]] = cols[2]
        old = _show_or_absent(root, mb, PENDING_FILE)
        old_allow = _show_or_absent(root, mb, ALLOW_FILE)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("cannot resolve the merge base against %s (fail closed): %s" % (ref, exc))
    return (mb, renames, parse_git_list(old, "base-pending", False), parse_git_list(old_allow, "base-allow", False))


def merge_base_hits(root: Path, allow: List[Entry], pend: Optional[List[Entry]] = None) -> Optional[List[str]]:
    """Run the merge-base rules (#4919, #4996, #5103, #5298, #5299) against the base named by
    EXEC_SECRET_ARGV_BASE (any ref) or GITHUB_BASE_REF (a pull request). Unresolved means red:
    in CI a missing base, or a named base that cannot be resolved, is a FAULT (fail closed).
    Outside CI with no base named, returns None: the rule was not evaluated, and run() says so."""
    ref = base_ref()
    if not ref:
        if in_ci():
            raise RuntimeError("no merge base named in CI: set EXEC_SECRET_ARGV_BASE or GITHUB_BASE_REF "
                               "(unresolved means red, #4996)")
        return None
    _mb, renames, base_pend, base_allow = base_state(root, ref)
    hits = allow_from_pending(allow, base_pend, renames)
    hits.extend(allow_like_vanished_pending(allow, base_allow, base_pend, pend or []))
    hits.extend(allow_text_pending_elsewhere(allow, base_allow, base_pend, pend or [], renames))
    hits.extend(allow_added_in_pending_file(allow, base_allow, base_pend, renames))
    hits.extend(allow_text_once_pending(allow, base_allow, renames, removed_pending_rows(root)))
    return hits


def empty_scan_faults(n_exec: int, allow: List[Entry], found: Dict[str, List[Found]]) -> List[str]:
    """A scan that saw nothing is a fault, never a pass (fail closed)."""
    out: List[str] = []
    if n_exec == 0:
        out.append("scanned 0 executable files (fail closed)")
    if not allow:
        out.append("allowlist is empty (fail closed)")
    if not any(not r.lower().endswith((".md", ".html", ".htm")) for r in found):
        out.append("zero triggered lines (fail closed)")
    return out


def run(root: Path) -> int:
    try:
        dl = load_denylist(root)
        found, n_exec, n_prose = scan_repo(root, dl)
        allow, pend, faults = load_lists(root)
        base_hits = merge_base_hits(root, allow, pend)
    except Exception as exc:  # noqa: BLE001 - fail closed
        print("FAULT: %s" % exc, file=sys.stderr)
        return 2
    faults.extend(empty_scan_faults(n_exec, allow, found))
    if faults:
        print("\n".join("FAULT: " + f for f in faults), file=sys.stderr)
        return 2
    hits, report, stats = judge(found, allow, pend, dl)
    hits.extend(check_allow_vs_denylist(found, allow))
    if base_hits is None:
        print("NOTE: merge-base rule NOT evaluated: no EXEC_SECRET_ARGV_BASE or GITHUB_BASE_REF is set "
              "(outside CI only; in CI this is a FAULT)", file=sys.stderr)
    else:
        hits.extend(base_hits)
    for line in report:
        print(line)
    if hits:
        for h in hits:
            print("HIT " + h, file=sys.stderr)
        print("FAIL: check-exec-secret-argv: %d defect(s). An unknown triggered line is red: review it, then "
              "fix it or add it with scripts/regen-exec-secret-argv-allow.py --accept-new --why <#issue|reason>"
              % len(hits), file=sys.stderr)
        return 1
    n_allow_lines = sum(e[2] for e in allow)
    print("PASS: check-exec-secret-argv: %d executable files and %d prose files scanned, %d triggered lines "
          "(%d allow entries covering %d lines, %d pending entries covering %d lines, listed not approved)"
          % (n_exec, n_prose, sum(len(v) for v in found.values()), len(allow), n_allow_lines,
             len(pend), stats["pending"]) + ("; merge-base rule not evaluated" if base_hits is None else ""))
    return 0


# ---------------------------------------------------------------- self-test
def probe_files() -> List[Tuple[str, str, str]]:
    """(label, file name, text) red probes: each is a line with a secret on an argv (or in a
    header variable that is expanded into one). No tool-specific rule is needed for the
    unknown-tool probes: they are red because the line is triggered and not allowed."""
    P = "ProbeValue1"
    sh = "#!/bin/bash\n%s\n"
    rows = [
        # #4813-#4819 and #4859: variable and literal forms
        ("4813 curl -u variable", "p.sh", 'curl -u "admin:$API_PW" https://h/x'),
        ("4813 curl -u literal", "p.sh", "curl -u admin:$P https://h/x".replace("$P", P)),
        ("4814 mysql -p variable", "p.sh", 'mysql -u root -p"$DB_PASSWORD" db'),
        ("4814 mysql -p literal", "p.sh", "mysql -u root -p$P db".replace("$P", P)),
        ("4814 mysql --password= literal", "p.sh", "mysqldump --password=$P db".replace("$P", P)),
        ("4815 sshpass -p variable", "p.sh", 'sshpass -p "$SSH_PASS" ssh h true'),
        ("4815 sshpass -p literal", "p.sh", "sshpass -p $P ssh h true".replace("$P", P)),
        ("4816 redis-cli -a variable", "p.sh", 'redis-cli -a "$REDIS_PASS" ping'),
        ("4816 redis-cli -a literal", "p.sh", "redis-cli -a $P ping".replace("$P", P)),
        ("4817 psql -v pw variable", "p.sh", "psql -v pw=\"$PW\" -c 'select 1'"),
        ("4817 psql -v pw literal", "p.sh", "psql -v pw=\"$P\" -c 'select 1'".replace("$P", P)),
        ("4818 curl Authorization variable", "p.sh", 'curl -H "Authorization: Bearer $TOKEN" https://h'),
        ("4818 curl Authorization literal", "p.sh", "curl -H 'Authorization: Bearer $P' https://h".replace("$P", P)),
        ("4819 docker login -p variable", "p.sh", 'docker login -u u -p "$REG_TOKEN" reg.example'),
        ("4819 docker login -p literal", "p.sh", "docker login -u u -p $P reg.example".replace("$P", P)),
        ("4859 psql path form", "p.sh", '/usr/bin/psql --variable=pw="$PW" -c "select 1"'),
        ("4859 psql joined -vpw", "p.sh", 'x=$(psql -vpw="$PW" -c "select 1")'),
        ("4859 psql --set", "p.sh", 'psql --set pw="$PW" -c "select 1"'),
        # #4826 names
        ("4826 DB_KEY via systemd-run", "p.sh", 'systemd-run --setenv=AI_MEMORY_DB_KEY="$K" /bin/true'),
        ("4826 PASSPHRASE via sudo env", "p.sh", 'sudo env PASSPHRASE="$X" /bin/true'),
        ("4826 AUTH via kubectl", "p.sh", 'kubectl exec pod -- env AUTH="$X" /bin/true'),
        ("4826 DBPW via timeout", "p.sh", 'timeout 5 env DBPW="$X" /bin/true'),
        # #4827
        ("4827 docker build --build-arg", "p.sh", 'docker build --build-arg DB_PASSWORD="$P" .'),
        # #4808
        ("4808 dollar-quoted PASSWORD", "p.sh", 'psql -c "ALTER ROLE r PASSWORD $$$PW$$"'),
        ("4808 docker -e DSN name", "p.sh", 'docker run -e AI_MEMORY_STORE_URL="$U" img'),
        ("4808 ssh remote env DSN", "p.sh", 'ssh h "AI_MEMORY_STORE_URL=$U /bin/true"'),
        ("4808 non-pw variable name", "p.sh", 'docker run -e DB_SECRET="$S" img'),
        # header variable that is expanded into a curl or ssh argv later
        ("header variable built from a key", "p.sh", "keyhdr=\"-H 'x-api-key: $API_KEY'\""),
        ("header array", "p.sh", 'KEY_HDR=(-H "X-API-Key: $EFFECTIVE_KEY")'),
        ("header array spread over lines", "p.sh", 'HDRS=(\n  -H "X-Agent: a"\n  -H "X-API-Key: $K"\n)'),
        ("printf of a key header into a script", "p.sh", "printf 'curl -H \"x-api-key: %s\"\\n' \"$KEY\" > run.sh"),
        ("ssh_node with curl -H key inline", "p.sh", 'ssh_node "$ip" "curl -fsS -H \'x-api-key: $api_key\' https://h"'),
        ("backslash continuation", "p.sh", 'curl -sS \\\n  --max-time 5 \\\n  -H "X-API-Key: $KEY" \\\n  https://h'),
        # three invented tools no rule knows
        ("invented tool zorbctl", "p.sh", 'zorbctl sync --auth-secret "$VAL" --to h'),
        ("invented tool frobnicate", "p.sh", 'frobnicate login --token="$T"'),
        ("invented tool quuxd", "p.sh", "quuxd -H 'x-api-key: $K' --url https://h"),
        # file classes
        ("workflow run", ".github/workflows/p.yml",
         "jobs:\n  a:\n    steps:\n      - run: |\n          zorbctl --opt ${{ secrets.DEPLOY_TOKEN }}\n"),
        ("workflow inline run", ".github/workflows/p.yml",
         "jobs:\n  a:\n    steps:\n      - run: zorbctl --opt ${{ secrets.DEPLOY_TOKEN }}\n"),
        ("compose healthcheck", "docker-compose.yml",
         "services:\n  a:\n    healthcheck:\n      test: [\"CMD-SHELL\", \"curl -H 'X-API-Key: $$K' http://x\"]\n"),
        ("compose command list item", "docker-compose.yml",
         "services:\n  a:\n    command:\n      - serve\n      - --api-key\n      - $K\n"),
        ("dockerfile RUN", "Dockerfile", "FROM x\nRUN zorbctl --pw \"$PW\"\n"),
        ("dockerfile.variant CMD", "Dockerfile.p", "FROM x\nCMD [\"zorbctl\", \"--token\", \"abc\"]\n"),
        ("service ExecStart", "p.service", "[Service]\nExecStart=/usr/bin/zorbctl --api-key abc\n"),
        ("makefile recipe", "Makefile", "all:\n\tzorbctl --token $(TOKEN)\n"),
        ("suffix-less shebang script", "bin/tool", "#!/bin/sh\nzorbctl --token \"$TOKEN\"\n"),
    ]
    # #4903 #4926 #4904 #4923-#4928 (round 2 of PR 4891): forms the first reviewers planted
    P2 = "ProbeValue1"
    raw_rows = [
        ("4911 prose --store-url with a userinfo password", "d.md",
         "```bash\nzorbctl serve --store-" "url postgres://u:$P@h/d\n```\n".replace("$P", P2)),
        ("4911 prose --store-url with a variable value", "d.md",
         "```bash\nzorbctl serve --store-" "url $URL\n```\n"),
        ("4903 comment ending in backslash hides the next line", "p.sh",
         '#!/bin/bash\n# note \\\ncurl -H "Authorization: Bearer $TOKEN" https://h\n'),
        ("4926 continuation splits a flag name", "p.sh", "#!/bin/bash\nzorbctl --to\\\nken=$P h\n".replace("$P", P2)),
        ("4926 continuation splits a header name", "p.sh",
         '#!/bin/bash\nzorbctl -H "x-api-\\\nkey: $P" h\n'.replace("$P", P2)),
        ("4904 x-vault-token header", "p.sh", "#!/bin/bash\nzorbctl -H \"X-Vault-Token: $v\" h\n"),
        ("4904 private-token header", "p.sh", "#!/bin/bash\nzorbctl -H \"PRIVATE-TOKEN: $v\" h\n"),
        ("4904 x-secret header", "p.sh", "#!/bin/bash\nzorbctl -H \"X-Secret: $v\" h\n"),
        ("4925 cookie header", "p.sh", "#!/bin/bash\ncurl -H 'Cookie: session=$P' h\n".replace("$P", P2)),
        ("4925 json body password", "p.sh", "#!/bin/bash\ncurl -d '{\"password\":\"$P\"}' h\n".replace("$P", P2)),
        ("4925 hmac and jwt flags", "p.sh", "#!/bin/bash\nzorbctl --jwt $P --psk $P\n".replace("$P", P2)),
        ("4925 publish token name", "p.sh", '#!/bin/bash\nzorbctl --opt "$NPM_PUBLISH_TOKEN"\n'),
        ("4925 secret id name", "p.sh", '#!/bin/bash\nvault write auth/approle/login secret_id="$SECRET_ID"\n'),
        ("4924 command substitution cat key file", "p.sh", '#!/bin/bash\nzorbctl --opt "$(cat /etc/app/db.key)"\n'),
        ("4924 backtick key file", "p.sh", "#!/bin/bash\nzorbctl --opt `cat /etc/app/db.key`\n"),
        ("4924 gh auth token", "p.sh", '#!/bin/bash\nzorbctl --opt "$(gh auth token)"\n'),
        ("4924 vault kv get", "p.sh", '#!/bin/bash\nzorbctl --opt "$(vault kv get -field=v kv/app)"\n'),
        ("4923 zsh script", "p.zsh", "#!/bin/zsh\nzorbctl --token $P\n".replace("$P", P2)),
        ("4923 bats test", "p.bats", "#!/usr/bin/env bats\nzorbctl --token $P\n".replace("$P", P2)),
        ("4923 sh.in template", "p.sh.in", "#!/bin/sh\nzorbctl --token $P\n".replace("$P", P2)),
        ("4923 suffix-less script with no shebang", "p/deploy", "zorbctl --token $P\n".replace("$P", P2)),
        ("4923 socket unit", "p.socket", "[Socket]\nExecStartPre=/usr/bin/zorbctl --token $P\n".replace("$P", P2)),
        ("4923 systemd drop-in", "p.service.d/override.conf",
         "[Service]\nExecStart=/usr/bin/zorbctl --token $P\n".replace("$P", P2)),
        ("4923 service.in template", "p.service.in", "[Service]\nExecStart=/usr/bin/zorbctl --token $P\n".replace("$P", P2)),
        ("4923 k8s manifest command", "p/deploy.yaml",
         'spec:\n  containers:\n  - name: a\n    command: ["zorbctl", "--token", "$P"]\n'.replace("$P", P2)),
        ("4923 docker stack file", "p/stack.yml", "services:\n  a:\n    command: zorbctl --token $P\n".replace("$P", P2)),
        ("4923 python subprocess", "p.py", "import subprocess\nsubprocess.run(['zorbctl', '--token', '$P'])\n".replace("$P", P2)),
        ("4923 node child_process", "p.mjs", "import { spawn } from 'node:child_process';\nspawn('zorbctl', ['--token', '$P']);\n".replace("$P", P2)),
        ("4923 non-memory cloud-init template", "infra/p/cloud-init-agent2.yaml.tpl",
         "#cloud-config\nruncmd:\n  - zorbctl --token $P\n".replace("$P", P2)),
        ("4905 plain multi-line scalar run", ".github/workflows/p.yml",
         "jobs:\n  a:\n    steps:\n      - run: zorbctl --opt\n          --token $P\n".replace("$P", P2)),
        ("4927 run key with a space before the colon", ".github/workflows/p.yml",
         "jobs:\n  a:\n    steps:\n      - run : zorbctl --token $P\n".replace("$P", P2)),
        ("4927 flow-mapping step", ".github/workflows/p.yml",
         "jobs:\n  a:\n    steps:\n      - {name: x, run: zorbctl --token $P}\n".replace("$P", P2)),
        ("4927 yaml anchor read through an alias", ".github/workflows/p.yml",
         "x: &c zorbctl --token $P\njobs:\n  a:\n    steps:\n      - run: *c\n".replace("$P", P2)),
        ("4927 container options -e", ".github/workflows/p.yml",
         "jobs:\n  a:\n    container:\n      image: x\n      options: -e DB_PASSWORD=${{ secrets.DBP }}\n"),
        ("4927 toJSON(secrets) on argv", ".github/workflows/p.yml",
         "jobs:\n  a:\n    steps:\n      - run: zorbctl --opt '${{ toJSON(secrets) }}'\n"),
        ("4927 compose flow-mapping service", "docker-compose.yml",
         "services:\n  a: {image: x, command: zorbctl --token $P}\n".replace("$P", P2)),
        ("4927 compose alias of an x- anchor", "docker-compose.yml",
         'x-cmd: &cmd ["zorbctl", "--token", "$P"]\nservices:\n  a:\n    command: *cmd\n'.replace("$P", P2)),
        ("4907 workflow named compose-x.yml", ".github/workflows/compose-x.yml",
         "jobs:\n  a:\n    steps:\n      - run: zorbctl --token $P\n".replace("$P", P2)),
        ("4907 workflow named dockerfile-x.yml", ".github/workflows/dockerfile-x.yml",
         "jobs:\n  a:\n    steps:\n      - run: zorbctl --token $P\n".replace("$P", P2)),
        ("4908 dockerfile RUN heredoc body", "Dockerfile", "FROM x\nRUN <<EOF\nzorbctl --token $P\nEOF\n".replace("$P", P2)),
        ("4908 dockerfile ONBUILD RUN", "Dockerfile", "FROM x\nONBUILD RUN zorbctl --token $P\n".replace("$P", P2)),
        ("4908 dockerfile escape directive", "Dockerfile",
         "# escape=`\nFROM x\nRUN zorbctl `\n  --token $P\n".replace("$P", P2)),
        ("4928 makefile lower-case variable", "Makefile", "all:\n\tzorbctl --opt $(api_token)\n"),
        ("4928 makefile RECIPEPREFIX", "Makefile", ".RECIPEPREFIX = >\nall:\n> zorbctl --token $P\n".replace("$P", P2)),
    ]
    out = []
    for label, name, body in rows:
        text = body if name.endswith((".yml", ".yaml", ".service", "Makefile", "Dockerfile", "Dockerfile.p")) \
            or name.startswith("Dockerfile") else sh % body
        out.append((label, name, text))
    out.extend(raw_rows)
    return out


def green_probes() -> List[Tuple[str, str, str]]:
    """Lines that are not triggered: no secret-like name and no denylist hit."""
    return [
        ("file flag", "g.sh", "#!/bin/bash\nmysql --defaults-extra-file=/run/x.cnf db\n"),
        ("sshpass file", "g.sh", '#!/bin/bash\nsshpass -f "$PWF" ssh h true\n'),
        ("curl netrc", "g.sh", '#!/bin/bash\ncurl --netrc-file "$NETRC" https://h\n'),
        ("passed and author are not secret names", "g.sh", '#!/bin/bash\necho "$passed of $total by $author"\n'),
        ("comment line", "g.sh", '#!/bin/bash\n# curl -H "x-api-key: $KEY"\necho ok\n'),
        ("a plain compose command", "docker-compose.yml", "services:\n  a:\n    command: [\"serve\", \"--port\", \"1\"]\n"),
        ("4911 prose --store-url named without a value", "g.md",
         "```text\nError: --db and --store-url are mutually exclusive. Pass exactly one.\n```\n"),
        ("4911 prose --store-url followed by a bare word", "g.md", "```text\ncurator --store-url postgres (epoch host)\n```\n"),
        ("4911 prose model token limit", "g.md", "```bash\nenv OLLAMA_MAX_DRAFT_TOKENS=4 ollama serve\n```\n"),
        ("not an executable file", "notes.txt", 'curl -H "x-api-key: $KEY" https://h\n'),
        ("cloud-init memory template stays with its own gate", "infra/p/cloud-init-memory.yaml.tpl", 'curl -H "x-api-key: $KEY" https://h\n'),
    ]


# Safe forms that mention a secret name: triggered, then approved by an allow entry.
ALLOWED_FORMS = [
    ("stdin form", 'docker login -u u --password-stdin reg.example < "$TOKEN_FILE"'),
    ("password file flag", 'tool --password-file /run/secrets/pw'),
    ("env prefix read by the child", 'MYSQL_PWD="$PW" mysql -u root db'),
    ("exported variable read by the child", 'export REDISCLI_AUTH="$A"'),
    ("-e NAME with no value", 'docker run -e PGPASSWORD img'),
    ("curl body from stdin", 'curl --data @- https://h/ < "$TOKEN_FILE"'),
    ("curl config from stdin", 'curl -K - https://h/ < "$TOKEN_FILE"'),
]


def _scan_one(dl, name: str, text: str) -> List[Found]:
    if name.lower().endswith((".md", ".html", ".htm")):
        return scan_prose_file(dl, name, text) or []
    res = scan_exec_file(dl, name, text)
    return res or []


def _mutate(text: str, start: int, end: int) -> str:
    phys = text.split("\n")
    last = phys[end - 1]
    cut = last.rfind("</pre")  # an html block closes on its last line; mark the text, not the tag
    phys[end - 1] = (last[:cut] + " #m" + last[cut:]) if cut >= 0 else last + " #m"
    return "\n".join(phys)


# Round-3 probes (#4891): each rule of CRED_TOOL_RE and the Dockerfile join has red probes that
# must be denylist-tagged (so never allow-able) and green probes that must stay allow-able.
ROUND3_RED = [
    # combined short flags and the long forms of every curl and wget credential option (#4993)
    ("curl -su", 'curl -su "u:$X" h'),
    ("curl -fsSLu", 'curl -fsSLu u:"$X" h'),
    ("curl -sU proxy user", 'curl -sU "p:$X" h'),
    ("curl --proxy-user", 'curl --proxy-user "p:$X" h'),
    ("curl -sE cert password", 'curl -sE "c.pem:$X" h'),
    ("curl --cert password", 'curl --cert c.pem:"$X" h'),
    ("curl -E quoted cert password", "curl -E 'c.pem':\"$X\" h"),
    ("curl --tlspassword", 'curl --tlspassword "$X" h'),
    ("curl --proxy-tlspassword", 'curl --proxy-tlspassword "$X" h'),
    ("curl --oauth2-bearer", 'curl --oauth2-bearer "$X" h'),
    ("curl --pass", 'curl --pass "$X" --key k.pem h'),
    ("mysql --password with a space", 'mysql -u r --password "$X" db'),
    ("5464 mariadb --pas space", 'mariadb -u r --pas "$X" db'),
    ("5464 mysql --pass= glued", 'mysql -u r --pass="$X" db'),
    ("5502 mysqldump --pa unique prefix", 'mysqldump --pa="$DB_PASSWORD" db'),
    ("5502 mysqladmin --pa unique prefix", 'mysqladmin --pa "$DB_PASSWORD" status'),
    ("5502 mariadb-dump --pa unique prefix", 'mariadb-dump --pa="$DB_PASSWORD" db'),
    ("5502 mariadb-admin --pa unique prefix", 'mariadb-admin --pa=$DB_PASSWORD status'),
    ("5502 mysql --loose-pas", 'mysql --loose-pas="$DB_PASSWORD" db'),
    ("5502 mysqldump --loose-pa", 'mysqldump --loose-pa="$DB_PASSWORD" db'),
    ("5502 mariadb --loose-password", 'mariadb --loose-password="$DB_PASSWORD" db'),
    ("5502 mysqladmin --loose-passw backtick", 'mysqladmin --loose-passw=`cat f` status'),
    # whole family keyed on the option shape, not on a client name list (#5583)
    ("5583 mysqlcheck --pa", 'mysqlcheck --pa="$DB_PASSWORD" db'),
    ("5583 mysqlpump --pa", 'mysqlpump --pa="$DB_PASSWORD" db'),
    ("5583 mysqlbinlog --pa", 'mysqlbinlog --pa="$DB_PASSWORD" db'),
    ("5583 mysqlshow --pa", 'mysqlshow --pa="$DB_PASSWORD" db'),
    ("5583 mysqlslap --pa", 'mysqlslap --pa="$DB_PASSWORD" db'),
    ("5583 mysqlimport --pa", 'mysqlimport --pa="$DB_PASSWORD" db'),
    ("5583 mysql_upgrade --pa", 'mysql_upgrade --pa="$DB_PASSWORD" db'),
    ("5583 mariadb-check --pa", 'mariadb-check --pa="$DB_PASSWORD" db'),
    ("5583 mariadb-import --pa", 'mariadb-import --pa="$DB_PASSWORD" db'),
    ("5583 mariadb-backup --pa", 'mariadb-backup --pa="$DB_PASSWORD" db'),
    ("5583 mariadb-show --pa", 'mariadb-show --pa="$DB_PASSWORD" db'),
    ("5583 mariadb-slap --pa", 'mariadb-slap --pa="$DB_PASSWORD" db'),
    ("5583 mariadb-binlog --pa", 'mariadb-binlog --pa="$DB_PASSWORD" db'),
    ("5583 mariadb-upgrade --pa", 'mariadb-upgrade --pa="$DB_PASSWORD" db'),
    ("5583 mysqlcheck --pas", 'mysqlcheck --pas="$X" db'),
    ("5583 mysqlslap --passw", 'mysqlslap --passw="$X" -q f'),
    ("5583 mysqlimport --passwo space", 'mysqlimport --passwo "$X" db f'),
    ("5583 mysqlpump --passwor", 'mysqlpump --passwor=$X'),
    ("5583 mysqlshow --pass", 'mysqlshow --pass="$X"'),
    ("5583 mysql_upgrade --pas backtick", 'mysql_upgrade --pas=`cat f`'),
    ("5583 mariadb-backup --password", 'mariadb-backup --password="$X" --backup'),
    ("5583 mysqlimport -p attached", 'mysqlimport -p"$X" db f'),
    ("5583 mysqlcheck -p attached", 'mysqlcheck -p$X db'),
    ("5583 mysqlslap -p attached", 'mysqlslap -p`cat f` -q f'),
    ("5583 mariadb-backup -p attached", 'mariadb-backup -p"$X" --backup'),
    ("5583 mysqlpump -p attached", 'mysqlpump -p"${DB_PASSWORD}"'),
    ("5583 mysql_upgrade -p attached", 'mysql_upgrade -p"$X"'),
    ("5583 mysqlbinlog -p attached", 'mysqlbinlog -p"$X" f'),
    ("5583 mysqlcheck --loose_pa", 'mysqlcheck --loose_pa="$X" db'),
    ("5583 mariadb-import --loose_pas", 'mariadb-import --loose_pas="$X" db f'),
    ("5583 mysqlimport --loose-pa", 'mysqlimport --loose-pa="$X" db f'),
    ("5583 mysqlslap --loose_password", 'mysqlslap --loose_password=$X'),
    ("5583 path-prefixed mysqlcheck --pa", '/usr/bin/mysqlcheck --pa="$X" db'),
    ("5583 path-prefixed mysqlimport -p", '/opt/mysql/bin/mysqlimport -p"$X" db f'),
    ("5583 exe mysqlpump --pa", './mysqlpump.exe --pa=$X'),
    ("5583 quoted path mysqlslap --passw", '"/usr/local/mysql/bin/mysqlslap" --passw="$X"'),
    ("5583 windows path mysqlcheck.exe", 'C:\\mysql\\bin\\mysqlcheck.exe --pa="$X" db'),
    ("5583 upper-case exe MYSQLDUMP.EXE -p", 'MYSQLDUMP.EXE -p"$X" db'),
    ("5583 sudo mysqlimport -p", 'sudo -u deploy mysqlimport -p"$X" db f'),
    ("5583 env mysqlcheck --pas", 'env MYSQL_HOST=h mysqlcheck --pas="$X" db'),
    ("5583 nice mysqlslap --passw", 'nice -n5 mysqlslap --passw=$X'),
    ("5583 ssh mysqlpump --pa", 'ssh h mysqlpump --pa="$X"'),
    ("5583 time mariadb-backup --pa", 'time mariadb-backup --pa="$X" --backup'),
    ("5583 docker exec mysqlimport -p", 'docker exec -i db mysqlimport -p"$X" d f'),
    # the loose_ underscore spelling: my_getopt reads the special prefix loose followed by - or _ (#5582)
    ("5582 mysql --loose_pas", 'mysql --loose_pas="$DB_PASSWORD" db'),
    ("5582 mysqldump --loose_pa", 'mysqldump --loose_pa="$DB_PASSWORD" db'),
    ("5582 mariadb --loose_password", 'mariadb --loose_password="$DB_PASSWORD" db'),
    ("5582 mysqladmin --loose_passw backtick", 'mysqladmin --loose_passw=`cat f` status'),
    ("5582 mariadb-dump --loose_pa", 'mariadb-dump --loose_pa=$DB_PASSWORD db'),
    ("5582 mysql --loose_pass space", 'mysql -u r --loose_pass "$X" db'),
    ("5464 mysqladmin --passw= glued", 'mysqladmin --passw=$X status'),
    ("5464 mysqldump --passwo space", 'mysqldump --passwo $X db'),
    ("5464 mariadb --passwor= glued", 'mariadb --passwor="$X" db'),
    ("5464 mysql --pass= backtick", 'mysql --pass=`cat f` db'),
    ("5464 mysqldump --pas backtick", 'mysqldump --pas "`cat f`" db'),
    ("mysqldump --password unquoted", 'mysqldump --password $X db'),
    ("mariadb --password=", 'mariadb -u r --password="$X" db'),
    ("redis-cli --pass=", 'redis-cli --pass="$X" ping'),
    ("redis-cli --pass with a space", 'redis-cli --pass "$X" ping'),
    ("wget --password=", 'wget --password="$X" h'),
    ("wget --http-password", 'wget --http-password "$X" h'),
    ("wget --ftp-password", 'wget --ftp-password "$X" h'),
    ("wget -e http_password", 'wget -e "http_password=$X" h'),
    ("wget -qe password", 'wget -qe password="$X" h'),
    ("wget --execute=proxy_passwd", 'wget --execute=proxy_passwd="$X" h'),
    # wgetrc names ignore case, dashes and underscores and allow spaces around = (#5293)
    # getopt takes any unique prefix of a long option; wget keeps deprecated aliases (#5300)
    ("wget --passwo prefix", 'wget --passwo="$X" h'),
    ("wget --http-passwd alias", 'wget --http-passwd="$X" h'),
    ("wget --proxy-passwd alias", 'wget --proxy-passwd "$X" h'),
    ("wget --ftp-pass prefix", 'wget --ftp-pass="$X" h'),
    ("wget -e spaces around =", 'wget -e "http_password = $X" h'),
    ("wget -e no separator", 'wget -e "httppassword=$X" h'),
    ("wget -e upper case", 'wget -e "HTTP_PASSWORD=$X" h'),
    ("wget -e dashed proxy alias", 'wget -e "proxy-passwd=$X" h'),
    ("wget -e ftpPassword", 'wget -e ftpPassword="$X" h'),
    ("wget -e doubled separators", 'wget --execute "HTTP__PASS-WORD=$X" h'),
    ("wget -e name from an expansion", 'wget -e "$K=$V" h'),
    ("wget -e inside sh -c", 'sh -c "wget -e \\"HTTP_PASSWORD=$X\\" h"'),
    # getopt takes any unique prefix of --execute: --exe is the shortest (#5293)
    ("wget --exe prefix", 'wget --exe "http_password=$X" h'),
    ("wget --exec prefix", 'wget --exec "http_password=$X" h'),
    ("wget --execu prefix", 'wget --execu "http_password=$X" h'),
    ("wget --execut prefix, =", 'wget --execut="https_password=$X" h'),
    # quoted and partly quoted user parts (#5101)
    ("curl -u single-quoted user", "curl -u 'u':\"$X\" h"),
    ("curl -u double-quoted user", 'curl -u "u":"$X" h'),
    ("curl --user braced", 'curl --user u:"${X}" h'),
    ("curl -u three quoted parts", "curl -u \"u\"':'\"$X\" h"),
    # header names in any letter case, with tabs, after combined flags, partly quoted (#4997, #4993)
    ("curl -H upper case", 'curl -H "AUTHORIZATION: Bearer $X" h'),
    ("curl -H tab after colon", 'curl -H "X-Api-Key:\t$X" h'),
    ("curl -H tab before colon", 'curl -H "X-Auth-Token\t: $X" h'),
    ("curl -sSH partly quoted", "curl -sSH 'Authorization: Bearer '\"$X\" h"),
    ("wget --header= Authorization", 'wget --header="Authorization: token $X" h'),
    ("ssh payload escaped quotes, Authorization", 'ssh h "curl -H \\"Authorization: Bearer $X\\" https://h/"'),
    ("ssh payload escaped quotes, combined flags", 'ssh h "curl -sH \\"X-API-Key: $X\\" https://h/"'),
    ("sh -c payload escaped quotes", 'sh -c "curl --header=\\"Authorization: token $X\\" h"'),
    ("curl -H Api-Key without the x- prefix", 'curl -H "Api-Key: $X" h'),
    ("curl -u backtick substitution word", 'curl -u admin:`cat $PW_FILE` h'),
    ("curl -u ANSI-C quoted user part", "curl -u $'u:'$X h"),
    ("curl -H ANSI-C quoted header", "curl -H $'Authorization: Bearer '$X h"),
    ("curl --proxy-header", 'curl --proxy-header "Proxy-Authorization: Basic $X" h'),
    # a command substitution in a credential header value is on argv as well (#5304)
    ("wget --https-password backtick", 'wget --https-password `cat f` h'),
    ("wget --proxy-passwd backtick", 'wget --proxy-passwd `cat f` h'),
    # two- and three-letter prefixes are ambiguous in wget (it refuses them) and are flagged all the
    # same: the generated alternation starts at two letters, and a shorter start would pass them (#5300)
    ("wget --pa two-letter prefix", 'wget --pa "$X" h'),
    ("wget --pas three-letter prefix", 'wget --pas="$X" h'),
    ("wget --ht two-letter http prefix", 'wget --ht "$X" h'),
    ("wget --passwo= backtick prefix", 'wget --passwo=`cat f` h'),
    ("wget --password= backtick", 'wget --password=`cat f` h'),
    ("sshpass -p backtick", 'sshpass -p `cat $F` ssh h'),
    ("sshpass -p backtick no dollar", 'sshpass -p `cat f` ssh h'),
    ("redis-cli -a backtick", 'redis-cli -a `cat f` ping'),
    ("redis-cli --pass backtick", 'redis-cli --pass `cat f` ping'),
    ("mysql --password= backtick", 'mysql --password=`cat f` db'),
    ("mysql -p glued backtick", 'mysql -p`cat f` db'),
    ("mysqldump -p quoted backtick", 'mysqldump -u r -p"`cat f`" db'),
    ("curl -E key password backtick", 'curl -E c.pem:`cat f` h'),
    ("curl --cert key password backtick", 'curl --cert c.pem:`cat f` h'),
    ("curl -H backtick bearer", 'curl -H "Authorization: Bearer `cat f`" h'),
    ("curl -H backtick api key", 'curl -H "X-API-KEY: `cat f`" h'),
    ("curl -H backtick after the quote", "curl -H 'Authorization: Bearer '`cat f` h"),
    ("wget --header= backtick", 'wget --header="Authorization: token `cat f`" h'),
    # a spelling the closed world does not recognise as a non-password option is reported (#5631, #5635); these were
    # green when only the password spellings were read
    ("mysql --password-file is not --password (closed world: reported)", 'mysql -u r --password-file="$PW_FILE" db'),
    ("5464 mysql --pa is ambiguous, not --password (closed world: reported)", 'mysql -u r --pa="$X" db'),
    ("5464 mysql --pass-file is not --pass (closed world: reported)", 'mysql -u r --pass-file="$PW_FILE" db'),
    ("5502 mariadb --pa is ambiguous, not --password (closed world: reported)", 'mariadb -u r --pa="$X" db'),
    ("5502 mysql --loose-pa is ambiguous, not --password (closed world: reported)", 'mysql --loose-pa="$X" db'),
    ("5583 mysqlcheck --pass-file is not --pass (closed world: reported)", 'mysqlcheck --pass-file="$PW_FILE" db'),
    ("5583 mysqlimport -p then a space prompts (closed world: reported)", 'mysqlimport -u r -p "$DB_NAME" f'),
    ("5583 mysqlslap --pass_word is no option (closed world: reported)", 'mysqlslap --pass_word="$X"'),
    ("5583 mysqlcheck --pass-word is no option (closed world: reported)", 'mysqlcheck --pass-word="$X" db'),
    ("5583 an interactive mariadb --pa is ambiguous (closed world: reported)", 'mariadb --pa="$X" db'),
    ("5583 an interactive mysql.exe --loose_pa is ambiguous (closed world: reported)", 'mysql.exe --loose_pa="$X" db'),
    ("5582 mysql --loose_pa is ambiguous, not --password (closed world: reported)", 'mysql --loose_pa="$X" db'),
    ("5582 mysqldump --loose_password-file is not --password (closed world: reported)", 'mysqldump --loose_password-file="$PW_FILE" db'),
    ("5582 mysql --loose_pager is not --password (closed world: reported)", 'mysql --loose_pager="$PAGER_CMD" db'),
    ("5502 mysqldump --pass-file is not --pass (closed world: reported)", 'mysqldump --pass-file="$PW_FILE" db'),
    ("5502 mariadb-dump --loose-password-file is not --password (closed world: reported)", 'mariadb-dump --loose-password-file="$PW_FILE" db'),
    ('5630 closed world: reported 1: short clusters ending in -p are read letter by letter', 'mysqldump -uroot -hdb -Bp"$DB_PASSWORD" db'),
    ('5630 closed world: reported 2: short clusters ending in -p are read letter by letter', 'mysql -sp$P'),
    ('5630 closed world: reported 3: short clusters ending in -p are read letter by letter', 'mysql -sp"$P" db'),
    ('5630 closed world: reported 4: short clusters ending in -p are read letter by letter', 'mysql -vvp"$P" db'),
    ('5630 closed world: reported 5: short clusters ending in -p are read letter by letter', 'mysql -Bsp"${DB_PASSWORD}"'),
    ('5630 closed world: reported 6: short clusters ending in -p are read letter by letter', 'mysqlcheck -Aqp"$X"'),
    ('5635 closed world: reported 1: a long option is clean only when it is a measured non-password option', 'mysql --password1="$X" db'),
    ('5635 closed world: reported 2: a long option is clean only when it is a measured non-password option', 'mysql --encrypt-key="$X" db'),
    ('5635 closed world: reported 3: a long option is clean only when it is a measured non-password option', 'mysql -u r --loose_pass "$X" db'),
    ('5635 closed world: reported 4: a long option is clean only when it is a measured non-password option', 'mysql --LOOSE-password="$X" db'),
    ('5635 closed world: reported 5: a long option is clean only when it is a measured non-password option', 'mysql --enable-loose-password="$X" db'),
    ('5635 closed world: reported 6: a long option is clean only when it is a measured non-password option', 'mysql --skip-password="$X" db'),
    ('5635 closed world: reported 7: a long option is clean only when it is a measured non-password option', 'mysql --pager="$X" db'),
    ('5635 closed world: reported 8: a long option is clean only when it is a measured non-password option', 'mysql --uri "$URI"'),
    ('5635 closed world: reported 9: a long option is clean only when it is a measured non-password option', 'mysqldump --pa "$X" db'),
    ('5635 closed world: reported 10: a long option is clean only when it is a measured non-password option', 'mysqldump --p="$X" db'),
    ('5635 closed world: reported 11: a long option is clean only when it is a measured non-password option', 'mysql --password-file="$F" db'),
    ('5636 closed world: reported 1: an operand that follows a password command word is a credential', 'mysqladmin -u root password "$NEW"'),
    ('5636 closed world: reported 2: an operand that follows a password command word is a credential', 'mysqladmin password "x$NEW"'),
    ('5636 closed world: reported 3: an operand that follows a password command word is a credential', 'mysqladmin old-password "$X"'),
    ('5636 closed world: reported 4: an operand that follows a password command word is a credential', 'mariadb-admin pass "$X"'),
    ('5636 closed world: reported 5: an operand that follows a password command word is a credential', 'mysqladmin -u root password "new-${SUFFIX}"'),
    ('5637 closed world: reported 1: the value of -e, --execute and --init-command is not read as safe', 'mysql -e "ALTER USER x IDENTIFIED BY \'$P\'"'),
    ('5637 closed world: reported 2: the value of -e, --execute and --init-command is not read as safe', 'mysql --execute="SET PASSWORD=\'$P\'" db'),
    ('5637 closed world: reported 3: the value of -e, --execute and --init-command is not read as safe', 'mysql --init-command="SET PASSWORD=\'$P\'" db'),
    ('5637 closed world: reported 4: the value of -e, --execute and --init-command is not read as safe', 'mysql -e"SELECT \'$P\'"'),
    ('5637 closed world: reported 5: the value of -e, --execute and --init-command is not read as safe', 'mysql -u r -e "CREATE USER y IDENTIFIED BY \'${PW}\'" db'),
    ('5638 closed world: reported 1: a family head is read in any letter case', 'MySQLDump -p"$X" db'),
    ('5638 closed world: reported 2: a family head is read in any letter case', 'MariaDB-Dump --pa="$X" db'),
    ('5638 closed world: reported 3: a family head is read in any letter case', 'MYSQL.EXE -p"$X"'),
    ('5638 closed world: reported 4: a family head is read in any letter case', 'MySql -sp"$X"'),
    ('5638 closed world: reported 5: a family head is read in any letter case', 'Mysqladmin password "$X"'),
    ('5639 closed world: reported 1: an expansion-led operand before -- may be an option; after -- it is not', 'mysql ${ARGS} db'),
    ('5639 closed world: reported 2: an expansion-led operand before -- may be an option; after -- it is not', 'mysql $ARGS'),
    ('5639 closed world: reported 3: an expansion-led operand before -- may be an option; after -- it is not', 'mysql "$@"'),
    ('5639 closed world: reported 4: an expansion-led operand before -- may be an option; after -- it is not', 'mysql -h h $(cat args)'),
    ('5639 closed world: reported 5: an expansion-led operand before -- may be an option; after -- it is not', 'mysql -h "$H" -u "$U" "$DB"'),
    ('5639 closed world: reported 6: an expansion-led operand before -- may be an option; after -- it is not', 'mysql -u r -p "$DB_NAME" f'),
    ('5639 closed world: reported 7: an expansion-led operand before -- may be an option; after -- it is not', 'mysqldump -- db "$X" password "$Y"'),
    ('5631 closed world: reported 1: quoted words are read as the shell reads them', 'mysql "-p$P" db'),
    ('5631 closed world: reported 2: quoted words are read as the shell reads them', 'mysql "-p${DB_PASSWORD}" db'),
    ('5631 closed world: reported 3: quoted words are read as the shell reads them', 'mysqldump "--password=$DB_PASSWORD" db'),
    ('5631 closed world: reported 4: quoted words are read as the shell reads them', "mysql '-p$P' db"),
    ('5631 closed world: reported 5: quoted words are read as the shell reads them', 'mysql --pas"sword"="$X" db'),
    ('5631 closed world: reported 6: quoted words are read as the shell reads them', 'mysql --"password"="$X" db'),
    ('5631 closed world: reported 7: quoted words are read as the shell reads them', 'mysql -p"$X"'),
    ('5631 closed world: reported 8: quoted words are read as the shell reads them', 'ssh h "mysql -u r -p$X"'),
    ('5631 closed world: reported 9: quoted words are read as the shell reads them', 'bash -c "mysqldump -u r -p\\"$X\\" db | gzip"'),
    ('5631 closed world: reported 10: quoted words are read as the shell reads them', "sh -c 'mysql -p$P db'"),
    ('5682 red 1: every -e and --execute option of a wget command is read', 'wget -e robots=off -e "http_password=$X" URL'),
    ('5682 red 2: every -e and --execute option of a wget command is read', 'wget -e robots=off --execute "ftp_password=$X" URL'),
    ('5682 red 3: every -e and --execute option of a wget command is read', 'wget --exe robots=off --exec "http_password=$X" URL'),
    ('5682 red 4: every -e and --execute option of a wget command is read', 'wget -q -e robots=off -e timestamping=on -e "proxy_password=$X" URL'),
    ('5683 mutant pin: reported 1: the password command word of mysqladmin is matched in any letter case', 'mysqladmin PASSWORD "$X"'),
    ('5684 mutant pin: reported 1: an operand after old-password or pass is a credential when it is not led by a dollar sign', 'mysqladmin old-password "x$NEW"'),
    ('5684 mutant pin: reported 2: an operand after old-password or pass is a credential when it is not led by a dollar sign', 'mariadb-admin pass "x$X"'),
    ('5685 mutant pin: reported 1: an expansion inside a long option name is reported', 'mysql --$OPT db'),
    ('5689 mutant pin: reported 1: a head under a libexec directory is a command', '/usr/libexec/mysqlcheck --password="$X"'),
    ('5737 mutant pin: reported 1: a head under a libexec directory is a command even when no other pattern tags the line', '/usr/libexec/mysqlcheck -u r "$X"'),
    ('5746 mutant pin: reported 1: -p followed by a value-option letter still carries the password', 'mysql -ph$X db'),
    ('5746 mutant pin: reported 2: -p followed by a value-option letter still carries the password', 'mysql -pP"$X" db'),
    ('5820 wrapper pin: reported 1: sudo inside an ssh payload is read like sudo outside it', 'ssh dbhost "sudo mysql -uroot -p$X app"'),
    ('5820 wrapper pin: reported 2: exec inside a sh -c payload', 'sh -c "exec mysql -uroot -p$X"'),
    ('5820 wrapper pin: reported 3: sudo after a semicolon inside a single-quoted payload', "sh -c 'cd /x; sudo mysql -p$X'"),
    ('5820 wrapper pin: reported 4: timeout inside a docker exec payload', 'docker exec db bash -c "timeout 5 mysqladmin -uroot -p$X ping"'),
    ('5820 wrapper pin: reported 5: an env assignment inside a kubectl exec payload', "kubectl exec db -- sh -c 'FOO=x mysql -p$X'"),
    ('5821 substitution pin: reported 1: a head printed by command -v is the command word', '$(command -v mysql) -uroot -p"$X"'),
    ('5821 substitution pin: reported 2: a quoted which substitution', '"$(which mysqldump)" -uroot -p"$X" app'),
    ('5821 substitution pin: reported 3: sudo before a type -P substitution', 'sudo $(type -P mysql) -p"$X"'),
    ('5821 substitution pin: reported 4: a substitution inside a sh -c payload', 'sh -c "$(which mysql) -p$X"'),
    ('5821 substitution pin: reported 5: an escaped substitution in an ssh payload runs on the far side', 'ssh h "sudo \\$(which mysql) -p$X"'),
    ('5821 substitution pin: reported 6: nested substitutions', '$(realpath $(command -v mysql)) -p"$X"'),
    ('5683 mutant pin: reported 2: the password command word of mysqladmin is matched in any letter case', 'mysqladmin PASSWORD "x$NEW"'),
]
ROUND3_GREEN = [
    ("5583 mysqlpump --parallel-schemas is not --password", 'mysqlpump --parallel-schemas="$SCHEMA_LIST"'),
    ("5583 mysqlimport -P is the port", 'mysqlimport -P "$DB_PORT" db f'),
    ("5583 docker publish with a variable and no family client", 'docker run -p"$HOST_PORT:80" nginx'),
    ("5583 an environment variable name is not a family client", 'docker run -e MYSQL_ROOT_PASSWORD -p"$HOST_PORT:3306" img'),
    ("5583 a tool whose name only ends in a client name is no client", 'xmysql -p"$DB_PASSWORD"'),
    ("5583 a later command after && is not an argument of the client", 'mysqldump db && echo -p"$DB_PASSWORD"'),
    ("5583 an assignment named like a client is no command", 'mysql_args=(-x -p"$DB_PASSWORD")'),
    ("5583 a mariadb-named assignment is no command", 'mariadb_opts="-x --password=$DB_PASSWORD"'),
    ("redis-cli --pass-file is not --pass", 'redis-cli --pass-file "$PW_FILE" ping'),
    ("wget -e non-credential settings", 'wget -e robots=off -e "https_proxy=$PROXY_HOST" -O "$TOKEN_FILE" h'),
    ("wget --passive-ftp is not a password option", 'wget --passive-ftp -O "$TOKEN_FILE" h'),
    ("curl --tlsuser is not a password", 'curl --tlsuser "$TLS_USER" h'),
    ("curl output file with an ANSI-C word", "curl -o \"$TOKEN_FILE\" $'h'"),
    ("curl --user-agent= is not --user", 'curl --user-agent="$UA" h'),
    ("wget -U is the user agent", 'wget -U "$UA" h'),
    ("curl -E with a file only", 'curl -E "$CERT_PATH" h'),
    ("curl -E with a default file", 'curl -E "${CERT_FILE:-/x.pem}" h'),
    ("curl body from stdin", 'curl --data @- https://h/ < "$TOKEN_FILE"'),
    ("curl config from stdin", 'curl -K - https://h/ < "$TOKEN_FILE"'),
    ("docker login --password-stdin", 'docker login -u u --password-stdin reg < "$TOKEN_FILE"'),
    ("ssh payload non-credential header", 'ssh h "curl -sH \\"X-Request-Id: $REQ_ID\\" h"'),
    ("curl -sH non-credential header", 'curl -sH "X-Request-Id: $REQ_ID" h'),
    ("sort -u after curl", 'curl -o "$OUT" h && sort -u "$TOKEN_FILE"'),
    ("curl --cert-type is not --cert", 'curl --cert-type=P12:$CERT_TYPE -o "$TOKEN_FILE" h'),
    ('5630 closed world: clean 1: short clusters ending in -p are read letter by letter', 'mysql -hp$P db'),
    ('5630 closed world: clean 2: short clusters ending in -p are read letter by letter', 'mysql -sh"$H" db'),
    ('5630 closed world: clean 3: short clusters ending in -p are read letter by letter', 'mysql -u"$U" -h"$H" db'),
    ('5630 closed world: clean 4: short clusters ending in -p are read letter by letter', 'mysql -Bs db'),
    ('5635 closed world: clean 1: a long option is clean only when it is a measured non-password option', 'mysql --host "$H" --user "$U" --port "$P" db'),
    ('5635 closed world: clean 2: a long option is clean only when it is a measured non-password option', 'mysql --defaults-file="$F" db'),
    ('5635 closed world: clean 3: a long option is clean only when it is a measured non-password option', 'mysql --login-path="$LP" db'),
    ('5635 closed world: clean 4: a long option is clean only when it is a measured non-password option', 'mysql --defaults-extra-file="$F" db'),
    ('5635 closed world: clean 5: a long option is clean only when it is a measured non-password option', 'mysql --po="$P" db'),
    ('5635 closed world: clean 6: a long option is clean only when it is a measured non-password option', 'mysql --loose-port="$P" db'),
    ('5635 closed world: clean 7: a long option is clean only when it is a measured non-password option', 'mysql --skip-ssl --ssl-key="$K" db'),
    ('5635 closed world: clean 8: a long option is clean only when it is a measured non-password option', 'mysql --user="$U" --database="$D"'),
    ('5636 closed world: clean 1: an operand that follows a password command word is a credential', 'mysqladmin -u root status'),
    ('5636 closed world: clean 2: an operand that follows a password command word is a credential', 'mysqladmin ping -h "$H"'),
    ('5636 closed world: clean 3: an operand that follows a password command word is a credential', 'mysqladmin -h "$H" -- status'),
    ('5637 closed world: clean 1: the value of -e, --execute and --init-command is not read as safe', 'mysql -e "SELECT 1" db'),
    ('5637 closed world: clean 2: the value of -e, --execute and --init-command is not read as safe', "mysql --execute='SELECT 1' db"),
    ('5637 closed world: clean 3: the value of -e, --execute and --init-command is not read as safe', 'mysql -u "$U" -e "SHOW TABLES" db'),
    ('5638 closed world: clean 1: a family head is read in any letter case', 'MYSQL_PWD="$PW" mysql -u root db'),
    ('5638 closed world: clean 2: a family head is read in any letter case', 'MYSQL_HOST="$H" ./run.sh'),
    ('5638 closed world: clean 3: a family head is read in any letter case', 'export MYSQL_ROOT_PASSWORD="$X"'),
    ('5639 closed world: clean 1: an expansion-led operand before -- may be an option; after -- it is not', 'mysql -h "$H" -- "$DB"'),
    ('5639 closed world: clean 2: an expansion-led operand before -- may be an option; after -- it is not', 'mysql -h h -- "$DB" "$TABLE"'),
    ('5639 closed world: clean 3: an expansion-led operand before -- may be an option; after -- it is not', 'mysql -h "$H" db'),
    ('5631 closed world: clean 1: quoted words are read as the shell reads them', 'apt-get install -y mysql-client "$PKG"'),
    ('5631 closed world: clean 2: quoted words are read as the shell reads them', 'chown -R mysql:mysql "$DIR"'),
    ('5631 closed world: clean 3: quoted words are read as the shell reads them', 'curl http://mysql:3306/$X'),
    ('5682 green 1: every -e and --execute option of a wget command is read', 'wget -e robots=off -e timestamping=on URL'),
    ('5682 green 2: every -e and --execute option of a wget command is read', 'wget -e robots=off --execute "dirstruct=off" "$URL"'),
    ('5686 mutant pin: clean 1: the maximum- prefix of a long option is read', 'mysql --maximum-max-allowed-packet="$X" db'),
    ('5687 mutant pin: clean 1: the -v letter takes no value', 'mysqldump -v "pre$DB"'),
    ('5688 mutant pin: clean 1: the -S letter takes a socket value', 'mysql -S "$SOCK" db'),
    ('5690 mutant pin: clean 1: a command substitution that closes ends the command', 'v=$(mysql -N --foo=r) $X'),
    ('5694 mutant pin: clean 1: the target of a redirect is not an operand', 'mysql db < "$FILE"'),
    ('5694 mutant pin: clean 2: the target of a redirect is not an operand', 'mysqldump -u r db > "$OUT"'),
    ('5696 mutant pin: clean 1: an escaped space stays inside its word', 'mysql -u r x\\ "$Y"'),
    ('5697 mutant pin: clean 1: a head inside an echoed quoted string is not a command', 'echo "restoring mysql $DB"'),
    ('5697 mutant pin: clean 2: a head inside an echoed quoted string is not a command', 'echo "see mysql -p$X"'),
    ('5729 mutant pin: clean 1: a semicolon ends the mysql command', 'mysql -u r db; echo "$X"'),
    ('5729 mutant pin: clean 2: a pipe ends the mysql command', 'mysql -u r db | grep "$X"'),
    ('5738 mutant pin: clean 1: a semicolon ends the wget command', 'wget -q URL; ls -e "http_password=$X"'),
    ('5738 mutant pin: clean 2: a pipe ends the wget command', 'wget URL | tee -e "http_password=$X"'),
    ('5820 wrapper pin: clean 1: a wrapper inside an echoed string is no command', 'echo "run sudo mysql -p$X"'),
    ('5820 wrapper pin: clean 2: a wrapper inside a printf operand is no command', "printf '%s\\n' \"now sudo mysql -p$X\""),
    ('5820 wrapper pin: clean 3: a wrapped head in a payload with clean words', 'ssh h "sudo mysql -uroot -h $H app"'),
    ('5821 substitution pin: clean 1: a substitution glued to a word is no command word', 'x$(command -v mysql) "$X"'),
    ('5821 substitution pin: clean 2: a substitution head with clean words', '$(command -v mysql) -uroot -h "$H" app'),
    ('5821 substitution pin: clean 3: a substitution that is an echo operand', 'echo "$(mysql --version)" "$X"'),
]

# Raw logical-line text that holds a newline (the arm is a function of text; every unit the gate builds today is
# joined with spaces): a newline ends the command like a semicolon does (#5691).
ROUND3_MYSQL_RAW_GREEN = [
    ("5691 mutant pin: a newline ends the mysql command", 'mysql -u r db\necho "$X"'),
    ("5695 mutant pin: a literal value glued to -p is not this arm's concern", 'mysql ' + '-p' + 'Secret db'),
]
# Dockerfile continuations: comment lines, blank lines, CRLF and the escape directive (#4995)
ROUND3_DOCKER_RED = [
    ("CRLF continuation", 'FROM x\r\nRUN apk add y \\\r\n  && curl -u "u:$X" h\r\n'),
    ("CRLF comment in continuation", 'FROM x\r\nRUN apk add y \\\r\n  # note\r\n  && curl -u "u:$X" h\r\n'),
    ("comment, blank, comment ending in a backslash",
     'FROM x\nRUN apk add y \\\n  # note\n\n  # more \\\n  && curl -sH "Authorization: Bearer $X" h\n'),
    ("escape directive with a comment", '# escape=`\nFROM x\nRUN apk add y `\n  # note\n  && curl -su "u:$X" h\n'),
]
ROUND3_DOCKER_GREEN = [
    ("a credential only in a comment line", 'FROM x\nRUN apk add y \\\n  # curl -u "u:$X" h\n  && true\n'),
]


def round3_probe_cases(dl) -> Tuple[List[str], int]:
    """Red probes are denylist-tagged and refused for allow; green probes are not tagged and,
    when triggered, an allow entry approves them through the real gate checks."""
    bad: List[str] = []
    n = 0
    for label, line in ROUND3_RED:
        n += 1
        res = scan_exec_file(dl, "c.sh", "#!/bin/bash\n%s\n" % line) or []
        if not any("denylist" in r[2] for r in res):
            bad.append("round-3 red probe is not tagged denylist: %s" % label)
        elif not check_allow_vs_denylist({"c.sh": res}, [("reason: r", "c.sh", 1, norm(line), 1)]):
            bad.append("round-3 red probe could be allowed: %s" % label)
    for label, line in ROUND3_GREEN:
        n += 1
        res = scan_exec_file(dl, "c.sh", "#!/bin/bash\n%s\n" % line) or []
        ent = [("reason: r", "c.sh", 1, r[1], 1) for r in res]
        if any("denylist" in r[2] for r in res) or check_allow_vs_denylist({"c.sh": res}, ent) or \
                judge({"c.sh": res}, ent, [], dl)[0]:
            bad.append("round-3 green probe is not allow-able: %s" % label)
    for label, text in ROUND3_MYSQL_RAW_GREEN:
        n += 1
        if mysql_family_hit(text):
            bad.append("round-3 raw mysql green probe was reported: %s" % label)
    for label, text in ROUND3_DOCKER_RED:
        n += 1
        if not any("denylist" in r[2] for r in scan_exec_file(dl, "Dockerfile", text) or []):
            bad.append("round-3 Dockerfile probe hid the credential line: %s" % label)
    for label, text in ROUND3_DOCKER_GREEN:
        n += 1
        if any("denylist" in r[2] for r in scan_exec_file(dl, "Dockerfile", text) or []):
            bad.append("round-3 Dockerfile green probe was tagged: %s" % label)
    return bad, n


def _run_wiring_cases(root: Path, t: Path) -> Tuple[List[str], int]:
    """Drive run() on a throwaway git repository under .local-runs. A control whose helper is
    proved elsewhere must also change the exit code of the real gate path (#4910)."""
    import shutil
    bad: List[str] = []
    keys = ("EXEC_SECRET_ARGV_BASE", "GITHUB_BASE_REF", "GITHUB_ACTIONS", "CI")
    saved = {k: os.environ.get(k) for k in keys}
    ok_line = "export API_TOKEN"
    deny_line = 'mysql -u r -p"$PW" db'
    pl = "x --token $T"
    base_ref = "refs/remotes/origin/self-test-base"

    def git(*a: str) -> str:
        return subprocess.run(["git", "-C", str(t), "-c", "user.name=self-test", "-c",
                               "user.email=self-test@invalid", "-c", "commit.gpgsign=false"] + list(a),
                              check=True, capture_output=True).stdout.decode("utf-8", "replace")

    def lists(allow: List[str], pend: List[str], rel: str = "a.sh") -> None:
        (t / ALLOW_FILE).write_text("".join("reason: self-test | %s | 1 | %s\n" % (rel, x) for x in allow))
        (t / PENDING_FILE).write_text("".join("#1 | %s | 1 | %s\n" % (rel, x) for x in pend))

    cases = [0]  # every driven run() and every regen main() call is one case: the count cannot drift (#5303)

    def gate(**env: str) -> Tuple[int, str]:
        cases[0] += 1
        for k in keys:
            os.environ.pop(k, None)
        os.environ.update(env)
        out = io.StringIO()
        with contextlib.redirect_stderr(out), contextlib.redirect_stdout(out):
            rc = run(t)
        return rc, out.getvalue()

    def from_pending(msg: str) -> None:
        git("reset", "-q", "--hard", base_ref)
        git("clean", "-q", "-fdx")
        git("add", "-A")
        git("commit", "-q", "--allow-empty", "-m", msg)

    try:
        (t / "scripts" / "qc-allowlists").mkdir(parents=True)
        shutil.copy(str(root / DENYLIST), str(t / DENYLIST))
        (t / "a.sh").write_text("#!/bin/bash\n%s\n" % ok_line)
        lists([ok_line], [])
        git("init", "-q")
        git("add", "-A")
        git("commit", "-q", "-m", "base")
        rc, out = gate()
        if rc != 0:
            return ["the run() wiring fixture is not green (%d): %s" % (rc, out.strip()[:160])], cases[0]
        # outside CI with no base named the run says the merge-base rule was not evaluated (#4996)
        if "NOT evaluated" not in out or "merge-base rule not evaluated" not in out:
            bad.append("run() outside CI with no base did not say the merge-base rule was not evaluated (#4996)")
        # in CI with no base named the run is a FAULT: unresolved means red (#4996)
        if gate(GITHUB_ACTIONS="true")[0] != 2:
            bad.append("run() in GitHub Actions with no merge base named passed (#4996)")
        if gate(CI="true")[0] != 2:
            bad.append("run() in CI with no merge base named passed (#4996)")
        # an empty allowlist and no triggered line are faults of run(), not only of the helper
        lists([], [])
        (t / "a.sh").write_text("#!/bin/bash\ntrue\n")
        if gate()[0] != 2:
            bad.append("run() passed an empty scan (#4910)")
        # an allow entry for a denylist-flagged line is red in run()
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n" % (ok_line, deny_line))
        lists([ok_line, deny_line], [])
        if gate()[0] != 1:
            bad.append("run() let an allow entry approve a denylist-flagged line (#4910)")
        # an executable file with no scan class is a fault of run() (#4923)
        (t / "a.sh").write_text("#!/bin/bash\n%s\n" % ok_line)
        lists([ok_line], [])
        (t / "tool.bin").write_text("plain data\n")
        os.chmod(str(t / "tool.bin"), 0o755)
        git("add", "tool.bin")
        if gate()[0] != 2:
            bad.append("run() passed an executable file with no scan class (#4923)")
        git("rm", "-q", "--cached", "tool.bin")
        (t / "tool.bin").unlink()
        # a line pending at the merge base cannot move to allow by a list edit (#4919): both base sources
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n" % (ok_line, pl))
        lists([ok_line], [pl])
        git("add", "-A")
        git("commit", "-q", "-m", "pending")
        git("update-ref", base_ref, "HEAD")
        lists([ok_line, pl], [])
        git("add", "-A")
        git("commit", "-q", "-m", "launder")
        if gate(EXEC_SECRET_ARGV_BASE=base_ref)[0] != 1:
            bad.append("run() let an allow entry approve a line pending at the merge base (#4919)")
        if gate(GITHUB_BASE_REF="self-test-base")[0] != 1:
            bad.append("run() ignored GITHUB_BASE_REF for the merge-base check (#4919)")
        if gate(EXEC_SECRET_ARGV_BASE="refs/heads/no-such-base")[0] != 2:
            bad.append("run() passed with a merge base it cannot resolve (#4919)")
        # the same move with an unrelated edit of the file is still refused (#4996)
        from_pending("edit")
        (t / "a.sh").write_text("#!/bin/bash\n# note\n%s\n%s\n" % (ok_line, pl))
        lists([ok_line, pl], [])
        git("add", "-A")
        git("commit", "-q", "-m", "edit and launder")
        if gate(EXEC_SECRET_ARGV_BASE=base_ref, GITHUB_ACTIONS="true")[0] != 1:
            bad.append("run() let a pending line move to allow next to an unrelated edit of its file (#4996)")
        # ... and with a rename of the file (#4996)
        from_pending("rename")
        git("mv", "a.sh", "b.sh")
        lists([ok_line, pl], [], "b.sh")
        git("add", "-A")
        git("commit", "-q", "-m", "rename and launder")
        if gate(EXEC_SECRET_ARGV_BASE=base_ref)[0] != 1:
            bad.append("run() let a pending line move to allow under a renamed file (#4996)")
        # ... and as a lightly edited copy of the line (#5103)
        from_pending("cosmetic")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n" % (ok_line, pl + "2"))
        lists([ok_line, pl + "2"], [])
        git("add", "-A")
        git("commit", "-q", "-m", "cosmetic edit and launder")
        if gate(EXEC_SECRET_ARGV_BASE=base_ref)[0] != 1:
            bad.append("run() let an edited copy of a pending line move to allow (#5103)")
        # a real fix takes the line off the argv: no entry is needed and the run is green
        from_pending("fix")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n" % ok_line)
        lists([ok_line], [])
        git("add", "-A")
        git("commit", "-q", "-m", "fix")
        rc, out = gate(EXEC_SECRET_ARGV_BASE=base_ref, GITHUB_ACTIONS="true")
        if rc != 0:
            bad.append("run() refused a real fix of a pending line (%d): %s" % (rc, out.strip()[:160]))
        # base 2: the pending line of a.sh is also allowed in c.sh, so the text-counted rule skips it
        # and only the (file, text) rule with the rename map can see the move (#4996)
        base2 = "refs/remotes/origin/self-test-base2"

        def rows(allow: List[Tuple[str, str]], pend: List[Tuple[str, str]]) -> None:
            (t / ALLOW_FILE).write_text("".join("reason: self-test | %s | 1 | %s\n" % r for r in allow))
            (t / PENDING_FILE).write_text("".join("#1 | %s | 1 | %s\n" % r for r in pend))

        def from_base2(msg: str) -> None:
            git("reset", "-q", "--hard", base2)
            git("clean", "-q", "-fdx")
            git("add", "-A")
            git("commit", "-q", "--allow-empty", "-m", msg)

        def commit_all(msg: str) -> None:
            git("add", "-A")
            git("commit", "-q", "-m", msg)

        git("reset", "-q", "--hard", base_ref)
        (t / "c.sh").write_text("#!/bin/bash\n%s\n" % pl)
        rows([("a.sh", ok_line), ("c.sh", pl)], [("a.sh", pl)])
        commit_all("base2")
        git("update-ref", base2, "HEAD")
        rc, out = gate(EXEC_SECRET_ARGV_BASE=base2)
        if rc != 0:
            bad.append("the second merge-base fixture is not green (%d): %s" % (rc, out.strip()[:160]))
        # the base pending list is unreadable (git show fails): a FAULT, not an empty list (#5297)
        blob = git("rev-parse", "%s:%s" % (base2, PENDING_FILE)).strip()
        loose = t / ".git" / "objects" / blob[:2] / blob[2:]
        if not loose.is_file():
            bad.append("the unreadable-base case could not find the loose blob (#5297)")
        else:
            aside = t / ".git" / "unreadable-blob"
            loose.rename(aside)
            try:
                if gate(EXEC_SECRET_ARGV_BASE=base2)[0] != 2 or \
                        gate(EXEC_SECRET_ARGV_BASE=base2, GITHUB_ACTIONS="true")[0] != 2:
                    bad.append("run() passed when the base pending list could not be read (#5297)")
            finally:
                aside.rename(loose)
        # a missing TREE object: show fails and so does ls-tree, which must not read as "absent" (#5297).
        # The change touches nothing under scripts/, so the diff of the two trees does not descend into it.
        git("reset", "-q", "--hard", base2)
        git("commit", "-q", "--allow-empty", "-m", "nothing under scripts")
        tree = git("rev-parse", "%s:scripts" % base2).strip()
        lost = t / ".git" / "objects" / tree[:2] / tree[2:]
        if not lost.is_file():
            bad.append("the missing-tree case could not find the loose tree object (#5297)")
        else:
            aside = t / ".git" / "missing-tree"
            lost.rename(aside)
            try:
                rc, out = gate(EXEC_SECRET_ARGV_BASE=base2)
                # the message names the merge base: the history scan (#5299) also faults on this repository,
                # and only the message tells the two apart
                if rc != 2 or "cannot resolve the merge base" not in out:
                    bad.append("run() read a base whose tree object is missing as an absent list (%d): %s"
                               % (rc, out.strip()[:160]))
            finally:
                aside.rename(lost)
        # a base without the list files is proven absent, not unreadable: green (#5297)
        git("rm", "-q", "--", ALLOW_FILE, PENDING_FILE)
        commit_all("lists absent")
        git("update-ref", "refs/remotes/origin/self-test-base3", "HEAD")
        git("rm", "-q", "--ignore-unmatch", "c.sh")
        (t / ALLOW_FILE).parent.mkdir(parents=True, exist_ok=True)
        rows([("a.sh", ok_line)], [("a.sh", pl)])  # no allow entry for pending text: the F3 rule stays quiet
        commit_all("lists back")
        rc, out = gate(EXEC_SECRET_ARGV_BASE="refs/remotes/origin/self-test-base3")
        if rc != 0:
            bad.append("run() refused a base where the list files do not exist (%d): %s" % (rc, out.strip()[:160]))
        # copy then move (#5295): step 1 allows the pending text in a new file, step 2 moves the line
        # there with a count bump. Both are refused, the second against the first as its base.
        step1, step2 = "refs/remotes/origin/self-test-step1", "refs/remotes/origin/self-test-step2"
        from_base2("copy1")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n" % (ok_line, pl))
        (t / "w.sh").write_text("#!/bin/bash\n%s\n" % pl)
        rows([("a.sh", ok_line), ("c.sh", pl), ("w.sh", pl)], [("a.sh", pl)])
        commit_all("copy the pending line into an allowing file")
        git("update-ref", step1, "HEAD")
        if gate(EXEC_SECRET_ARGV_BASE=base2)[0] != 1:
            bad.append("run() let a pending line be allowed as a copy in another file (#5295)")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n" % ok_line)
        (t / "w.sh").write_text("#!/bin/bash\n%s\n%s\n" % (pl, pl))
        (t / ALLOW_FILE).write_text("reason: self-test | a.sh | 1 | %s\nreason: self-test | c.sh | 1 | %s\n"
                                    "reason: self-test | w.sh | 2 | %s\n" % (ok_line, pl, pl))
        (t / PENDING_FILE).write_text("")
        commit_all("move the pending line into the allowing file")
        git("update-ref", step2, "HEAD")
        if gate(EXEC_SECRET_ARGV_BASE=step1)[0] != 1:
            bad.append("run() let a pending line move into a file that allows its text with a count bump (#5295)")
        from_base2("rename2")
        git("mv", "a.sh", "b.sh")
        git("rm", "-q", "c.sh")
        rows([("b.sh", ok_line), ("b.sh", pl)], [])
        commit_all("rename, drop the allowed copy and launder")
        if gate(EXEC_SECRET_ARGV_BASE=base2)[0] != 1:
            bad.append("run() let a pending line move to allow under a renamed file when its text is "
                       "also allowed elsewhere (#4996)")
        from_base2("move2")
        git("rm", "-q", "c.sh")
        rows([("a.sh", ok_line), ("a.sh", pl)], [])
        commit_all("drop the allowed copy and launder")
        if gate(EXEC_SECRET_ARGV_BASE=base2)[0] != 1:
            bad.append("run() let a pending line move to allow when its text is also allowed elsewhere (#4919)")
        # a new line that only looks like a line still pending is not a launder of that line, but its file
        # had a pending row at the base, so since #5298 (5-agent vote 4d3ea1c5) the new entry is refused
        from_base2("near2")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n%s\n" % (ok_line, pl, pl + "2"))
        rows([("a.sh", ok_line), ("c.sh", pl), ("a.sh", pl + "2")], [("a.sh", pl)])
        commit_all("a new line near a line that stays pending")
        rc, out = gate(EXEC_SECRET_ARGV_BASE=base2)
        if rc != 1 or "no allow entry may be added or raised" not in out:
            bad.append("run() let a new line near a still-pending line into its file (%d): %s"
                       % (rc, out.strip()[:160]))
        # a real fix of the pending line keeps the copy allowed at the base: green
        from_base2("fix2")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n" % ok_line)
        rows([("a.sh", ok_line), ("c.sh", pl)], [])
        commit_all("fix the pending line")
        rc, out = gate(EXEC_SECRET_ARGV_BASE=base2)
        if rc != 0:
            bad.append("run() refused a real fix next to an allow entry kept from the base (%d): %s"
                       % (rc, out.strip()[:160]))
        # #5298 (5-agent vote 4d3ea1c5): no allow entry is added or raised in a file that had a pending
        # row at the base. base2 holds a pending row in a.sh; a.sh stays pending in every case below.
        nl = "export SERVICE_PASSWORD"
        from_base2("freeze new")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n%s\n" % (ok_line, pl, nl))
        rows([("a.sh", ok_line), ("c.sh", pl), ("a.sh", nl)], [("a.sh", pl)])
        commit_all("a new allow entry in a file with a pending row")
        if gate(EXEC_SECRET_ARGV_BASE=base2)[0] != 1:
            bad.append("run() let a new allow entry into a file that had a pending row at the base (#5298)")
        from_base2("freeze other file")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n" % (ok_line, pl))
        (t / "d.sh").write_text("#!/bin/bash\n%s\n" % nl)
        rows([("a.sh", ok_line), ("c.sh", pl), ("d.sh", nl)], [("a.sh", pl)])
        commit_all("a new allow entry in a file with no pending row")
        rc, out = gate(EXEC_SECRET_ARGV_BASE=base2)
        if rc != 0:
            bad.append("run() refused a new allow entry in a file with no pending row (%d): %s"
                       % (rc, out.strip()[:160]))
        from_base2("freeze raise")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n%s\n" % (ok_line, ok_line, pl))
        (t / ALLOW_FILE).write_text("reason: self-test | a.sh | 2 | %s\nreason: self-test | c.sh | 1 | %s\n"
                                    % (ok_line, pl))
        commit_all("a raised allow count in a file with a pending row")
        if gate(EXEC_SECRET_ARGV_BASE=base2)[0] != 1:
            bad.append("run() let an allow count be raised in a file that had a pending row at the base (#5298)")
        from_base2("freeze removed")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n" % (ok_line, nl))
        rows([("a.sh", ok_line), ("c.sh", pl), ("a.sh", nl)], [])
        commit_all("the pending row is removed and a new allow entry added in the same file")
        if gate(EXEC_SECRET_ARGV_BASE=base2)[0] != 1:
            bad.append("run() let a new allow entry in when the same change removed the pending row (#5298)")
        from_base2("freeze rename")
        git("mv", "a.sh", "b.sh")
        (t / "b.sh").write_text("#!/bin/bash\n%s\n%s\n%s\n" % (ok_line, pl, nl))
        rows([("b.sh", ok_line), ("c.sh", pl), ("b.sh", nl)], [("b.sh", pl)])
        commit_all("a renamed file with a pending row gets a new allow entry")
        if gate(EXEC_SECRET_ARGV_BASE=base2)[0] != 1:
            bad.append("run() let a new allow entry into a renamed file that had a pending row (#5298)")
        from_base2("freeze rename unchanged")
        git("mv", "a.sh", "b.sh")
        rows([("b.sh", ok_line), ("c.sh", pl)], [("b.sh", pl)])
        commit_all("a renamed file with a pending row keeps its allow entries unchanged")
        rc, out = gate(EXEC_SECRET_ARGV_BASE=base2)
        if rc != 0:
            bad.append("run() judged an unchanged allow entry again in a renamed frozen file (%d): %s"
                       % (rc, out.strip()[:160]))
        # #5420: an allow entry that is unchanged except for its file's rename is not judged again, also
        # when its text is pending in another file (the rename map in allow_text_pending_elsewhere)
        from_base2("rename unchanged elsewhere")
        git("mv", "c.sh", "e.sh")
        rows([("a.sh", ok_line), ("e.sh", pl)], [("a.sh", pl)])
        commit_all("the file that allows a text pending elsewhere is renamed")
        rc, out = gate(EXEC_SECRET_ARGV_BASE=base2)
        if rc != 0:
            bad.append("run() judged an unchanged allow entry again after a rename (text pending elsewhere) "
                       "(%d): %s" % (rc, out.strip()[:160]))
        # #5295: the text of a pending row added in THIS change (pending at head, not at the base) is
        # not approved by a new allow entry in another file either
        from_base2("head pending")
        (t / "d.sh").write_text("#!/bin/bash\n%s\n" % nl)
        (t / "e.sh").write_text("#!/bin/bash\n%s\n" % nl)
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n" % (ok_line, pl))
        rows([("a.sh", ok_line), ("c.sh", pl), ("d.sh", nl)], [("a.sh", pl), ("e.sh", nl)])
        commit_all("a pending row and a new allow entry with the same text in one change")
        rc, out = gate(EXEC_SECRET_ARGV_BASE=base2)
        if rc != 1 or "pending in a file" not in out:
            bad.append("run() let a new allow entry approve a text that is pending only at head (%d): %s"
                       % (rc, out.strip()[:160]))
        # #5299 (5-agent vote 4d3ea1c5): a pending row that an earlier change removed may not come back
        # as an allow entry with its exact text; the merge base no longer has the row, only history does
        from_base2("hist fix")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n" % ok_line)
        rows([("a.sh", ok_line), ("c.sh", pl)], [])
        commit_all("the pending row is removed with a real fix")
        hist_base = "refs/remotes/origin/self-test-hist"
        git("update-ref", hist_base, "HEAD")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n" % (ok_line, pl))
        rows([("a.sh", ok_line), ("c.sh", pl), ("a.sh", pl)], [])
        commit_all("the removed pending text comes back as an allow entry")
        rc, out = gate(EXEC_SECRET_ARGV_BASE=hist_base)
        if rc != 1 or "removed in commit" not in out:
            bad.append("run() let the exact text of a removed pending row back in as an allow entry "
                       "(%d): %s" % (rc, out.strip()[:160]))
        # ... an unrelated new allow entry is green
        git("reset", "-q", "--hard", hist_base)
        (t / "d.sh").write_text("#!/bin/bash\n%s\n" % nl)
        rows([("a.sh", ok_line), ("c.sh", pl), ("d.sh", nl)], [])
        commit_all("an unrelated allow entry")
        rc, out = gate(EXEC_SECRET_ARGV_BASE=hist_base)
        if rc != 0:
            bad.append("run() refused an allow entry unrelated to any removed pending row (%d): %s"
                       % (rc, out.strip()[:160]))
        # ... an entry whose text was pending once, unchanged except that its file was renamed, is not judged again
        git("reset", "-q", "--hard", hist_base)
        git("mv", "c.sh", "e.sh")
        rows([("a.sh", ok_line), ("e.sh", pl)], [])
        commit_all("a renamed file keeps an allow entry whose text was pending once")
        rc, out = gate(EXEC_SECRET_ARGV_BASE=hist_base)
        if rc != 0:
            bad.append("run() judged an unchanged allow entry again after its file was renamed (%d): %s"
                       % (rc, out.strip()[:160]))
        # ... a shallow clone cannot answer, so the run is red and says how to fetch the history
        shallow = t.parent / (t.name + "-shallow")
        shutil.rmtree(str(shallow), ignore_errors=True)
        subprocess.run(["git", "clone", "-q", "--depth", "1", "file://" + str(t), str(shallow)],
                       check=True, capture_output=True)
        shutil.copy(str(root / DENYLIST), str(shallow / DENYLIST))
        shutil.copy(str(root / "scripts" / "check-exec-secret-argv.py"), str(shallow / "scripts"))
        cases[0] += 1
        for k in keys:
            os.environ.pop(k, None)
        os.environ["EXEC_SECRET_ARGV_BASE"] = "HEAD"
        out = io.StringIO()
        with contextlib.redirect_stderr(out), contextlib.redirect_stdout(out):
            rc = run(shallow)
        if rc != 2 or "shallow" not in out.getvalue() or "fetch" not in out.getvalue():
            bad.append("run() passed or gave no remedy on a shallow clone (%d): %s" % (rc, out.getvalue().strip()[:160]))
        shutil.rmtree(str(shallow), ignore_errors=True)
        # the scan itself: the list renamed between two paths is followed, and a list with no history is a fault
        hist = t.parent / (t.name + "-hist")
        shutil.rmtree(str(hist), ignore_errors=True)
        hist.mkdir(parents=True)

        def h(*a: str) -> None:
            subprocess.run(["git", "-C", str(hist), "-c", "user.name=self-test", "-c", "user.email=self-test@invalid",
                            "-c", "commit.gpgsign=false"] + list(a), check=True, capture_output=True)

        h("init", "-q")
        (hist / "README").write_text("x\n")
        (hist / "old-pending.txt").write_text("".join("#1 | a%d.sh | 1 | %s%d\n" % (i, pl, i) for i in range(4)))
        h("add", "-A")
        h("commit", "-q", "-m", "one")
        (hist / "old-pending.txt").write_text("".join("#1 | a%d.sh | 1 | %s%d\n" % (i, pl, i) for i in range(1, 4)))
        h("commit", "-q", "-a", "-m", "two")
        (hist / PENDING_FILE).parent.mkdir(parents=True, exist_ok=True)
        h("mv", "old-pending.txt", PENDING_FILE)
        h("commit", "-q", "-m", "three")
        cases[0] += 1
        try:
            gone = removed_pending_rows(hist)
        except RuntimeError as exc:
            gone = {}
            bad.append("the history scan faulted on a renamed list (%s)" % exc)
        if pl + "0" not in gone or pl + "1" in gone:
            bad.append("the history scan did not follow the renamed list or named a kept row (%s)" % sorted(gone))
        cases[0] += 1
        shutil.rmtree(str(hist / ".git"))
        h("init", "-q")
        (hist / "README").write_text("x\n")
        h("add", "README")
        h("commit", "-q", "-m", "no history for the list")
        try:
            removed_pending_rows(hist)
            bad.append("a list with no history was an empty answer, not a fault (#5299)")
        except RuntimeError as exc:
            if "empty" not in str(exc):
                bad.append("a list with no history faulted with the wrong message (%s)" % exc)
        shutil.rmtree(str(hist), ignore_errors=True)
        # regen main(): a pending row pruned from the working tree but committed at HEAD is still
        # refused for allow by --accept-new (#4996), through the real argument path
        from_base2("regen")
        pr = "unset API_TOKEN"
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n%s\n" % (ok_line, pl, pr))
        rows([("a.sh", ok_line), ("c.sh", pl)], [("a.sh", pl), ("a.sh", pr)])
        commit_all("a second pending line")
        rows([("a.sh", ok_line), ("c.sh", pl)], [("a.sh", pl)])
        shutil.copy(str(root / "scripts" / "check-exec-secret-argv.py"), str(t / "scripts"))
        spec = importlib.util.spec_from_file_location("regen_self_test",
                                                      str(root / "scripts" / "regen-exec-secret-argv-allow.py"))
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load the regen tool for the self-test")
        regen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(regen)  # type: ignore[union-attr]
        cases[0] += 1
        out = io.StringIO()
        with contextlib.redirect_stderr(out), contextlib.redirect_stdout(out):
            rc = regen.main(["regen", "--accept-new", "--why", "reason: self-test", "--match", "unset",
                             "--root", str(t)])
        if rc != 1 or "the line is pending" not in out.getvalue():
            bad.append("regen --accept-new approved a pending line pruned before the run (%d): %s"
                       % (rc, out.getvalue().strip()[:160]))
        # regen main() reads the base too (#5298): the pending row of a.sh is gone at HEAD, but base2 had it
        from_base2("regen freeze")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n" % (ok_line, nl))
        rows([("a.sh", ok_line), ("c.sh", pl)], [])
        commit_all("the pending row is gone at HEAD")
        (t / "a.sh").write_text("#!/bin/bash\n%s\n%s\n" % (ok_line, nl))
        shutil.copy(str(root / "scripts" / "check-exec-secret-argv.py"), str(t / "scripts"))
        for base_env, want in ((base2, 1), ("", 0)):
            cases[0] += 1
            for k in keys:
                os.environ.pop(k, None)
            if base_env:
                os.environ["EXEC_SECRET_ARGV_BASE"] = base_env
            out = io.StringIO()
            with contextlib.redirect_stderr(out), contextlib.redirect_stdout(out):
                rc = regen.main(["regen", "--accept-new", "--why", "reason: self-test", "--match", "SERVICE",
                                 "--root", str(t)])
            if rc != want or (want == 1 and "pending row" not in out.getvalue()):
                bad.append("regen --accept-new ignored the pending row at the merge base (#5298; base %r, %d): %s"
                           % (base_env, rc, out.getvalue().strip()[:160]))
        # regen --accept-new reads the same history (#5299): no base is named here, and the exact text of the
        # pending row removed earlier in this history is still refused for allow
        git("checkout", "-q", "--", ".")  # the run above may have written the lists
        bk = "export BACKFILL_TOKEN"
        (t / "d.sh").write_text("#!/bin/bash\n%s\n" % bk)
        rows([("a.sh", ok_line), ("c.sh", pl)], [("d.sh", bk)])
        commit_all("a pending row for the history scan of regen")
        rows([("a.sh", ok_line), ("c.sh", pl)], [])
        (t / "d.sh").write_text("#!/bin/bash\n:\n")
        commit_all("the pending row is removed again")
        (t / "d.sh").write_text("#!/bin/bash\n%s\n" % bk)
        shutil.copy(str(root / "scripts" / "check-exec-secret-argv.py"), str(t / "scripts"))
        cases[0] += 1
        for k in keys:
            os.environ.pop(k, None)
        out = io.StringIO()
        with contextlib.redirect_stderr(out), contextlib.redirect_stdout(out):
            rc = regen.main(["regen", "--accept-new", "--why", "reason: self-test", "--match", "BACKFILL",
                             "--root", str(t)])
        if rc != 1 or "removed in commit" not in out.getvalue():
            bad.append("regen --accept-new did not read the history of the pending list (#5299; %d): %s"
                       % (rc, out.getvalue().strip()[:160]))
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return bad, cases[0]


def _history_cases(t: Path) -> Tuple[List[str], int]:
    """removed_pending_rows on synthetic histories (#5299, #5463): a pending row removed by a linear
    commit, by a merge (against either parent, an evil merge, an octopus merge), behind a revert pair or
    behind a replace ref is named; a row that stays is not; history the scan cannot follow is a fault."""
    gone_row, kept_row = "export SERVICE_PASSWORD", "export KEPT_TOKEN"
    bad: List[str] = []
    n = 0

    def git(repo: Path, *a: str) -> str:
        return subprocess.run(["git", "-C", str(repo), "-c", "user.name=self-test", "-c",
                               "user.email=self-test@invalid", "-c", "commit.gpgsign=false"] + list(a),
                              check=True, capture_output=True).stdout.decode("utf-8", "replace")

    def put(repo: Path, rel: str, text: str) -> None:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(text.encode("utf-8"))  # bytes: no newline translation (#5501)

    def rows(repo: Path, *texts: str) -> None:
        put(repo, PENDING_FILE, "".join("#1 | a.sh | 1 | %s\n" % x for x in texts))

    def commit(repo: Path, msg: str) -> None:
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", msg)

    def fresh(name: str) -> Path:
        repo = t / name
        repo.mkdir(parents=True)
        git(repo, "init", "-q", "-b", "develop")
        rows(repo, gone_row, kept_row)
        commit(repo, "the list")
        return repo

    def diverge(repo: Path, tag: str) -> None:
        put(repo, "n-%s.txt" % tag, "x\n")
        commit(repo, "diverge " + tag)

    def drop(repo: Path) -> None:
        rows(repo, kept_row)

    def judge_repo(label: str, repo: Path, want_gone: bool = True) -> None:
        nonlocal n
        n += 1
        try:
            found = removed_pending_rows(repo)
        except RuntimeError as exc:
            bad.append("the history scan faulted on %s: %s" % (label, exc))
            return
        if (gone_row in found) != want_gone or kept_row in found:
            bad.append("the history scan %s for %s (%s)" % (
                "missed the removed row" if want_gone else "named a row that stayed", label, sorted(found)))

    repo = fresh("linear")
    drop(repo)
    commit(repo, "remove")
    judge_repo("a linear removal", repo)
    repo = fresh("keep")
    diverge(repo, "keep")
    judge_repo("a list that never lost a row", repo, False)
    # an evil merge: both parents carry the row and the merge drops it (#5463)
    repo = fresh("evil")
    git(repo, "checkout", "-q", "-b", "side")
    diverge(repo, "side")
    git(repo, "checkout", "-q", "develop")
    diverge(repo, "dev")
    git(repo, "merge", "-q", "--no-ff", "--no-commit", "side")
    drop(repo)
    commit(repo, "evil merge")
    judge_repo("a row dropped in an evil merge", repo)
    # a clean merge that brings in a removal made on the other parent (#5463)
    repo = fresh("clean-side")
    git(repo, "checkout", "-q", "-b", "side")
    drop(repo)
    commit(repo, "side removes")
    git(repo, "checkout", "-q", "develop")
    diverge(repo, "dev")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge side", "side")
    judge_repo("a removal merged from the second parent", repo)
    # ... and a removal made on the first parent while the second parent still carries the row
    repo = fresh("clean-first")
    git(repo, "checkout", "-q", "-b", "side")
    diverge(repo, "side")
    git(repo, "checkout", "-q", "develop")
    drop(repo)
    commit(repo, "develop removes")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge side", "side")
    judge_repo("a removal on the first parent of a merge", repo)
    # an octopus merge that drops the row (#5463)
    repo = fresh("octopus")
    for b in ("s1", "s2"):
        git(repo, "checkout", "-q", "-b", b, "develop")
        diverge(repo, b)
    git(repo, "checkout", "-q", "develop")
    diverge(repo, "dev")
    git(repo, "merge", "-q", "-s", "octopus", "--no-commit", "s1", "s2")
    drop(repo)
    commit(repo, "octopus drops the row")
    judge_repo("a row dropped in an octopus merge", repo)
    # a removal and its revert on a side branch: the merge is identical to its first parent for the list (#5463)
    repo = fresh("revert-pair")
    git(repo, "checkout", "-q", "-b", "side")
    drop(repo)
    commit(repo, "side removes")
    git(repo, "revert", "--no-edit", "HEAD")
    git(repo, "checkout", "-q", "develop")
    diverge(repo, "dev")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge side", "side")
    judge_repo("a removal behind a revert pair", repo)
    # the list renamed and rewritten in one commit: no rename is detected, so the old path shows its rows as removed (#5466)
    repo = t / "rename-rewrite"
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "develop")
    old = "scripts/qc-allowlists/old-pending.txt"
    put(repo, old, "".join("#1 | a.sh | 1 | %s\n" % x for x in (gone_row, kept_row)))
    commit(repo, "the list at its old path")
    put(repo, old, "#1 | a.sh | 1 | %s\n" % kept_row)
    commit(repo, "remove the row at the old path")
    (repo / old).unlink()
    rows(repo, *("export OTHER_TOKEN_%d" % i for i in range(6)))
    commit(repo, "move and rewrite the list in one commit")
    n += 1
    try:
        if gone_row not in removed_pending_rows(repo):
            bad.append("the history scan missed a row removed before the list was renamed and rewritten (#5466)")
    except RuntimeError as exc:
        bad.append("the history scan faulted on a list renamed and rewritten in one commit: %s" % exc)
    # a pure rename of the list keeps every row: nothing is removed, so nothing is named (#5466 precision pin)
    # (both orders: git lists the deleted old path before or after the new one, #5505, mutant R7-24)
    for tag, from_path in (("after", old), ("before", "scripts/qc-allowlists/aa-pending.txt")):
        repo = t / ("rename-pure-" + tag)
        repo.mkdir(parents=True)
        git(repo, "init", "-q", "-b", "develop")
        put(repo, from_path, "".join("#1 | a.sh | 1 | %s\n" % x for x in (gone_row, kept_row)))
        commit(repo, "the list at its old path")
        (repo / PENDING_FILE).parent.mkdir(parents=True, exist_ok=True)
        git(repo, "mv", from_path, PENDING_FILE)
        commit(repo, "pure rename")
        n += 1
        try:
            if removed_pending_rows(repo):
                bad.append("a pure rename of the list (old path sorted %s) named a row as removed (#5466)" % tag)
        except RuntimeError as exc:
            bad.append("the history scan faulted on a pure rename of the list: %s" % exc)
    # the list renamed onto the allow list path with one row dropped, then both files restored: git rename
    # detection shows the removed row under the allow path, which the scan skips (#5500)
    repo = t / "rename-onto-allow"
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "develop")
    others = "".join("#1 | a.sh | 1 | export OTHER_TOKEN_%d\n" % i for i in range(30))
    both = others + "#1 | b.sh | 1 | %s\n" % gone_row
    allow_text = "reason: x | z.sh | 1 | echo hi\n"
    put(repo, PENDING_FILE, both)
    put(repo, ALLOW_FILE, allow_text)
    commit(repo, "both lists")
    (repo / ALLOW_FILE).unlink()
    commit(repo, "delete the allow list")
    git(repo, "mv", PENDING_FILE, ALLOW_FILE)
    put(repo, ALLOW_FILE, others)
    commit(repo, "rename the pending list onto the allow path and drop a row")
    put(repo, ALLOW_FILE, allow_text)
    put(repo, PENDING_FILE, others)
    commit(repo, "restore the allow list and recreate the pending list")
    judge_repo("a row dropped while the list was renamed onto the allow path", repo)
    # a removed content line that reads like a diff header must not retarget the scan at the allow list (#5463)
    repo = t / "forged-header"
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "develop")
    put(repo, PENDING_FILE, "-- a/%s\n" % ALLOW_FILE + "".join("#1 | a.sh | 1 | %s\n" % x for x in (gone_row, kept_row)))
    commit(repo, "the list with a header-like line")
    rows(repo, kept_row)
    commit(repo, "remove the header-like line and a row")
    judge_repo("a row removed right after a header-like content line", repo)
    # an allow row whose reason is an issue number is not a pending row: its removal names nothing (#5299)
    repo = fresh("allow-reason")
    put(repo, ALLOW_FILE, "#123 | a.sh | 1 | export ALLOW_ONLY\n")
    commit(repo, "an allow row with an issue reason")
    put(repo, ALLOW_FILE, "")
    commit(repo, "drop it")
    n += 1
    try:
        if "export ALLOW_ONLY" in removed_pending_rows(repo):
            bad.append("the removal of an allow row was read as a removed pending row (#5299)")
    except RuntimeError as exc:
        bad.append("the history scan faulted on an allow row with an issue reason: %s" % exc)
    # a deleted allow list: its header pair ends in /dev/null, which must not become a path whose rows are
    # collected (#5504, mutant M15: taking the path from any header line)
    repo = fresh("allow-deleted")
    put(repo, ALLOW_FILE, "#123 | a.sh | 1 | export ALLOW_ONLY\n")
    commit(repo, "an allow row with an issue reason")
    (repo / ALLOW_FILE).unlink()
    commit(repo, "delete the allow list")
    judge_repo("a deleted allow list", repo, False)
    n += 1
    try:
        if "export ALLOW_ONLY" in removed_pending_rows(repo):
            bad.append("the deletion of the allow list was read as removed pending rows (#5504)")
    except RuntimeError as exc:
        bad.append("the history scan faulted on a deleted allow list: %s" % exc)
    # a row removed from the list while the same text is added in another file: the move is not netted, so the
    # removal is named (#5505, mutant R7-03: netting under any path)
    repo = fresh("moved-elsewhere")
    drop(repo)
    put(repo, "docs/elsewhere.txt", "#1 | a.sh | 1 | %s\n" % gone_row)
    commit(repo, "remove the row and add its text in another file")
    judge_repo("a row moved into another file", repo)
    # one commit that edits the allow list and drops a pending row: the pending file's rows must not be read
    # under the allow list path (#5505, mutant R7-24: the hunk state kept across files)
    repo = fresh("two-files")
    put(repo, ALLOW_FILE, "reason: x | z.sh | 1 | echo hi\n")
    commit(repo, "an allow row")
    put(repo, ALLOW_FILE, "reason: x | z.sh | 1 | echo hi\nreason: y | y.sh | 1 | echo yo\n")
    drop(repo)
    commit(repo, "edit the allow list and drop a pending row in one commit")
    judge_repo("a row dropped in a commit that also edits the allow list", repo)
    # a row removed twice names the newest removing commit (#5505, mutant M16: assignment for setdefault)
    repo = fresh("twice")
    drop(repo)
    commit(repo, "first removal")
    rows(repo, gone_row, kept_row)
    commit(repo, "the row returns")
    drop(repo)
    commit(repo, "second removal")
    newest = git(repo, "log", "-1", "--format=%h").strip()
    n += 1
    try:
        if removed_pending_rows(repo).get(gone_row) != newest:
            bad.append("a row removed twice did not name the newest removing commit (#5505)")
    except RuntimeError as exc:
        bad.append("the history scan faulted on a row removed twice: %s" % exc)
    # a replace ref that hides the removing commit from every default git view (#5463)
    repo = fresh("replace")
    drop(repo)
    commit(repo, "remove")
    git(repo, "replace", "HEAD", "HEAD~1")
    judge_repo("a removal hidden behind a replace ref", repo)
    # a graft that makes the removing commit a root: git honours .git/info/grafts even with
    # --no-replace-objects, so the scan points GIT_GRAFT_FILE at the null device (#5503)
    repo = fresh("graft")
    drop(repo)
    commit(repo, "remove")
    (repo / ".git" / "info").mkdir(parents=True, exist_ok=True)
    (repo / ".git" / "info" / "grafts").write_text(git(repo, "rev-parse", "HEAD").strip() + "\n")
    judge_repo("a removal hidden behind a graft", repo)
    # every line-terminator and trailing-whitespace form of a row is read as the row (#5501): a row that ends
    # in CRLF, a row with trailing blanks, and a row hidden behind a lone CR in a comment line
    for tag, enc in (("crlf", lambda r: r + "\r\n"), ("trailing-blanks", lambda r: r + " \t\n"),
                     ("lone-cr", lambda r: "# note\r" + r + "\n"), ("vt", lambda r: r + "\x0b\n"),
                     ("leading-blank", lambda r: "  " + r + "\n")):
        repo = t / ("form-" + tag)
        repo.mkdir(parents=True)
        git(repo, "init", "-q", "-b", "develop")
        put(repo, PENDING_FILE, enc("#1 | b.sh | 1 | " + gone_row) + enc("#1 | a.sh | 1 | " + kept_row))
        commit(repo, "rows in the %s form" % tag)
        put(repo, PENDING_FILE, enc("#1 | a.sh | 1 | " + kept_row))
        commit(repo, "drop the row")
        judge_repo("a row dropped in the %s form" % tag, repo)
    # history the scan cannot follow is a fault: a committed row no scanned commit added (#5463)
    repo = fresh("unfollowable")
    n += 1
    real_git = globals()["_git"]

    def blind_git(r: Path, *a: str) -> str:
        out = real_git(r, *a)
        return "\n".join(x for x in out.split("\n") if not x.startswith("+#")) if "log" in a else out

    globals()["_git"] = blind_git
    try:
        removed_pending_rows(repo)
        bad.append("a committed row that no scanned commit added was an answer, not a fault (#5463)")
    except RuntimeError as exc:
        if "cannot be followed" not in str(exc):
            bad.append("an unfollowable history faulted with the wrong message (%s)" % exc)
    finally:
        globals()["_git"] = real_git
    return bad, n


def _git_funnel_cases(t: Path) -> Tuple[List[str], int]:
    """Every git read of the gate runs in the closed-world funnel (#5581): replace refs of a blob and of a
    commit, grafts (file and env), alternate or other object directories, GIT_DIR and GIT_WORK_TREE elsewhere,
    another index, injected config (env, global, system, repo-local), attributes that mark the list binary and
    a GIT_SHALLOW_FILE that hides a shallow clone each leave the answer unchanged or make it a fault."""
    import shutil
    gone_row, kept_row = "export SERVICE_PASSWORD", "export KEPT_TOKEN"
    bad: List[str] = []
    n = 0

    def git(repo: Path, *a: str) -> str:
        return subprocess.run(["git", "-C", str(repo), "-c", "user.name=self-test", "-c",
                               "user.email=self-test@invalid", "-c", "commit.gpgsign=false"] + list(a),
                              check=True, capture_output=True).stdout.decode("utf-8", "replace")

    def put(repo: Path, rel: str, text: str) -> None:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(text.encode("utf-8"))

    def rows(*texts: str) -> str:
        return "".join("#1 | a.sh | 1 | %s\n" % x for x in texts)

    def build(name: str) -> Tuple[Path, Dict[str, str]]:
        repo = t / name
        repo.mkdir(parents=True)
        git(repo, "init", "-q", "-b", "develop")
        shas: Dict[str, str] = {}
        put(repo, PENDING_FILE, rows(gone_row, kept_row))
        put(repo, "n.txt", "x\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "A")
        shas["A"] = git(repo, "rev-parse", "HEAD").strip()
        put(repo, "m.txt", "y\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "B")
        shas["B"] = git(repo, "rev-parse", "HEAD").strip()
        git(repo, "branch", "base")
        put(repo, PENDING_FILE, rows(kept_row))
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "C")
        shas["C"] = git(repo, "rev-parse", "HEAD").strip()
        return repo, shas

    def marker_prog(name: str) -> Tuple[Path, Path]:
        """An executable that records that it ran and fails; git runs it without a shell for some keys."""
        mark, prog = t / (name + "-ran"), t / (name + "-prog")
        prog.write_text("#!%s\nimport pathlib\npathlib.Path(%r).write_text('ran')\nraise SystemExit(1)\n"
                        % (sys.executable, str(mark)))
        prog.chmod(0o755)
        return mark, prog

    def check(label: str, repo: Path, shas: Dict[str, str], env: Optional[Dict[str, str]] = None) -> None:
        """The three readers of the gate (merge base state, history scan, file list) answer as on a clean repo."""
        nonlocal n
        n += 1
        env = env or {}
        _GIT_PROVEN.clear()  # the isolation proof is per process; every case proves it again under its own environment
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            mb, _ren, pend, _al = base_state(repo, "base")
            gone = removed_pending_rows(repo)
            files = tracked_files(repo)
        except (RuntimeError, subprocess.CalledProcessError) as exc:
            bad.append("the gate's git reads faulted on %s: %s (#5581)" % (label, str(exc)[:100]))
            return
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        if mb != shas["B"]:
            bad.append("the merge base followed %s: %s, not %s (#5581)" % (label, mb[:9], shas["B"][:9]))
        elif not any(e[3] == gone_row for e in pend):
            bad.append("the merge-base list read through %s lost the pending row (#5581)" % label)
        elif gone_row not in gone or kept_row in gone:
            bad.append("the history scan was misled by %s (%s) (#5581)" % (label, sorted(gone)))
        elif PENDING_FILE not in files or "n.txt" not in files or "m.txt" not in files:
            bad.append("the tracked file list was misled by %s (#5581)" % label)

    repo, shas = build("control")
    check("an untouched repo (control)", repo, shas)
    repo, shas = build("blob")
    blob_b = git(repo, "rev-parse", "%s:%s" % (shas["B"], PENDING_FILE)).strip()
    edited = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], check=True,
                            capture_output=True, input=rows(kept_row).encode("utf-8")).stdout.decode().strip()
    git(repo, "replace", blob_b, edited)
    check("a replace ref on the base list blob", repo, shas)
    repo, shas = build("graft-ref")
    git(repo, "replace", "--graft", shas["C"], shas["A"])
    check("git replace --graft of the head commit", repo, shas)
    repo, shas = build("graft-file")
    (repo / ".git" / "info").mkdir(parents=True, exist_ok=True)
    (repo / ".git" / "info" / "grafts").write_text("%s %s\n" % (shas["C"], shas["A"]))
    check("a .git/info/grafts entry", repo, shas)
    graft_env = t / "graft-env.txt"
    graft_env.write_text("%s %s\n" % (shas["C"], shas["A"]))
    check("GIT_GRAFT_FILE", repo, shas, {"GIT_GRAFT_FILE": str(graft_env)})
    empty_dir = t / "empty-objects"
    empty_dir.mkdir()
    repo, shas = build("env-objects")
    check("GIT_ALTERNATE_OBJECT_DIRECTORIES", repo, shas, {"GIT_ALTERNATE_OBJECT_DIRECTORIES": str(empty_dir)})
    check("GIT_OBJECT_DIRECTORY", repo, shas, {"GIT_OBJECT_DIRECTORY": str(empty_dir)})
    # an object the repository lacks is not supplied by the caller's GIT_ALTERNATE_OBJECT_DIRECTORIES: unresolved is red
    arepo, ashas = build("alt-supplied")
    alt = t / "alt-objects"
    shutil.copytree(str(arepo / ".git" / "objects"), str(alt))
    blob = git(arepo, "rev-parse", "%s:%s" % (ashas["B"], PENDING_FILE)).strip()
    (arepo / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
    n += 1
    os.environ["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(alt)
    try:
        base_state(arepo, "base")
        bad.append("an object missing from the repository was supplied by GIT_ALTERNATE_OBJECT_DIRECTORIES (#5581)")
    except RuntimeError:
        pass
    finally:
        os.environ.pop("GIT_ALTERNATE_OBJECT_DIRECTORIES", None)
    decoy = t / "decoy"
    decoy.mkdir()
    git(decoy, "init", "-q", "-b", "develop")
    put(decoy, PENDING_FILE, rows("export DECOY_ONLY"))
    git(decoy, "add", "-A")
    git(decoy, "commit", "-q", "-m", "decoy")
    check("GIT_DIR and GIT_WORK_TREE elsewhere", repo, shas,
          {"GIT_DIR": str(decoy / ".git"), "GIT_WORK_TREE": str(decoy)})
    shallow_list = t / "shallow-list"
    shallow_list.write_text(shas["C"] + "\n")
    check("GIT_SHALLOW_FILE naming a commit of a complete repo", repo, shas, {"GIT_SHALLOW_FILE": str(shallow_list)})
    check("GIT_INDEX_FILE elsewhere", repo, shas, {"GIT_INDEX_FILE": str(t / "no-such-index")})
    check("GIT_CONFIG_COUNT injecting i18n.logOutputEncoding", repo, shas,
          {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "i18n.logOutputEncoding", "GIT_CONFIG_VALUE_0": "UTF-16"})
    check("GIT_CONFIG_COUNT injecting diff.mnemonicPrefix", repo, shas,
          {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "diff.mnemonicPrefix", "GIT_CONFIG_VALUE_0": "true"})
    glob = t / "global.cfg"
    glob.write_text("[i18n]\n\tlogOutputEncoding = UTF-16\n")
    check("GIT_CONFIG_GLOBAL injecting i18n.logOutputEncoding", repo, shas, {"GIT_CONFIG_GLOBAL": str(glob)})
    check("GIT_CONFIG_SYSTEM injecting i18n.logOutputEncoding", repo, shas, {"GIT_CONFIG_SYSTEM": str(glob)})
    home = t / "home"
    home.mkdir()
    (home / ".gitconfig").write_text("[i18n]\n\tlogOutputEncoding = UTF-16\n[core]\n\tuseReplaceRefs = true\n")
    check("a global ~/.gitconfig injecting i18n.logOutputEncoding", repo, shas, {"HOME": str(home)})
    # the pins hold even when the caller's HOME and XDG_CONFIG_HOME would reach git (#5634): the global scope is
    # named by GIT_CONFIG_GLOBAL, not only hidden by stripping HOME
    kept_before = GIT_ENV_KEEP
    globals()["GIT_ENV_KEEP"] = tuple(kept_before) + ("HOME", "XDG_CONFIG_HOME")
    try:
        check("a global ~/.gitconfig with HOME on the keep list", repo, shas, {"HOME": str(home)})
        pins = _git_child_env()
        n += 1
        for name, want in (("GIT_CONFIG_GLOBAL", os.devnull), ("GIT_CONFIG_SYSTEM", os.devnull),
                           ("GIT_CONFIG_NOSYSTEM", "1"), ("GIT_NO_REPLACE_OBJECTS", "1"),
                           ("GIT_GRAFT_FILE", os.devnull)):
            if pins.get(name) != want:
                bad.append("the git child environment does not pin %s to %r (#5634)" % (name, want))
    finally:
        globals()["GIT_ENV_KEEP"] = kept_before
    repo, shas = build("local-config")
    with open(str(repo / ".git" / "config"), "a") as fh:
        fh.write("[i18n]\n\tlogOutputEncoding = UTF-16\n")
    check("a repo-local i18n.logOutputEncoding", repo, shas)
    repo, shas = build("local-prefix")
    with open(str(repo / ".git" / "config"), "a") as fh:
        fh.write("[diff]\n\tnoprefix = true\n")
    check("a repo-local diff.noprefix", repo, shas)
    repo, shas = build("local-oddprefix")
    with open(str(repo / ".git" / "config"), "a") as fh:
        fh.write("[diff]\n\tsrcPrefix = zz\n\tdstPrefix = yy\n")
    check("a repo-local diff.srcPrefix and diff.dstPrefix", repo, shas)
    repo, shas = build("local-mnemonic")
    with open(str(repo / ".git" / "config"), "a") as fh:
        fh.write("[diff]\n\tmnemonicPrefix = true\n[log]\n\tshowSignature = true\n")
    check("a repo-local diff.mnemonicPrefix and log.showSignature", repo, shas)
    repo, shas = build("local-fsmonitor")
    marker = t / "fsmonitor-ran"
    hook = t / "fsmonitor-hook.py"
    hook.write_text("import pathlib, sys\npathlib.Path(%r).write_text('ran')\nsys.exit(1)\n" % str(marker))
    with open(str(repo / ".git" / "config"), "a") as fh:
        fh.write("[core]\n\tfsmonitor = %s %s\n" % (sys.executable, hook))
    check("a repo-local core.fsmonitor program", repo, shas)
    n += 1
    if marker.exists():
        bad.append("a repo-local core.fsmonitor program ran during the gate's git reads (#5633)")
    # the pins are visible to git itself: a config read through the funnel names them (#5692)
    n += 1
    for key, want in (("core.fsmonitor", "false"), ("core.hookspath", os.devnull)):
        got = _git_exec(repo, ["config", "--get", key]).stdout.decode("utf-8", "replace").strip()
        if got != want:
            bad.append("the funnel does not pin %s to %r (read back %r) (#5692)" % (key, want, got))
    repo, shas = build("local-textconv")
    tconv = t / "textconv-hook.py"
    tmark = t / "textconv-ran"
    tconv.write_text("import pathlib, sys\npathlib.Path(%r).write_text('ran')\nsys.stdout.write(open(sys.argv[1]).read())\n"
                     % str(tmark))
    put(repo, ".gitattributes", "%s diff=tc\n*.sh diff=tc\n" % PENDING_FILE)
    with open(str(repo / ".git" / "config"), "a") as fh:
        fh.write("[diff \"tc\"]\n\ttextconv = %s %s\n" % (sys.executable, tconv))
    check("a repo-local textconv driver on the list and on scripts", repo, shas)
    n += 1
    try:
        _show_or_absent(repo, "HEAD", PENDING_FILE)
    except (RuntimeError, subprocess.CalledProcessError, OSError):
        pass
    if tmark.exists():
        bad.append("a repo-local textconv program ran during the gate's git reads (#5693)")
    # a signed history read with a repo-local log.showSignature runs no verifier program (#5822): every commit of
    # the case repo gets a gpgsig header of the kind each verifier key serves
    for kind, key, armor in (("ssh", "gpg.ssh.program", "SSH SIGNATURE"), ("pgp", "gpg.program", "PGP SIGNATURE"),
                             ("openpgp", "gpg.openpgp.program", "PGP SIGNATURE"),
                             ("x509", "gpg.x509.program", "SIGNED MESSAGE")):
        repo, shas = build("signed-" + kind)
        new: Dict[str, str] = {}
        prev = ""
        for name in ("A", "B", "C"):
            head, _sep, msg = git(repo, "cat-file", "commit", shas[name]).partition("\n\n")
            head = re.sub(r"^parent \S+$", "parent " + prev, head, flags=re.M)
            body = t / ("signed-%s-%s.commit" % (kind, name))
            body.write_text("%s\ngpgsig -----BEGIN %s-----\n U0lH\n -----END %s-----\n\n%s" % (head, armor, armor, msg))
            new[name] = prev = git(repo, "hash-object", "-t", "commit", "-w", str(body)).strip()
        git(repo, "update-ref", "refs/heads/develop", new["C"])
        git(repo, "update-ref", "refs/heads/base", new["B"])
        mark, prog = marker_prog("verifier-" + kind)
        group = "gpg" if kind == "pgp" else 'gpg "%s"' % kind
        with open(str(repo / ".git" / "config"), "a") as fh:
            fh.write("[log]\n\tshowSignature = true\n[%s]\n\tprogram = %s\n" % (group, prog))
            if kind == "ssh":
                fh.write("\tallowedSignersFile = %s\n" % os.devnull)
        check("a repo-local log.showSignature and %s on a signed history" % key, repo, new)
        n += 1
        if mark.exists():
            bad.append("a repo-local %s ran during the gate's git reads of a signed history (#5822)" % key)
    # the verifier pins are visible to git itself: a config read through the funnel names them (#5822)
    n += 1
    for key, want in (("log.showsignature", "false"),) + tuple((k, os.devnull) for k in GIT_VERIFIER_KEYS):
        try:
            got = _git_exec(repo, ["config", "--get", key]).stdout.decode("utf-8", "replace").strip()
        except subprocess.CalledProcessError:
            got = ""
        if got != want:
            bad.append("the funnel does not pin %s to %r (read back %r) (#5822)" % (key, want, got))
    repo, shas = build("attr-info")
    (repo / ".git" / "info").mkdir(parents=True, exist_ok=True)
    (repo / ".git" / "info" / "attributes").write_text("%s -diff\n" % PENDING_FILE)
    check("a -diff attribute on the list (.git/info/attributes)", repo, shas)
    repo, shas = build("attr-tree")
    put(repo, ".gitattributes", "%s -diff\n" % PENDING_FILE)
    check("a -diff attribute on the list (.gitattributes)", repo, shas)
    # a shallow clone stays a shallow fault when GIT_SHALLOW_FILE names an empty file
    repo, shas = build("shallow-src")
    shallow = t / "shallow-clone"
    subprocess.run(["git", "clone", "-q", "--depth", "1", "file://" + str(repo), str(shallow)], check=True,
                   capture_output=True)
    empty_file = t / "empty-shallow"
    empty_file.write_text("")
    for label, env in (("a shallow clone (control)", {}), ("GIT_SHALLOW_FILE hiding a shallow clone",
                                                          {"GIT_SHALLOW_FILE": str(empty_file)})):
        n += 1
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        _GIT_PROVEN.clear()
        try:
            removed_pending_rows(shallow)
            bad.append("%s was read as a complete history (#5581)" % label)
        except RuntimeError as exc:
            if "shallow" not in str(exc):
                bad.append("%s faulted with the wrong message: %s (#5581)" % (label, str(exc)[:100]))
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    shutil.rmtree(str(shallow), ignore_errors=True)
    # a partial clone faults closed and runs no transport program of its config when a read needs a missing
    # object (#5823): the lazy fetch would run remote.origin.uploadpack
    repo, shas = build("partial-src")
    git(repo, "config", "uploadpack.allowFilter", "true")
    partial = t / "partial-clone"
    subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", "file://" + str(repo), str(partial)],
                   check=True, capture_output=True)
    lmark, lprog = marker_prog("transport")
    git(partial, "config", "remote.origin.uploadpack", str(lprog))
    n += 1
    _GIT_PROVEN.clear()
    try:
        removed_pending_rows(partial)
    except (RuntimeError, subprocess.CalledProcessError):
        pass
    if lmark.exists():
        bad.append("a partial clone ran a repo-configured transport program during the gate's git reads (#5823)")
    shutil.rmtree(str(partial), ignore_errors=True)
    # the isolation is proven, not assumed: a child environment that leaves a global or system config in reach is
    # a fault, and the proof runs once per repository, not once per call
    repo, shas = build("proof")
    sysconf = t / "system.cfg"
    sysconf.write_text("[i18n]\n\tlogOutputEncoding = UTF-16\n")
    real_env, real_exec = globals()["_git_child_env"], globals()["_git_exec"]
    for label, leaked, child_env in (
            ("global", "global", {"PATH": os.environ.get("PATH", ""), "HOME": str(home)}),
            ("system", "system", {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_SYSTEM": str(sysconf),
                                  "GIT_CONFIG_GLOBAL": os.devnull})):
        n += 1
        globals()["_git_child_env"] = lambda ce=child_env: dict(ce)
        globals()["_GIT_PROVEN"].clear()
        try:
            _git(repo, "rev-parse", "HEAD")
            bad.append("a child environment that reads a %s config was accepted (#5581)" % label)
        except RuntimeError as exc:
            if "not isolated" not in str(exc) or leaked not in str(exc):
                bad.append("the isolation proof faulted with the wrong message: %s (#5581)" % str(exc)[:100])
        finally:
            globals()["_git_child_env"] = real_env
    n += 1
    calls: List[str] = []

    def counting_exec(r: Path, a: Sequence[str]) -> "subprocess.CompletedProcess[bytes]":
        calls.append(a[0])
        return real_exec(r, a)

    globals()["_git_exec"] = counting_exec
    globals()["_GIT_PROVEN"].clear()
    try:
        _git(repo, "rev-parse", "HEAD")
        _git(repo, "rev-parse", "HEAD")
    finally:
        globals()["_git_exec"] = real_exec
    if calls.count("config") != 1 or calls.count("rev-parse") != 2:
        bad.append("the isolation proof did not run exactly once per repository: %s (#5581)" % calls)
    return bad, n


# Functions that may spawn a process: the funnel itself, and the self-test fixtures that build their own
# throwaway repositories (they are never part of a scan of the checkout).
FUNNEL_SPAWNERS = frozenset({"_git_exec", "_run_wiring_cases", "_history_cases", "_git_funnel_cases",
                             "_terminator_cases"})
_SPAWN_ATTRS = frozenset({"system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execle",
                          "execlp", "execlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "spawnl", "spawnle",
                          "spawnlp", "spawnlpe", "posix_spawn", "posix_spawnp", "fork", "forkpty", "startfile"})
# The only names of subprocess that may appear outside the funnel: constants and exception types, never a callable (#5632).
_SUBPROCESS_PLAIN = frozenset({"PIPE", "DEVNULL", "STDOUT", "CalledProcessError", "TimeoutExpired",
                               "CompletedProcess", "SubprocessError"})
_PROCESS_MODULES = frozenset({"pty", "ctypes", "multiprocessing", "asyncio", "commands", "popen2", "pexpect"})
# importlib may load a module from a path (the denylist import); import_module and __import__ are the bypass.
_IMPORTLIB_PLAIN = frozenset({"util", "machinery"})
_DYNAMIC_NAMES = frozenset({"__import__", "eval", "exec", "compile", "getattr", "setattr", "vars", "globals",
                            "locals", "__builtins__"})


def funnel_bypasses(source: str) -> List[str]:
    """Every place that can start a process outside the funnel (#5581, #5632): any use of the name subprocess other
    than a constant or an exception type, an os spawn, exec or fork name (called or not), a bare os or sys.modules
    reference, an import of a process module (pty, ctypes, multiprocessing, asyncio, ...), and a dynamic
    lookup (getattr, vars, globals, eval, exec, __import__), all outside FUNNEL_SPAWNERS. Closed world: any new way to
    run git must go through _git_exec, so a new caller is refused here, not found by a review. This is a regression
    guard, not a security boundary: a name built from strings at run time is not seen."""
    import ast
    tree = ast.parse(source)
    out: List[str] = []

    def add(node: "ast.AST", what: str, owner: str) -> None:
        out.append("line %d: %s outside the git funnel (in %s)" % (node.lineno, what, owner or "module level"))

    def walk(node: "ast.AST", owner: str, parent: "Optional[ast.AST]") -> None:
        for child in ast.iter_child_nodes(node):
            sub = owner
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and not owner:
                sub = child.name
            top = (child.module or "").split(".")[0] if isinstance(child, ast.ImportFrom) else ""
            if isinstance(child, ast.ImportFrom) and (top in ("subprocess", "os", "sys") or top in _PROCESS_MODULES) \
                    and (top in ("subprocess",) or top in _PROCESS_MODULES or any(
                        a.name in _SPAWN_ATTRS or a.name in ("*", "modules") for a in child.names)):
                out.append("line %d: from %s import (hides a process start from this check)" % (child.lineno, child.module))
            if isinstance(child, ast.Import):
                for a in child.names:
                    if a.name == "subprocess" and a.asname:
                        out.append("line %d: import subprocess as an alias" % child.lineno)
                    if a.name.split(".")[0] in _PROCESS_MODULES:
                        out.append("line %d: import %s (a process start this check cannot follow)" % (child.lineno, a.name))
            if owner not in FUNNEL_SPAWNERS:
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    base_of = parent if isinstance(parent, ast.Attribute) and parent.value is child else None
                    if child.id == "subprocess" and not (base_of is not None and base_of.attr in _SUBPROCESS_PLAIN):
                        add(child, "the name subprocess is used" + (" (.%s)" % base_of.attr if base_of is not None else ""), owner)
                    elif child.id == "os" and base_of is None:
                        add(child, "the name os is used as a value", owner)
                    elif child.id in _PROCESS_MODULES:
                        add(child, "the name %s is used" % child.id, owner)
                    elif child.id == "importlib" and not (base_of is not None and base_of.attr in _IMPORTLIB_PLAIN):
                        add(child, "importlib is used beyond importlib.util", owner)
                    elif child.id in _DYNAMIC_NAMES:
                        add(child, "%s can start a process unseen" % child.id, owner)
                elif isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                    if child.value.id == "os" and child.attr in _SPAWN_ATTRS:
                        add(child, "os.%s" % child.attr, owner)
                    elif child.value.id == "sys" and child.attr == "modules":
                        add(child, "sys.modules", owner)
            walk(child, sub, child)

    walk(tree, "", None)
    return out


def _funnel_structure_cases() -> Tuple[List[str], int]:
    """The gate's own source has no process start outside the funnel (#5581), and the check itself sees every
    bypass form it names."""
    bad: List[str] = []
    n = 0
    n += 1
    own = funnel_bypasses(Path(__file__).read_text(encoding="utf-8"))
    if own:
        bad.append("a process is started outside the git funnel: %s (#5581)" % own[0])
    for label, src in (
            ("subprocess.run in a helper", "import subprocess\ndef f():\n    subprocess.run(['git'])\n"),
            ("subprocess.check_output at module level", "import subprocess\nx = subprocess.check_output(['git'])\n"),
            ("subprocess.Popen in a nested def", "import subprocess\ndef f():\n    def g():\n        subprocess.Popen(['git'])\n"),
            ("os.system", "import os\ndef f():\n    os.system('git log')\n"),
            ("os.popen", "import os\ndef f():\n    os.popen('git log')\n"),
            ("from subprocess import run", "from subprocess import run\n"),
            ("import subprocess as alias", "import subprocess as sp\n"),
            ("from os import system", "from os import system\n"),
            ("__import__", "def f():\n    __import__('subprocess')\n"),
            ("a funnel name reused as a nested def", "import subprocess\ndef f():\n    def _git_exec():\n        subprocess.run(['git'])\n"),
            ("5632 subprocess bound to another name", "import subprocess\ndef f():\n    sp = subprocess\n    sp.run(['git'])\n"),
            ("5632 getattr on subprocess", "import subprocess\ndef f():\n    getattr(subprocess, 'run')(['git'])\n"),
            ("5632 importlib import_module", "import importlib\ndef f():\n    importlib.import_module('subprocess').run(['git'])\n"),
            ("5632 pty.spawn", "import pty\ndef f():\n    pty.spawn(['git', 'log'])\n"),
            ("5632 pty imported from", "from pty import spawn\n"),
            ("5632 a method of the run function", "import subprocess\ndef f():\n    subprocess.run.__call__(['git'])\n"),
            ("5632 os.system taken without a call", "import os\ndef f():\n    g = os.system\n"),
            ("5632 os bound to another name", "import os\ndef f():\n    o = os\n    o.system('git log')\n"),
            ("5632 sys.modules lookup", "import sys\ndef f():\n    sys.modules['subprocess'].run(['git'])\n"),
            ("5632 os.fork", "import os\ndef f():\n    os.fork()\n"),
            ("5632 vars lookup", "def f():\n    vars()['x']\n")):
        n += 1
        if not funnel_bypasses(src):
            bad.append("the funnel check missed a bypass: %s (#5581)" % label)
    for label, src in (
            ("the funnel itself", "import subprocess\ndef _git_exec():\n    subprocess.run(['git'])\n"),
            ("a fixture helper nested in a spawner", "import subprocess\ndef _history_cases():\n    def git():\n        subprocess.run(['git'])\n"),
            ("only the exception name", "import subprocess\ndef f():\n    try:\n        pass\n    except subprocess.CalledProcessError:\n        pass\n"),
            ("5632 a constant of subprocess", "import subprocess\ndef f():\n    return subprocess.PIPE\n"),
            ("5632 os.environ and os.path are no spawn", "import os\ndef f():\n    return os.environ.get('A'), os.path.join('a')\n"),
            ("5632 importlib.util loads a module from a path", "import importlib.util\ndef f():\n    return importlib.util.spec_from_file_location('a', 'b')\n")):
        n += 1
        if funnel_bypasses(src):
            bad.append("the funnel check refused a clean source: %s (#5581)" % label)
    return bad, n


def _terminator_cases(root: Path, t: Path) -> Tuple[List[str], int]:
    """The real gate path on lists with line-terminator and trailing-whitespace forms (#5501): at the tip any
    form other than LF is a fault; at the merge base every form is read as the row, so a row cannot be
    hidden from the base rules by its line ending. A control with an LF row is red for the same change."""
    import shutil
    bad: List[str] = []
    n = 0
    keys = ("EXEC_SECRET_ARGV_BASE", "GITHUB_BASE_REF", "GITHUB_ACTIONS", "CI")
    saved = {k: os.environ.get(k) for k in keys}
    ok_line, nl = "export API_TOKEN", "export SERVICE_PASSWORD"
    base_ref = "refs/remotes/origin/self-test-base"

    def git(*a: str) -> str:
        return subprocess.run(["git", "-C", str(t), "-c", "user.name=self-test", "-c",
                               "user.email=self-test@invalid", "-c", "commit.gpgsign=false"] + list(a),
                              check=True, capture_output=True).stdout.decode("utf-8", "replace")

    def put(rel: str, text: str) -> None:
        (t / rel).write_bytes(text.encode("utf-8"))

    def lists(allow_rows: List[str], pend_rows: List[str], eol: str = "\n") -> None:
        put(ALLOW_FILE, "".join(r + eol for r in allow_rows))
        put(PENDING_FILE, "".join(r + eol for r in pend_rows))

    def gate(**env: str) -> Tuple[int, str]:
        for k in keys:
            os.environ.pop(k, None)
        os.environ.update(env)
        out = io.StringIO()
        with contextlib.redirect_stderr(out), contextlib.redirect_stdout(out):
            rc = run(t)
        return rc, out.getvalue()

    ok_row = "reason: self-test | a.sh | 1 | " + ok_line
    pend_row = "#1 | b.sh | 1 | " + nl
    moved_row = "reason: self-test | b.sh | 1 | " + nl
    try:
        (t / "scripts" / "qc-allowlists").mkdir(parents=True)
        shutil.copy(str(root / DENYLIST), str(t / DENYLIST))
        put("a.sh", "#!/bin/bash\n%s\n" % ok_line)
        put("b.sh", "#!/bin/bash\n%s\n" % nl)
        for tag, eol in (("lf", "\n"), ("crlf", "\r\n"), ("lone-cr", "\r"), ("trailing-blanks", " \t\n")):
            git("init", "-q")
            lists([ok_row], [pend_row], eol)
            if tag == "lone-cr":  # the whole file is one line to a reader that splits on LF only
                put(PENDING_FILE, "# note" + eol + pend_row + eol)
            git("add", "-A")
            git("commit", "-q", "--allow-empty", "-m", "base " + tag)
            git("update-ref", base_ref, "HEAD")
            # one change drops the pending row and adds an allow entry with the same text
            lists([ok_row, moved_row], [])
            git("add", "-A")
            git("commit", "-q", "-m", "launder " + tag)
            n += 1
            rc, out = gate(EXEC_SECRET_ARGV_BASE=base_ref)
            if rc != 1 or "pending at the merge base" not in out:
                bad.append("a pending row in the %s form was hidden from the merge-base rules (%d): %s"
                           % (tag, rc, out.strip()[:140]))
            git("reset", "-q", "--hard", base_ref)
            # the tip itself: any terminator other than LF in a list is a fault (LF with blanks is a normalisation fault)
            n += 1
            rc, out = gate()
            if tag == "lf":
                if rc != 0:
                    bad.append("the LF control list was refused at the tip (%d): %s" % (rc, out.strip()[:140]))
            elif rc != 2 or "FAULT" not in out:
                bad.append("a list in the %s form was accepted at the tip (%d): %s" % (tag, rc, out.strip()[:140]))
            shutil.rmtree(str(t / ".git"))
        # every terminator of the class, one by one (#5505): the tip refuses it, a diff line holding it reads
        # as two rows, and the LF control is clean
        for ch in "\r\v\f\x1c\x1d\x1e\x85\u2028\u2029":  # spelled out: not the constant under test
            n += 1
            if not terminator_faults("x" + ch + "y\n", "t"):
                bad.append("the tip accepted line terminator U+%04X in a list (#5501)" % ord(ch))
            n += 1
            if len(diff_rows("#1 | b.sh | 1 | one" + ch + "#2 | c.sh | 2 | two")) != 2:
                bad.append("a diff line holding line terminator U+%04X did not read as two rows (#5501)" % ord(ch))
        n += 1
        if terminator_faults("x\ny\n", "t") or len(diff_rows("#1 | b.sh | 1 | one")) != 1:
            bad.append("the LF control was refused or misread (#5501)")
        # a row read from git that does not parse is a fault, never a silent skip (#5501, mutant R7-07)
        n += 1
        try:
            parse_git_list("#1 | b.sh | many | export SERVICE_PASSWORD\n", "base-pending", True)
            bad.append("a malformed row read from git was skipped instead of raised (#5501)")
        except RuntimeError:
            pass
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return bad, n


def hardening_cases(root: Path, dl) -> Tuple[List[str], int]:
    """Fail-closed cases of the gate itself (#4901, #4909, #4919, #4920, #4922). Returns
    (failures, case count)."""
    import tempfile
    bad: List[str] = []
    n = 0
    # #4901: a comment inside an array does not hide the closing paren; a runaway array is a fault
    n += 1
    units = join_logical(_numbered('A=(\n  a # (note\n  b\n)\ncurl -H "X-API-Key: $K" h\n'))
    if units[0][:2] != (1, 4) or units[1][0] != 5:
        bad.append("array with an inline comment did not close at its own paren (#4901)")
    n += 1
    try:
        join_logical(_numbered("A=(\n" + "x # (\n" * (ARRAY_JOIN_MAX + 5)))
        bad.append("a runaway array was joined without a fault (#4901)")
    except RuntimeError:
        pass
    # #5420: the rename map keeps an unchanged entry of a renamed file out of the judgement
    n += 1
    moved = [("reason: r", "e.sh", 1, "x --token $T", 5)]
    had = [("reason: r", "c.sh", 1, "x --token $T", 2)]
    row = [("#1", "a.sh", 1, "x --token $T", 3)]
    if allow_text_pending_elsewhere(moved, had, row, row, {"c.sh": "e.sh"}):
        bad.append("an unchanged entry of a renamed file was judged again (#5420)")
    n += 1
    if len(allow_text_pending_elsewhere(moved, had, row, row, {})) != 1:
        bad.append("without the rename an entry in a new file was not judged (#5420)")
    # #5295: allow_text_pending_elsewhere reads the pending rows at the base AND at head (each half alone)
    n += 1
    ent = [("reason: r", "b.sh", 1, "x --token $T", 5)]
    row = [("#1", "a.sh", 1, "x --token $T", 3)]
    if len(allow_text_pending_elsewhere(ent, [], [], row, {})) != 1:
        bad.append("a new allow entry was not refused for a text pending only at head (#5295)")
    n += 1
    if len(allow_text_pending_elsewhere(ent, [], row, [], {})) != 1:
        bad.append("a new allow entry was not refused for a text pending only at the base (#5295)")
    # #4919/#4996: an allow entry for a line that was pending at the base is refused, also when
    # the file was edited or renamed in the same change; a changed line (a new key) is not
    n += 3
    ent = [("reason: r", "a.sh", 1, "x --token $T", 1)]
    if not allow_from_pending(ent, [("#1", "a.sh", 1, "x --token $T", 1)], {}):
        bad.append("an allow entry for a pending line passed (#4919)")
    if not allow_from_pending(ent, [("#1", "old/a.sh", 1, "x --token $T", 1)], {"old/a.sh": "a.sh"}):
        bad.append("an allow entry for a pending line passed after a rename of its file (#4996)")
    if allow_from_pending(ent, [("#1", "a.sh", 1, "x --token $OTHER", 1)], {}):
        bad.append("an allow entry for a changed line was refused (#4919)")
    # round-2 security: a cosmetic edit of a pending line does not make it allow-able
    n += 2
    pl = 'ssh h "curl -fsS --max-time 10 $(hdrs) https://x/y"'
    if not allow_like_vanished_pending([("reason: r", "b.sh", 1, pl.replace("10", "11"), 1)], [],
                                       [("#1", "a.sh", 1, pl, 1)], []):
        bad.append("an allow entry for an edited copy of a vanished pending line passed")
    if allow_like_vanished_pending([("reason: r", "a.sh", 1, "cat /etc/hostname", 1),
                                    ("reason: r", "b.sh", 1, pl.replace("10", "12"), 1)],
                                   [("reason: r", "a.sh", 1, pl.replace("10", "12"), 1)],
                                   [("#1", "a.sh", 1, pl, 1)], [("#1", "b.sh", 1, pl, 1)]):
        bad.append("an unrelated new allow entry or a renamed file's entries were refused as edited pending lines")
    n += 1
    if not allow_like_vanished_pending([("reason: r", "a.sh", 1, pl, 1)], [],
                                       [("#1", "a.sh", 1, pl, 1), ("#1", "c.sh", 1, pl, 1)],
                                       [("#1", "c.sh", 1, pl, 1)]):
        bad.append("a pending line moved to allow passed because the same text stays pending in another file")
    # #4920: credential flags fed from a variable are denylist-tagged, so never allow-able
    for label, line in (("mysql -p", 'mysql -u r -p"$X" db'), ("sshpass -p", 'sshpass -p "$X" ssh h'),
                        ("redis-cli -a", 'redis-cli -a "$X" ping'), ("curl -u", 'curl -u "u:$X" h'),
                        ("curl -u neutral", 'curl -u u:$X h'), ("curl -u quoted value", 'curl -u u:"$X" h'),
                        ("curl --user quoted parts", "curl --user 'u':\"$X\" h"),
                        ("curl -su combined", 'curl -su "u:$X" h'),
                        ("curl -sH x-api-key combined", 'curl -sH "x-api-key: $X" h'),
                        ("docker login --password", 'docker login -u u --password "$X" reg'),
                        ("curl -H x-auth-token", 'curl -H "x-auth-token: $X" h'),
                        ("curl -H Authorization mixed case", 'curl -H "Authorization: Bearer $X" h'),
                        ("wget --header=", 'wget --header="x-api-key: $X" h')):
        n += 1
        res = scan_exec_file(dl, "c.sh", "#!/bin/bash\n%s\n" % line) or []
        if not any("denylist" in r[2] for r in res):
            bad.append("%s fed from a variable is not tagged denylist (#4920)" % label)
        elif not check_allow_vs_denylist({"c.sh": res}, [("reason: r", "c.sh", 1, norm(line), 1)]):
            bad.append("%s fed from a variable could be allowed (#4920)" % label)
    # combined short flags carry a header the same as -H does (#4904, #4993)
    for label, line in (("curl -sH X-Secret-Key", 'curl -sH "X-Secret-Key: $X" h'),
                        ("curl -fsSH PRIVATE-TOKEN", "curl -fsSH 'PRIVATE-TOKEN: '\"$X\" h")):
        n += 1
        if not scan_exec_file(dl, "c.sh", "#!/bin/bash\n%s\n" % line):
            bad.append("%s is not triggered (#4904)" % label)
    # the stdin form is the safe form: never denylist-tagged (#4994)
    n += 1
    sl = 'docker login -u u --password-stdin reg < "$TOKEN_FILE"'
    if any("denylist" in r[2] for r in scan_exec_file(dl, "c.sh", "#!/bin/bash\n%s\n" % sl) or []):
        bad.append("docker login --password-stdin is tagged denylist (#4994)")
    rb, rn = round3_probe_cases(dl)
    bad.extend(rb)
    n += rn
    # a Dockerfile comment line inside a RUN continuation does not end the instruction (#4995)
    for label, mid in (("comment", "  # note\n"), ("comment ending in a backslash", "  # note \\\n"),
                       ("blank line", "\n")):
        n += 1
        df = "FROM x\nRUN apk add y \\\n%s  && tool --opt $API_TOKEN\n" % mid
        if not scan_exec_file(dl, "Dockerfile", df):
            bad.append("a Dockerfile %s inside a RUN continuation hid the next line (#4995)" % label)
    # the judge refuses a line held in both lists, and a prose line held in allow (#4910)
    n += 3
    one = {"a.sh": [(1, "x --token $T", ["flag"])]}
    both = judge(one, [("reason: r", "a.sh", 1, "x --token $T", 1)], [("#1", "a.sh", 1, "x --token $T", 1)], dl)[0]
    if not any("both allowed and pending" in h for h in both):
        bad.append("a line held in both lists passed the judge (#4910)")
    prose_hit = judge({"a.md": [(1, "x --token $T", ["flag"])]},
                      [("reason: r", "a.md", 1, "x --token $T", 1)], [], dl)[0]
    if not any("cannot be allowed" in h for h in prose_hit):
        bad.append("a prose line held in allow passed the judge (#4910)")
    if len(empty_scan_faults(0, [("reason: r", "a.sh", 1, "x", 1)], one)) != 1:
        bad.append("a scan of zero executable files was not a fault (#4910)")
    # the CI job checks out full history, which the merge-base rule (#4919) needs (#4910)
    n += 1
    wf = (root / ".github" / "workflows" / "c8-precheck.yml").read_text(encoding="utf-8")
    m = re.search(r"\n  exec-secret-argv-gate:\n(.*?)(?=\n  [A-Za-z0-9_-]+:\n|\Z)", wf, re.S)
    if not m or "fetch-depth: 0" not in m.group(1):
        bad.append("the exec-secret-argv-gate CI job does not check out full history (#4919)")
    # ... and names a merge base on the merge_group and push legs too (#4996)
    n += 1
    job = m.group(1) if m else ""
    if not re.search(r"EXEC_SECRET_ARGV_BASE:.*github\.event\.merge_group\.base_sha.*github\.event\.before.*"
                     r"default_branch", job):
        bad.append("the exec-secret-argv-gate CI job names no merge base for merge_group or push (#4996)")
    # an extensionless dotfile is a script only when its first line is a shell shebang (#4910)
    n += 2
    if file_class(".runner", "#!/bin/bash\ncurl x\n") != "shell":
        bad.append("a dotfile with a shell shebang was not classed as shell (#4910)")
    if file_class(".runner", "plain notes\n") is not None:
        bad.append("a dotfile with no shebang was classed as a script (#4910)")
    # #4922 and #4909: scratch roots under the checkout's .local-runs
    scratch = root / ".local-runs"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(scratch)) as td:
        t = Path(td)
        (t / "scripts").mkdir()
        (t / "scripts" / "check-docs-no-argv-secrets.py").write_text("raise ValueError('boom')\n")
        n += 1
        with contextlib.redirect_stderr(io.StringIO()):
            rc = run(t)
        if rc != 2:
            bad.append("a non-listed exception in the denylist import exited %r, not 2 (#4922)" % rc)
        (t / "big.sh").write_bytes(b"#!/bin/bash\n" + b"#" * (MAX_BYTES + 1))
        (t / "bad.sh").write_bytes(b"#!/bin/bash\n\xff\xfe curl -H 'x-api-key: $K' h\n")
        (t / "real.sh").write_text("#!/bin/bash\ntrue\n")
        os.symlink("/etc/hostname", str(t / "out.sh"))
        os.symlink("real.sh", str(t / "in.sh"))
        n += 4
        try:
            read_tracked(t, "big.sh")
            bad.append("an over-size .sh was skipped without a fault (#4909)")
        except RuntimeError:
            pass
        if "x-api-key" not in (read_tracked(t, "bad.sh") or ""):
            bad.append("a non-UTF-8 .sh was not read (#4909)")
        try:
            read_tracked(t, "out.sh")
            bad.append("a symlink out of the tree was skipped without a fault (#4909)")
        except RuntimeError:
            pass
        if read_tracked(t, "in.sh") != "#!/bin/bash\ntrue\n":
            bad.append("a symlink inside the tree was not followed (#4909)")
    # the real gate path applies every control, not only its helper (#4910)
    with tempfile.TemporaryDirectory(dir=str(scratch)) as td:
        wb, wn = _run_wiring_cases(root, Path(td))
    bad.extend(wb)
    # the history scan on merge, revert and replace-ref histories (#5299, #5463)
    with tempfile.TemporaryDirectory(dir=str(scratch)) as td:
        hb, hn = _history_cases(Path(td))
    bad.extend(hb)
    # every git read in the closed-world funnel (#5581)
    with tempfile.TemporaryDirectory(dir=str(scratch)) as td:
        fb, fn = _git_funnel_cases(Path(td))
    bad.extend(fb)
    sb, sn = _funnel_structure_cases()
    bad.extend(sb)
    # the lists read with every line-terminator and trailing-whitespace form (#5501)
    with tempfile.TemporaryDirectory(dir=str(scratch)) as td:
        tb, tn = _terminator_cases(root, Path(td))
    bad.extend(tb)
    return bad, n + wn + hn + fn + sn + tn


def self_test(root: Path) -> int:
    dl = load_denylist(root)
    bad: List[str] = []
    red = green = 0
    for label, name, text in probe_files():
        found = {name: _scan_one(dl, name, text)}
        hits, _, _ = judge(found, [], [], dl)
        red += 1
        if not hits:
            bad.append("red probe stayed green: " + label)
    for label, name, text in green_probes():
        found = {name: _scan_one(dl, name, text)}
        hits, _, _ = judge(found, [], [], dl)
        green += 1
        if hits:
            bad.append("green probe went red: %s: %s" % (label, hits[0][:100]))
    allowed = 0
    for label, line in ALLOWED_FORMS:
        text = "#!/bin/bash\n%s\n" % line
        found = {"a.sh": _scan_one(dl, "a.sh", text)}
        if not found["a.sh"]:
            bad.append("allowed-form probe is not triggered: " + label)
            continue
        entries = [("reason: probe", "a.sh", 1, norm(line), 1)]
        hits, _, _ = judge(found, entries, [], dl)
        hits = hits + check_allow_vs_denylist(found, entries)  # the real gate path (#4994)
        allowed += 1
        if hits:
            bad.append("allowed form went red: %s: %s" % (label, hits[0][:100]))
        # the same entry must go red when the line changes, grows or disappears
        for kind, newtext in (("changed", text.replace(line, line + " #m")),
                              ("duplicated", text + line + "\n"), ("removed", "#!/bin/bash\n")):
            f2 = {"a.sh": _scan_one(dl, "a.sh", newtext)}
            h2, _, _ = judge(f2, entries, [], dl)
            if not h2:
                bad.append("allow entry stayed green when the line was %s: %s" % (kind, label))
    # a pending entry passes, and goes stale when the line is gone
    pl = 'zorbctl --auth-secret "$VAL"'
    ptext = "#!/bin/bash\n%s\n" % pl
    pfound = {"p.sh": _scan_one(dl, "p.sh", ptext)}
    pent = [("#1", "p.sh", 1, norm(pl), 1)]
    h, rep, _ = judge(pfound, [], pent, dl)
    if h or not rep:
        bad.append("pending entry did not pass and report")
    h, _, _ = judge({"p.sh": []}, [], pent, dl)
    if not h:
        bad.append("stale pending entry stayed green")
    # list-file form faults
    for label, body, pend in (
            ("malformed", "reason: r | a.sh | 1", False), ("bad why", "ok | a.sh | 1 | x", False),
            ("zero count", "reason: r | a.sh | 0 | x", False), ("not normalised", "reason: r | a.sh | 1 | x  y", False),
            ("pending with bad why", "baseline | a.sh | 1 | x", True),
            ("pending with a reason and no issue", "reason: r | a.sh | 1 | x", True),
            ("duplicate", "reason: r | a.sh | 1 | x\nreason: r | a.sh | 1 | x", False)):
        faults: List[str] = []
        parse_entries(body, "t", pend, faults)
        if not faults:
            bad.append("list-file fault not raised: " + label)
    # every real allow and pending entry, mutated on its OWN line, must be red
    allow, pend, lfaults = load_lists(root)
    if lfaults:
        bad.extend(lfaults)
    cache: Dict[str, str] = {}
    mut_ok = mut_n = 0
    for kind, entries in (("allow", allow), ("pending", pend)):
        for e in entries:
            rel = e[1]
            if rel not in cache:
                cache[rel] = (root / rel).read_text(encoding="utf-8")
            text = cache[rel]
            prose = rel.lower().endswith((".md", ".html", ".htm"))
            res = scan_prose_file(dl, rel, text) if prose else scan_exec_file(dl, rel, text)
            hit = next((ln for ln in (res or []) if ln[1] == e[3]), None)
            mut_n += 1
            if hit is None:
                bad.append("%s entry matches nothing: %s" % (kind, e[3][:80]))
                continue
            units = prose_units(rel, text) if prose else exec_units(rel, text)
            unit = next((u for u in (units or []) if u[0] == hit[0]), None)
            if unit is None:
                bad.append("%s entry has no unit: %s" % (kind, e[3][:80]))
                continue
            mtext = _mutate(text, unit[0], unit[1])
            res2 = scan_prose_file(dl, rel, mtext) if prose else scan_exec_file(dl, rel, mtext)
            mine_a = [x for x in allow if x[1] == rel]
            mine_p = [x for x in pend if x[1] == rel]
            hits, _, _ = judge({rel: res2 or []}, mine_a, mine_p, dl, only=[rel])
            if hits:
                mut_ok += 1
            else:
                bad.append("%s entry mutation stayed green: %s" % (kind, e[3][:80]))
    # a mistyped argument exits 2
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            build_parser().parse_args(["--bogus"])
            bad.append("a mistyped argument was accepted")
        except SystemExit as exc:
            if exc.code != 2:
                bad.append("a mistyped argument exited %r, not 2" % exc.code)
    # regen refusal cases
    regen_bad, regen_n = regen_cases(root)
    bad.extend(regen_bad)
    hard_bad, hard_n = hardening_cases(root, dl)
    bad.extend(hard_bad)
    if bad:
        print("\n".join("SELF-TEST FAIL: " + b for b in bad), file=sys.stderr)
        return 1
    print("SELF-TEST PASS: %d red probes flagged, %d green probes clean, %d allowed forms approved and "
          "red when changed, %d of %d allow and pending entry mutations red, %d regen refusal cases, "
          "%d gate hardening cases, mistyped argument exits 2" % (red, green, allowed, mut_ok, mut_n, regen_n, hard_n))
    return 0


def regen_cases(root: Path) -> Tuple[List[str], int]:
    spec = importlib.util.spec_from_file_location("regen_exec", str(root / "scripts/regen-exec-secret-argv-allow.py"))
    if spec is None or spec.loader is None:
        return ["cannot load the regen script"], 0
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod.refusal_cases(root), mod.REFUSAL_CASE_COUNT


# ---------------------------------------------------------------- cli
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Closed-world gate against secrets on a process argv (executable files).")
    ap.add_argument("--self-test", action="store_true", help="red probes, green probes, allow-entry mutations")
    ap.add_argument("--list", action="store_true", help="print every triggered line, then exit")
    ap.add_argument("--root", default=str(ROOT), help="repository root (default: this checkout)")
    return ap


def main(argv: List[str]) -> int:
    args = build_parser().parse_args(argv[1:])
    root = Path(args.root)
    try:
        if args.self_test:
            return self_test(root)
        if args.list:
            dl = load_denylist(root)
            found, _, _ = scan_repo(root, dl)
            for rel, lines in sorted(found.items()):
                for start, text, reasons in lines:
                    print("%s:%d [%s] %s" % (rel, start, ",".join(reasons[:3]), dl.redact(text)))
            return 0
        return run(root)
    except Exception as exc:  # noqa: BLE001 - every failure of the gate itself fails closed
        print("FAULT: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
