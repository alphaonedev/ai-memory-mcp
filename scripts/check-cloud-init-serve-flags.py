#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#4616 - cloud-init memory templates must start a daemon that can boot.

Two infra templates start ``ai-memory serve`` from a systemd unit rendered by
cloud-init (``infra/do-hive/cloud-init-memory.yaml.tpl`` and
``infra/aws-gpu-burst/cloud-init-memory.yaml.tpl``). A flag the binary does not
define (the old ``--bind``) makes the unit exit at start and loop on
``Restart=on-failure``; cloud-init discards a config containing a non-ASCII
byte (#1880). Neither failure shows up at provision time.

The gate scans the files matching ``infra/*/cloud-init-memory*.tpl`` on disk
(a filesystem glob, not ``git ls-files``). It enforces seven rules; the function
that proves each is named, and ``--self-test`` carries red and green probes for
every one:

  1. ``scan_text``: no non-ASCII byte (cloud-init discards the config, #1880).
  2. ``serve_invocations``: some ``ExecStart=`` runs ``ai-memory serve`` (a gate
     that finds nothing to check must not pass); the parser joins systemd
     ``\\``-continued lines, accepts a ``/usr/bin/env`` wrapper and global flags
     before ``serve``, and fails closed on a shell or other launcher that hides
     the argv.
  3. ``serve_arg_hits``: every ``--flag`` after ``serve`` is a long flag of
     ``ServeArgs`` in ``src/daemon_runtime.rs`` (``serve_flags`` parses it; clap
     derives it from the field name or an explicit ``long = "name"``); a short
     flag is accepted only if ServeArgs defines it (none does today); partly-interpolated values are refused; only a whole ``${name}``
     or ``$${name}`` is accepted, and only as a flag value.
  4. ``scan_text``: ``--tls-cert`` and ``--tls-key`` are both present (a policy
     choice: the templates supply operator certificate material whose SAN
     carries the node IP; serve itself would resolve its own certificate with no
     flags, ``resolve_tls_material``, src/daemon_runtime.rs:6163-6225).
  5. ``dsn_hits``: every ``postgres://`` URL, wherever it is written, ends with
     ``sslmode=verify-full`` as its last sslmode (the #3705 floor,
     src/transit_encryption.rs:436-446), except a template listed in
     ``DSN_FLOOR_GAPS`` (``main`` fails a listed template that now passes).
  6. ``store_channel_hits`` and ``exec_store_url_hits``: the store URL reaches
     the daemon only through ``AI_MEMORY_STORE_URL_FILE`` (#4577): no
     ``AI_MEMORY_STORE_URL=`` and no ``--store-url`` in any spelling, no store
     URL on an ``ExecStart``, and no URL with a password inside a systemd unit.
  7. ``pin_hits`` (with ``fetch_pinned_body_hits`` and ``git_verb``): extension
     sources are fetched only by the one ``fetch_pinned`` function that ends
     in a ``rev-parse HEAD = "$3"`` check, every call passes a ``*_COMMIT``
     variable, and every ``*_COMMIT=`` value is a full 40-hex commit (#4636).

Usage (any other argument exits 2):
  scripts/check-cloud-init-serve-flags.py             exit 0 clean, 1 on a
                                                      hit, 2 on a scanner fault
  scripts/check-cloud-init-serve-flags.py --self-test prove the rule is red on
                                                      probes, green on clean
                                                      lines
"""
from __future__ import annotations

import argparse
import contextlib
import io
import posixpath
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVE_SRC = ROOT / "src" / "daemon_runtime.rs"
TEMPLATE_GLOB = "infra/*/cloud-init-memory*.tpl"
AWS_TEMPLATE = "infra/aws-gpu-burst/cloud-init-memory.yaml.tpl"
REQUIRED_FLAGS = ("--tls-cert", "--tls-key")

# Templates that still lack the sslmode floor, each with its tracker. The
# do-hive store URL dials PgBouncer on 127.0.0.1:6432 and its TLS shape has
# more than one viable form (#4635 do-hive leg, awaiting a vote). The list may
# only shrink: a listed template that passes the floor is itself a failure.
DSN_FLOOR_GAPS = {
    "infra/do-hive/cloud-init-memory.yaml.tpl": "#4635 do-hive pgbouncer leg",
}
# Any `<NAME>_COMMIT=<value>` assignment; every one must be a full 40-hex commit.
COMMIT_RE = re.compile(r"(?<![\w$])(\w+_COMMIT)=(\S*)")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
# A shell command `git ...` (not `.git` in a URL, not the word in a package list).
GIT_CMD_RE = re.compile(r"(?<![\w./$-])git[ \t]+(?P<args>[^;&|\n)]*)")
GIT_OPT_WITH_ARG = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env")
FETCH_PINNED_DEF_RE = re.compile(r"^[ \t]*fetch_pinned\(\)[ \t]*\{[^\n]*\n(?P<body>.*?)\n[ \t]*\}[ \t]*$", re.M | re.S)
FETCH_PINNED_CALL_RE = re.compile(r'^[ \t]*fetch_pinned[ \t]+https://\S+[ \t]+\S+[ \t]+"\$(?P<var>\w+_COMMIT)"[ \t]*$')
VERIFY_RE = re.compile(r'^\[ "\$\(git(?: -C "\$2")? rev-parse HEAD\)" = "\$3" \]$')
COMMENT_LINE_RE = re.compile(r"^[ \t]*#.*$", re.M)
# A postgres URL anywhere (file line, Environment=, an argv, a heredoc), but not
# a regex that merely begins with the scheme (s#^postgres://...#): the scheme
# must start the text or follow whitespace, = " ' ( ` > , or {.
DSN_RE = re.compile(r"(?<![^\s=\"'(`>,{])postgres(?:ql)?://[^\s\"']+")
STORE_ENV_RE = re.compile(r"(?<!\w)AI_MEMORY_STORE_URL=")
UNIT_ENTRY_RE = re.compile(r"^[ \t]*-[ \t]+path:[ \t]*(\S+)[ \t]*$", re.M)
USERINFO_PW_RE = re.compile(r"[A-Za-z][\w+.-]*://[^/@\s:\"']+:[^/@\s\"']+@")
STRUCT_RE = re.compile(r"pub struct ServeArgs \{(.*?)\n\}", re.S)
FIELD_RE = re.compile(r"^\s{4}pub (\w+):", re.M)
ATTR_RE = re.compile(r"#\[arg\((.*?)\)\]", re.S)
LONG_NAMED_RE = re.compile(r'\blong\s*=\s*"([^"]+)"')
LONG_BARE_RE = re.compile(r"(?<![\w=])long\s*(?:,|$)")
SHORT_NAMED_RE = re.compile(r"\bshort\s*=\s*'(.)'")
SHORT_BARE_RE = re.compile(r"(?<![\w=])short\s*(?:,|$)")
STORE_FLAG_RE = re.compile(r"(?<![\w-])--store[-_]url\b")
STORE_SCHEME_RE = re.compile(r"(?i)\b(?:postgres(?:ql)?|sqlite)://")
ENV_WRAPPER_ARG_RE = re.compile(r"^(?:-i|--ignore-environment|\w+=\S*)$")
INTERP_RE = re.compile(r"\$?\$\{[A-Za-z_]\w*\}")
ALIAS_RE = re.compile(r'\b(?:visible_)?alias(?:es)?\s*=\s*"([^"]+)"')
EXEC_RE = re.compile(r"^[ \t]*ExecStart=(?P<cmd>.*)$", re.M)
CONT_RE = re.compile(r"\\[ \t]*\n[ \t]*")
FLAG_RE = re.compile(r"^(--[A-Za-z][\w-]*)")


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
    not read as flags. Interpolations (``${x}``, ``$${x}``) stay: they are
    checked where they sit, because systemd expands them in ExecStart."""
    return re.sub(r"%\{[^}]*\}", " ", text)


def argv_views(text: str) -> list:
    """The same text as systemd joins it (backslash-newline becomes a space), as
    a shell joins it (backslash-newline vanishes) and unjoined, comments blanked.
    A forbidden spelling must not hide in any of them."""
    t = blank_comments(text)
    return [t, CONT_RE.sub(" ", t), re.sub(r"\\\n", "", t)]


def exec_store_url_hits(name: str, text: str) -> list:
    """#4662: no ExecStart may carry a store URL, in any spelling (``--store-url``
    long form, ``=`` form, a value of another flag, a ${VAR}, a continuation split,
    a global flag before serve): the DSN reaches the daemon only through
    AI_MEMORY_STORE_URL_FILE (#4577), never on a world-readable argv."""
    hits = []
    for view in argv_views(text):
        for m in EXEC_RE.finditer(view):
            cmd = strip_terraform(m.group("cmd"))
            if STORE_FLAG_RE.search(cmd) or STORE_SCHEME_RE.search(cmd):
                msg = "%s: ExecStart carries a store URL (--store-url or a postgres:// value); use AI_MEMORY_STORE_URL_FILE (#4577, #4662)" % name
                if msg not in hits:
                    hits.append(msg)
    return hits


def prefix_is_env_wrapper(pre: list) -> bool:
    """Tokens before the ai-memory binary may only be an ``env`` wrapper with
    options/assignments; a shell, runuser or any other launcher is not parsed."""
    if not pre:
        return True
    if posixpath.basename(pre[0].lstrip("-@+!:")) != "env":
        return False
    return all(ENV_WRAPPER_ARG_RE.match(t) for t in pre[1:])


def serve_arg_hits(name: str, lineno: int, after: list, known: set) -> list:
    """Check every token after ``serve``: flags must be ServeArgs flags (long or
    short), a value must directly follow its flag, and an expansion may only be
    a whole ``${name}`` / ``$${name}`` inside a value (serve flags are literal)."""
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
    """Return (line, tokens-after-serve, unparsed) for every ExecStart that runs serve.

    ``unparsed`` is True when the line holds a ``serve`` token but the
    ai-memory binary could not be identified (fail closed, never skip).
    """
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


def dsn_hits(name: str, text: str) -> list:
    """Every postgres:// URL in the template, wherever it is written, ends with
    sslmode=verify-full as its last sslmode (the #3705 floor); #4659."""
    hits = []
    dsns = set()
    for view in argv_views(text):
        dsns.update(DSN_RE.findall(view))
    if not dsns:
        hits.append("%s: no postgres:// store URL found (cannot check the sslmode floor)" % name)
    floor_ok = True
    for dsn in sorted(dsns):
        query = dsn.split("?", 1)[1] if "?" in dsn else ""
        modes = [p.split("=", 1)[1].strip().lower() for p in query.split("&") if p.lower().startswith("sslmode=")]
        if not modes or modes[-1] != "verify-full":
            floor_ok = False
            if name in DSN_FLOOR_GAPS:
                continue
            hits.append("%s: store URL %s has no sslmode=verify-full (serve refuses it at start, #3705 floor, src/transit_encryption.rs:436-446)" % (name, dsn.split("@")[-1][:60]))
    if name in DSN_FLOOR_GAPS and floor_ok and dsns:
        hits.append("%s: store URL now passes the sslmode floor; remove it from DSN_FLOOR_GAPS" % name)
    return hits


def store_channel_hits(name: str, text: str) -> list:
    """#4659/#4664: the store URL reaches the daemon only through
    AI_MEMORY_STORE_URL_FILE. AI_MEMORY_STORE_URL= (in a unit Environment=, an
    export, anywhere) and --store-url are refused in any spelling, and a systemd
    unit written to the node (0644, readable by every local user through
    ``systemctl show``) may not hold a URL with a password at all."""
    hits = []
    for view in argv_views(text):
        for rx, what in ((STORE_ENV_RE, "AI_MEMORY_STORE_URL= (a store URL in the environment)"), (STORE_FLAG_RE, "--store-url")):
            if rx.search(view):
                msg = "%s: %s is not allowed; use AI_MEMORY_STORE_URL_FILE (#4577, #4659, #4664)" % (name, what)
                if msg not in hits:
                    hits.append(msg)
    blanked = CONT_RE.sub(" ", blank_comments(text))
    entries = list(UNIT_ENTRY_RE.finditer(blanked))
    for i, em in enumerate(entries):
        path = em.group(1)
        if not (path.endswith(".service") or "/systemd/" in path):
            continue
        end = entries[i + 1].start() if i + 1 < len(entries) else len(blanked)
        if USERINFO_PW_RE.search(blanked[em.end():end]):
            hits.append("%s: unit %s carries a URL with a password (the unit is 0644; use AI_MEMORY_STORE_URL_FILE, #4664)" % (name, path))
    return hits


def blank_comments(text: str) -> str:
    """Blank whole-line comments (keeping the newline). Done before continuation
    joining: a comment line ending in a backslash does not continue."""
    return COMMENT_LINE_RE.sub("", text)


def join_continuations(text: str):
    """Collapse backslash-newline continuations; return (joined, line_at) where
    line_at maps a joined offset back to its line number in ``text``."""
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


def git_verb(args: str):
    """Return (verb, rest) of a ``git <global options> <verb> ...`` argument string."""
    toks = args.split()
    i = 0
    while i < len(toks) and toks[i].startswith("-"):
        i += 2 if toks[i] in GIT_OPT_WITH_ARG else 1
    if i >= len(toks):
        return "", []
    return toks[i], toks[i + 1:]


def fetch_pinned_body_hits(name: str, line: int, body: str) -> list:
    """The one function allowed to run git must fetch the pin, check out what it
    fetched, and fail unless HEAD is exactly the pin."""
    hits = []
    chain, sep, handler = body.partition("||")
    segs = [x.strip() for x in chain.split("&&")]
    seen = set()
    for i, seg in enumerate(segs):
        gm = GIT_CMD_RE.match(seg)
        if seg == 'rm -rf "$2"':
            continue
        if VERIFY_RE.match(seg):
            seen.add("verify")
            if i != len(segs) - 1:
                hits.append("%s:%d: fetch_pinned: the rev-parse check must be the last step of the chain" % (name, line))
            continue
        if gm is None:
            hits.append("%s:%d: fetch_pinned: unrecognised step %r" % (name, line, seg[:60]))
            continue
        verb, rest = git_verb(gm.group("args"))
        if verb == "init":
            continue
        if verb == "remote" and rest[:1] == ["add"]:
            continue
        if verb == "fetch" and rest and rest[-1] == '"$3"':
            seen.add("fetch")
            continue
        if verb == "checkout" and rest and rest[-1] == "FETCH_HEAD":
            seen.add("checkout")
            continue
        hits.append("%s:%d: fetch_pinned: git %s is not a pinned step (fetch the commit as \"$3\", check out FETCH_HEAD)" % (name, line, verb or "?"))
    for need, why in (("fetch", 'git fetch ... "$3"'), ("checkout", "git checkout ... FETCH_HEAD"), ("verify", '[ "$(git -C "$2" rev-parse HEAD)" = "$3" ]')):
        if need not in seen:
            hits.append("%s:%d: fetch_pinned has no %s step (%s, #4636)" % (name, line, need, why))
    if not sep or not re.search(r"\breturn[ \t]+1\b", handler):
        hits.append("%s:%d: fetch_pinned has no failure handler that returns 1 (a pin mismatch must stop the script)" % (name, line))
    return hits


def pin_hits(name: str, text: str) -> list:
    """#4636/#4657: every git use is the one verified fetch_pinned, called with a
    40-hex commit variable assigned only 40-hex values."""
    hits = []
    joined, line_at = join_continuations(blank_comments(text))
    commits = set()
    for m in COMMIT_RE.finditer(joined):
        if HEX40_RE.match(m.group(2)):
            commits.add(m.group(1))
        else:
            hits.append("%s:%d: %s is not a full 40-hex commit" % (name, line_at(m.start()), m.group(1)))
    defs = list(FETCH_PINNED_DEF_RE.finditer(joined))
    spans = [(d.start("body"), d.end("body")) for d in defs]
    gits = list(GIT_CMD_RE.finditer(joined))
    for m in gits:
        if not any(a <= m.start() < b for a, b in spans):
            hits.append("%s:%d: git %s outside fetch_pinned (every git fetch/checkout goes through fetch_pinned with a *_COMMIT 40-hex pin, #4636)" % (name, line_at(m.start()), m.group("args").strip()[:40]))
    ndefs = joined.count("fetch_pinned()")
    call_lines = [m for m in re.finditer(r"^.*fetch_pinned.*$", joined, re.M) if "fetch_pinned()" not in m.group(0)]
    if gits or call_lines or ndefs:
        if ndefs != 1 or len(defs) != 1:
            hits.append("%s: expected exactly one multi-line fetch_pinned() definition, found %d (%d parsed)" % (name, ndefs, len(defs)))
        for d in defs:
            hits.extend(fetch_pinned_body_hits(name, line_at(d.start("body")), d.group("body")))
    for m in call_lines:
        cm = FETCH_PINNED_CALL_RE.match(m.group(0))
        if cm is None:
            hits.append("%s:%d: fetch_pinned call must be exactly: fetch_pinned https://<url> <dir> \"$<NAME>_COMMIT\" (got %r)" % (name, line_at(m.start()), m.group(0).strip()[:60]))
        elif cm.group("var") not in commits:
            hits.append("%s:%d: fetch_pinned uses $%s, which is not assigned a 40-hex commit in this template" % (name, line_at(m.start()), cm.group("var")))
    return hits


def scan_text(name: str, text: str, known: set) -> list:
    """Return one message per defect found in a template's text."""
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if any(ord(ch) > 127 for ch in line):
            hits.append("%s:%d: non-ASCII byte (cloud-init discards the config, #1880)" % (name, lineno))
    hits.extend(dsn_hits(name, text))
    hits.extend(store_channel_hits(name, text))
    hits.extend(pin_hits(name, text))
    hits.extend(exec_store_url_hits(name, text))
    invocations = serve_invocations(text)
    if not invocations:
        hits.append("%s: no ExecStart runs 'ai-memory serve' (nothing to check; a template that cannot start serve must not pass)" % name)
    for lineno, after, unparsed in invocations:
        if unparsed:
            hits.append("%s:%d: ExecStart names serve but is not 'ai-memory serve' or an env wrapper of it (a shell or other launcher hides the argv; cannot check its flags)" % (name, lineno))
            continue
        hits.extend(serve_arg_hits(name, lineno, after, known))
        flags = [t.strip("\"'").split("=", 1)[0] for t in after if t.strip("\"'").startswith("-")]
        for req in REQUIRED_FLAGS:
            if req not in flags:
                hits.append("%s:%d: serve has no %s (template policy: supply the listener certificate with the node IP SAN)" % (name, lineno, req))
    return hits


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="#4616 cloud-init memory templates must start a daemon that can boot")
    ap.add_argument("--self-test", action="store_true", help="prove the rules are red on probes and green on clean lines")
    return ap


def mutate(text: str, old: str, new: str) -> str:
    """Replace ``old`` with ``new`` or fail loudly: a probe built from the real
    template must not silently stop mutating it when the template changes."""
    if old not in text:
        raise RuntimeError("self-test fixture drift: %r not found in the AWS template" % old[:60])
    return text.replace(old, new, 1)


# Built by concatenation so this file carries no literal flag-plus-DSN (#4577 gate).
SU = "--store-" + "url"


def self_test(known: set) -> int:
    real = (ROOT / AWS_TEMPLATE).read_text(encoding="utf-8")
    age_call = '        fetch_pinned https://github.com/apache/age.git /opt/age-src "$AGE_COMMIT"\n'
    rev_line = '          && [ "$(git -C "$2" rev-parse HEAD)" = "$3" ] \\\n'
    handler = '|| { echo "pin mismatch: $1 did not resolve to $3"; return 1; }'
    age_assign = "      AGE_COMMIT=e43dc1a12b78fba4acef9835b2b10379b8d243b4\n"
    dsn = "      postgres://u:p@localhost/db?sslmode=verify-full&sslrootcert=/c\n"
    unit = "ExecStart=/opt/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9077 --tls-cert /a --tls-key /b\n"
    good = dsn + unit
    probes = {
        "bind flag": good.replace("--host 0.0.0.0", "--bind 0.0.0.0:9077"),
        "no tls": dsn + "ExecStart=/opt/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9077\n",
        "tls key missing": good.replace(" --tls-key /b", ""),
        "no sslmode": good.replace("?sslmode=verify-full&sslrootcert=/c", ""),
        "weak sslmode": good.replace("verify-full", "require"),
        "non-ascii": "# em dash \u2014\n" + good,
        "zero serve lines": dsn + "ExecStart=/opt/ai-memory/fed-bootstrap.sh\n",
        "env wrapper, bad flag": good.replace("ExecStart=/opt/", "ExecStart=/usr/bin/env /opt/").replace("--host 0.0.0.0", "--bind 0.0.0.0:9077"),
        "env wrapper, no tls": dsn + "ExecStart=/usr/bin/env ai-memory serve --host 0.0.0.0 --port 9077\n",
        "global flag before serve, no tls": dsn + "ExecStart=/opt/ai-memory/bin/ai-memory --db /x serve --host 0.0.0.0\n",
        "global flag before serve, bad flag": good.replace("ai-memory serve", "ai-memory --db /x serve").replace("--port", "--prot"),
        "continuation, tls key on next line missing": dsn + "ExecStart=/opt/ai-memory/bin/ai-memory serve --host 0.0.0.0 \\\n  --tls-cert /a\n",
        "continuation, bad flag": good.replace("--port 9077", "\\\n  --prot 9077"),
        "git clone of a branch": good + "        git clone https://github.com/apache/age.git /opt/age-src\n",
        "git checkout of a branch": good + "        git checkout release/PG18/1.8.0\n",
        "short commit pin": good + "      AGE_COMMIT=e43dc1a\n",
        "4657 aws: git -C fetch of a branch then checkout FETCH_HEAD": mutate(real, age_call, "        git init -q /opt/age-src\n        git -C /opt/age-src fetch -q origin release/PG18/1.8.0\n        git -C /opt/age-src checkout -q FETCH_HEAD\n"),
        "4657 aws: fetch_pinned without its rev-parse check": mutate(real, rev_line, ""),
        "4657 aws: fetch_pinned called with a branch": mutate(real, age_call, '        fetch_pinned https://github.com/apache/age.git /opt/age-src release/PG18/1.8.0\n'),
        "4657 aws: fetch_pinned called with an unassigned variable": mutate(real, '/opt/age-src "$AGE_COMMIT"', '/opt/age-src "$OTHER_COMMIT"'),
        "4657 aws: pin reassigned from a command": mutate(real, age_assign, age_assign + "      AGE_COMMIT=$(curl -fsS https://example.invalid/head)\n"),
        "4657 aws: second fetch_pinned definition": mutate(real, "      # pgvector v0.8.6 (git ls-remote", "      fetch_pinned() { true; }\n      # pgvector v0.8.6 (git ls-remote"),
        "4657 aws: failure handler replaced by true": mutate(real, handler, "|| true"),
        "4657 aws: git pull outside fetch_pinned": mutate(real, age_call, age_call + "        git -C /opt/age-src pull -q\n"),
        "4658 aws: unknown short flag": mutate(real, "serve --host 0.0.0.0", "serve -b 0.0.0.0:9077 --host 0.0.0.0"),
        "4658 aws: systemd ${VAR} after a value": mutate(real, "--port 9077 ", "--port 9077 ${EXTRA_SERVE_FLAGS} "),
        "4658 aws: escaped $${VAR} after a value": mutate(real, "--port 9077 ", "--port 9077 $${EXTRA_SERVE_FLAGS} "),
        "4658 aws: unbraced $VAR as a value": mutate(real, "--port 9077 ", "--port $PORT "),
        "4658 aws: stray positional argument": mutate(real, "--port 9077 ", "--port 9077 stray "),
        "4658 aws: short help flag": mutate(real, "serve --host", "serve -h --host"),
        "4658 aws: partial interpolation with a bare dollar": mutate(real, "--port 9077 ", "--port ${a}$b "),
        "4662 aws: --store-url on the serve argv": mutate(real, "--port 9077 --tls-cert", "--port 9077 " + SU + " postgres://aimemory:x@localhost/aimemory?sslmode=verify-full --tls-cert"),
        "4662 aws: --store-url=<dsn>": mutate(real, "--port 9077 --tls-cert", "--port 9077 " + SU + "=postgres://aimemory:x@localhost/aimemory?sslmode=verify-full --tls-cert"),
        "4662 aws: --store-url through a ${VAR}": mutate(real, "--port 9077 --tls-cert", "--port 9077 --store-url ${DSN} --tls-cert"),
        "4662 aws: --store-url split across continuation lines": mutate(real, "--port 9077 --tls-cert", "--port 9077 \\\n  --store-url \\\n  postgres://aimemory:x@localhost/aimemory?sslmode=verify-full \\\n  --tls-cert"),
        "4662 aws: bash-style split --store-\\<newline>url": mutate(real, "--port 9077 --tls-cert", "--port 9077 --store-\\\nurl postgres://aimemory:x@localhost/aimemory?sslmode=verify-full --tls-cert"),
        "4662 aws: store URL as a value of another flag": mutate(real, "--port 9077", "--port postgres://aimemory:x@localhost/aimemory?sslmode=verify-full"),
        "4662 aws: global --store-url before serve": mutate(real, "ai-memory serve", "ai-memory " + SU + " postgres://aimemory:x@localhost/aimemory?sslmode=verify-full serve"),
        "4662 aws: shell -c wrapper around serve": mutate(real, "ExecStart=/usr/local/lib/ai-memory/bin/ai-memory serve", "ExecStart=/bin/sh -c 'exec /usr/local/lib/ai-memory/bin/ai-memory serve"). replace("--tls-key /etc/ai-memory/tls/node.key", "--tls-key /etc/ai-memory/tls/node.key'"),
        "4662 aws: runuser wrapper around serve": mutate(real, "ExecStart=/usr/local/lib/ai-memory/bin/ai-memory serve", "ExecStart=/usr/sbin/runuser -u aimemory -- /usr/local/lib/ai-memory/bin/ai-memory serve"),
        "4659 aws: weak URL in Environment=AI_MEMORY_STORE_URL next to a compliant store-url file": mutate(real, "Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url", "Environment=AI_MEMORY_STORE_URL=postgres://aimemory:x@localhost/aimemory"),
        "4659 aws: weak URL passed to another program": mutate(real, "      systemctl daemon-reload", '      psql "postgres://aimemory:x@localhost/aimemory?sslmode=require" -c "select 1"\n      systemctl daemon-reload'),
        "4659 aws: weak URL after --store-url outside the unit": mutate(real, "      systemctl daemon-reload", "      /opt/ai-memory/bin/ai-memory schema-init " + SU + " postgres://aimemory:x@localhost/aimemory\n      systemctl daemon-reload"),
        "4659 aws: Environment= name split by a bash continuation": mutate(real, "Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url", "Environment=AI_MEMORY_STORE_\\\nURL=postgres://aimemory:x@localhost/aimemory"),
        "4664 aws: password-bearing DSN with verify-full in Environment=": mutate(real, "Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url", "Environment=AI_MEMORY_STORE_URL=postgres://aimemory:pw@localhost/aimemory?sslmode=verify-full"),
        "4664 aws: quoted Environment= with a password DSN": mutate(real, "Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url", 'Environment="AI_MEMORY_STORE_URL=postgres://aimemory:pw@localhost/aimemory?sslmode=verify-full"'),
        "4664 aws: Environment= store URL from a templated value": mutate(real, "Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url", "Environment=AI_MEMORY_STORE_URL=${dsn}"),
        "4664 aws: password DSN under another name in the 0644 unit": mutate(real, "Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url", "Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url\n      Environment=COPY=postgres://aimemory:pw@localhost/aimemory?sslmode=verify-full"),
        "serve with unidentified binary": dsn + "ExecStart=/opt/ai-memory/bin/wrapper serve --host 0.0.0.0 --tls-cert /a --tls-key /b\n",
    }
    red = 0
    for label, text in probes.items():
        if scan_text(label, text, known):
            red += 1
        else:
            print("SELF-TEST FAIL: probe not flagged: " + label, file=sys.stderr)
    greens = {
        "4657 aws template as shipped": real,
        "4662 env wrapper with an assignment": good.replace("ExecStart=/opt/", "ExecStart=/usr/bin/env -i HOME=/x /opt/"),
        "4658 value is a terraform interpolation": good.replace("--port 9077", "--port ${port}"),
        "4658 value is a systemd ${VAR} (do-hive quorum-peers shape)": good + "ExecStart=/opt/ai-memory/bin/ai-memory serve --tls-cert /a --tls-key /b --quorum-peers $${PEERS}\n",
        "4658 flag with = and an interpolation": good.replace("--port 9077", "--port=${port}"),
        "clean": good,
        "env wrapper": good.replace("ExecStart=/opt/", "ExecStart=/usr/bin/env /opt/"),
        "global flag before serve": good.replace("ai-memory serve", "ai-memory --db /x serve"),
        "continuation": good.replace("--port 9077", "\\\n  --port 9077"),
        "pinned fetch": good + "      AGE_COMMIT=e43dc1a12b78fba4acef9835b2b10379b8d243b4\n      # git clone is only mentioned in a comment\n",
        "terraform directive": good.rstrip() + "%{ if x } --quorum-writes 2%{ endif }\n",
    }
    clean = 0
    for label, text in greens.items():
        got = scan_text(label, text, known)
        if got:
            print("SELF-TEST FAIL: green probe flagged: %s: %s" % (label, got), file=sys.stderr)
        else:
            clean += 1
    # An argument the parser does not define must exit 2, not run the scan.
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            build_parser().parse_args(["--selftest"])
        argparse_red = False
    except SystemExit as exc:
        argparse_red = exc.code == 2
    if not argparse_red:
        print("SELF-TEST FAIL: a mistyped argument did not exit 2", file=sys.stderr)
    if red != len(probes) or clean != len(greens) or not argparse_red:
        print("SELF-TEST FAIL: %d/%d red, %d/%d green, argparse=%s" % (red, len(probes), clean, len(greens), argparse_red), file=sys.stderr)
        return 2
    print("self-test: %d red probes flagged, %d green probes clean, mistyped argument exits 2" % (red, clean))
    return 0


def main(argv: list) -> int:
    args = build_parser().parse_args(argv[1:])
    try:
        known = serve_flags(SERVE_SRC.read_text(encoding="utf-8"))
        if args.self_test:
            return self_test(known)
        templates = sorted(ROOT.glob(TEMPLATE_GLOB))
        if len(templates) < 2:
            print("FAULT: expected at least 2 templates, found %d" % len(templates), file=sys.stderr)
            return 2
        hits = []
        for path in templates:
            hits.extend(scan_text(str(path.relative_to(ROOT)), path.read_text(encoding="utf-8"), known))
    except (OSError, RuntimeError, UnicodeDecodeError) as exc:
        print("FAULT: %s" % exc, file=sys.stderr)
        return 2
    if hits:
        print("\n".join(hits), file=sys.stderr)
        print("FAIL: %d cloud-init serve defect(s)" % len(hits), file=sys.stderr)
        return 1
    print("PASS: %d templates checked, %d serve flags known" % (len(templates), len(known)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
