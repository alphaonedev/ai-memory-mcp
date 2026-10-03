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
(a filesystem glob, not ``git ls-files``). For each template it fails when:

  * the template has no ``ExecStart=`` that runs ``ai-memory serve`` (a gate
    that finds nothing to check must not pass); the parser joins systemd
    ``\\``-continued lines, accepts a ``/usr/bin/env`` wrapper, and accepts
    global flags between the binary and ``serve``;
  * a ``--flag`` after ``serve`` is not a long flag of ``ServeArgs`` in
    ``src/daemon_runtime.rs`` (clap derives it from the field name, or from an
    explicit ``long = "name"``);
  * ``--tls-cert`` / ``--tls-key`` are not both present (a policy choice: the
    templates supply operator certificate material whose SAN carries the
    node IP; serve itself would resolve its own certificate with no flags,
    ``resolve_tls_material``, src/daemon_runtime.rs:6163-6225);
  * the ``postgres://`` store URL has no ``sslmode=verify-full`` (the #3705
    floor, src/transit_encryption.rs:436-446), except a template listed in
    ``DSN_FLOOR_GAPS``; or
  * the template runs ``git clone`` / ``git checkout`` of an extension source
    (#4636: use ``fetch_pinned`` with a ``*_COMMIT=<40 hex>`` variable), or a
    ``*_COMMIT=`` value is not a full 40-hex commit; or
  * the template contains a non-ASCII byte.

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
DSN_RE = re.compile(r"^\s+(postgres(?:ql)?://\S+)\s*$", re.M)
STRUCT_RE = re.compile(r"pub struct ServeArgs \{(.*?)\n\}", re.S)
FIELD_RE = re.compile(r"^\s{4}pub (\w+):", re.M)
ATTR_RE = re.compile(r"#\[arg\((.*?)\)\]", re.S)
LONG_NAMED_RE = re.compile(r'\blong\s*=\s*"([^"]+)"')
LONG_BARE_RE = re.compile(r"(?<![\w=])long\s*(?:,|$)")
ALIAS_RE = re.compile(r'\b(?:visible_)?alias(?:es)?\s*=\s*"([^"]+)"')
EXEC_RE = re.compile(r"^[ \t]*ExecStart=(?P<cmd>.*)$", re.M)
CONT_RE = re.compile(r"\\[ \t]*\n[ \t]*")
FLAG_RE = re.compile(r"^(--[A-Za-z][\w-]*)")


def serve_flags(source: str) -> set:
    """Long flags clap derives for ServeArgs: field name, or explicit long = name."""
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
    if not flags:
        raise RuntimeError("ServeArgs exposes no long flags")
    return flags


def strip_terraform(text: str) -> str:
    """Drop terraform directives and interpolations so their words are not read as flags."""
    text = re.sub(r"%\{[^}]*\}", " ", text)
    return re.sub(r"\$\$?\{[^}]*\}", " ", text)


def serve_invocations(text: str) -> list:
    """Return (line, tokens-after-serve, unparsed) for every ExecStart that runs serve.

    ``unparsed`` is True when the line holds a ``serve`` token but the
    ai-memory binary could not be identified (fail closed, never skip).
    """
    joined = CONT_RE.sub(" ", text)
    found = []
    for m in EXEC_RE.finditer(joined):
        tokens = strip_terraform(m.group("cmd")).split()
        if "serve" not in tokens:
            continue
        line = joined.count("\n", 0, m.start()) + 1
        bin_idx = next((i for i, t in enumerate(tokens) if posixpath.basename(t.lstrip("-@+!:")) == "ai-memory"), None)
        if bin_idx is None or "serve" not in tokens[bin_idx + 1:]:
            found.append((line, [], True))
            continue
        verb = tokens.index("serve", bin_idx + 1)
        found.append((line, tokens[verb + 1:], False))
    return found


def dsn_hits(name: str, text: str) -> list:
    hits = []
    dsns = DSN_RE.findall(text)
    if not dsns:
        hits.append("%s: no postgres:// store URL line found (cannot check the sslmode floor)" % name)
    floor_ok = True
    for dsn in dsns:
        query = dsn.split("?", 1)[1] if "?" in dsn else ""
        modes = [p.split("=", 1)[1].strip().lower() for p in query.split("&") if p.lower().startswith("sslmode=")]
        if not modes or modes[-1] != "verify-full":
            floor_ok = False
            if name in DSN_FLOOR_GAPS:
                continue
            hits.append("%s: store URL has no sslmode=verify-full (serve refuses it at start, #3705 floor, src/transit_encryption.rs:436-446)" % name)
    if name in DSN_FLOOR_GAPS and floor_ok and dsns:
        hits.append("%s: store URL now passes the sslmode floor; remove it from DSN_FLOOR_GAPS" % name)
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
    hits.extend(pin_hits(name, text))
    invocations = serve_invocations(text)
    if not invocations:
        hits.append("%s: no ExecStart runs 'ai-memory serve' (nothing to check; a template that cannot start serve must not pass)" % name)
    for lineno, after, unparsed in invocations:
        if unparsed:
            hits.append("%s:%d: ExecStart names serve but the ai-memory binary was not identified (cannot check its flags)" % (name, lineno))
            continue
        flags = []
        for tok in after:
            fm = FLAG_RE.match(tok)
            if fm:
                flags.append(fm.group(1))
        for flag in flags:
            if flag not in known:
                hits.append("%s:%d: serve flag %s is not a ServeArgs field (unit would exit at start)" % (name, lineno, flag))
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
