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
    floor, src/transit_encryption.rs:436-446);
  * the store URL dials the PgBouncer port 6432 (#4654: the daemon connects
    straight to Postgres so one verified TLS hop covers the whole path);
  * a template that configures a local Postgres lacks ``ssl = on`` or a
    ``hostssl`` pg_hba line (#4654);
  * a template that downloads ``ai_memory_image_url`` does not check
    ``sha256sum -c`` before ``tar`` extracts it, or ignores a failed
    download or extraction with ``|| true`` (#4637);
  * a ``CREATE USER ... PASSWORD '${...}'`` puts a terraform value straight
    into a SQL literal (#4638); or
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
REQUIRED_FLAGS = ("--tls-cert", "--tls-key")

# The PgBouncer listen port. No template store URL may dial it (#4654).
PGBOUNCER_PORT = "6432"
GIT_FLOAT_RE = re.compile(r"^\s*(?:[^#\s][^#]*?)?\bgit\s+(?:clone|checkout)\b", re.M)
COMMIT_RE = re.compile(r"^\s*(\w+_COMMIT)=(\S+)\s*$", re.M)
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
DSN_RE = re.compile(r"^\s+(postgres(?:ql)?://\S+)\s*$", re.M)
TF_INTERP_RE = re.compile(r"\$\{[^}]*\}")
HOST_PORT_RE = re.compile(r"@([^/?#@]*)(?:[/?#]|$)")
CREATE_USER_RE = re.compile(r"PASSWORD\s+'\$\{", re.I)
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
    # A terraform interpolation (the urlencoded password) must not end the URL
    # early or hide the query string: read it as one opaque character.
    dsns = DSN_RE.findall(TF_INTERP_RE.sub("X", text))
    if not dsns:
        hits.append("%s: no postgres:// store URL line found (cannot check the sslmode floor)" % name)
    for dsn in dsns:
        base, _, query = dsn.partition("?")
        modes = [p.split("=", 1)[1].strip().lower() for p in query.split("&") if p.lower().startswith("sslmode=")]
        if not modes or modes[-1] != "verify-full":
            hits.append("%s: store URL has no sslmode=verify-full (serve refuses it at start, #3705 floor, src/transit_encryption.rs:436-446)" % name)
        hp = HOST_PORT_RE.search(base)
        if hp and hp.group(1).rpartition(":")[2] == PGBOUNCER_PORT:
            hits.append("%s: store URL dials the pgbouncer port %s (#4654: connect straight to postgres; a transaction pooler drops the session state the driver sets)" % (name, PGBOUNCER_PORT))
    return hits


def provision_hits(name: str, text: str) -> list:
    """#4635/#4637/#4638: the Postgres TLS block, the digest check and the role password."""
    hits = []
    if "/etc/postgresql/" in text:
        if "ssl = on" not in text:
            hits.append("%s: configures a local postgres without 'ssl = on' (#4635)" % name)
        if not re.search(r"hostssl\s", text):
            hits.append("%s: configures a local postgres with no 'hostssl' pg_hba line (#4635)" % name)
    for m in CREATE_USER_RE.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        hits.append("%s:%d: a terraform value is written straight into a SQL password literal (decode and quote it on the node, #4638)" % (name, lineno))
    if "ai_memory_image_url" in text:
        check = text.find("sha256sum -c")
        extract = text.find("tar -xzf")
        if check < 0 or (0 <= extract < check):
            hits.append("%s: the ai-memory tarball is not digest-checked (sha256sum -c) before tar extracts it (#4637)" % name)
        for m in re.finditer(r"^[^#\n]*\b(?:curl|tar)\b[^\n]*\|\|\s*true\s*$", text, re.M):
            lineno = text.count("\n", 0, m.start()) + 1
            hits.append("%s:%d: a failed tarball download or extraction is ignored with '|| true' (#4637)" % (name, lineno))
    return hits


def pin_hits(name: str, text: str) -> list:
    """#4636: extension sources are fetched by full commit, never by a movable ref."""
    hits = []
    for m in GIT_FLOAT_RE.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        hits.append("%s:%d: git clone/checkout of a movable ref (use fetch_pinned with a *_COMMIT 40-hex pin, #4636)" % (name, lineno))
    for m in COMMIT_RE.finditer(text):
        if not HEX40_RE.match(m.group(2)):
            lineno = text.count("\n", 0, m.start()) + 1
            hits.append("%s:%d: %s is not a full 40-hex commit" % (name, lineno, m.group(1)))
    return hits


def scan_text(name: str, text: str, known: set) -> list:
    """Return one message per defect found in a template's text."""
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if any(ord(ch) > 127 for ch in line):
            hits.append("%s:%d: non-ASCII byte (cloud-init discards the config, #1880)" % (name, lineno))
    hits.extend(dsn_hits(name, text))
    hits.extend(provision_hits(name, text))
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


def self_test(known: set) -> int:
    dsn = "      postgres://u:p@localhost/db?sslmode=verify-full&sslrootcert=/c\n"
    unit = "ExecStart=/opt/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9077 --tls-cert /a --tls-key /b\n"
    good = dsn + unit
    pg_conf = '      PGCONF="/etc/postgresql/18/main/postgresql.conf"\n'
    ssl = '      printf "ssl = on\\n" >> "$PGCONF"\n'
    hba = '      printf "hostssl aimemory aimemory 127.0.0.1/32 scram-sha-256\\n" >> "$HBA"\n'
    fetch = '      curl -fsSL "${ai_memory_image_url}" -o "$DL/a.tar.gz"\n'
    digest = '      echo "${ai_memory_image_sha256}  $DL/a.tar.gz" | sha256sum -c -\n'
    extract = '      tar -xzf "$DL/a.tar.gz" -C /opt/ai-memory/bin\n'
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
        "serve with unidentified binary": dsn + "ExecStart=/opt/ai-memory/bin/wrapper serve --host 0.0.0.0 --tls-cert /a --tls-key /b\n",
        "pgbouncer port": good.replace("@localhost/", "@localhost:6432/"),
        "local postgres without ssl": good + pg_conf + hba,
        "local postgres without hostssl": good + pg_conf + ssl,
        "raw password in a SQL literal": good + "      psql -c \"CREATE USER aimemory WITH PASSWORD '${db_password}';\"\n",
        "tarball with no digest check": good + fetch + extract,
        "tarball extracted before the digest check": good + fetch + extract + digest,
        "tarball download ignores failure": good + fetch.rstrip() + " || true\n" + digest + extract,
        "tarball extraction ignores failure": good + fetch + digest + extract.rstrip() + " || true\n",
    }
    # #4654: probes judged under the do-hive template's own name, each with the
    # message fragment that must be among the hits, so neither a per-template
    # exemption nor an unrelated hit can make them pass.
    hive = "infra/do-hive/cloud-init-memory.yaml.tpl"
    named_probes = {
        "do-hive store URL without verify-full": (hive, good.replace("?sslmode=verify-full&sslrootcert=/c", ""), "no sslmode=verify-full"),
        "do-hive store URL with weak sslmode": (hive, good.replace("verify-full", "require"), "no sslmode=verify-full"),
        "do-hive store URL on the pgbouncer port": (hive, good.replace("@localhost/", "@127.0.0.1:6432/"), "pgbouncer port"),
        "do-hive store URL on a host-qualified pgbouncer port": (hive, good.replace("@localhost/", "@localhost:6432/"), "pgbouncer port"),
    }
    red = 0
    for label, text in probes.items():
        if scan_text(label, text, known):
            red += 1
        else:
            print("SELF-TEST FAIL: probe not flagged: " + label, file=sys.stderr)
    for label, (name, body, fragment) in named_probes.items():
        probes[label] = body
        if any(fragment in hit for hit in scan_text(name, body, known)):
            red += 1
        else:
            print("SELF-TEST FAIL: probe not flagged: " + label, file=sys.stderr)
    greens = {
        "clean": good,
        "env wrapper": good.replace("ExecStart=/opt/", "ExecStart=/usr/bin/env /opt/"),
        "global flag before serve": good.replace("ai-memory serve", "ai-memory --db /x serve"),
        "continuation": good.replace("--port 9077", "\\\n  --port 9077"),
        "pinned fetch": good + "      AGE_COMMIT=e43dc1a12b78fba4acef9835b2b10379b8d243b4\n      # git clone is only mentioned in a comment\n",
        "interpolated password in the url": good.replace("postgres://u:p@", "postgres://u:${urlencode(db_password)}@"),
        "local postgres with tls": good + pg_conf + ssl + hba,
        "digest checked before extract": good + fetch + digest + extract,
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
