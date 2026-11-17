#!/usr/bin/env python3
"""Tainted-job boundary classifier for every GitHub Actions workflow (umbrella #9452).

Invariant: after the first step of a job that runs pull-request code, no step of that
job holds (i) a secret, (ii) a write token, (iii) an output that feeds a gate decision,
or (iv) persistent state that a trusted run later reads.

The module parses each workflow with a fail-closed YAML subset parser (standard library
only), finds the taint point of every job and reports each violation as
(workflow, job, step, class). A workflow or a job this module cannot classify is a
failure, never clean. Known violations are listed in ``TAINT_ALLOW``; every row names the
open issue of the fix that removes it, the row count is pinned and a row that no longer
matches a violation is a failure.

decision: own stdlib subset parser over PyYAML because the lane binds the standard library
and any YAML form outside the subset must fail closed rather than parse loosely.
decision: violations are keyed by step label (name, else ``id:<id>``, else ``uses:`` or
``run#<n>``) over line numbers because a row must survive unrelated edits.
decision: the rule for persistent runner state reads the OS boundary facts of
``RUNNER_BOUNDARY_FACTS`` (issue #9455) over any path layout, because a path split on one
OS user is not a boundary (3-agent vote (71472661), condition T-4).

Usage: python3 scripts/ci/taint_boundary.py [--repo PATH] [--verdicts]
Exit codes: 0 no problem, 1 problems found, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

WORKFLOW_DIR = ".github/workflows"
WORKFLOW_SUFFIXES = (".yml", ".yaml")
ACTION_FILE_NAMES = ("action.yml", "action.yaml")
MAX_YAML_BYTES = 8 * 1024 * 1024
MAX_INDIRECTION_DEPTH = 8
MAX_VAR_RESOLVE_DEPTH = 8

CLASS_SECRET = "i"
CLASS_WRITE_TOKEN = "ii"
CLASS_GATE_OUTPUT = "iii"
CLASS_PERSISTENT_STATE = "iv"
CLASSES = (CLASS_SECRET, CLASS_WRITE_TOKEN, CLASS_GATE_OUTPUT, CLASS_PERSISTENT_STATE)

# Events whose run executes pull-request code (pull_request_target only with a head checkout).
PR_CODE_EVENTS = frozenset({"pull_request", "merge_group"})
PR_EVENTS = PR_CODE_EVENTS | {"pull_request_target"}
TRUSTED_EVENTS = frozenset({"push", "schedule", "workflow_dispatch", "release", "repository_dispatch"})
CALL_EVENT = "workflow_call"
KNOWN_EVENTS = PR_EVENTS | TRUSTED_EVENTS | {CALL_EVENT}

TRUSTED_CHECKOUT_REFS = frozenset({"${{ github.event.pull_request.base.sha }}"})
CHECKOUT_ACTION = "actions/checkout"
UPLOAD_ACTION = "actions/upload-artifact"
DOWNLOAD_MARKERS = ("actions/download-artifact", "gh run download", "download-artifact")

# Every action a workflow may use, by name without ref. ``pr_code``: running the action
# executes pull-request code. ``default_token``: the action reads github.token by default.
# ``script_input``: an input whose text runs as shell commands.
@dataclass(frozen=True)
class ActionFacts:
    pr_code: bool = False
    default_token: bool = False
    script_input: str = ""
    pr_code_unless: tuple[tuple[str, str], ...] = ()


KNOWN_ACTIONS: dict[str, ActionFacts] = {
    "actions/attest-build-provenance": ActionFacts(default_token=True),
    "actions/cache": ActionFacts(),
    "actions/checkout": ActionFacts(),
    "actions/setup-node": ActionFacts(),
    "actions/setup-python": ActionFacts(),
    "actions/upload-artifact": ActionFacts(),
    "Swatinem/rust-cache": ActionFacts(),
    # The build reads its token only for a git-URL context; no RUN step of the Dockerfile
    # receives it. A `secrets:` input naming a secret is still (i) through the `with:` scan.
    "docker/build-push-action": ActionFacts(pr_code=True),
    "docker://rhysd/actionlint": ActionFacts(),
    "docker/login-action": ActionFacts(),
    "docker/setup-buildx-action": ActionFacts(),
    "dtolnay/rust-toolchain": ActionFacts(),
    "github/codeql-action/analyze": ActionFacts(default_token=True),
    "github/codeql-action/init": ActionFacts(pr_code=True, default_token=True,
                                             pr_code_unless=(("build-mode", "none"),)),
    "marocchino/sticky-pull-request-comment": ActionFacts(default_token=True),
    "nttld/setup-ndk": ActionFacts(),
    "pypa/gh-action-pypi-publish": ActionFacts(default_token=True),
    "reactivecircus/android-emulator-runner": ActionFacts(script_input="script"),
    "softprops/action-gh-release": ActionFacts(default_token=True),
    "taiki-e/install-action": ActionFacts(),
}

GITHUB_HOSTED_LABEL_RE = re.compile(r"^(ubuntu|macos|windows)-(latest|\d+(\.\d+)?)(-(arm|arm64|large|xlarge|intel))?$")
EXPR_OPEN = "${{"
EXPR_CLOSE = "}}"
# Searched inside one `${{ }}` body only (see _has_secret_ref).
SECRET_REF_RE = re.compile(r"\bsecrets\b|\bgithub\s*(\.\s*token\b|\[\s*['\"]token['\"]\s*\])", re.I)
STEP_OUTPUT_REF_RE = re.compile(r"\bsteps\.([A-Za-z0-9_-]+)\.outputs\b")
EVENT_EQ_RE = re.compile(r"^github\.event_name\s*==\s*'([a-z_]+)'$")
MATRIX_RUNS_ON_RE = re.compile(r"^\$\{\{\s*(fromJSON\(\s*)?matrix\.([A-Za-z0-9_-]+)\s*\)?\s*\}\}$")
CHECKOUT_IN_RUN_RE = re.compile(r"\bgit\s+(?:-\S+\s+)*(checkout|switch|worktree|fetch|pull)\b")
BASE_MATERIALISE_RE = re.compile(r"\bgit\s+(?:--?\S+\s+)*show\b|\bgit\(\s*\"show\"")


# Persistent-runner OS boundary facts (issue #9455, 3-agent vote (71472661) T-1/T-4). A
# runner label is a boundary only when the pull-request tier runs as its own OS user that
# cannot write any trusted path, and a test in the repository proves the permission error
# on each. Until the fix lands no label has facts, so a tainted self-hosted job is (iv).
RUNNER_BOUNDARY_FACTS: dict[str, dict[str, object]] = {}
BOUNDARY_REQUIRED_TRUE = ("trusted_root_unwritable", "trusted_cargo_home_unwritable",
                          "trusted_rustup_toolchains_unwritable", "trusted_path_entries_unwritable",
                          "trusted_home_credentials_unreadable")


@dataclass(frozen=True)
class AllowRow:
    """A known violation, allowed only while its fix issue is open."""

    workflow: str
    job: str
    step: str
    classes: tuple[str, ...]
    issue: int | None


# The six hits of the survey at a028c45e. Removing a row is the fix lane's job; adding a
# row needs an issue number from the deputy (the pin moves with it).
TAINT_ALLOW: tuple[AllowRow, ...] = (
    AllowRow("ci.yml", "classify", "id:impact", (CLASS_GATE_OUTPUT,), 9454),
    AllowRow("c8-precheck.yml", "required-contexts-gate",
             # The workflow name runs into a YAML comment at ` #`; the label is the parsed name.
             "Declared-vs-live required-context drift (#3554 /", (CLASS_SECRET,), 9454),
    AllowRow("ci.yml", "check", "Prune stale runner TMPDIR (#8634)", (CLASS_PERSISTENT_STATE,), 9455),
    AllowRow("cert-postgres-age.yml", "cert-postgres-age", "Prune stale runner TMPDIR (#8634)",
             (CLASS_PERSISTENT_STATE,), 9455),
    AllowRow("postgres-ignored.yml", "postgres-ignored", "Prune stale runner TMPDIR (#8634)",
             (CLASS_PERSISTENT_STATE,), 9455),
    AllowRow("coverage.yml", "per-module-thresholds", "Post coverage to PR (sticky) (#1993)",
             (CLASS_WRITE_TOKEN, CLASS_SECRET), 9456),
)
TAINT_ALLOW_PIN = 6


class Unclassifiable(Exception):
    """A form this module cannot classify; always reported as a failure."""


# ---------------------------------------------------------------------------------------
# YAML subset parser
# ---------------------------------------------------------------------------------------

PLAIN_TRUE = frozenset({"true", "True", "TRUE"})
PLAIN_FALSE = frozenset({"false", "False", "FALSE"})
PLAIN_NULL = frozenset({"null", "Null", "NULL", "~"})
INT_RE = re.compile(r"^[-+]?[0-9]+$")
FLOAT_RE = re.compile(r"^[-+]?([0-9]+\.[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?$")
REFUSED_LEAD = "&*!%@`?|>{}[],#'\""
BLOCK_HEADER_RE = re.compile(r"^([|>])([-+]?)([1-9]?)([-+]?)$")
DQ_ESCAPES = {"\\": "\\", '"': '"', "/": "/", "n": "\n", "t": "\t", "r": "\r", "0": "\0",
              "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "v": "\v", " ": " "}


class YamlError(Unclassifiable):
    """The text is outside the YAML subset."""


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_comment(text: str) -> str:
    """Cut a `` #`` comment from a plain (unquoted) tail."""
    for idx, ch in enumerate(text):
        if ch == "#" and (idx == 0 or text[idx - 1] in " \t"):
            return text[:idx].rstrip()
    return text.rstrip()


class _YamlSubset:
    """Block mappings and sequences, single-line scalars and flow collections, block scalars.

    Anchors, aliases, tags, merge keys, complex keys, multi-line flow or quoted scalars and
    multi-line plain scalars are refused (YamlError).
    """

    def __init__(self, text: str, label: str) -> None:
        if len(text.encode("utf-8", "surrogatepass")) > MAX_YAML_BYTES:
            raise YamlError(f"{label}: larger than {MAX_YAML_BYTES} bytes")
        self.label = label
        self.lines = text.replace("\r\n", "\n").split("\n")
        self.i = 0
        for n, line in enumerate(self.lines):
            lead = line[: len(line) - len(line.lstrip(" \t"))]
            if "\t" in lead and line.strip():
                raise YamlError(f"{label}: line {n + 1}: tab in indentation")

    def err(self, msg: str, line: int | None = None) -> YamlError:
        return YamlError(f"{self.label}: line {(self.i if line is None else line) + 1}: {msg}")

    def skip(self) -> None:
        while self.i < len(self.lines):
            s = self.lines[self.i].strip()
            if s == "" or s.startswith("#"):
                self.i += 1
                continue
            break

    def parse(self) -> object:
        self.skip()
        if self.i < len(self.lines) and self.lines[self.i].rstrip() == "---":
            self.i += 1
            self.skip()
        if self.i >= len(self.lines):
            raise self.err("empty document")
        node = self.block(_indent(self.lines[self.i]))
        self.skip()
        if self.i < len(self.lines):
            raise self.err("content outside the document structure (bad indentation or a second document)")
        return node

    def block(self, indent: int) -> object:
        body = self.lines[self.i][indent:]
        if body == "-" or body.startswith("- "):
            return self.seq(indent)
        return self.mapping(indent)

    def split_key(self, body: str) -> tuple[str, str]:
        if body[:1] in ("'", '"'):
            key, rest = self.quoted(body)
            rest = rest.lstrip(" ")
            if not rest.startswith(":"):
                raise self.err("quoted key without `:`")
            rest = rest[1:]
            if rest and rest[0] != " ":
                raise self.err("`:` after a key must be followed by a space")
            return key, rest
        if body[:1] in REFUSED_LEAD or body.startswith("<<") or body.startswith("- "):
            raise self.err(f"key form outside the subset: {body[:40]!r}")
        m = re.search(r":( |$)", body)
        if not m:
            raise self.err(f"expected `key: value`, found {body[:60]!r}")
        key = body[: m.start()].rstrip()
        if not key or " #" in key or key.startswith("#"):
            raise self.err("empty or commented key")
        return key, body[m.end():]

    def mapping(self, indent: int) -> dict[str, object]:
        out: dict[str, object] = {}
        while True:
            self.skip()
            if self.i >= len(self.lines):
                break
            line = self.lines[self.i]
            ind = _indent(line)
            if ind < indent:
                break
            if ind > indent:
                raise self.err("unexpected indentation (a multi-line plain scalar is outside the subset)")
            body = line[ind:]
            if body == "-" or body.startswith("- "):
                break
            key, rest = self.split_key(body)
            if key in out:
                raise self.err(f"duplicate key {key!r}")
            row = self.i
            self.i += 1
            out[key] = self.value(rest, indent, row)
        return out

    def seq(self, indent: int) -> list[object]:
        out: list[object] = []
        while True:
            self.skip()
            if self.i >= len(self.lines):
                break
            line = self.lines[self.i]
            ind = _indent(line)
            if ind < indent:
                break
            if ind > indent:
                raise self.err("unexpected indentation inside a sequence")
            body = line[ind:]
            if not (body == "-" or body.startswith("- ")):
                break
            if body == "-":
                row = self.i
                self.i += 1
                out.append(self.value("", indent, row))
                continue
            item = body[2:]
            col = ind + 2 + _indent(item)
            item = item.lstrip(" ")
            if item.startswith("#"):
                row = self.i
                self.i += 1
                out.append(self.value("", indent, row))
                continue
            if item == "-" or item.startswith("- ") or self.is_entry(item):
                self.lines[self.i] = " " * col + item
                out.append(self.block(col))
                continue
            row = self.i
            self.i += 1
            out.append(self.value(item, indent, row))
        return out

    def is_entry(self, text: str) -> bool:
        if text[:1] in ("'", '"'):
            try:
                _, rest = self.quoted(text)
            except YamlError:
                return False
            return rest.lstrip(" ").startswith(":")
        if text[:1] in "[{":
            return False
        cut = _strip_comment(text)
        return bool(re.search(r":( |$)", cut))

    def value(self, rest: str, indent: int, row: int) -> object:
        stripped = rest.strip()
        if stripped == "" or stripped.startswith("#"):
            self.skip()
            if self.i >= len(self.lines):
                return None
            nxt = self.lines[self.i]
            ind = _indent(nxt)
            body = nxt[ind:]
            if ind > indent:
                return self.block(ind)
            if ind == indent and (body == "-" or body.startswith("- ")):
                return self.seq(ind)
            return None
        if stripped[0] in "|>":
            return self.block_scalar(_strip_comment(stripped), indent, row)
        return self.inline(stripped, row)

    def block_scalar(self, header: str, indent: int, row: int) -> str:
        m = BLOCK_HEADER_RE.match(header)
        if not m or (m.group(2) and m.group(4)):
            raise self.err(f"block scalar header {header!r} outside the subset", row)
        style, chomp, explicit = m.group(1), m.group(2) or m.group(4), m.group(3)
        raw: list[str] = []
        content_indent = indent + int(explicit) if explicit else -1
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.strip() == "":
                raw.append(line)
                self.i += 1
                continue
            ind = _indent(line)
            if content_indent < 0:
                if ind <= indent:
                    break
                content_indent = ind
            if ind < content_indent:
                break
            raw.append(line)
            self.i += 1
        trailing = 0
        while raw and raw[-1].strip() == "":
            raw.pop()
            trailing += 1
        if content_indent < 0:
            content_indent = indent + 1
        for line in raw:
            if line.strip() and _indent(line) < content_indent:
                raise self.err("block scalar line less indented than its first line", row)
        lines = [ln[content_indent:] if ln.strip() else "" for ln in raw]
        if style == "|":
            text = "\n".join(lines)
        else:
            text = self.fold(lines)
        if not lines:
            return "\n" * trailing if chomp == "+" else ""
        if chomp == "-":
            return text
        if chomp == "+":
            return text + "\n" + "\n" * trailing
        return text + "\n"

    @staticmethod
    def fold(lines: list[str]) -> str:
        out = ""
        prev_normal: bool | None = None
        breaks = 0
        for line in lines:
            if line == "":
                breaks += 1
                continue
            normal = not line.startswith((" ", "\t"))
            if prev_normal is None:
                out += "\n" * breaks
            elif prev_normal and normal:
                out += " " if breaks == 0 else "\n" * breaks
            else:
                out += "\n" * (breaks + 1)
            out += line
            prev_normal = normal
            breaks = 0
        return out

    def quoted(self, text: str) -> tuple[str, str]:
        q = text[0]
        out: list[str] = []
        idx = 1
        while idx < len(text):
            ch = text[idx]
            if q == "'":
                if ch == "'":
                    if text[idx + 1: idx + 2] == "'":
                        out.append("'")
                        idx += 2
                        continue
                    return "".join(out), text[idx + 1:]
                out.append(ch)
                idx += 1
                continue
            if ch == '"':
                return "".join(out), text[idx + 1:]
            if ch == "\\":
                nxt = text[idx + 1: idx + 2]
                if nxt in DQ_ESCAPES:
                    out.append(DQ_ESCAPES[nxt])
                    idx += 2
                    continue
                width = {"x": 2, "u": 4, "U": 8}.get(nxt)
                hexpart = text[idx + 2: idx + 2 + width] if width else ""
                if not width or not re.fullmatch(r"[0-9A-Fa-f]+", hexpart or "-") or len(hexpart) != width:
                    raise self.err("unsupported escape in a double-quoted scalar")
                out.append(chr(int(hexpart, 16)))
                idx += 2 + width
                continue
            out.append(ch)
            idx += 1
        raise self.err("unterminated or multi-line quoted scalar")

    def inline(self, text: str, row: int) -> object:
        if text[0] in ("'", '"'):
            val, rest = self.quoted(text)
            if _strip_comment(rest).strip():
                raise self.err("text after a quoted scalar", row)
            return val
        if text[0] == "[":
            return self.flow(text, "[", "]", row)
        if text[0] == "{":
            return self.flow(text, "{", "}", row)
        if text[0] in REFUSED_LEAD or text.startswith("- ") or text.startswith("<<"):
            raise self.err(f"scalar form outside the subset: {text[:40]!r}", row)
        plain = _strip_comment(text)
        if re.search(r": |:$", plain) or " #" in plain:
            raise self.err("a plain scalar holding `: ` (a nested mapping on one line)", row)
        return self.typed(plain)

    @staticmethod
    def typed(plain: str) -> object:
        if plain in PLAIN_TRUE:
            return True
        if plain in PLAIN_FALSE:
            return False
        if plain in PLAIN_NULL or plain == "":
            return None
        if INT_RE.match(plain) and not re.match(r"^[-+]?0[0-9]", plain):
            return int(plain)
        if FLOAT_RE.match(plain):
            return float(plain)
        return plain

    def flow(self, text: str, open_ch: str, close_ch: str, row: int) -> object:
        cut = _strip_comment(text)
        if not cut.endswith(close_ch):
            raise self.err("multi-line or nested flow collection", row)
        inner = cut[1:-1].strip()
        parts: list[str] = []
        cur = ""
        idx = 0
        while idx < len(inner):
            ch = inner[idx]
            if ch in ("'", '"'):
                val, rest = self.quoted(inner[idx:])
                consumed = len(inner[idx:]) - len(rest)
                cur += inner[idx: idx + consumed]
                idx += consumed
                continue
            if ch in "[]{}":
                raise self.err("nested flow collection", row)
            if ch == ",":
                parts.append(cur.strip())
                cur = ""
                idx += 1
                continue
            cur += ch
            idx += 1
        if cur.strip():
            parts.append(cur.strip())
        elif parts:
            raise self.err("trailing comma in a flow collection", row)
        if open_ch == "[":
            return [self.flow_scalar(p, row) for p in parts]
        out: dict[str, object] = {}
        for p in parts:
            m = re.match(r"^('(?:[^']|'')*'|\"(?:[^\"\\]|\\.)*\"|[^:'\"]+?)\s*:\s+(.*)$", p)
            if not m:
                raise self.err(f"flow mapping entry {p!r} outside the subset", row)
            key = self.flow_scalar(m.group(1), row)
            if not isinstance(key, str) or key in out:
                raise self.err("bad or duplicate flow mapping key", row)
            out[key] = self.flow_scalar(m.group(2), row)
        return out

    def flow_scalar(self, part: str, row: int) -> object:
        if part == "":
            raise self.err("empty flow entry", row)
        if part[0] in ("'", '"'):
            val, rest = self.quoted(part)
            if rest.strip():
                raise self.err("text after a quoted flow scalar", row)
            return val
        if part[0] in REFUSED_LEAD or ": " in part:
            raise self.err(f"flow scalar {part!r} outside the subset", row)
        return self.typed(part)


def parse_yaml(text: str, label: str) -> object:
    """Parse ``text`` inside the subset or raise YamlError (a failure, never clean)."""
    return _YamlSubset(text, label).parse()


# ---------------------------------------------------------------------------------------
# Shell command classification
# ---------------------------------------------------------------------------------------

INERT_COMMANDS = frozenset("""
: [ [[ ]] true false echo printf test exit return set shopt export unset local declare readonly
typeset cd pwd mkdir rmdir rm cp mv ln touch cat head tail wc sort uniq tr cut grep egrep fgrep
sed awk jq date sleep printenv basename dirname realpath readlink stat ls tee chmod chown du df
free uname whoami id hostname type which hash git gh curl wget tar gzip gunzip zstd xz unzip zip
sha256sum sha1sum sha512sum shasum md5sum base64 diff cmp comm paste join expr seq read wait kill
trap shift break continue let mapfile readarray getconf nproc od xxd hexdump file ps pgrep lsof
ss ip openssl install mktemp sync truncate dd rsync column fold fmt nl rev tac numfmt bc logger
flock getent groups ulimit umask pushd popd sqlite3 psql pg_isready createdb dropdb pg_dump
pg_ctl pg_config apt-get apt dpkg brew systemctl launchctl rustup sccache actionlint shellcheck
docker xcrun adb sdkmanager avdmanager emulator lscpu vm_stat sysctl sw_vers cmake-version
iconv envsubst yes cksum split fallocate mkswap swapon swapoff find xargs env sudo timeout nice nohup exec command time stdbuf
""".split())
PR_CODE_COMMANDS = frozenset("""
cargo cargo-llvm-cov npm npx yarn pnpm node deno bun pytest make gmake ninja go rustc gradle
mvn tox nox pre-commit just bazel source . eval
""".split())
SHELL_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while", "until",
                            "esac", "!", "{", "}", "function", "in", "select"})
PREFIX_COMMANDS = {"sudo": "-u -g -h -p -C", "timeout": "-s -k --signal --kill-after",
                   "nice": "-n", "nohup": "", "exec": "-a", "command": "", "time": "",
                   "stdbuf": "-i -o -e", "env": "-u -C -S --unset --chdir", "xargs":
                   "-I -L -n -P -d -s -E -a --max-args --max-procs --delimiter --replace"}
INTERPRETERS = frozenset({"python", "python3", "python3.12", "python3.13", "python3.14"})
SHELLS = frozenset({"bash", "sh", "zsh", "dash"})
SAFE_ISOLATED_PY_MODULES = frozenset({"json.tool", "venv"})
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=")
HEREDOC_RE = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
VERSION_ARGS = frozenset({"--version", "-V", "version", "-v"})


@dataclass
class _Lexed:
    commands: list[list[str]] = field(default_factory=list)
    subs: list[str] = field(default_factory=list)
    heredoc_bodies: list[tuple[str, bool]] = field(default_factory=list)


def _lex(text: str) -> _Lexed:
    """Split shell text into simple commands (lists of raw words).

    Quotes are kept in the raw word; ``$(...)`` and backtick bodies are returned in ``subs``
    for recursive classification; heredoc bodies are returned with their quoted flag.
    """
    out = _Lexed()
    cmd: list[str] = []
    word = ""
    in_word = False
    pending_heredocs: list[tuple[str, bool, bool]] = []
    idx = 0
    n = len(text)

    def end_word() -> None:
        nonlocal word, in_word
        if in_word:
            cmd.append(word)
        word = ""
        in_word = False

    def end_cmd() -> None:
        nonlocal cmd
        end_word()
        if cmd:
            out.commands.append(cmd)
        cmd = []

    def read_balanced(start: int) -> int:
        """Return the index just past the ``)`` closing a ``$(`` that opened before start."""
        depth = 1
        j = start
        while j < n:
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c == "'":
                k = text.find("'", j + 1)
                j = n if k < 0 else k + 1
                continue
            if c == '"':
                j = read_dq(j + 1)
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        raise Unclassifiable("unbalanced `$(` in run text")

    def read_dq(start: int) -> int:
        j = start
        while j < n:
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c == '"':
                return j + 1
            if c == "$" and text.startswith("$((", j):
                j = read_balanced(j + 3)
                j = j + 1 if j < n and text[j] == ")" else j
                continue
            if c == "$" and text.startswith("$(", j):
                end = read_balanced(j + 2)
                out.subs.append(text[j + 2: end - 1])
                j = end
                continue
            if c == "`":
                k = text.find("`", j + 1)
                if k < 0:
                    raise Unclassifiable("unbalanced backtick in run text")
                out.subs.append(text[j + 1: k])
                j = k + 1
                continue
            j += 1
        raise Unclassifiable("unterminated double quote in run text")

    while idx < n:
        ch = text[idx]
        if ch == "\n":
            end_cmd()
            idx += 1
            for delim, strip_tabs, quoted in pending_heredocs:
                body: list[str] = []
                while idx <= n:
                    nl = text.find("\n", idx)
                    line = text[idx:] if nl < 0 else text[idx:nl]
                    idx = n + 1 if nl < 0 else nl + 1
                    test_line = line.lstrip("\t") if strip_tabs else line
                    if test_line.strip() == delim:
                        break
                    body.append(line)
                else:
                    raise Unclassifiable(f"heredoc `{delim}` is not terminated")
                out.heredoc_bodies.append(("\n".join(body), quoted))
            pending_heredocs = []
            idx = min(idx, n)
            continue
        if ch in " \t":
            end_word()
            idx += 1
            continue
        if ch == "\\":
            if text[idx + 1: idx + 2] == "\n":
                idx += 2
                continue
            word += text[idx: idx + 2]
            in_word = True
            idx += 2
            continue
        if ch == "#" and not in_word:
            nl = text.find("\n", idx)
            idx = n if nl < 0 else nl
            continue
        if ch == "'":
            k = text.find("'", idx + 1)
            if k < 0:
                raise Unclassifiable("unterminated single quote in run text")
            word += text[idx: k + 1]
            in_word = True
            idx = k + 1
            continue
        if ch == '"':
            end = read_dq(idx + 1)
            word += text[idx:end]
            in_word = True
            idx = end
            continue
        if ch == "`":
            k = text.find("`", idx + 1)
            if k < 0:
                raise Unclassifiable("unbalanced backtick in run text")
            out.subs.append(text[idx + 1: k])
            word += text[idx: k + 1]
            in_word = True
            idx = k + 1
            continue
        if ch == "$" and text.startswith("$((", idx):
            end = read_balanced(idx + 3)
            end = end + 1 if end < n and text[end] == ")" else end
            word += text[idx:end]
            in_word = True
            idx = end
            continue
        if ch == "$" and text.startswith("$(", idx):
            end = read_balanced(idx + 2)
            out.subs.append(text[idx + 2: end - 1])
            word += text[idx:end]
            in_word = True
            idx = end
            continue
        if ch == "$" and text.startswith("${", idx):
            k = text.find("}", idx)
            if k < 0:
                raise Unclassifiable("unbalanced `${` in run text")
            word += text[idx: k + 1]
            in_word = True
            idx = k + 1
            continue
        if ch == "<" and text.startswith("<<", idx) and not text.startswith("<<<", idx):
            m = HEREDOC_RE.match(text, idx)
            if not m:
                raise Unclassifiable("heredoc form outside the classifier subset")
            end_word()
            pending_heredocs.append((m.group(3), m.group(1) == "-", bool(m.group(2))))
            idx = m.end()
            continue
        if ch in "<>" and text.startswith(("<(", ">("), idx):
            end = read_balanced(idx + 2)
            out.subs.append(text[idx + 2: end - 1])
            end_word()
            idx = end
            continue
        if ch in ";&|()":
            two = text[idx: idx + 2]
            end_cmd()
            if two in (";;", "&&", "||", ";&", "|&", "((", "))"):
                cmd.append(two) if two in ("((", "))", ";;") else None
                idx += 2
            else:
                cmd.append(ch) if ch in "()" else None
                idx += 1
            if cmd:
                out.commands.append(cmd)
                cmd = []
            continue
        if ch in "<>":
            end_word()
            j = idx
            while j < n and text[j] in "<>&|":
                j += 1
            fd_dup = text[j - 1] == "&" and j < n and (text[j].isdigit() or text[j] == "-")
            while fd_dup and j < n and (text[j].isdigit() or text[j] == "-"):
                j += 1
            cmd.append("<redirfd>" if fd_dup else "<redir>")
            idx = j
            continue
        word += ch
        in_word = True
        idx += 1
    if pending_heredocs:
        raise Unclassifiable("heredoc without a body")
    end_cmd()
    return out


def _unquote(word: str) -> str:
    if len(word) >= 2 and word[0] == word[-1] and word[0] in "'\"":
        return word[1:-1]
    return word


@dataclass
class _ShellCtx:
    materialised: bool
    assigns: dict[str, str] = field(default_factory=dict)
    functions: set[str] = field(default_factory=set)


def _resolve_root(word: str, ctx: _ShellCtx) -> str:
    """Expand a leading ``$VAR``/``${VAR}`` from assignments made in the same run text."""
    w = _unquote(word)
    for _ in range(MAX_VAR_RESOLVE_DEPTH):
        m = re.match(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)(:-[^}]*)?\}?(.*)$", w)
        if not m or m.group(1) == "RUNNER_TEMP" or m.group(1) not in ctx.assigns:
            return w
        w = _unquote(ctx.assigns[m.group(1)]) + m.group(3)
    return w


def _trusted_temp_path(word: str, ctx: _ShellCtx) -> bool:
    """A path under RUNNER_TEMP counts as trusted only after a base materialisation in this job."""
    root = _resolve_root(word, ctx)
    return ctx.materialised and bool(re.match(r"^\$\{?RUNNER_TEMP(\}|:-[^}]*\}|/|$)", root))


def _python_runs_pr_code(args: list[str], ctx: _ShellCtx) -> bool:
    isolated = False
    idx = 0
    while idx < len(args):
        a = _unquote(args[idx])
        if a == "<redir>":
            idx += 2
            continue
        if a == "<redirfd>":
            idx += 1
            continue
        if a in VERSION_ARGS and idx == 0:
            return False
        if a == "-":
            return not isolated
        if a == "-c":
            return not isolated
        if a == "-m":
            mod = _unquote(args[idx + 1]) if idx + 1 < len(args) else ""
            return not (isolated and mod in SAFE_ISOLATED_PY_MODULES)
        if a in ("-W", "-X"):
            idx += 2
            continue
        if a.startswith("-") and len(a) > 1 and not a.startswith("--"):
            if "c" in a[1:] or "m" in a[1:]:
                return True
            isolated = isolated or "I" in a[1:]
            idx += 1
            continue
        if a.startswith("--"):
            return True
        return not (isolated and _trusted_temp_path(args[idx], ctx))
    return not isolated


def _command_runs_pr_code(words: list[str], ctx: _ShellCtx, depth: int) -> bool:
    if depth > MAX_INDIRECTION_DEPTH:
        raise Unclassifiable("command nesting deeper than the bound")
    # Drop redirection operators and their targets.
    clean: list[str] = []
    skip = False
    for w in words:
        if skip:
            skip = False
            continue
        if w == "<redir>":
            skip = True
            continue
        if w == "<redirfd>":
            continue
        clean.append(w)
    words = clean
    while words and (words[0] in SHELL_KEYWORDS or ASSIGN_RE.match(words[0])):
        if ASSIGN_RE.match(words[0]) and len(words) == 1:
            name, _, value = words[0].partition("=")
            ctx.assigns[name.rstrip("+")] = value
        words = words[1:]
    if not words:
        return False
    head = _unquote(words[0])
    args = words[1:]
    if head in ctx.functions:
        return False
    if head in PREFIX_COMMANDS:
        if head == "command" and args[:1] in (["-v"], ["-V"]):
            return False
        opts = PREFIX_COMMANDS[head].split()
        rest = list(args)
        while rest and _unquote(rest[0]).startswith("-"):
            opt = _unquote(rest.pop(0))
            if opt in opts and rest:
                rest.pop(0)
        if head == "timeout" and rest:
            rest.pop(0)
        while head == "env" and rest and ASSIGN_RE.match(rest[0]):
            rest.pop(0)
        if not rest:
            return False
        return _command_runs_pr_code(rest, ctx, depth + 1)
    if any(c in head for c in "$`"):
        return True
    base = head.rsplit("/", 1)[-1]
    if "/" in head and not head.startswith("/"):
        return True
    if head.startswith("/") and base not in INERT_COMMANDS and base not in INTERPRETERS | SHELLS:
        return True
    if args and all(_unquote(a) in VERSION_ARGS for a in args[:1]) and len(args) == 1:
        return False
    if base in INTERPRETERS:
        return _python_runs_pr_code(args, ctx)
    if base in SHELLS:
        plain = [a for a in args if not _unquote(a).startswith("-")]
        if "-c" in [_unquote(a) for a in args] and plain:
            return _shell_runs_pr_code(_unquote(plain[0]), ctx, depth + 1)
        return True
    if base in PR_CODE_COMMANDS:
        return True
    if base == "docker":
        sub = [_unquote(a) for a in args if not _unquote(a).startswith("-")]
        return bool(sub) and sub[0] in ("build", "buildx", "compose", "image") and sub[:2] != ["image", "inspect"]
    if base in ("sed", "awk"):
        flat = [_unquote(a) for a in args]
        for opt_idx, a in enumerate(flat):
            if a in ("-f", "--file") and opt_idx + 1 < len(flat) and not flat[opt_idx + 1].startswith("/"):
                return True
        return False
    if base == "find":
        flat = [_unquote(a) for a in args]
        for opt_idx, a in enumerate(flat):
            if a in ("-exec", "-execdir", "-ok", "-okdir"):
                tail = []
                for t in flat[opt_idx + 1:]:
                    if t in (";", "\\;", "+"):
                        break
                    tail.append(t)
                if tail and _command_runs_pr_code(tail, ctx, depth + 1):
                    return True
        return False
    if base in ("pip", "pip3"):
        # decision: every pip call is PR code over "named packages are inert" because pip
        # reads its configuration and constraints from the working tree, which is the PR tree.
        return True
    if base == "psql":
        flat = [_unquote(a) for a in args]
        return any(a in ("-f", "--file") for a in flat)
    return base not in INERT_COMMANDS


def _shell_runs_pr_code(text: str, ctx: _ShellCtx, depth: int = 0) -> bool:
    """True when the shell text runs at least one command from the pull-request tree.

    Fail closed: an unknown command, a variable used as a command, a relative path, an
    interpreter on a workspace file or an interpreter without ``-I`` counts as PR code.
    """
    if depth > MAX_INDIRECTION_DEPTH:
        raise Unclassifiable("command nesting deeper than the bound")
    lexed = _lex(text)
    runs = False
    in_case = 0
    case_wait_in = False
    case_pattern = False
    in_test = False
    in_arith = False
    for i, words in enumerate(lexed.commands):
        nxt = lexed.commands[i + 1] if i + 1 < len(lexed.commands) else []
        if in_test:
            in_test = "]]" not in words
            continue
        if in_arith:
            in_arith = words != ["))"]
            continue
        if words == [";;"]:
            case_pattern = bool(in_case)
            continue
        if words == ["(("]:
            in_arith = True
            continue
        if "[[" in words[:2] and "]]" not in words:
            in_test = True
        if words == ["("] and i > 0 and lexed.commands[i - 1] and nxt == [")"]:
            continue
        if words in (["("], [")"], ["(("], ["))"]):
            if words == [")"] and case_pattern:
                case_pattern = False
            continue
        if len(words) == 1 and nxt == ["("] and ASSIGN_RE.match(words[0]) is None:
            peek = lexed.commands[i + 2] if i + 2 < len(lexed.commands) else []
            if peek == [")"]:
                ctx.functions.add(_unquote(words[0]))
                continue
        if words[0] == "function" and len(words) >= 2:
            ctx.functions.add(_unquote(words[1]))
            continue
        if words[0] == "case":
            in_case += 1
            case_wait_in = True
            if "in" in words:
                case_wait_in = False
                case_pattern = True
            continue
        if case_wait_in:
            if "in" in words:
                case_wait_in = False
                case_pattern = True
            continue
        if in_case and words[0] == "esac":
            in_case -= 1
            case_pattern = False
            continue
        if in_case and case_pattern:
            # Words before `)` are a case pattern; the `)` token ends it.
            continue
        if in_case and nxt == [")"]:
            continue
        if words[0] in ("for", "select"):
            continue
        if words[0] == "((":
            continue
        if _command_runs_pr_code(words, ctx, depth):
            runs = True
    for idx, (body, quoted) in enumerate(lexed.heredoc_bodies):
        if not quoted and ("$(" in body or "`" in body):
            subs = _lex("echo \"" + body.replace("\\", "\\\\").replace('"', '\\"') + "\"").subs
            for sub in subs:
                runs = _shell_runs_pr_code(sub, ctx, depth + 1) or runs
    for sub in lexed.subs:
        runs = _shell_runs_pr_code(sub, ctx, depth + 1) or runs
    return runs


# ---------------------------------------------------------------------------------------
# Workflow analysis
# ---------------------------------------------------------------------------------------

EXPR_PLACEHOLDER = "GHA_EXPR"
DEFAULT_SHELLS = frozenset({"bash", "sh"})
TOKEN_SCOPES_WRITE = "write"
LOCAL_PREFIX = "./"


@dataclass(frozen=True)
class Violation:
    """One step of one job that breaks the boundary in one class."""

    workflow: str
    job: str
    step: str
    klass: str
    detail: str


@dataclass
class ScanResult:
    violations: list[Violation] = field(default_factory=list)
    unclassifiable: list[str] = field(default_factory=list)
    verdicts: dict[tuple[str, str], str] = field(default_factory=dict)
    taint_steps: dict[tuple[str, str], str] = field(default_factory=dict)


@dataclass
class _Step:
    label: str
    body: dict[str, object]
    index: int


def _split_expressions(text: str) -> tuple[list[str], list[str]]:
    """Split text into the literal parts and the ``${{ }}`` bodies in one linear pass.

    An unterminated expression keeps the rest of the text as its body (fail closed).
    """
    literals: list[str] = []
    bodies: list[str] = []
    pos = 0
    while True:
        start = text.find(EXPR_OPEN, pos)
        if start < 0:
            literals.append(text[pos:])
            return literals, bodies
        literals.append(text[pos:start])
        end = text.find(EXPR_CLOSE, start + len(EXPR_OPEN))
        if end < 0:
            bodies.append(text[start + len(EXPR_OPEN):])
            return literals, bodies
        bodies.append(text[start + len(EXPR_OPEN):end])
        pos = end + len(EXPR_CLOSE)


def _expr_free(text: str) -> str:
    literals, bodies = _split_expressions(text)
    if len(bodies) >= len(literals):
        raise Unclassifiable("unterminated `${{` expression")
    return EXPR_PLACEHOLDER.join(literals)


def _has_secret_ref(text: str) -> bool:
    return any(SECRET_REF_RE.search(body) for body in _split_expressions(text)[1])


def _workflow_events(doc: dict[str, object], label: str) -> set[str]:
    raw = doc.get("on")
    if isinstance(raw, str):
        events = {raw}
    elif isinstance(raw, list) and all(isinstance(e, str) for e in raw):
        events = set(raw)
    elif isinstance(raw, dict):
        events = set(raw)
    else:
        raise Unclassifiable(f"{label}: `on:` missing or of an unknown shape")
    unknown = events - KNOWN_EVENTS
    if unknown:
        raise Unclassifiable(f"{label}: unknown trigger(s) {sorted(unknown)}")
    return events


def _job_events(job: dict[str, object], events: set[str]) -> set[str]:
    """Narrow the events only for a pure disjunction of `github.event_name == 'x'` terms."""
    cond = job.get("if")
    if not isinstance(cond, str):
        return set(events)
    text = cond.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    names: set[str] = set()
    for term in text.split("||"):
        m = EVENT_EQ_RE.match(term.strip().strip("()").strip())
        if not m:
            return set(events)
        names.add(m.group(1))
    return events & names


def _permissions(job: dict[str, object], doc: dict[str, object], label: str) -> dict[str, str] | str:
    perms = job["permissions"] if "permissions" in job else doc.get("permissions", None)
    if "permissions" not in job and "permissions" not in doc:
        raise Unclassifiable(f"{label}: no `permissions:` at job or workflow level (default token scope unknown)")
    if perms is None:
        return {}
    if isinstance(perms, str):
        if perms in ("read-all", "write-all"):
            return perms
        raise Unclassifiable(f"{label}: permissions {perms!r} outside the known forms")
    if isinstance(perms, dict) and all(isinstance(v, str) and v in ("read", "write", "none") for v in perms.values()):
        return {str(k): str(v) for k, v in perms.items()}
    raise Unclassifiable(f"{label}: permissions block outside the known forms")


def _has_write(perms: dict[str, str] | str) -> bool:
    if isinstance(perms, str):
        return perms == "write-all"
    return any(v == TOKEN_SCOPES_WRITE for v in perms.values())


def _runs_on_legs(job: dict[str, object], label: str) -> list[tuple[str, ...]]:
    raw = job.get("runs-on")
    matrix = (job.get("strategy") or {}).get("matrix") if isinstance(job.get("strategy"), dict) else None

    def as_labels(value: object) -> tuple[str, ...]:
        if isinstance(value, str):
            return (value,)
        if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
            return tuple(value)
        if isinstance(value, dict):
            labels = value.get("labels")
            if labels is None and isinstance(value.get("group"), str):
                return ("group:" + value["group"],)
            return as_labels(labels)
        raise Unclassifiable(f"{label}: runs-on value {value!r} outside the known forms")

    if isinstance(raw, str):
        m = MATRIX_RUNS_ON_RE.match(raw.strip())
        if m:
            if not isinstance(matrix, dict):
                raise Unclassifiable(f"{label}: runs-on names a matrix axis but the matrix is not a mapping")
            axis = m.group(2)
            values: list[object] = []
            if isinstance(matrix.get(axis), list):
                values.extend(matrix[axis])
            for inc in matrix.get("include") or []:
                if isinstance(inc, dict) and axis in inc:
                    values.append(inc[axis])
            if not values:
                raise Unclassifiable(f"{label}: matrix axis {axis!r} has no static values")
            legs: list[tuple[str, ...]] = []
            for v in values:
                if m.group(1):
                    if not isinstance(v, str):
                        raise Unclassifiable(f"{label}: fromJSON matrix value is not a string")
                    try:
                        v = json.loads(v)
                    except ValueError as exc:
                        raise Unclassifiable(f"{label}: fromJSON matrix value is not JSON") from exc
                legs.append(as_labels(v))
            return legs
        if "${{" in raw:
            raise Unclassifiable(f"{label}: runs-on expression outside the known forms")
    if raw is None:
        raise Unclassifiable(f"{label}: job without runs-on")
    return [as_labels(raw)]


def _boundary_holds(label: str, repo_files: frozenset[str]) -> bool:
    """The T-1 OS boundary facts for one runner label (issue #9455); paths never decide."""
    facts = RUNNER_BOUNDARY_FACTS.get(label)
    if not isinstance(facts, dict):
        return False
    pr_user, trusted_user = facts.get("pr_tier_user"), facts.get("trusted_user")
    if not (isinstance(pr_user, str) and isinstance(trusted_user, str) and pr_user and trusted_user):
        return False
    if pr_user == trusted_user:
        return False
    if not all(facts.get(key) is True for key in BOUNDARY_REQUIRED_TRUE):
        return False
    proof = facts.get("proof_test")
    return isinstance(proof, str) and proof in repo_files


def _leg_persistent(leg: tuple[str, ...], repo_files: frozenset[str]) -> bool:
    hosted = [lab for lab in leg if GITHUB_HOSTED_LABEL_RE.match(lab)]
    if hosted and len(hosted) == len(leg):
        return False
    return not any(_boundary_holds(lab, repo_files) for lab in leg if lab != "self-hosted")


def _action_name(uses: str) -> str:
    if uses.startswith("docker://"):
        return uses.split(":", 2)[0] + ":" + uses.split(":", 2)[1].split("@")[0]
    return uses.split("@", 1)[0]


def _step_label(step: dict[str, object], position: int) -> str:
    if isinstance(step.get("name"), str) and step["name"]:
        return str(step["name"])
    if isinstance(step.get("id"), str):
        return f"id:{step['id']}"
    if isinstance(step.get("uses"), str):
        return f"uses:{step['uses']}"
    return f"run#{position}"


def _flatten_steps(steps: object, actions: dict[str, str], label: str, prefix: str = "",
                   depth: int = 0, seen: tuple[str, ...] = ()) -> list[_Step]:
    if depth > MAX_INDIRECTION_DEPTH:
        raise Unclassifiable(f"{label}: composite action nesting deeper than {MAX_INDIRECTION_DEPTH}")
    if not isinstance(steps, list):
        raise Unclassifiable(f"{label}: steps is not a list")
    out: list[_Step] = []
    for pos, step in enumerate(steps):
        if not isinstance(step, dict):
            raise Unclassifiable(f"{label}: step {pos} is not a mapping")
        has_run, has_uses = "run" in step, "uses" in step
        if has_run == has_uses:
            raise Unclassifiable(f"{label}: step {pos} needs exactly one of run/uses")
        step_label = prefix + _step_label(step, pos)
        out.append(_Step(step_label, step, len(out)))
        uses = step.get("uses")
        if isinstance(uses, str) and uses.startswith(LOCAL_PREFIX):
            path = uses[len(LOCAL_PREFIX):].rstrip("/")
            if path in seen:
                raise Unclassifiable(f"{label}: composite action cycle at {path}")
            text = actions.get(path)
            if text is None:
                raise Unclassifiable(f"{label}: local action {uses} not found")
            doc = parse_yaml(text, path)
            runs = doc.get("runs") if isinstance(doc, dict) else None
            if not isinstance(runs, dict) or runs.get("using") != "composite":
                continue
            inner = _flatten_steps(runs.get("steps"), actions, label, step_label + " > ", depth + 1, seen + (path,))
            for item in inner:
                item.body = dict(item.body, _composite=True)
                item.index = len(out)
                out.append(item)
    return out


def _dump(value: object) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _step_shell(step: dict[str, object], job: dict[str, object], doc: dict[str, object]) -> str:
    for holder in (step, ((job.get("defaults") or {}).get("run") or {}) if isinstance(job.get("defaults"), dict) else {},
                   ((doc.get("defaults") or {}).get("run") or {}) if isinstance(doc.get("defaults"), dict) else {}):
        if isinstance(holder, dict) and isinstance(holder.get("shell"), str):
            return holder["shell"].split()[0]
    return "bash"


def _step_runs_pr_code(step: _Step, job: dict[str, object], doc: dict[str, object], materialised: bool,
                       label: str) -> bool:
    body = step.body
    uses = body.get("uses")
    if isinstance(uses, str):
        if uses.startswith(LOCAL_PREFIX):
            return True
        name = _action_name(uses)
        facts = KNOWN_ACTIONS.get(name)
        if facts is None:
            raise Unclassifiable(f"{label}: step {step.label!r}: unknown action {name!r}")
        with_ = body.get("with") if isinstance(body.get("with"), dict) else {}
        if facts.script_input:
            script = with_.get(facts.script_input)
            if script is not None:
                return _shell_runs_pr_code(_expr_free(str(script)), _ShellCtx(materialised))
        if facts.pr_code:
            return not all(str(with_.get(k)) == v for k, v in facts.pr_code_unless) or not facts.pr_code_unless
        return False
    run = body.get("run")
    if not isinstance(run, str):
        raise Unclassifiable(f"{label}: step {step.label!r}: run is not text")
    shell = _step_shell(body, job, doc)
    if shell.rsplit("/", 1)[-1] not in DEFAULT_SHELLS:
        return True
    return _shell_runs_pr_code(_expr_free(run), _ShellCtx(materialised))


def _checkout_tree(step: dict[str, object], events: set[str]) -> str:
    """Return 'pr' when a checkout step puts a pull-request tree in the workspace, else 'trusted'."""
    with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
    ref = with_.get("ref")
    if "repository" in with_:
        return "pr"
    if ref is None:
        return "pr" if events & PR_CODE_EVENTS else "trusted"
    return "trusted" if str(ref).strip() in TRUSTED_CHECKOUT_REFS else "pr"


def _secret_in(step: dict[str, object]) -> bool:
    parts = [step.get("env"), step.get("with"), step.get("run")]
    return _has_secret_ref(_dump(parts))


def _analyse_job(wf: str, job_id: str, job: dict[str, object], doc: dict[str, object], events: set[str],
                 actions: dict[str, str], repo_files: frozenset[str], downloads: bool,
                 result: ScanResult) -> str:
    label = f"{wf}/{job_id}"
    job_events = _job_events(job, events)
    if not job_events & (PR_EVENTS | {CALL_EVENT}):
        return "trusted-only"
    perms = _permissions(job, doc, label)
    legs = _runs_on_legs(job, label)
    steps = _flatten_steps(job.get("steps"), actions, label)
    pr_tree = False
    materialised = False
    taint: _Step | None = None
    leaky_checkouts: list[_Step] = []
    for step in steps:
        body = step.body
        run = body.get("run") if isinstance(body.get("run"), str) else ""
        if BASE_MATERIALISE_RE.search(str(run)):
            materialised = True
        uses = body.get("uses")
        if isinstance(uses, str) and _action_name(uses) == CHECKOUT_ACTION:
            if _checkout_tree(body, job_events) == "pr":
                pr_tree = True
            with_ = body.get("with") if isinstance(body.get("with"), dict) else {}
            if with_.get("persist-credentials") is not False:
                leaky_checkouts.append(step)
            continue
        if run and CHECKOUT_IN_RUN_RE.search(str(run)) and job_events & PR_CODE_EVENTS:
            pr_tree = True
        if pr_tree and taint is None and _step_runs_pr_code(step, job, doc, materialised, label):
            taint = step
            break
    if taint is None:
        return "no-pr-code"
    result.taint_steps[(wf, job_id)] = taint.label
    after = [s for s in steps if s.index >= taint.index]
    found: list[Violation] = []

    def add(step: _Step, klass: str, detail: str) -> None:
        v = Violation(wf, job_id, step.label, klass, detail)
        if v not in found:
            found.append(v)

    # (i) a secret at or after the taint point.
    if _has_secret_ref(_dump([job.get("env"), doc.get("env")])):
        add(taint, CLASS_SECRET, "job or workflow env holds a secret for a tainted job")
    for step in leaky_checkouts:
        add(step, CLASS_SECRET, "checkout keeps the token in the workspace for later pull-request code")
    token_users: list[_Step] = []
    for step in after:
        uses = step.body.get("uses")
        default_token = isinstance(uses, str) and not uses.startswith(LOCAL_PREFIX) and \
            KNOWN_ACTIONS.get(_action_name(uses), ActionFacts()).default_token
        # A checkout after the taint point hands its token to git inside a workspace that
        # pull-request code has already run in, whatever `persist-credentials` says.
        late_checkout = step is not taint and isinstance(uses, str) and _action_name(uses) == CHECKOUT_ACTION
        if _secret_in(step.body) or default_token or late_checkout:
            add(step, CLASS_SECRET, "secret or token used after pull-request code ran")
            token_users.append(step)
    # (ii) a write token in a tainted job.
    if _has_write(perms):
        add(token_users[0] if token_users else taint, CLASS_WRITE_TOKEN, "job token has a write scope")
    # (iii) a job output fed by a step at or after the taint point.
    outputs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
    by_id = {s.body.get("id"): s for s in steps if isinstance(s.body.get("id"), str) and " > " not in s.label}
    for value in outputs.values():
        text = str(value)
        for step_id in STEP_OUTPUT_REF_RE.findall(text):
            ref = by_id.get(step_id)
            if ref is None:
                raise Unclassifiable(f"{label}: output names unknown step {step_id!r}")
            if ref.index >= taint.index:
                add(ref, CLASS_GATE_OUTPUT, "job output set at or after pull-request code ran")
        if re.search(r"\benv\.", text):
            add(taint, CLASS_GATE_OUTPUT, "job output read from the environment of a tainted job")
    # (iv) persistent state a trusted run later reads.
    if any(_leg_persistent(leg, repo_files) for leg in legs):
        add(taint, CLASS_PERSISTENT_STATE, "pull-request code runs on a persistent runner without the OS boundary")
    if downloads:
        for step in after:
            uses = step.body.get("uses")
            if isinstance(uses, str) and _action_name(uses) == UPLOAD_ACTION:
                add(step, CLASS_PERSISTENT_STATE, "artifact uploaded after pull-request code ran")
    result.violations.extend(found)
    return ",".join(sorted({v.klass for v in found}, key=CLASSES.index)) if found else "clean"


def _analyse_workflow(name: str, text: str, workflows: dict[str, str], actions: dict[str, str],
                      repo_files: frozenset[str], downloads: bool, result: ScanResult,
                      caller_events: set[str] | None = None, prefix: str = "", depth: int = 0) -> None:
    if depth > MAX_INDIRECTION_DEPTH:
        raise Unclassifiable(f"{name}: reusable workflow nesting deeper than {MAX_INDIRECTION_DEPTH}")
    doc = parse_yaml(text, name)
    if not isinstance(doc, dict):
        raise Unclassifiable(f"{name}: top level is not a mapping")
    events = _workflow_events(doc, name)
    if caller_events is not None:
        events = set(caller_events)
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise Unclassifiable(f"{name}: no jobs mapping")
    for job_id, job in jobs.items():
        key = (name if not prefix else prefix.split("/")[0], prefix.split("/", 1)[1] + job_id if prefix else job_id)
        try:
            if not isinstance(job, dict):
                raise Unclassifiable(f"{name}/{job_id}: job is not a mapping")
            uses = job.get("uses")
            if isinstance(uses, str):
                m = re.fullmatch(r"\./\.github/workflows/([^/@]+\.ya?ml)", uses)
                if not m or m.group(1) not in workflows:
                    raise Unclassifiable(f"{name}/{job_id}: reusable workflow {uses!r} not found in this repository")
                inner_prefix = f"{key[0]}/{key[1]} > "
                _analyse_workflow(m.group(1), workflows[m.group(1)], workflows, actions, repo_files, downloads,
                                  result, _job_events(job, events), inner_prefix, depth + 1)
                result.verdicts[key] = "reusable"
                continue
            result.verdicts[key] = _analyse_job(key[0], key[1], job, doc, events, actions, repo_files,
                                                downloads, result)
        except Unclassifiable as exc:
            result.unclassifiable.append(str(exc))
            result.verdicts[key] = "unclassifiable"


def scan_texts(workflows: dict[str, str], actions: dict[str, str] | None = None,
               repo_files: frozenset[str] | set[str] | None = None) -> ScanResult:
    """Classify every job of every workflow given as text (name -> YAML); actions: dir -> YAML."""
    actions = actions or {}
    files = frozenset(repo_files or ())
    result = ScanResult()
    downloads = any(marker in text for text in workflows.values() for marker in DOWNLOAD_MARKERS)
    for name in sorted(workflows):
        try:
            _analyse_workflow(name, workflows[name], workflows, actions, files, downloads, result)
        except Unclassifiable as exc:
            result.unclassifiable.append(str(exc))
            result.verdicts[(name, "*")] = "unclassifiable"
    return result


def load_repo(repo_root: Path) -> tuple[dict[str, str], dict[str, str], frozenset[str]]:
    """Read every workflow and local action of a checkout into memory."""
    wf_dir = repo_root / WORKFLOW_DIR
    workflows: dict[str, str] = {}
    for path in sorted(wf_dir.iterdir()):
        if path.suffix in WORKFLOW_SUFFIXES and path.is_file():
            if path.stat().st_size > MAX_YAML_BYTES:
                workflows[path.name] = "\t"  # refused by the parser: never silently skipped
                continue
            workflows[path.name] = path.read_text(encoding="utf-8")
    actions: dict[str, str] = {}
    gh_dir = repo_root / ".github"
    for path in sorted(gh_dir.rglob("*")):
        if path.name in ACTION_FILE_NAMES and path.is_file():
            actions[path.parent.relative_to(repo_root).as_posix()] = path.read_text(encoding="utf-8")
    files = frozenset(p.relative_to(repo_root).as_posix() for p in (repo_root / "scripts").rglob("*.py"))
    return workflows, actions, files


def check(result: ScanResult, allow: tuple[AllowRow, ...] = TAINT_ALLOW, pin: int = TAINT_ALLOW_PIN) -> list[str]:
    """Every problem: unclassifiable forms, violations without a row, stale rows, rows without an issue."""
    problems = [f"unclassifiable: {msg}" for msg in result.unclassifiable]
    if len(allow) != pin:
        problems.append(f"allow table has {len(allow)} rows, pin is {pin}")
    keys = [(r.workflow, r.job, r.step) for r in allow]
    for dup in sorted({k for k in keys if keys.count(k) > 1}):
        problems.append(f"duplicate allow row {dup}")
    violated = {(v.workflow, v.job, v.step, v.klass) for v in result.violations}
    allowed: set[tuple[str, str, str, str]] = set()
    for row in allow:
        if not isinstance(row.issue, int) or row.issue <= 0:
            problems.append(f"allow row without an open issue: {row.workflow}/{row.job}/{row.step}")
        if not row.classes or any(k not in CLASSES for k in row.classes):
            problems.append(f"allow row with an unknown class: {row.workflow}/{row.job}/{row.step}")
        for klass in row.classes:
            key = (row.workflow, row.job, row.step, klass)
            allowed.add(key)
            if key not in violated:
                problems.append(f"stale allow row (no longer violates class {klass}): "
                                f"{row.workflow}/{row.job}/{row.step}")
    for v in sorted(result.violations, key=lambda x: (x.workflow, x.job, x.step, x.klass)):
        if (v.workflow, v.job, v.step, v.klass) not in allowed:
            problems.append(f"violation class ({v.klass}) without an allow row: {v.workflow}/{v.job}/{v.step}: {v.detail}")
    return problems


def scan(repo_root: Path) -> ScanResult:
    workflows, actions, files = load_repo(repo_root)
    return scan_texts(workflows, actions, files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--verdicts", action="store_true", help="print the per-job verdict table")
    args = parser.parse_args(argv)
    result = scan(args.repo)
    if args.verdicts:
        for (wf, job), verdict in sorted(result.verdicts.items()):
            print(f"{wf}\t{job}\t{verdict}\t{result.taint_steps.get((wf, job), '-')}")
        for v in result.violations:
            print(f"violation\t{v.workflow}\t{v.job}\t{v.step}\t({v.klass})")
    problems = check(result)
    for line in problems:
        print(line)
    print(f"problems={len(problems)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
