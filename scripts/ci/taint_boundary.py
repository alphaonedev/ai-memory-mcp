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
decision: the persistent-runner rule of (iv) is R2 (ruling abf38892 section 7), read from
the workflow files alone, over declared host facts, because a fact table is a claim about a
host the classifier cannot check: a job whose ``runs-on`` can resolve to a runner that is
not provably GitHub-hosted (a literal or custom label, a list, a group, a matrix value, an
expression or a reusable-workflow input) has no trusted trigger. No environment variable,
path form, cache-directory name or runner label clears it; an unknown ``runs-on`` form is a
failure.
decision: every known trigger except ``pull_request`` counts as trusted for R2 over the
four the ruling names, because ``pull_request_target``, ``workflow_call``, ``release`` and
``repository_dispatch`` all run with trusted context and a trigger added later must fail
closed.

decision: closed positive lists over lists of known-bad forms (ruling b44e2422): every job
key, step key, shell, action, expression function and context, matrix form and command
word of a run step is on a closed list whose meaning the classifier knows, and every other
form is Unclassifiable with a named reason. Unclassifiable is a finding, never clean.

Limits: detection of a credential resident on a self-hosted host covers literal paths in
a step's text only; every other form rests on the runner boundary of issue #9455.

Usage: python3 scripts/ci/taint_boundary.py [--repo PATH] [--verdicts]
Exit codes: 0 no problem, 1 problems found, 2 usage error.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

WORKFLOW_DIR = ".github/workflows"
WORKFLOW_SUFFIXES = (".yml", ".yaml")
ACTION_FILE_NAMES = ("action.yml", "action.yaml")
MAX_YAML_BYTES = 8 * 1024 * 1024
MAX_INDIRECTION_DEPTH = 8
MAX_YAML_NESTING = 64
READ_CHUNK_BYTES = 1024 * 1024

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
# R2: a run of any of these on a persistent runner is a trusted run (fail closed).
R2_UNTRUSTED_EVENTS = frozenset({"pull_request"})
R2_TRUSTED_EVENTS = KNOWN_EVENTS - R2_UNTRUSTED_EVENTS
# The step key of an R2 violation: the job's runs-on, not one of its steps.
R2_STEP_LABEL = "runs-on"
R2_DETAIL = "job can run on a runner not provably GitHub-hosted and has a trusted trigger: {events}"
HOST_CREDENTIAL_DETAIL = "a credential resident on a self-hosted host read after pull-request code ran"

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
    # Its cache key runs the build tool over the workspace manifests: pull-request code
    # after a pull-request checkout (I-1).
    "Swatinem/rust-cache": ActionFacts(pr_code=True),
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
EVENT_EQ_RE = re.compile(r"^github\.event_name\s*==\s*'([a-z_]+)'$")
# Ruling 04701c74: a write to these runner command files at or after the taint point carries
# pull-request control into every later step of the job (actions and cleanup included); in
# a job holding a pull-request tree a write before any other pull-request code is itself
# the taint point, because the value may be read from the pull-request tree.
ENV_FILE_WRITE_RE = re.compile(r"\$\{?(?:GITHUB_ENV|GITHUB_PATH)\b")


@dataclass(frozen=True)
class AllowRow:
    """A known violation, allowed only while its fix issue is open."""

    workflow: str
    job: str
    step: str
    classes: tuple[str, ...]
    issue: int | None


# The six hits of the survey at a028c45e, the six host-credential reads and the R2 row of
# lifetime-tests (ruling abf38892 section 7). Removing a row is the fix lane's job; adding a
# row needs an issue number from the deputy (the pin moves with it).
TAINT_ALLOW: tuple[AllowRow, ...] = (
    AllowRow("ci.yml", "classify", "id:impact", (CLASS_GATE_OUTPUT,), 9454),
    AllowRow("c8-precheck.yml", "required-contexts-gate",
             # The workflow name runs into a YAML comment at ` #`; the label is the parsed name.
             "Declared-vs-live required-context drift (#3554 /", (CLASS_SECRET,), 9471),
    # R2: these jobs can run on a persistent self-hosted runner and have a trusted trigger.
    AllowRow("ci.yml", "check", R2_STEP_LABEL, (CLASS_PERSISTENT_STATE,), 9455),
    AllowRow("cert-postgres-age.yml", "cert-postgres-age", R2_STEP_LABEL, (CLASS_PERSISTENT_STATE,), 9455),
    AllowRow("postgres-ignored.yml", "postgres-ignored", R2_STEP_LABEL, (CLASS_PERSISTENT_STATE,), 9455),
    AllowRow("session-boot-lifetime.yml", "lifetime-tests", R2_STEP_LABEL, (CLASS_PERSISTENT_STATE,), 9455),
    AllowRow("coverage.yml", "per-module-thresholds", "Post coverage to PR (sticky) (#1993)",
             (CLASS_WRITE_TOKEN, CLASS_SECRET), 9456),
    # Ruling 04701c74: a credential resident on a self-hosted host read after pull-request code is (i); the
    # per-run pull-request-tier credential lands under #9455.
    AllowRow("ci.yml", "check", "Configure enterprise-fed tier (per-job ephemeral db, enterprise-fed legs only)",
             (CLASS_SECRET,), 9455),
    AllowRow("ci.yml", "check", "Cleanup enterprise-fed ephemeral db", (CLASS_SECRET,), 9455),
    AllowRow("cert-postgres-age.yml", "cert-postgres-age", "Point at the native enterprise-fed tier (per-job ephemeral db)",
             (CLASS_SECRET,), 9455),
    AllowRow("cert-postgres-age.yml", "cert-postgres-age", "Cleanup enterprise-fed ephemeral db", (CLASS_SECRET,), 9455),
    AllowRow("postgres-ignored.yml", "postgres-ignored", "Point at the native enterprise-fed tier (per-job ephemeral db)",
             (CLASS_SECRET,), 9455),
    AllowRow("postgres-ignored.yml", "postgres-ignored", "Cleanup enterprise-fed ephemeral db", (CLASS_SECRET,), 9455),
)
TAINT_ALLOW_PIN = 13
# The open fix issues an allow row may name; a row naming any other value is a finding.
FIX_ISSUES = frozenset({9454, 9455, 9456, 9471})
# A loader refusal travels as text with this marker; the parser reports its reason.
REFUSED_MARKER = "\x00taint-boundary-refused:"


class Unclassifiable(Exception):
    """A form this module cannot classify; always reported as a failure."""


# ---------------------------------------------------------------------------------------
# YAML subset parser
# ---------------------------------------------------------------------------------------

PLAIN_TRUE = frozenset({"true", "True", "TRUE"})
PLAIN_FALSE = frozenset({"false", "False", "FALSE"})
PLAIN_NULL = frozenset({"null", "Null", "NULL", "~"})
REFUSED_LEAD = "&*!%@`?|>{}[],#'\""
BLOCK_HEADER_RE = re.compile(r"^([|>])([-+]?)([1-9]?)([-+]?)$")
DQ_ESCAPES = {"\\": "\\", '"': '"', "/": "/", "n": "\n", "t": "\t", "r": "\r", "0": "\0",
              "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "v": "\v", " ": " "}

HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _is_int(plain: str) -> bool:
    body = plain[1:] if plain[:1] in "+-" else plain
    return bool(body) and body.isascii() and body.isdigit()


def _is_float(plain: str) -> bool:
    """`[-+]?(D+.D*|.D+)([eE][-+]?D+)?` by a linear scan."""
    body = plain[1:] if plain[:1] in "+-" else plain
    mant, _, exp = body.partition("e") if "e" in body else body.partition("E")
    if ("e" in body or "E" in body) and not (exp[1:] if exp[:1] in "+-" else exp).isdigit():
        return False
    whole, dot, frac = mant.partition(".")
    if not dot:
        return False
    if not all(part == "" or (part.isascii() and part.isdigit()) for part in (whole, frac)):
        return False
    return bool(whole) or bool(frac)


def _colon_at(text: str) -> int:
    """Index of the first `:` followed by a space or the end, else -1 (linear)."""
    pos = text.find(":")
    while pos >= 0:
        if pos + 1 == len(text) or text[pos + 1] == " ":
            return pos
        pos = text.find(":", pos + 1)
    return -1


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
        if text.startswith(REFUSED_MARKER):
            raise YamlError(f"{label}: {text[len(REFUSED_MARKER):]}")
        if len(text.encode("utf-8", "surrogatepass")) > MAX_YAML_BYTES:
            raise YamlError(f"{label}: larger than {MAX_YAML_BYTES} bytes")
        self.label = label
        self.lines = text.replace("\r\n", "\n").split("\n")
        self.i = 0
        self.depth = 0
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
        self.depth += 1
        try:
            if self.depth > MAX_YAML_NESTING:
                raise self.err(f"nesting deeper than {MAX_YAML_NESTING} levels")
            body = self.lines[self.i][indent:]
            if body == "-" or body.startswith("- "):
                return self.seq(indent)
            return self.mapping(indent)
        finally:
            self.depth -= 1

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
        idx = _colon_at(body)
        if idx < 0:
            raise self.err(f"expected `key: value`, found {body[:60]!r}")
        key = body[:idx].rstrip()
        if not key or " #" in key or key.startswith("#"):
            raise self.err("empty or commented key")
        return key, body[idx + 2:] if body[idx + 1:idx + 2] == " " else body[idx + 1:]

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
        return _colon_at(cut) >= 0

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
        val, end = self.quoted_at(text, 0)
        return val, text[end:]

    def quoted_at(self, text: str, start: int) -> tuple[str, int]:
        """The quoted scalar opening at ``start``: its value and the index after the quote."""
        q = text[start]
        out: list[str] = []
        idx = start + 1
        while idx < len(text):
            ch = text[idx]
            if q == "'":
                if ch == "'":
                    if text[idx + 1: idx + 2] == "'":
                        out.append("'")
                        idx += 2
                        continue
                    return "".join(out), idx + 1
                out.append(ch)
                idx += 1
                continue
            if ch == '"':
                return "".join(out), idx + 1
            if ch == "\\":
                nxt = text[idx + 1: idx + 2]
                if nxt in DQ_ESCAPES:
                    out.append(DQ_ESCAPES[nxt])
                    idx += 2
                    continue
                width = {"x": 2, "u": 4, "U": 8}.get(nxt)
                hexpart = text[idx + 2: idx + 2 + width] if width else ""
                if not width or len(hexpart) != width or not all(c in HEX_DIGITS for c in hexpart):
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
        if ": " in plain or plain.endswith(":") or " #" in plain:
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
        if _is_int(plain) and not (plain.lstrip("+-")[:1] == "0" and len(plain.lstrip("+-")) > 1):
            return int(plain)
        if _is_float(plain):
            return float(plain)
        return plain

    def flow(self, text: str, open_ch: str, close_ch: str, row: int) -> object:
        cut = _strip_comment(text)
        if not cut.endswith(close_ch):
            raise self.err("multi-line or nested flow collection", row)
        inner = cut[1:-1].strip()
        parts: list[str] = []
        cur: list[str] = []
        idx = 0
        while idx < len(inner):
            ch = inner[idx]
            if ch in ("'", '"'):
                _, end = self.quoted_at(inner, idx)
                cur.append(inner[idx:end])
                idx = end
                continue
            if ch in "[]{}":
                raise self.err("nested flow collection", row)
            if ch == ",":
                parts.append("".join(cur).strip())
                cur = []
                idx += 1
                continue
            cur.append(ch)
            idx += 1
        last = "".join(cur)
        if last.strip():
            parts.append(last.strip())
        elif parts:
            raise self.err("trailing comma in a flow collection", row)
        if any(p == "" for p in parts):
            raise self.err("empty flow entry", row)
        if open_ch == "[":
            return [self.flow_scalar(p, row) for p in parts]
        out: dict[str, object] = {}
        for p in parts:
            key_text, value_text = self.flow_entry(p, row)
            key = self.flow_scalar(key_text, row)
            if not isinstance(key, str) or key in out:
                raise self.err("bad or duplicate flow mapping key", row)
            out[key] = self.flow_scalar(value_text, row)
        return out

    def flow_entry(self, part: str, row: int) -> tuple[str, str]:
        """`key: value` of one flow mapping entry, by a linear scan."""
        if part[0] in ("'", '"'):
            _, end = self.quoted_at(part, 0)
            key_text, rest = part[:end], part[end:].lstrip()
        else:
            idx = _colon_at(part)
            key_text, rest = part[:max(idx, 0)].rstrip(), part[max(idx, 0):]
            if idx < 0 or not key_text or any(c in key_text for c in ":'\""):
                raise self.err(f"flow mapping entry {part[:40]!r} outside the subset", row)
        if not rest.startswith(":") or rest[1:2] not in (" ", "\t"):
            raise self.err(f"flow mapping entry {part[:40]!r} outside the subset", row)
        return key_text, rest[1:].strip()

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
# Shell classifier: one linear lexer and parser, then closed command lists
# ---------------------------------------------------------------------------------------
#
# decision: a closed command list with an argument grammar per entry over a list of known
# bad forms, because a form the classifier does not know must be a finding, never clean
# (conductor ruling b44e2422). Every command word outside COMMAND_HANDLERS, every git, gh
# and docker subcommand outside its list, every option that runs a command and every
# expansion the parser cannot follow raises Unclassifiable with its exact reason.

MARK = ""  # one `${{ }}` expression, replaced before the shell text is parsed
MARK_SHOWN = "${{ }}"
MAX_SHELL_NESTING = 64
MAX_PATH_FORMS = 64
WORD_END = frozenset(" \t\n;&|<>()")
REDIR_OPS = ("<<<", "<<-", "<<", ">>", "<&", ">&", "<>", ">|", "<", ">")
OUT_REDIRS = frozenset({">", ">>", ">|", "&>", "&>>", "<>"})
IN_REDIRS = frozenset({"<", "<<", "<<-", "<<<", "<&", "<>"})
COMPOUND_WORDS = frozenset({"{", "if", "while", "until", "for", "case", "function", "[["})
CLOSING_WORDS = frozenset({"then", "elif", "else", "fi", "do", "done", "esac", "}", "in", "]]"})
RT = "\x00RT"  # the runner temp directory
WS = "\x00WS"  # the workspace
GH_FILE = "\x00GH"  # a runner command file (GITHUB_OUTPUT and the rest): never a bound path
RUNNER_FILE_VARS = frozenset({"GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_STEP_SUMMARY", "GITHUB_STATE", "GITHUB_PATH"})
SYSTEM_BIN_DIRS = ("/usr/bin/", "/bin/", "/usr/local/bin/", "/usr/sbin/", "/sbin/")
STRICT_BASE = 2  # a base ref proven non-empty
MAYBE_EMPTY_BASE = 1  # a base ref that may be empty (an empty ref names the index)
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class _Word:
    """One shell word: parts are ("lit", s), ("var", name, modifier), ("sub", nodes), ("expr",), ("dyn",)."""

    __slots__ = ("parts", "raw", "plain", "quoted")

    def __init__(self) -> None:
        self.parts: list[tuple] = []
        self.raw = ""
        self.plain = True
        self.quoted = False

    @property
    def lit(self) -> str | None:
        out: list[str] = []
        for part in self.parts:
            if part[0] != "lit":
                return None
            out.append(part[1])
        return "".join(out)

    def shown(self) -> str:
        return self.raw.replace("'", "").replace('"', "").replace(MARK, MARK_SHOWN)

    def assignment(self) -> tuple[str, "_Word", bool] | None:
        """``NAME=value`` or ``NAME+=value`` with an unquoted name: (name, value word, append)."""
        m = NAME_RE.match(self.raw)
        if not m:
            return None
        end = m.end()
        append = self.raw.startswith("+=", end)
        if not append and self.raw[end:end + 1] != "=":
            return None
        cut = end + (2 if append else 1)
        first = self.parts[0] if self.parts else None
        if first is None or first[0] != "lit" or len(first[1]) < cut:
            return None
        value = _Word()
        value.raw = self.raw[cut:]
        value.plain = False
        rest = first[1][cut:]
        value.parts = ([("lit", rest)] if rest else []) + self.parts[1:]
        return m.group(0), value, append


class _Heredoc:
    __slots__ = ("delim", "strip", "quoted", "text", "word")

    def __init__(self, delim: str, strip: bool, quoted: bool) -> None:
        self.delim = delim
        self.strip = strip
        self.quoted = quoted
        self.text: str | None = None
        self.word: _Word | None = None


class _Cmd:
    __slots__ = ("assigns", "words", "redirs", "piped", "guarded")

    def __init__(self, piped: bool = False) -> None:
        self.assigns: list[tuple[str, _Word, bool]] = []
        self.words: list[_Word] = []
        self.redirs: list[tuple[str, str | None, object]] = []
        self.piped = piped
        self.guarded = False


def _mark_guarded(nodes: list[tuple]) -> None:
    for node in nodes:
        if node[0] == "cmd":
            node[1].guarded = True


class _Sh:
    """A single-pass recursive-descent parser over the bash subset a run step uses."""

    def __init__(self, text: str, depth: int) -> None:
        if depth > MAX_SHELL_NESTING:
            raise Unclassifiable(f"shell nesting deeper than {MAX_SHELL_NESTING} levels")
        self.s = text
        self.n = len(text)
        self.i = 0
        self.depth = depth
        self.buf: tuple | None = None
        self.pending: list[_Heredoc] = []

    def enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_SHELL_NESTING:
            raise Unclassifiable(f"shell nesting deeper than {MAX_SHELL_NESTING} levels")

    def leave(self) -> None:
        self.depth -= 1

    # -- tokens --------------------------------------------------------------------------
    def peek(self) -> tuple:
        if self.buf is None:
            self.buf = self._lex()
        return self.buf

    def next(self) -> tuple:
        tok = self.peek()
        self.buf = None
        return tok

    def _lex(self) -> tuple:
        s, n = self.s, self.n
        while True:
            i = self.i
            while i < n and s[i] in " \t":
                i += 1
            if i + 1 < n and s[i] == "\\" and s[i + 1] == "\n":
                self.i = i + 2
                continue
            self.i = i
            if i >= n:
                return ("eof",)
            if s[i] == "#":
                j = s.find("\n", i)
                self.i = n if j < 0 else j
                continue
            if s[i] == "\n":
                self.i = i + 1
                self._read_heredocs()
                return ("nl",)
            break
        j = i
        while j < n and "0" <= s[j] <= "9":
            j += 1
        fd = s[i:j] if j > i and j < n and s[j] in "<>" else None
        k = j if fd is not None else i
        c = s[k]
        if c in "<>":
            if fd is None and k + 1 < n and s[k + 1] == "(":
                word = _Word()
                word.plain = False
                self.i = k + 2
                word.parts.append(("sub", self._sub_body()))
                word.raw = s[k:self.i]
                return ("word", word)
            for op in REDIR_OPS:
                if s.startswith(op, k):
                    self.i = k + len(op)
                    return ("redir", op, fd)
        if c == "&":
            for op in ("&>>", "&>"):
                if s.startswith(op, k):
                    self.i = k + len(op)
                    return ("redir", op, None)
            op = "&&" if s.startswith("&&", k) else "&"
            self.i = k + len(op)
            return ("op", op)
        if c == "|":
            op = "||" if s.startswith("||", k) else "|&" if s.startswith("|&", k) else "|"
            self.i = k + len(op)
            return ("op", op)
        if c == ";":
            op = ";;&" if s.startswith(";;&", k) else ";;" if s.startswith(";;", k) else ";&" if s.startswith(";&", k) else ";"
            self.i = k + len(op)
            return ("op", op)
        if c in "()":
            self.i = k + 1
            return ("op", c)
        return ("word", self._word())

    def _word(self) -> _Word:
        s, n = self.s, self.n
        word = _Word()
        start = i = self.i
        buf: list[str] = []
        while i < n:
            c = s[i]
            if c in WORD_END:
                break
            if c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    raise Unclassifiable("unterminated single quote")
                buf.append(s[i + 1:j])
                word.quoted = True
                word.plain = False
                i = j + 1
                continue
            if c == '"':
                word.quoted = True
                word.plain = False
                i = self._dq(i + 1, word, buf)
                continue
            if c == "\\":
                if i + 1 < n:
                    if s[i + 1] == "\n":
                        i += 2
                        continue
                    buf.append(s[i + 1])
                    word.quoted = True
                    word.plain = False
                    i += 2
                    continue
                buf.append(c)
                i += 1
                continue
            if c in "$`" or c == MARK:
                _flush(word, buf)
                word.plain = False
                i = self._expansion(i, word)
                continue
            buf.append(c)
            i += 1
        _flush(word, buf)
        self.i = i
        word.raw = s[start:i]
        return word

    def _dq(self, i: int, word: _Word, buf: list[str]) -> int:
        s, n = self.s, self.n
        while i < n:
            c = s[i]
            if c == '"':
                return i + 1
            if c == "\\" and i + 1 < n and s[i + 1] in '$`"\\\n':
                if s[i + 1] != "\n":
                    buf.append(s[i + 1])
                i += 2
                continue
            if c in "$`" or c == MARK:
                _flush(word, buf)
                i = self._expansion(i, word)
                continue
            buf.append(c)
            i += 1
        raise Unclassifiable("unterminated double quote")

    def _sub_body(self) -> list[tuple]:
        """Parse a command list up to its `)`; self.i is just past the opening `(`."""
        self.enter()
        nodes = self.parse_list(frozenset({")"}))
        tok = self.next()
        if tok != ("op", ")"):
            raise Unclassifiable("unterminated command substitution")
        self.leave()
        return nodes

    def _expansion(self, i: int, word: _Word) -> int:
        s, n = self.s, self.n
        c = s[i]
        if c == MARK:
            word.parts.append(("expr",))
            return i + 1
        if c == "`":
            j = i + 1
            inner: list[str] = []
            while j < n and s[j] != "`":
                if s[j] == "\\" and j + 1 < n:
                    inner.append(s[j + 1] if s[j + 1] in "$`\\" else s[j:j + 2])
                    j += 2
                    continue
                inner.append(s[j])
                j += 1
            if j >= n:
                raise Unclassifiable("unterminated backquote")
            word.parts.append(("sub", _Sh("".join(inner), self.depth + 1).parse_all()))
            return j + 1
        nxt = s[i + 1] if i + 1 < n else ""
        if s.startswith("$((", i):
            end = _arith_end(s, i + 3)
            word.parts.append(("dyn",))
            return end
        if nxt == "(":
            self.i = i + 2
            word.parts.append(("sub", self._sub_body()))
            return self.i
        if nxt == "{":
            j = i + 2
            level = 0
            while j < n:
                ch = s[j]
                if ch == "`" or (ch == "$" and j + 1 < n and s[j + 1] == "("):
                    raise Unclassifiable("parameter expansion holding a command substitution")
                if ch == "\\":
                    j += 2
                    continue
                if ch == "{":
                    level += 1
                elif ch == "}":
                    if level == 0:
                        break
                    level -= 1
                j += 1
            else:
                raise Unclassifiable("unterminated parameter expansion")
            inner_text = s[i + 2:j]
            m = NAME_RE.match(inner_text)
            if m:
                word.parts.append(("var", m.group(0), inner_text[m.end():]))
            else:
                word.parts.append(("dyn",))
            return j + 1
        if nxt == "'":
            j = i + 2
            while j < n and s[j] != "'":
                j += 2 if s[j] == "\\" else 1
            if j >= n:
                raise Unclassifiable("unterminated single quote")
            word.parts.append(("dyn",))
            return j + 1
        if nxt == '"':
            end = self._dq(i + 2, word, [])
            word.parts.append(("dyn",))
            return end
        m = NAME_RE.match(s, i + 1)
        if m:
            word.parts.append(("var", m.group(0), ""))
            return m.end()
        if nxt and nxt in "0123456789@*#?$!-":
            word.parts.append(("dyn",))
            return i + 2
        word.parts.append(("lit", "$"))
        return i + 1

    def _read_heredocs(self) -> None:
        pending, self.pending = self.pending, []
        for doc in pending:
            lines: list[str] = []
            while True:
                if self.i >= self.n:
                    raise Unclassifiable(f"here-document without its terminator {doc.delim!r}")
                j = self.s.find("\n", self.i)
                end = self.n if j < 0 else j
                line = self.s[self.i:end]
                self.i = self.n if j < 0 else j + 1
                cmp_line = line.lstrip("\t") if doc.strip else line
                if cmp_line == doc.delim:
                    break
                lines.append(cmp_line)
            body = "\n".join(lines) + ("\n" if lines else "")
            if doc.quoted:
                doc.text = body
            else:
                doc.word = _Sh(body, self.depth + 1).heredoc_word()
                doc.text = doc.word.lit

    def heredoc_word(self) -> _Word:
        """An unquoted here-document body: expansions only (`\\` escapes `$`, backquote, `\\`)."""
        s, n = self.s, self.n
        word = _Word()
        word.plain = False
        buf: list[str] = []
        i = 0
        while i < n:
            c = s[i]
            if c == "\\" and i + 1 < n and s[i + 1] in "$`\\\n":
                if s[i + 1] != "\n":
                    buf.append(s[i + 1])
                i += 2
                continue
            if c in "$`" or c == MARK:
                _flush(word, buf)
                i = self._expansion(i, word)
                continue
            buf.append(c)
            i += 1
        _flush(word, buf)
        word.raw = s
        return word

    # -- grammar -------------------------------------------------------------------------
    def parse_all(self) -> list[tuple]:
        nodes = self.parse_list(frozenset())
        tok = self.peek()
        if tok[0] != "eof":
            raise Unclassifiable(f"unexpected {_tok_text(tok)!r} in shell text")
        if self.pending:
            raise Unclassifiable(f"here-document without its terminator {self.pending[0].delim!r}")
        return nodes

    def skip_nl(self) -> None:
        while self.peek()[0] == "nl":
            self.next()

    def expect_word(self, kw: str) -> None:
        tok = self.next()
        if not (tok[0] == "word" and tok[1].plain and tok[1].lit == kw):
            raise Unclassifiable(f"expected {kw!r}, found {_tok_text(tok)!r} in shell text")

    def expect_op(self, op: str) -> None:
        tok = self.next()
        if tok != ("op", op):
            raise Unclassifiable(f"expected {op!r}, found {_tok_text(tok)!r} in shell text")

    def parse_list(self, stops: frozenset[str]) -> list[tuple]:
        nodes: list[tuple] = []
        while True:
            tok = self.peek()
            kind = tok[0]
            if kind == "nl" or (kind == "op" and tok[1] in (";", "&") and tok[1] not in stops):
                self.next()
                continue
            if kind == "eof":
                return nodes
            if kind == "op" and tok[1] in stops:
                return nodes
            if kind == "word" and tok[1].plain and tok[1].lit in stops:
                return nodes
            nodes.extend(self.parse_and_or())

    def parse_and_or(self) -> list[tuple]:
        groups = [self.parse_pipeline()]
        while True:
            tok = self.peek()
            if tok[0] == "op" and tok[1] in ("&&", "||"):
                self.next()
                self.skip_nl()
                groups.append(self.parse_pipeline())
                continue
            break
        out = [node for group in groups for node in group]
        if len(groups) > 1:
            _mark_guarded(out)
        return out

    def parse_pipeline(self) -> list[tuple]:
        bang = False
        tok = self.peek()
        if tok[0] == "word" and tok[1].plain and tok[1].lit == "!":
            self.next()
            bang = True
        nodes = self.parse_command(False)
        while True:
            tok = self.peek()
            if tok[0] == "op" and tok[1] in ("|", "|&"):
                self.next()
                self.skip_nl()
                nodes.extend(self.parse_command(True))
                continue
            break
        if bang:
            _mark_guarded(nodes)
        return nodes

    def parse_command(self, piped: bool) -> list[tuple]:
        tok = self.peek()
        if tok[0] == "op":
            if tok[1] != "(":
                raise Unclassifiable(f"unexpected {tok[1]!r} in shell text")
            self.next()
            self.enter()
            if self.i < self.n and self.s[self.i] == "(" and self.buf is None:
                self.i = _arith_end(self.s, self.i + 1)
                self.leave()
                return self.trailing_redirs([])
            body = self.parse_list(frozenset({")"}))
            self.expect_op(")")
            self.leave()
            return self.trailing_redirs(body)
        if tok[0] in ("eof", "nl"):
            raise Unclassifiable("missing command in shell text")
        if tok[0] == "word" and tok[1].plain:
            kw = tok[1].lit
            if kw in COMPOUND_WORDS:
                return self.compound(kw)
            if kw in CLOSING_WORDS:
                raise Unclassifiable(f"unexpected {kw!r} in shell text")
        return self.parse_simple(piped)

    def compound(self, kw: str) -> list[tuple]:
        self.next()
        self.enter()
        if kw == "{":
            body = self.parse_list(frozenset({"}"}))
            self.expect_word("}")
        elif kw == "if":
            body = self.condition("then")
            body += self.parse_list(frozenset({"elif", "else", "fi"}))
            while True:
                tok = self.next()
                word = tok[1].lit if tok[0] == "word" and tok[1].plain else None
                if word == "elif":
                    body += self.condition("then")
                    body += self.parse_list(frozenset({"elif", "else", "fi"}))
                    continue
                if word == "else":
                    body += self.parse_list(frozenset({"fi"}))
                    self.expect_word("fi")
                    break
                if word == "fi":
                    break
                raise Unclassifiable(f"expected 'fi', found {_tok_text(tok)!r} in shell text")
        elif kw in ("while", "until"):
            body = self.condition("do")
            body += self.parse_list(frozenset({"done"}))
            self.expect_word("done")
        elif kw == "for":
            body = self.for_loop()
        elif kw == "case":
            body = self.case()
        elif kw == "function":
            tok = self.next()
            if tok[0] != "word" or tok[1].lit is None:
                raise Unclassifiable("function name is not a literal word")
            if self.peek() == ("op", "("):
                self.next()
                self.expect_op(")")
            self.skip_nl()
            body = [("func", tok[1].lit, self.parse_command(False))]
        else:  # [[
            body = self.dbracket()
        self.leave()
        return self.trailing_redirs(body)

    def condition(self, closer: str) -> list[tuple]:
        cond = self.parse_list(frozenset({closer}))
        _mark_guarded(cond)
        self.expect_word(closer)
        return cond

    def for_loop(self) -> list[tuple]:
        tok = self.next()
        if tok == ("op", "(") and self.i < self.n and self.s[self.i] == "(" and self.buf is None:
            self.i = _arith_end(self.s, self.i + 1)
            name, items = "", []
        else:
            if tok[0] != "word" or not tok[1].plain or not NAME_RE.fullmatch(tok[1].lit or ""):
                raise Unclassifiable("for-loop variable is not a name")
            name, items = tok[1].lit, None
            self.skip_nl()
            nxt = self.peek()
            if nxt[0] == "word" and nxt[1].plain and nxt[1].lit == "in":
                self.next()
                items = []
                while self.peek()[0] == "word":
                    items.append(self.next()[1])
        while True:
            tok = self.peek()
            if tok[0] == "nl" or tok == ("op", ";"):
                self.next()
                continue
            break
        self.expect_word("do")
        body = self.parse_list(frozenset({"done"}))
        self.expect_word("done")
        return [("for", name, items, body)]

    def case(self) -> list[tuple]:
        tok = self.next()
        if tok[0] != "word":
            raise Unclassifiable("case subject is not a word")
        words = [tok[1]]
        self.skip_nl()
        self.expect_word("in")
        body: list[tuple] = []
        while True:
            self.skip_nl()
            tok = self.peek()
            if tok[0] == "word" and tok[1].plain and tok[1].lit == "esac":
                self.next()
                break
            if tok == ("op", "("):
                self.next()
            while True:
                tok = self.next()
                if tok[0] != "word":
                    raise Unclassifiable(f"case pattern {_tok_text(tok)!r} is not a word")
                words.append(tok[1])
                tok = self.next()
                if tok == ("op", "|"):
                    continue
                if tok == ("op", ")"):
                    break
                raise Unclassifiable(f"unexpected {_tok_text(tok)!r} in a case pattern")
            body += self.parse_list(frozenset({";;", ";&", ";;&", "esac"}))
            tok = self.peek()
            if tok[0] == "op" and tok[1] in (";;", ";&", ";;&"):
                self.next()
        return [("words", words)] + body

    def dbracket(self) -> list[tuple]:
        words: list[_Word] = []
        while True:
            tok = self.next()
            if tok[0] in ("eof", "nl"):
                raise Unclassifiable("unterminated `[[`")
            if tok[0] == "word":
                if tok[1].plain and tok[1].lit == "]]":
                    return [("words", words)]
                words.append(tok[1])

    def trailing_redirs(self, body: list[tuple]) -> list[tuple]:
        cmd = _Cmd()
        while self.peek()[0] == "redir":
            cmd.redirs.append(self.redir_target(self.next()))
        return ([("cmd", cmd)] if cmd.redirs else []) + body

    def redir_target(self, tok: tuple) -> tuple[str, str | None, object]:
        op, fd = tok[1], tok[2]
        nxt = self.next()
        if nxt[0] != "word":
            raise Unclassifiable(f"redirection {op!r} without a target")
        if op in ("<<", "<<-"):
            delim = nxt[1].lit
            if delim is None:
                raise Unclassifiable("here-document delimiter is not a literal word")
            doc = _Heredoc(delim, op == "<<-", nxt[1].quoted)
            self.pending.append(doc)
            return op, fd, doc
        return op, fd, nxt[1]

    def parse_simple(self, piped: bool) -> list[tuple]:
        cmd = _Cmd(piped)
        while True:
            tok = self.peek()
            if tok[0] == "word":
                word = tok[1]
                self.next()
                if not cmd.words:
                    assign = word.assignment()
                    if assign is not None:
                        cmd.assigns.append(assign)
                        continue
                    if not cmd.assigns and word.plain and word.lit and self.peek() == ("op", "("):
                        self.next()
                        self.expect_op(")")
                        self.skip_nl()
                        return [("func", word.lit, self.parse_command(False))]
                cmd.words.append(word)
                continue
            if tok[0] == "redir":
                cmd.redirs.append(self.redir_target(self.next()))
                continue
            break
        if not (cmd.words or cmd.assigns or cmd.redirs):
            raise Unclassifiable(f"unexpected {_tok_text(self.peek())!r} in shell text")
        return [("cmd", cmd)]


def _flush(word: _Word, buf: list[str]) -> None:
    if buf:
        word.parts.append(("lit", "".join(buf)))
        buf.clear()


def _tok_text(tok: tuple) -> str:
    if tok[0] == "word":
        return tok[1].shown()
    if tok[0] in ("op", "redir"):
        return tok[1]
    return "end of line" if tok[0] == "nl" else "end of text"


def _arith_end(s: str, j: int) -> int:
    """Index just past the `))` closing arithmetic that starts at ``j``; refuses a substitution."""
    level = 0
    n = len(s)
    while j < n:
        ch = s[j]
        if ch == "`" or (ch == "$" and j + 1 < n and s[j + 1] == "("):
            raise Unclassifiable("arithmetic expansion holding a command substitution")
        if ch == "(":
            level += 1
        elif ch == ")":
            if level == 0:
                if j + 1 < n and s[j + 1] == ")":
                    return j + 2
                break
            level -= 1
        j += 1
    raise Unclassifiable("unterminated arithmetic expansion")


class _ShellCtx:
    """Facts one run step proves about itself, in order (I-2): nothing crosses into another step.

    ``strict`` False is the reading of a job with no pull-request trigger: only a pull-request
    fetch is looked for, and a command outside the lists is not a finding there.
    """

    def __init__(self, strict: bool = True, base: dict[str, int] | None = None, errexit: bool = True,
                 shadowed: frozenset[str] = frozenset(), action_dir: str | None = None) -> None:
        self.strict = strict
        # The directory of the local composite action this step belongs to (I-1: the one
        # meaning of GITHUB_ACTION_PATH the classifier knows); None outside such an action.
        self.action_dir = action_dir
        self.base: dict[str, int] = dict(base or {})
        self.errexit = errexit
        self.tmp: dict[str, set[str]] = {}
        self.bad: set[str] = set(shadowed)
        self.bound: set[str] = set()
        self.loops: dict[str, list[str] | None] = {}
        self.functions: set[str] = set()
        self.tree_change = False
        self.pr_fetch = False
        self.depth = 0

    def drop(self, name: str) -> None:
        self.base.pop(name, None)
        self.tmp.pop(name, None)
        self.bad.add(name)

    def assign(self, name: str, value: _Word, guarded: bool, append: bool) -> None:
        if name in self.bad:
            return
        if append:
            self.drop(name)
            return
        level = self.base_level(value, guarded)
        if level:
            if name in self.tmp:
                self.drop(name)
                return
            self.base[name] = min(self.base.get(name, level), level)
            return
        paths = self.norm(value)
        if paths and all(p.startswith(RT + "/") for p in paths) and name not in self.base:
            self.tmp.setdefault(name, set()).update(paths)
            return
        self.drop(name)

    def var_level(self, name: str) -> int:
        return 0 if name in self.bad else self.base.get(name, 0)

    def base_level(self, word: _Word, guarded: bool) -> int:
        """STRICT_BASE, MAYBE_EMPTY_BASE or 0 for a word used as a git revision."""
        parts = word.parts
        if not parts or word.lit == "":
            return MAYBE_EMPTY_BASE
        if len(parts) != 1:
            return 0
        part = parts[0]
        if part[0] == "var":
            level = self.var_level(part[1])
            if part[2] == "":
                return level
            if part[2].startswith(":?"):
                return STRICT_BASE if level else 0
            return 0
        if part[0] == "sub":
            return self.merge_base_level(part[1], guarded)
        return 0

    def merge_base_level(self, nodes: list[tuple], guarded: bool) -> int:
        """`$(git merge-base <refs>)`, optionally `|| echo "$ref"`: the ancestor of a base ref."""
        level = 0
        for node in nodes:
            if node[0] != "cmd" or node[1].assigns or not node[1].words:
                return 0
            cmd = node[1]
            if any(fd != "2" for _, fd, _ in cmd.redirs):
                return 0
            words = cmd.words
            if words[0].lit == "git" and len(words) > 2 and words[1].lit == "merge-base":
                refs = 0
                for word in words[2:]:
                    if word.lit is not None:
                        if word.lit.startswith("-") or word.lit == "HEAD":
                            continue
                        return 0
                    if not self.base_level(word, True):
                        return 0
                    refs += 1
                if not refs:
                    return 0
                # A failing merge-base aborts an errexit step; inside a list it yields "".
                this = STRICT_BASE if self.errexit and not guarded and len(nodes) == 1 else MAYBE_EMPTY_BASE
            elif words[0].lit == "echo" and len(words) == 2:
                this = self.base_level(words[1], True)
                if not this:
                    return 0
            else:
                return 0
            level = this if not level else min(level, this)
        return level

    def norm(self, word: _Word) -> set[str] | None:
        """Every normalised path the word can name, or None when it cannot be known."""
        forms = [""]
        for part in word.parts:
            if part[0] == "lit":
                forms = [f + part[1] for f in forms]
                continue
            if part[0] != "var":
                return None
            name, mod = part[1], part[2]
            if name in self.bad:
                return None
            if name == "RUNNER_TEMP" and mod in ("", ":-."):
                values = [RT]
            elif name == "GITHUB_WORKSPACE" and mod == "":
                values = [WS]
            elif name == "GITHUB_ACTION_PATH" and mod == "" and self.action_dir is not None:
                values = [self.action_dir]
            elif name in RUNNER_FILE_VARS and mod == "":
                values = [f"{GH_FILE}/{name}"]
            elif mod == "" and name in self.tmp:
                values = sorted(self.tmp[name])
            elif mod == "" and self.loops.get(name) is not None:
                values = list(self.loops[name] or [])
            else:
                return None
            forms = [f + v for f in forms for v in values]
            if len(forms) > MAX_PATH_FORMS:
                return None
        out: set[str] = set()
        for form in forms:
            comps = [c for c in form.split("/") if c not in ("", ".")]
            if ".." in comps:
                # `..` resolves only inside the workspace and never above its root.
                if not comps or comps[0] != WS:
                    return None
                stack: list[str] = []
                for comp in comps:
                    if comp != "..":
                        stack.append(comp)
                    elif len(stack) > 1:
                        stack.pop()
                    else:
                        return None
                comps = stack
            lead = "/" if form.startswith("/") else ""
            out.add(lead + "/".join(comps))
        return out

    def unbind(self, word: _Word) -> None:
        paths = self.norm(word)
        if paths is None:
            self.bound.clear()
        else:
            self.bound -= paths


def _run_nodes(nodes: list[tuple], ctx: _ShellCtx) -> bool:
    pr = False
    for node in nodes:
        kind = node[0]
        if kind == "cmd":
            pr |= _run_cmd(node[1], ctx)
        elif kind == "words":
            for word in node[1]:
                pr |= _run_subs(word, ctx)
        elif kind == "func":
            ctx.functions.add(node[1])
            pr |= _run_nodes(node[2], ctx)
        elif kind == "for":
            _, name, items, body = node
            for word in items or []:
                pr |= _run_subs(word, ctx)
            values = None
            if items is not None and all(w.lit is not None for w in items):
                values = [w.lit for w in items]
            if name:
                ctx.drop(name)
                ctx.bad.discard(name)
                ctx.loops[name] = values
            pr |= _run_nodes(body, ctx)
            if name:
                ctx.loops.pop(name, None)
                ctx.drop(name)
    return pr


def _run_subs(word: _Word, ctx: _ShellCtx) -> bool:
    pr = False
    for part in word.parts:
        if part[0] == "sub":
            pr |= _run_nodes(part[1], ctx)
    return pr


def _run_cmd(cmd: _Cmd, ctx: _ShellCtx) -> bool:
    pr = False
    for name, value, append in cmd.assigns:
        pr |= _run_subs(value, ctx)
        ctx.assign(name, value, cmd.guarded, append)
    for _, _, target in cmd.redirs:
        if isinstance(target, _Heredoc):
            if target.word is not None:
                pr |= _run_subs(target.word, ctx)
        else:
            pr |= _run_subs(target, ctx)
    for word in cmd.words:
        pr |= _run_subs(word, ctx)
    for op, fd, target in cmd.redirs:
        if op in OUT_REDIRS and isinstance(target, _Word) and fd != "0":
            ctx.unbind(target)
    if cmd.words:
        pr |= _dispatch(cmd.words, cmd, ctx)
    return pr


def _shell_text(code: str, ctx: _ShellCtx) -> bool:
    """Classify a command string that a command runs as shell (bash -c, trap, env -S, ...)."""
    ctx.depth += 1
    try:
        return _run_nodes(_Sh(code, ctx.depth).parse_all(), ctx)
    finally:
        ctx.depth -= 1


def _shell_runs_pr_code(text: str, ctx: _ShellCtx | None = None) -> bool:
    """True when the shell text runs pull-request code; Unclassifiable for every unknown form."""
    ctx = ctx if ctx is not None else _ShellCtx()
    return _run_nodes(_Sh(text, ctx.depth).parse_all(), ctx)


def _dispatch(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    head = words[0]
    name = head.lit
    if name is None or MARK in name or name == "":
        raise Unclassifiable(f"command word {head.shown()!r} is not a literal word")
    if name in ctx.functions:
        return False
    if "/" in name:
        if not name.startswith("/"):
            return True  # a program from the workspace
        if not name.startswith(SYSTEM_BIN_DIRS):
            raise Unclassifiable(f"command word {name!r} is not on the closed command list")
        name = name.rsplit("/", 1)[1]
    handler = _command_handler(name)
    if handler is None:
        if not ctx.strict:
            return False
        raise Unclassifiable(f"command word {name!r} is not on the closed command list")
    if name in PATH_WRITERS:
        for word in words[1:]:
            ctx.unbind(word)
    if ctx.strict:
        return handler(words, cmd, ctx)
    try:
        return handler(words, cmd, ctx)
    except Unclassifiable:
        return False


def _command_handler(name: str):
    if name.startswith("python") and _is_python_name(name):
        return _py_cmd
    if name.startswith("cargo-"):
        return _pr_code
    return COMMAND_HANDLERS.get(name)


def _is_python_name(name: str) -> bool:
    rest = name[len("python"):]
    return rest == "" or all(c.isascii() and (c.isdigit() or c == ".") for c in rest)


def _synthetic(words: list[_Word]) -> _Cmd:
    """The command an option runs (find -exec, xargs): it reads no here-document of ours."""
    cmd = _Cmd()
    cmd.words = words
    cmd.piped = True
    return cmd


def _stdin(cmd: _Cmd) -> tuple[str, object]:
    for op, fd, target in reversed(cmd.redirs):
        if op in IN_REDIRS and fd in (None, "0"):
            if isinstance(target, _Heredoc):
                return "doc", target
            if op == "<<<":
                return "string", target
            return "file", target
    return ("pipe", None) if cmd.piped else ("none", None)


def _stdin_code(cmd: _Cmd, check) -> bool:
    """Code read from stdin: a literal here-document or here-string is checked, anything else runs."""
    kind, target = _stdin(cmd)
    if kind == "doc" and target.text is not None:
        return check(target.text)
    if kind == "string" and target.lit is not None:
        return check(target.lit)
    return True


def _lits(words: list[_Word]) -> list[str | None]:
    return [w.lit for w in words]


def _inert(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    return False


def _pr_code(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    return True


def _version_only(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """node: only a version query is inert; every other form runs code."""
    return not all(w.lit in ("--version", "-v") for w in words[1:]) or len(words) == 1


def _binds(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """read, unset, export, local, declare and the rest: the names they set are unknown values."""
    for word in words[1:]:
        assign = word.assignment()
        if assign is not None:
            ctx.assign(assign[0], assign[1], cmd.guarded, assign[2])
            continue
        if word.lit and NAME_RE.fullmatch(word.lit) and words[0].lit in ("read", "unset", "mapfile", "readarray"):
            ctx.drop(word.lit)
    return False


def _shells(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """bash/sh: `-c STRING` is classified, a script file runs, stdin code is classified or runs."""
    i = 1
    while i < len(words):
        lit = words[i].lit
        if lit is None:
            return True
        if lit in ("-o", "+o"):
            i += 2
            continue
        if lit == "--":
            i += 1
            break
        if lit == "-":
            break
        if lit.startswith(("-", "+")) and len(lit) > 1:
            if "c" in lit[1:]:
                code = words[i + 1].lit if i + 1 < len(words) else None
                if code is None:
                    return True
                return _shell_text(code, ctx)
            i += 2 if "o" in lit[1:] else 1
            continue
        return True
    if i < len(words) and words[i].lit != "-":
        return True
    return _stdin_code(cmd, lambda text: _shell_text(text, ctx))


PY_INERT_MODULES = frozenset({"json.tool"})
PY_MODULES = frozenset({
    "json", "sys", "re", "pathlib", "collections", "itertools", "functools", "math", "string", "textwrap",
    "hashlib", "base64", "datetime", "time", "argparse", "csv", "fnmatch", "typing", "dataclasses", "enum",
    "statistics", "decimal", "struct", "binascii", "shlex", "glob", "unicodedata", "difflib", "operator",
})
PY_RUN_NAMES = frozenset({"exec", "eval", "compile", "execfile", "breakpoint", "__import__"})
PY_FLAG_CHARS = frozenset("EsSBuOqbPd")


def _py_code(code: str) -> bool:
    """Python text under `-I`: closed module list, no dunder name; exec/eval/compile run code."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise Unclassifiable("python code does not parse") from exc
    runs = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in PY_MODULES:
                    raise Unclassifiable(f"python module {alias.name!r} is not on the closed module list")
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            if node.level or module not in PY_MODULES:
                raise Unclassifiable(f"python module {module!r} is not on the closed module list")
        elif isinstance(node, ast.Name):
            if node.id.startswith("__") and node.id.endswith("__"):
                raise Unclassifiable("python code uses a dunder name")
            if node.id in PY_RUN_NAMES:
                runs = True
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__"):
                raise Unclassifiable("python code uses a dunder name")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.startswith("__") and node.value.endswith("__"):
                raise Unclassifiable("python code uses a dunder name")
    return runs


def _interp_path(word: _Word, ctx: _ShellCtx, isolated: bool) -> bool:
    lit = word.lit
    if lit is not None and not lit.startswith("/") and MARK not in lit:
        return True  # a script from the workspace
    paths = ctx.norm(word)
    if paths and all(p.startswith(WS + "/") for p in paths):
        return True
    if paths and all(p in ctx.bound for p in paths):
        return not isolated
    raise Unclassifiable(f"interpreter path {word.shown()!r} is neither in the workspace nor bound to base content")


def _py_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """python: -c CODE and stdin code are checked only under -I; -m json.tool under -I is inert."""
    isolated = False
    i = 1
    while i < len(words):
        lit = words[i].lit
        if lit is None:
            return _interp_path(words[i], ctx, isolated)
        if lit in ("-V", "--version", "-VV", "-h", "--help"):
            return False
        if lit in ("-W", "-X"):
            i += 2
            continue
        if lit == "-":
            return _stdin_code(cmd, _py_code) if isolated else True
        if lit.startswith("--"):
            raise Unclassifiable(f"python option {lit!r} is not on the closed option list")
        if lit.startswith("-") and len(lit) > 1:
            for pos, ch in enumerate(lit[1:], start=1):
                if ch == "I":
                    isolated = True
                elif ch in ("c", "m"):
                    arg = lit[pos + 1:] or (words[i + 1].lit if i + 1 < len(words) else None)
                    if ch == "m":
                        return not (isolated and arg in PY_INERT_MODULES)
                    if not isolated or arg is None:
                        return True
                    return _py_code(arg)
                elif ch not in PY_FLAG_CHARS:
                    raise Unclassifiable(f"python option '-{ch}' is not on the closed option list")
            i += 1
            continue
        return _interp_path(words[i], ctx, isolated)
    return _stdin_code(cmd, _py_code) if isolated else True


GIT_C_KEYS = frozenset({
    "user.name", "user.email", "safe.directory", "advice.detachedhead", "init.defaultbranch", "core.quotepath",
    "color.ui", "protocol.version", "gc.auto", "maintenance.auto", "fetch.prune", "pull.rebase",
})
GIT_GLOBAL_FLAGS = frozenset({
    "--no-pager", "-P", "--paginate", "-p", "--no-replace-objects", "--literal-pathspecs", "--glob-pathspecs",
    "--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks", "--bare",
})
GIT_GLOBAL_ARGS = frozenset({"-C", "--git-dir", "--work-tree", "--namespace"})
GIT_INERT = frozenset({
    "status", "log", "diff", "show", "rev-parse", "rev-list", "merge-base", "cat-file", "ls-files", "ls-tree",
    "ls-remote", "describe", "name-rev", "for-each-ref", "symbolic-ref", "shortlog", "blame", "grep", "fetch",
    "add", "commit", "push", "remote", "init", "clone", "tag", "branch", "notes", "count-objects", "fsck",
    "gc", "version", "check-ignore", "check-attr", "diff-tree", "diff-index", "diff-files", "show-ref",
    "hash-object", "verify-commit", "verify-tag", "config", "format-patch", "rm", "mv", "clean", "update-ref",
    "write-tree", "check-ref-format", "var", "help", "range-diff", "cherry", "interpret-trailers", "mktree",
    "commit-tree", "merge-tree", "prune", "repack", "pack-refs", "reflog", "worktree", "bisect", "submodule",
    "reset", "stash", "read-tree",
})
GIT_TREE = frozenset({"checkout", "switch", "restore", "pull", "merge", "rebase", "cherry-pick", "revert", "am", "apply"})
GIT_CONFIG_SET_KEYS = GIT_C_KEYS
GIT_CONFIG_READ = frozenset({"--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin", "--name-only"})


def _git_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """git: closed global options and -c keys, closed subcommands; a tree change is recorded."""
    i = 1
    n = len(words)
    while i < n:
        lit = words[i].lit
        if lit is None:
            raise Unclassifiable(f"git subcommand {words[i].shown()!r} is not a literal word")
        if lit == "-c":
            pair = words[i + 1].lit if i + 1 < n else None
            if pair is None:
                raise Unclassifiable("git -c value is not a literal word")
            key = pair.split("=", 1)[0]
            if key.lower() not in GIT_C_KEYS:
                raise Unclassifiable(f"git -c key {key!r} is not on the closed key list")
            i += 2
            continue
        if lit in GIT_GLOBAL_ARGS:
            i += 2
            continue
        if lit in GIT_GLOBAL_FLAGS or lit.startswith(("--git-dir=", "--work-tree=", "--namespace=")):
            i += 1
            continue
        if lit in ("--version", "--help", "-h"):
            return False
        if lit.startswith("-"):
            raise Unclassifiable(f"git option {lit!r} is not on the closed option list")
        break
    if i >= n:
        return False
    sub = words[i].lit or ""
    args = words[i + 1:]
    lits = _lits(args)
    if sub in GIT_TREE:
        ctx.tree_change = True
        if sub == "rebase":
            for pos, lit in enumerate(lits):
                if lit in ("--exec", "-x"):
                    code = lits[pos + 1] if pos + 1 < len(lits) else None
                    return True if code is None else _shell_text(code, ctx)
                if lit is not None and lit.startswith("--exec="):
                    return _shell_text(lit[len("--exec="):], ctx)
        return False
    if sub not in GIT_INERT:
        raise Unclassifiable(f"git subcommand {sub!r} is not on the closed list")
    if sub == "fetch":
        if any(lit is not None and "pull/" in lit for lit in lits):
            ctx.pr_fetch = True
            ctx.tree_change = True
        return False
    if sub == "worktree":
        if lits[:1] == ["add"]:
            ctx.tree_change = True
        return False
    if sub == "reset":
        if any(lit in ("--hard", "--merge", "--keep") for lit in lits):
            ctx.tree_change = True
        return False
    if sub == "stash":
        if lits[:1] and lits[0] not in ("list", "show"):
            ctx.tree_change = True
        return False
    if sub == "read-tree":
        if "-u" in lits:
            ctx.tree_change = True
        return False
    if sub == "bisect":
        if lits[:1] == ["run"]:
            return True if len(args) < 2 else _dispatch(args[1:], _synthetic(args[1:]), ctx)
        return False
    if sub == "submodule":
        rest = [lit for lit in lits if lit is None or not lit.startswith("-")]
        if rest[:1] == ["foreach"]:
            code = rest[1:]
            if not code or any(lit is None for lit in code):
                return True
            return _shell_text(" ".join(code), ctx)
        if rest[:1] == ["update"]:
            ctx.tree_change = True
        return False
    if sub == "config":
        return _git_config(lits)
    if sub == "show":
        _git_show_bind(args, cmd, ctx)
    return False


def _git_config(lits: list[str | None]) -> bool:
    positional: list[str | None] = []
    setting = False
    i = 0
    while i < len(lits):
        lit = lits[i]
        if lit in ("--file", "-f", "--blob", "--type", "--default"):
            i += 2
            continue
        if lit in ("--add", "--replace-all"):
            setting = True
        elif lit is not None and lit.startswith("-"):
            if lit in GIT_CONFIG_READ:
                return False
        else:
            positional.append(lit)
        i += 1
    if not positional:
        return False
    key = positional[0]
    if key is None:
        raise Unclassifiable("git config key is not a literal word")
    if (setting or len(positional) > 1) and key.lower() not in GIT_CONFIG_SET_KEYS:
        raise Unclassifiable(f"git config key {key!r} is not on the closed key list")
    return False


def _git_show_bind(args: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> None:
    """`git show "<base ref>:<path>" > <runner temp path>` binds that path to base content."""
    if len(args) != 1:
        return
    parts = args[0].parts
    if len(parts) < 2 or parts[0][0] != "var" or parts[1][0] != "lit" or not parts[1][1].startswith(":"):
        return
    level = ctx.var_level(parts[0][1])
    mod = parts[0][2]
    if not ((mod == "" and level == STRICT_BASE) or (mod.startswith(":?") and level)):
        return
    dests = [t for op, fd, t in cmd.redirs if op in (">", ">|") and fd in (None, "1") and isinstance(t, _Word)]
    if len(dests) != 1:
        return
    paths = ctx.norm(dests[0])
    if paths and all(p.startswith(RT + "/") for p in paths):
        ctx.bound |= paths


GH_INERT = frozenset({
    "api", "run", "issue", "release", "repo", "workflow", "auth", "label", "cache", "search", "status",
    "ruleset", "secret", "variable", "pr", "version",
})


def _gh_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """gh: closed subcommands; `gh pr checkout` is a pull-request tree change; extensions run code."""
    if len(words) < 2:
        return False
    sub = words[1].lit
    if sub is None:
        raise Unclassifiable(f"gh subcommand {words[1].shown()!r} is not a literal word")
    if sub in ("--version", "--help", "-h"):
        return False
    if sub == "extension":
        return True
    if sub not in GH_INERT:
        raise Unclassifiable(f"gh subcommand {sub!r} is not on the closed list")
    if sub == "pr" and len(words) > 2 and words[2].lit in ("checkout", "co"):
        ctx.pr_fetch = True
        ctx.tree_change = True
    return False


DOCKER_GLOBAL_ARGS = frozenset({"--config", "-H", "--host", "--context", "-c", "--log-level", "-l"})
DOCKER_RUNS = frozenset({"run", "exec", "build", "buildx", "compose", "create", "start", "restart", "commit"})
DOCKER_INERT = frozenset({
    "ps", "images", "inspect", "pull", "push", "login", "logout", "logs", "rm", "rmi", "stop", "kill", "tag",
    "version", "info", "network", "volume", "system", "manifest", "save", "load", "cp", "wait", "port", "top",
    "stats", "history", "events", "image", "container",
})


def _docker_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """docker: a container or build runs code (it can mount the workspace); the rest is inert."""
    lits = _lits(words[1:])
    i = 0
    while i < len(lits):
        lit = lits[i]
        if lit is None:
            raise Unclassifiable(f"docker subcommand {words[i + 1].shown()!r} is not a literal word")
        if lit in DOCKER_GLOBAL_ARGS:
            i += 2
            continue
        if lit in ("--version", "-v", "--help"):
            return False
        if lit.startswith("-"):
            i += 1
            continue
        break
    if i >= len(lits):
        return False
    sub = lits[i]
    if sub in DOCKER_RUNS:
        return True
    if sub not in DOCKER_INERT:
        raise Unclassifiable(f"docker subcommand {sub!r} is not on the closed list")
    if sub in ("image", "container") and i + 1 < len(lits):
        return lits[i + 1] in DOCKER_RUNS or lits[i + 1] is None
    return False


def _sed_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """sed: -f runs a file; the program is parsed and the `e` command or `s///e` runs code."""
    scripts: list[str | None] = []
    first: str | None = None
    have_first = False
    i = 1
    while i < len(words):
        lit = words[i].lit
        if lit is None:
            if not scripts and not have_first:
                return True
            i += 1
            continue
        if lit in ("-e", "--expression"):
            scripts.append(words[i + 1].lit if i + 1 < len(words) else None)
            i += 2
            continue
        if lit.startswith("--expression="):
            scripts.append(lit.split("=", 1)[1])
        elif lit in ("-f", "--file") or lit.startswith("--file="):
            return True
        elif lit.startswith(("-i", "--in-place")) or lit in ("-n", "--quiet", "--silent", "-E", "-r",
                                                               "--regexp-extended", "-s", "--separate",
                                                               "-u", "--unbuffered", "-z", "--null-data",
                                                               "--posix", "--debug", "--"):
            pass
        elif lit.startswith("-") and len(lit) > 1 and not lit.startswith("--"):
            for pos, ch in enumerate(lit[1:], start=1):
                if ch in "nErsuz":
                    continue
                if ch == "e":
                    scripts.append(lit[pos + 1:] or (words[i + 1].lit if i + 1 < len(words) else None))
                    if not lit[pos + 1:]:
                        i += 1
                    break
                if ch == "f":
                    return True
                raise Unclassifiable(f"sed option '-{ch}' is not on the closed option list")
        elif lit.startswith("--"):
            raise Unclassifiable(f"sed option {lit!r} is not on the closed option list")
        elif not have_first:
            first = lit
            have_first = True
        i += 1
    if not scripts:
        scripts = [first] if have_first else []
    for script in scripts:
        if script is None or _sed_program(script):
            return True
    return False


SED_SIMPLE = frozenset("=dDgGhHlnNpPqQxzF{}")


def _sed_until(text: str, i: int, stop: str) -> int:
    """Index of the next unescaped ``stop`` from ``i`` (or the end)."""
    n = len(text)
    while i < n and text[i] != stop:
        i += 2 if text[i] == "\\" else 1
    return i


def _sed_program(text: str) -> bool:
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in " \t\n;!":
            i += 1
            continue
        while i < n and (text[i].isdigit() or text[i] in "$,~+"):
            i += 1
        if i < n and text[i] == "/":
            i = _sed_until(text, i + 1, "/") + 1
            continue
        if i < n and text[i] == "\\" and i + 1 < n:
            i = _sed_until(text, i + 2, text[i + 1]) + 1
            continue
        if i >= n:
            break
        c = text[i]
        if c in " \t\n;!,":
            continue
        if c in SED_SIMPLE:
            i += 1
            continue
        if c == "#" or c in ":aicrRwW":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in "btT":
            j = i + 1
            while j < n and text[j] not in ";\n":
                j += 1
            i = j
            continue
        if c == "e":
            return True
        if c in "sy":
            if i + 1 >= n:
                raise Unclassifiable(f"sed command {c!r} without its delimiter")
            delim = text[i + 1]
            j = _sed_until(text, i + 2, delim)
            j = _sed_until(text, j + 1, delim) + 1
            while j < n and text[j] not in ";\n}":
                flag = text[j]
                if flag == "e":
                    return True
                if flag == "w":
                    k = text.find("\n", j)
                    j = n if k < 0 else k
                    break
                if not (flag in "gpiImM" or flag.isdigit()):
                    if flag in " \t":
                        j += 1
                        continue
                    raise Unclassifiable(f"sed flag {flag!r} is not on the closed sed list")
                j += 1
            i = j
            continue
        raise Unclassifiable(f"sed command {c!r} is not on the closed sed list")
    return False


def _awk_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """awk: -f/-i/-E load a program file; the program text may not call system() or pipe."""
    program: str | None = None
    have = False
    i = 1
    while i < len(words):
        lit = words[i].lit
        if lit is None:
            if not have:
                return True
            i += 1
            continue
        if lit in ("-f", "--file", "-i", "--include", "-E", "--exec") or lit.startswith(("-f", "--file=")):
            return True
        if lit in ("-F", "-v", "--field-separator", "--assign"):
            i += 2
            continue
        if lit in ("-e", "--source"):
            program = words[i + 1].lit if i + 1 < len(words) else None
            if program is None:
                return True
            have = True
            i += 2
            continue
        if lit.startswith(("-F", "-v")) or lit == "--":
            i += 1
            continue
        if lit.startswith("-") and len(lit) > 1:
            raise Unclassifiable(f"awk option {lit!r} is not on the closed option list")
        if not have:
            program = lit
            have = True
        i += 1
    if program is not None:
        _awk_program(program)
    return False


def _awk_program(text: str) -> None:
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i = _sed_until(text, i + 1, '"') + 1
            continue
        if c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "|":
            if i + 1 < n and text[i + 1] == "|":
                i += 2
                continue
            raise Unclassifiable("awk program pipes to or from a command")
        if c == "@":
            raise Unclassifiable("awk program loads a source file")
        if c.isalpha() or c == "_":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            name = text[i:j]
            k = j
            while k < n and text[k] in " \t":
                k += 1
            if name == "system" and k < n and text[k] == "(":
                raise Unclassifiable("awk program calls system()")
            i = j
            continue
        i += 1


def _exec_options(tool: str, names: frozenset[str], shorts: str, detail: str = "runs a command"):
    """A command whose listed options run (or load) code; every other option is inert data."""

    def handler(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
        for pos, word in enumerate(words[1:], start=1):
            lit = word.lit
            if lit is None:
                continue
            if lit.startswith("--"):
                name = lit.split("=", 1)[0]
                if any(full.startswith(name) and len(name) > 4 for full in names if full.startswith("--")):
                    raise Unclassifiable(f"{tool} option {name!r} {detail}")
                continue
            if lit in names or any(lit.startswith(full) for full in names if not full.startswith("--")):
                exact = next(full for full in sorted(names, key=len, reverse=True) if lit.startswith(full))
                raise Unclassifiable(f"{tool} option {exact!r} {detail}")
            cluster = lit[1:] if lit.startswith("-") else (lit if pos == 1 and tool == "tar" else "")
            for ch in cluster:
                if ch in shorts:
                    raise Unclassifiable(f"{tool} option '-{ch}' {detail}")
        return False

    return handler


TAR_EXEC = frozenset({"--to-command", "--use-compress-program", "--checkpoint-action", "--info-script",
                      "--new-volume-script", "--rsh-command", "--rmt-command"})
RSYNC_EXEC = frozenset({"--rsh", "--rsync-path"})
SORT_EXEC = frozenset({"--compress-program"})
ZIP_EXEC = frozenset({"-TT", "--unzip-command"})
OPENSSL_LOAD = frozenset({"-engine", "-provider", "-provider-path", "-keyform"})
INSTALL_EXEC = frozenset({"--strip-program"})
PSQL_ARG = frozenset({"-h", "-p", "-U", "-d", "-v", "-P", "-L", "-T", "-F", "-R", "--host", "--port", "--username",
                      "--dbname", "--set", "--variable", "--pset", "--log-file", "--field-separator"})
PSQL_FLAG = frozenset({"-q", "-t", "-A", "-X", "-w", "-W", "-e", "-E", "-b", "-n", "-s", "-S", "-x", "-1", "-a",
                       "-z", "-0", "-H", "--quiet", "--tuples-only", "--no-align", "--no-psqlrc", "--no-password",
                       "--echo-all", "--echo-queries", "--echo-errors", "--single-transaction", "--expanded",
                       "--csv", "--html"})

# One-letter psql options with an argument the option loop reads itself.
PSQL_TAKES_ARG = frozenset({"-c", "-f", "-o"})

def _psql_sql(text: str) -> bool:
    if "\\" in text:
        raise Unclassifiable("psql meta-command in SQL text")
    if "program" in text.lower():
        raise Unclassifiable("psql SQL text runs a program")
    return False


def _psql_unbundle(lit: str | None) -> list[str | None]:
    """`-tAc` is `-t -A -c` (getopt): listed one-letter flags, then at most one letter that takes
    an argument, glued (`-cSQL`) or in the next word. Any other letter keeps the bundle whole,
    so the option check below refuses it."""
    if lit is None or lit.startswith("--") or len(lit) <= 2 or lit[0] != "-":
        return [lit]
    out: list[str | None] = []
    for pos, letter in enumerate(lit[1:], start=1):
        opt = "-" + letter
        if opt in PSQL_FLAG:
            out.append(opt)
            continue
        if opt in PSQL_ARG or opt in PSQL_TAKES_ARG:
            rest = lit[pos + 1:]
            return out + [opt] + ([rest] if rest else []) if out else [lit]
        return [lit]
    return out


def _psql_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """psql: -f runs a file; -c text and stdin text are checked (no meta-command, no PROGRAM)."""
    sql: list[str | None] = []
    lits: list[str | None] = []
    for word in words:
        lits.extend(_psql_unbundle(word.lit))
    i = 1
    while i < len(lits):
        lit = lits[i]
        if lit is None:
            i += 1
            continue
        name = lit.split("=", 1)[0] if lit.startswith("--") else lit
        if name in ("-f", "--file") or lit.startswith("-f"):
            return True
        if name in ("-c", "--command"):
            if "=" in lit:
                sql.append(lit.split("=", 1)[1])
                i += 1
            else:
                sql.append(lits[i + 1] if i + 1 < len(lits) else None)
                i += 2
            continue
        if name in ("-o", "--output"):
            target = lit.split("=", 1)[1] if "=" in lit else (lits[i + 1] if i + 1 < len(lits) else None)
            if target is None or target.startswith("|"):
                raise Unclassifiable("psql option '-o' runs a command")
            i += 1 if "=" in lit else 2
            continue
        if name in PSQL_ARG:
            i += 1 if "=" in lit else 2
            continue
        if name in PSQL_FLAG or (len(lit) > 2 and lit[:2] in PSQL_ARG):
            i += 1
            continue
        if lit.startswith("-"):
            raise Unclassifiable(f"psql option {lit!r} is not on the closed option list")
        i += 1
    if sql:
        return any(text is None or _psql_sql(text) for text in sql)
    return _stdin_code(cmd, _psql_sql)


def _sqlite_sql(text: str) -> bool:
    for line in text.split("\n"):
        if line.lstrip().startswith("."):
            raise Unclassifiable("sqlite3 dot-command in SQL text")
    if "load_extension" in text.lower():
        raise Unclassifiable("sqlite3 SQL text loads an extension")
    return False


def _sqlite_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """sqlite3: -init runs a file; SQL text after the database is checked; stdin code runs."""
    positional: list[str | None] = []
    i = 1
    while i < len(words):
        lit = words[i].lit
        if lit in ("-init", "--init"):
            return True
        if lit in ("-cmd", "--cmd"):
            text = words[i + 1].lit if i + 1 < len(words) else None
            if text is None or _sqlite_sql(text):
                return True
            i += 2
            continue
        if lit in ("-separator", "-newline", "-nullvalue"):
            i += 2
            continue
        if lit is not None and lit.startswith("-"):
            i += 1
            continue
        positional.append(lit)
        i += 1
    if len(positional) > 1:
        return any(text is None or _sqlite_sql(text) for text in positional[1:])
    return _stdin_code(cmd, _sqlite_sql)


def _find_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """find: -exec/-execdir/-ok/-okdir run their command; every other primary is inert."""
    pr = False
    i = 1
    n = len(words)
    while i < n:
        if words[i].lit in ("-exec", "-execdir", "-ok", "-okdir"):
            j = i + 1
            while j < n and words[j].lit not in (";", "+"):
                j += 1
            if j >= n or j == i + 1:
                raise Unclassifiable("find -exec without a command and its terminator")
            pr |= _dispatch(words[i + 1:j], _synthetic(words[i + 1:j]), ctx)
            i = j + 1
            continue
        i += 1
    return pr


XARGS_FLAGS = frozenset({"-0", "-r", "-t", "-x", "-p", "--null", "--no-run-if-empty", "--verbose", "--exit",
                         "--interactive", "--open-tty", "-o"})
XARGS_ARGS = frozenset({"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a", "--max-args", "--max-procs", "--delimiter",
                        "--max-lines", "--max-chars", "--arg-file", "--replace", "--eof"})


def _xargs_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    i = 1
    while i < len(words):
        lit = words[i].lit
        if lit is None:
            break
        if lit in XARGS_FLAGS:
            i += 1
        elif lit in XARGS_ARGS:
            i += 2
        elif lit.startswith("--") and lit.split("=", 1)[0] in XARGS_ARGS:
            i += 1
        elif len(lit) > 2 and lit[:2] in XARGS_ARGS:
            i += 1
        elif lit == "--":
            i += 1
            break
        elif lit.startswith("-") and len(lit) > 1:
            raise Unclassifiable(f"xargs option {lit!r} is not on the closed option list")
        else:
            break
    rest = words[i:]
    return _dispatch(rest, _synthetic(rest), ctx) if rest else False


def _wrapper(tool: str, flags: frozenset[str], args: frozenset[str], needs_command: bool = True,
             positional: int = 0):
    """A command that runs the rest of its words as a command after its own options."""

    def handler(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
        i = 1
        while i < len(words):
            lit = words[i].lit
            if lit is None:
                break
            if lit in flags:
                i += 1
                continue
            if lit in args:
                i += 2
                continue
            if lit.startswith("--") and lit.split("=", 1)[0] in args:
                i += 1
                continue
            if len(lit) > 2 and lit[:2] in args:
                i += 1
                continue
            if lit == "--":
                i += 1
                break
            if lit.startswith("-") and len(lit) > 1:
                if tool == "nice" and lit[1:].isdigit():
                    i += 1
                    continue
                raise Unclassifiable(f"{tool} option {lit!r} is not on the closed option list")
            break
        i += positional
        rest = words[i:]
        if not rest:
            if needs_command:
                raise Unclassifiable(f"{tool} without a command")
            return False
        return _dispatch(rest, cmd, ctx)

    return handler


def _env_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    """env: -S STRING is shell text; NAME=VALUE words are skipped; the rest is a command."""
    i = 1
    while i < len(words):
        word = words[i]
        lit = word.lit
        if lit in ("-i", "-0", "--null", "--ignore-environment", "-"):
            i += 1
            continue
        if lit in ("-u", "--unset", "-C", "--chdir"):
            i += 2
            continue
        if lit is not None and lit.startswith(("--unset=", "--chdir=")):
            i += 1
            continue
        if lit is not None and (lit.startswith("-S") or lit.startswith("--split-string")):
            code = lit[2:] if lit.startswith("-S") and len(lit) > 2 else (
                lit.split("=", 1)[1] if "=" in lit else (words[i + 1].lit if i + 1 < len(words) else None))
            return True if code is None else _shell_text(code, ctx)
        if lit == "--":
            i += 1
            break
        if word.assignment() is not None:
            i += 1
            continue
        if lit is not None and lit.startswith("-"):
            raise Unclassifiable(f"env option {lit!r} is not on the closed option list")
        break
    rest = words[i:]
    return _dispatch(rest, cmd, ctx) if rest else False


SUDO_FLAGS = frozenset({"-E", "-n", "-H", "-k", "-S", "-b", "-P", "--preserve-env", "--non-interactive"})
SUDO_ARGS = frozenset({"-u", "-g", "-C", "-p", "--user", "--group"})


def _sudo_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    i = 1
    while i < len(words):
        lit = words[i].lit
        if lit is None:
            break
        if lit in SUDO_FLAGS or lit.startswith("--preserve-env="):
            i += 1
            continue
        if lit in SUDO_ARGS:
            i += 2
            continue
        if lit.startswith(("--user=", "--group=")) or (len(lit) > 2 and lit[:2] in ("-u", "-g")):
            i += 1
            continue
        if lit == "--":
            i += 1
            break
        if lit.startswith("-"):
            raise Unclassifiable(f"sudo option {lit!r} is not on the closed option list")
        if words[i].assignment() is not None:
            i += 1
            continue
        break
    rest = words[i:]
    if not rest:
        raise Unclassifiable("sudo without a command")
    return _dispatch(rest, cmd, ctx)


def _flock_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    i = 1
    while i < len(words):
        lit = words[i].lit
        if lit in ("-s", "-x", "-e", "-n", "-u", "-o", "-F", "--shared", "--exclusive", "--nonblock", "--nb",
                   "--unlock", "--close", "--no-fork", "--verbose"):
            i += 1
            continue
        if lit in ("-w", "-E", "--timeout", "--wait", "--conflict-exit-code"):
            i += 2
            continue
        if lit is not None and lit.startswith("-") and not lit[1:].isdigit():
            raise Unclassifiable(f"flock option {lit!r} is not on the closed option list")
        break
    i += 1  # the lock file or descriptor
    if i < len(words) and words[i].lit in ("-c", "--command"):
        code = words[i + 1].lit if i + 1 < len(words) else None
        return True if code is None else _shell_text(code, ctx)
    rest = words[i:]
    return _dispatch(rest, cmd, ctx) if rest else False


def _trap_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    if len(words) < 2:
        return False
    code = words[1].lit
    if code is None:
        return True
    if code in ("-", "-p", "-l", "--"):
        return False
    return _shell_text(code, ctx)


def _command_cmd(words: list[_Word], cmd: _Cmd, ctx: _ShellCtx) -> bool:
    i = 1
    while i < len(words) and words[i].lit == "-p":
        i += 1
    if i < len(words) and words[i].lit in ("-v", "-V"):
        return False
    rest = words[i:]
    return _dispatch(rest, cmd, ctx) if rest else False


INERT_COMMANDS = frozenset({
    "echo", "printf", "cat", "tac", "grep", "egrep", "fgrep", "wc", "head", "tail", "cut", "tr", "uniq", "tee",
    "mkdir", "mktemp", "rm", "rmdir", "cp", "mv", "ln", "touch", "chmod", "chown", "chgrp", "ls", "basename",
    "dirname", "realpath", "readlink", "pwd", "cd", "pushd", "popd", "test", "[", "true", "false", ":", "exit",
    "return", "break", "continue", "shift", "set", "shopt", "ulimit", "umask", "wait", "sleep", "date", "seq",
    "expr", "printenv", "nproc", "getconf", "uname", "hostname", "whoami", "id", "groups", "df", "du", "free",
    "uptime", "stat", "file", "which", "type", "hash", "diff", "cmp", "comm", "paste", "join", "column", "fold",
    "fmt", "nl", "rev", "split", "numfmt", "truncate", "dd", "sha256sum", "sha1sum", "sha512sum", "md5sum",
    "cksum", "b2sum", "shasum", "base64", "base32", "od", "xxd", "hexdump", "strings", "gzip", "gunzip", "zcat",
    "xz", "unxz", "bzip2", "zstd", "unzip", "jq", "curl", "wget", "ps", "pgrep", "kill", "sync", "iconv",
    "envsubst", "tput", "logger", "getopts", "let", "times", "pg_isready", "lscpu", "lsblk", "nslookup", "ss",
    "sha224sum", "sha384sum",
})
PR_CODE_COMMANDS = frozenset({
    "make", "cargo", "rustc", "rustup", "rustfmt", "npm", "npx", "yarn", "pnpm", "deno", "bun", "go", "pip",
    "pip3", "pipx", "pytest", "tox", "nox", "poetry", "uv", "uvx", "maturin", "mvn", "gradle", "cmake", "ninja",
    "meson", "bazel", "just", "cc", "gcc", "g++", "clang", "clang++", "cross", "wasm-pack", "source", ".",
    "eval", "perl", "ruby", "php", "lua", "java", "dotnet", "swift", "xcodebuild",
})
# Commands that write the paths in their arguments: a base-bound path named there is unbound.
PATH_WRITERS = frozenset({"cp", "mv", "install", "tee", "ln", "touch", "dd", "rsync", "tar", "unzip", "chmod",
                          "sed", "patch", "truncate", "curl", "wget", "rm"})
COMMAND_HANDLERS = {name: _inert for name in INERT_COMMANDS}
COMMAND_HANDLERS.update({name: _pr_code for name in PR_CODE_COMMANDS})
COMMAND_HANDLERS.update({
    "node": _version_only,
    "bash": _shells, "sh": _shells, "dash": _shells,
    "git": _git_cmd, "gh": _gh_cmd, "docker": _docker_cmd,
    "sed": _sed_cmd, "awk": _awk_cmd, "gawk": _awk_cmd, "mawk": _awk_cmd,
    "tar": _exec_options("tar", TAR_EXEC, "IF"),
    "rsync": _exec_options("rsync", RSYNC_EXEC, "e"),
    "sort": _exec_options("sort", SORT_EXEC, ""),
    "zip": _exec_options("zip", ZIP_EXEC, ""),
    "openssl": _exec_options("openssl", OPENSSL_LOAD, "", "loads code"),
    "install": _exec_options("install", INSTALL_EXEC, ""),
    "psql": _psql_cmd, "sqlite3": _sqlite_cmd,
    "find": _find_cmd, "xargs": _xargs_cmd,
    "timeout": _wrapper("timeout", frozenset({"--preserve-status", "--foreground", "-v", "--verbose"}),
                        frozenset({"-s", "-k", "--signal", "--kill-after"}), positional=1),
    "nice": _wrapper("nice", frozenset(), frozenset({"-n", "--adjustment"}), needs_command=False),
    "nohup": _wrapper("nohup", frozenset(), frozenset()),
    "stdbuf": _wrapper("stdbuf", frozenset(), frozenset({"-i", "-o", "-e", "--input", "--output", "--error"})),
    "time": _wrapper("time", frozenset({"-p"}), frozenset(), needs_command=False),
    "exec": _wrapper("exec", frozenset({"-c", "-l"}), frozenset({"-a"}), needs_command=False),
    "setsid": _wrapper("setsid", frozenset({"-f", "-w", "-c", "--fork", "--wait", "--ctty"}), frozenset()),
    "ionice": _wrapper("ionice", frozenset({"-t"}), frozenset({"-c", "-n", "--class", "--classdata"})),
    "env": _env_cmd, "sudo": _sudo_cmd, "flock": _flock_cmd, "trap": _trap_cmd, "command": _command_cmd,
    "read": _binds, "unset": _binds, "export": _binds, "local": _binds, "declare": _binds, "typeset": _binds,
    "readonly": _binds, "mapfile": _binds, "readarray": _binds,
})


# ---------------------------------------------------------------------------------------
# Workflow analysis
# ---------------------------------------------------------------------------------------

EXPR_PLACEHOLDER = "GHA_EXPR"
DEFAULT_SHELLS = frozenset({"bash", "sh"})
TOKEN_SCOPES_WRITE = "write"
LOCAL_PREFIX = "./"
LOCAL_WORKFLOW_PREFIX = "./.github/workflows/"
WINDOWS_LABEL_WORD = "windows"
# I-1: the job and step keys whose meaning the classifier knows.
JOB_KEYS = frozenset({
    "name", "runs-on", "steps", "needs", "if", "timeout-minutes", "permissions", "outputs", "env", "strategy",
    "environment", "continue-on-error", "container", "services", "uses", "with", "secrets", "defaults",
    "concurrency",
})
STEP_KEYS = frozenset({
    "uses", "with", "name", "if", "run", "env", "timeout-minutes", "shell", "id", "continue-on-error",
    "working-directory",
})
COMPOSITE_MARK = "_composite"
MATRIX_ROW_KEYS = frozenset({"include", "exclude"})
# I-1: the expression vocabulary. A function, a context or a `github.` field outside these
# lists is Unclassifiable.
EXPR_FUNCTIONS = frozenset({
    "contains", "startsWith", "endsWith", "format", "join", "toJSON", "fromJSON", "hashFiles", "success",
    "always", "cancelled", "failure",
})
EXPR_CONTEXTS = frozenset({
    "github", "env", "secrets", "vars", "inputs", "matrix", "steps", "job", "runner", "needs", "strategy",
})
EXPR_LITERALS = frozenset({"true", "false", "null"})
EXPR_OPERATOR_CHARS = frozenset("()!=<>&|,")
EXPR_NUMBER_CHARS = frozenset("0123456789abcdefABCDEFxX.+-")
GITHUB_FIELDS = frozenset({
    "actor", "base_ref", "event", "event_name", "ref", "ref_name", "ref_type", "repository", "repository_owner",
    "repository_id", "run_attempt", "run_id", "run_number", "sha", "token", "workflow", "head_ref", "server_url",
    "api_url", "workspace", "job", "action_path", "triggering_actor",
})
# Event fields that hold no free text: a sha, a number, a closed word or a name of a closed
# character set. Every other event field is text the event author controls.
SAFE_EVENT_FIELDS = frozenset({
    "pull_request.base.sha", "pull_request.head.sha", "pull_request.number", "pull_request.author_association",
    "merge_group.base_sha", "merge_group.head_sha", "before", "action", "pull_request.user.login",
    "pull_request.head.repo.full_name",
})
SAFE_EVENT_PREFIXES = ("inputs.",)
EVENT_TEXT_FIELDS = frozenset({"head_ref"})
# Environment values that name the base commit of a pull request, by the events where the
# value is proven non-empty.
BASE_REF_EXPRS = {
    "${{ github.event.pull_request.base.sha }}": frozenset({"pull_request", "pull_request_target"}),
    "${{ github.event.merge_group.base_sha }}": frozenset({"merge_group"}),
}
# Names the shell scanner gives a fixed meaning; an env value that redefines one shadows it.
SCANNER_NAMES = frozenset({"RUNNER_TEMP", "GITHUB_WORKSPACE", "GITHUB_ACTION_PATH"}) | RUNNER_FILE_VARS
# The verdict of a job or workflow the classifier cannot read: a finding, never clean.
UNCLASSIFIABLE = "unclassifiable"
EARLY_SECRET_DETAIL = "secret held before pull-request code ran can persist into it"
CONTAINER_DETAIL = "container or service holds a secret for a tainted job"
# Host-resident credentials (ruling 04701c74), matched by a linear token scan.
HOME_PREFIXES = ("$home/.", "${home}/.", "~/.")
CREDENTIAL_STORES = ("pgpass", "netrc", "git-credentials", "ssh", "aws", "kube", "gnupg", "docker/config.json",
                     "config/gh", "config/copr", "config/git/credentials")
CREDENTIAL_WORDS = ("url", "pass", "token", "secret", "cred", "key", "auth")
CONTAINER_SOCKET = "/var/run/docker.sock"
DB_SUPERUSER = "postgres"
WORD_LEAD_PUNCT = "(;&|`$\"'"
WORD_TRAIL_PUNCT = ")\"';&|`"


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


def _joined(text: str, mark: str) -> str:
    literals, bodies = _split_expressions(text)
    if len(bodies) >= len(literals):
        raise Unclassifiable("unterminated `${{` expression")
    return mark.join(literals)


def _expr_free(text: str) -> str:
    return _joined(text, EXPR_PLACEHOLDER)


def _has_secret_ref(text: str) -> bool:
    return any(SECRET_REF_RE.search(body) for body in _split_expressions(text)[1])


def _is_ident_char(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch in "_-")


def _expr_quoted(body: str, i: int) -> tuple[str, int]:
    """A single-quoted expression string from ``i`` (the quote): its value and the end index."""
    out: list[str] = []
    j = i + 1
    while True:
        k = body.find("'", j)
        if k < 0:
            raise Unclassifiable("unterminated string in an expression")
        out.append(body[j:k])
        if body[k + 1:k + 2] == "'":
            out.append("'")
            j = k + 2
            continue
        return "".join(out), k + 1


def _expression_refs(body: str) -> tuple[list[tuple[str, ...]], set[str]]:
    """Every context path and every function of one ``${{ }}`` body, in one linear pass.

    A path is a tuple of its parts (``*`` for a wildcard). A form outside the closed
    expression grammar is Unclassifiable.
    """
    paths: list[tuple[str, ...]] = []
    funcs: set[str] = set()
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch.isspace() or ch in EXPR_OPERATOR_CHARS:
            i += 1
            continue
        if ch == "'":
            _, i = _expr_quoted(body, i)
            continue
        if ch.isdigit() or (ch == "-" and body[i + 1:i + 2].isdigit()):
            i += 1
            while i < n and body[i] in EXPR_NUMBER_CHARS:
                i += 1
            continue
        if not (ch.isascii() and (ch.isalpha() or ch == "_")):
            raise Unclassifiable(f"expression character {ch!r} is not on the closed list")
        j = i
        while j < n and _is_ident_char(body[j]):
            j += 1
        ident = body[i:j]
        k = j
        while k < n and body[k] == " ":
            k += 1
        if k < n and body[k] == "(":
            if ident not in EXPR_FUNCTIONS:
                raise Unclassifiable(f"expression function {ident!r} is not on the closed function list")
            funcs.add(ident)
            i = k
            continue
        if ident in EXPR_LITERALS:
            i = j
            continue
        parts = [ident]
        while j < n:
            if body[j] == ".":
                j += 1
                if j < n and body[j] == "*":
                    parts.append("*")
                    j += 1
                    continue
                start = j
                while j < n and _is_ident_char(body[j]):
                    j += 1
                if start == j:
                    raise Unclassifiable("expression path ends in a bare `.`")
                parts.append(body[start:j])
                continue
            if body[j] == "[":
                j += 1
                while j < n and body[j] == " ":
                    j += 1
                if j < n and body[j] == "'":
                    value, j = _expr_quoted(body, j)
                elif j < n and body[j] == "*":
                    value, j = "*", j + 1
                else:
                    raise Unclassifiable("expression index is not a quoted name")
                while j < n and body[j] == " ":
                    j += 1
                if j >= n or body[j] != "]":
                    raise Unclassifiable("expression index is not closed")
                parts.append(value)
                j += 1
                continue
            break
        _check_context(parts)
        paths.append(tuple(parts))
        i = j
    return paths, funcs


def _check_context(parts: list[str]) -> None:
    if parts[0] not in EXPR_CONTEXTS:
        raise Unclassifiable(f"expression context {parts[0]!r} is not on the closed context list")
    if parts[0] == "github" and len(parts) > 1 and parts[1] not in GITHUB_FIELDS:
        raise Unclassifiable(f"expression context {'github.' + parts[1]!r} is not on the closed context list")


def _expression_contexts(body: str) -> list[str]:
    """The context paths of one expression body, dotted (I-1, linear)."""
    return [".".join(path) for path in _expression_refs(body)[0]]


def _text_refs(text: str) -> tuple[list[tuple[str, ...]], set[str]]:
    paths: list[tuple[str, ...]] = []
    funcs: set[str] = set()
    for body in _split_expressions(text)[1]:
        got, used = _expression_refs(body)
        paths.extend(got)
        funcs |= used
    return paths, funcs


def _is_event_text(path: tuple[str, ...]) -> bool:
    """A path whose value is free text the event author controls (or the whole event)."""
    if path[0] != "github":
        return False
    if len(path) == 1:
        return True
    if path[1] in EVENT_TEXT_FIELDS:
        return True
    if path[1] != "event":
        return False
    if len(path) == 2:
        return True
    rest = ".".join(path[2:])
    return rest not in SAFE_EVENT_FIELDS and not rest.startswith(SAFE_EVENT_PREFIXES)


def _strings(value: object) -> list[str]:
    """Every string inside a parsed YAML value (keys of mappings included)."""
    out: list[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            for key, val in item.items():
                out.append(str(key))
                stack.append(val)
        elif isinstance(item, list):
            stack.extend(item)
    return out


def _if_text(cond: object) -> str:
    """An `if:` value as expression text: a bare condition is one expression."""
    if not isinstance(cond, str):
        return ""
    return cond if EXPR_OPEN in cond else EXPR_OPEN + cond + EXPR_CLOSE


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
    if not events:
        raise Unclassifiable(f"{label}: `on:` names no trigger")
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
    if "permissions" not in job and "permissions" not in doc:
        raise Unclassifiable(f"{label}: no `permissions:` at job or workflow level (default token scope unknown)")
    perms = job["permissions"] if "permissions" in job else doc["permissions"]
    if perms is None:
        raise Unclassifiable(f"{label}: `permissions:` is null")
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


def _check_matrix(job: dict[str, object], label: str) -> None:
    """I-1: a matrix is a mapping of literal lists; an expression anywhere is Unclassifiable."""
    strategy = job.get("strategy")
    if strategy is None:
        return
    if not isinstance(strategy, dict):
        raise Unclassifiable(f"{label}: strategy is not a mapping")
    matrix = strategy.get("matrix")
    if matrix is None:
        return
    if isinstance(matrix, str) and EXPR_OPEN in matrix:
        raise Unclassifiable(f"{label}: matrix is an expression")
    if not isinstance(matrix, dict):
        raise Unclassifiable(f"{label}: matrix is not a mapping")
    for axis, values in matrix.items():
        if axis in MATRIX_ROW_KEYS:
            if isinstance(values, str) and EXPR_OPEN in values:
                raise Unclassifiable(f"{label}: matrix {axis} holds an expression")
            if not isinstance(values, list) or not all(isinstance(row, dict) for row in values):
                raise Unclassifiable(f"{label}: matrix {axis} is not a list of mappings")
            if any(EXPR_OPEN in text for text in _strings(values)):
                raise Unclassifiable(f"{label}: matrix {axis} holds an expression")
            continue
        if isinstance(values, str) and EXPR_OPEN in values:
            raise Unclassifiable(f"{label}: matrix axis {axis!r} is an expression")
        if not isinstance(values, list):
            raise Unclassifiable(f"{label}: matrix axis {axis!r} is not a list")
        if any(EXPR_OPEN in text for text in _strings(values)):
            raise Unclassifiable(f"{label}: matrix axis {axis!r} is an expression")


def _check_job_form(job: dict[str, object], label: str) -> None:
    for key in job:
        if key not in JOB_KEYS:
            raise Unclassifiable(f"{label}: job key {key!r} is not on the closed list")
    _check_matrix(job, label)


def _matrix_axis(raw: str) -> tuple[str, bool] | None:
    """`${{ matrix.<axis> }}` or `${{ fromJSON(matrix.<axis>) }}`: the axis and the fromJSON flag."""
    text = raw.strip()
    if not (text.startswith(EXPR_OPEN) and text.endswith(EXPR_CLOSE)) or text.count(EXPR_OPEN) != 1:
        return None
    body = text[len(EXPR_OPEN):-len(EXPR_CLOSE)].strip()
    from_json = body.startswith("fromJSON(") and body.endswith(")")
    if from_json:
        body = body[len("fromJSON("):-1].strip()
    if not body.startswith("matrix."):
        return None
    axis = body[len("matrix."):]
    if not axis or not all(_is_ident_char(ch) for ch in axis):
        return None
    return axis, from_json


def _runs_on_legs(job: dict[str, object], label: str) -> list[tuple[str, ...]]:
    raw = job.get("runs-on")
    matrix = (job.get("strategy") or {}).get("matrix") if isinstance(job.get("strategy"), dict) else None

    def checked(labels: tuple[str, ...]) -> tuple[str, ...]:
        for lab in labels:
            if not lab.strip():
                raise Unclassifiable(f"{label}: empty runs-on label")
            try:
                _expr_free(lab)
            except Unclassifiable as exc:
                raise Unclassifiable(f"{label}: runs-on {exc}") from exc
        return labels

    def as_labels(value: object) -> tuple[str, ...]:
        if isinstance(value, str):
            return checked((value,))
        if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
            return checked(tuple(value))
        if isinstance(value, dict):
            labels, group = value.get("labels"), value.get("group")
            if group is not None and not (isinstance(group, str) and group.strip()):
                raise Unclassifiable(f"{label}: runs-on group {group!r} outside the known forms")
            # A runner group is never provably GitHub-hosted: its name stays in the leg.
            group_leg = ("group:" + group,) if isinstance(group, str) else ()
            if labels is None and group_leg:
                return group_leg
            return as_labels(labels) + group_leg
        raise Unclassifiable(f"{label}: runs-on value {value!r} outside the known forms")

    if isinstance(raw, str):
        found = _matrix_axis(raw)
        if found is not None:
            axis, from_json = found
            if not isinstance(matrix, dict):
                raise Unclassifiable(f"{label}: runs-on names a matrix axis but the matrix is not a mapping")
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
                if from_json:
                    if not isinstance(v, str):
                        raise Unclassifiable(f"{label}: fromJSON matrix value is not a string")
                    try:
                        v = json.loads(v)
                    except ValueError as exc:
                        raise Unclassifiable(f"{label}: fromJSON matrix value is not JSON") from exc
                legs.append(as_labels(v))
            return legs
        # Any other expression (an input, a variable, an event field) can name any runner:
        # it is one opaque leg, never hosted, so R2 treats it as persistent.
    if raw is None:
        raise Unclassifiable(f"{label}: job without runs-on")
    return [as_labels(raw)]


def _leg_hosted(leg: tuple[str, ...]) -> bool:
    """True only when every label of the leg is a GitHub-hosted image label."""
    # fullmatch: `$` alone also matches before a trailing line break.
    hosted = [lab for lab in leg if GITHUB_HOSTED_LABEL_RE.fullmatch(lab)]
    return bool(hosted) and len(hosted) == len(leg)


def _r2_trusted(legs: list[tuple[str, ...]], job_events: set[str]) -> list[str]:
    """R2: the trusted triggers of a job that can run on a runner not provably hosted."""
    if all(_leg_hosted(leg) for leg in legs):
        return []
    return sorted(job_events & R2_TRUSTED_EVENTS)


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
                # The mark holds the directory of the innermost composite action of the step.
                item.body = dict(item.body, **{COMPOSITE_MARK: item.body.get(COMPOSITE_MARK) or path})
                item.index = len(out)
                out.append(item)
    return out


def _dump(value: object) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _shell_holder(job: dict[str, object], doc: dict[str, object]) -> list[dict[str, object]]:
    holders: list[dict[str, object]] = []
    for owner in (job, doc):
        defaults = owner.get("defaults")
        run = defaults.get("run") if isinstance(defaults, dict) else None
        if isinstance(run, dict):
            holders.append(run)
    return holders


def _check_shell(step: _Step, job: dict[str, object], doc: dict[str, object], windows: bool) -> None:
    """I-1: a run step runs under bash or sh, named or by the default of a Linux or macOS leg."""
    if "run" not in step.body:
        return
    for holder in [step.body] + _shell_holder(job, doc):
        if "shell" not in holder:
            continue
        value = holder["shell"]
        if not isinstance(value, str) or not value.strip():
            raise Unclassifiable("`shell:` is empty")
        first = value.split()[0]
        if first.rsplit("/", 1)[-1] not in DEFAULT_SHELLS:
            raise Unclassifiable(f"shell {first!r} is not on the closed shell list")
        return
    if windows:
        raise Unclassifiable("the default shell of a Windows leg is pwsh, which is not on the closed shell list")


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


def _bare_word(word: str) -> str:
    return word.lstrip(WORD_LEAD_PUNCT).rstrip(WORD_TRAIL_PUNCT)


def _is_program(word: str, name: str) -> bool:
    bare = _bare_word(word)
    return bare == name or bare.endswith("/" + name)


def _names_superuser(word: str) -> bool:
    return _bare_word(word) == DB_SUPERUSER


def _home_credential(text: str) -> bool:
    """A home-directory dot path naming a credential store or a credential word (linear)."""
    for prefix in HOME_PREFIXES:
        pos = 0
        while True:
            k = text.find(prefix, pos)
            if k < 0:
                break
            start = k + len(prefix)
            for store in CREDENTIAL_STORES:
                end = start + len(store)
                if text.startswith(store, start) and (end >= len(text) or not _is_ident_char(text[end])
                                                      or text[end] == "-"):
                    return True
            end = start
            while end < len(text) and (_is_ident_char(text[end]) or text[end] == "."):
                end += 1
            name = text[start:end]
            if any(word in name for word in CREDENTIAL_WORDS):
                return True
            pos = max(end, k + 1)
    return False


def _sudo_superuser(words: list[str]) -> bool:
    for i, word in enumerate(words):
        if not _is_program(word, "sudo"):
            continue
        j = i + 1
        while j < len(words) and words[j].startswith("-"):
            opt = words[j]
            if opt in ("-u", "--user") and j + 1 < len(words) and _names_superuser(words[j + 1]):
                return True
            if opt in ("-u" + DB_SUPERUSER, "--user=" + DB_SUPERUSER):
                return True
            j += 1
    return False


def _psql_superuser(words: list[str]) -> bool:
    start = next((i for i, word in enumerate(words) if _is_program(word, "psql")), None)
    if start is None:
        return False
    for j in range(start + 1, len(words)):
        opt = words[j]
        if opt in ("-U", "--username") and j + 1 < len(words) and _names_superuser(words[j + 1]):
            return True
        if opt in ("-U" + DB_SUPERUSER, "--username=" + DB_SUPERUSER):
            return True
    return False


def _host_credential_in(step: dict[str, object]) -> bool:
    """A credential resident on a self-hosted host named by the step (ruling 04701c74).

    Linear token scan over the step's run, with and env text: a home-directory dot path of a
    credential store or credential word, the container socket, a database superuser by sudo
    or psql. Limits: a path assembled from variables, a credential in the runner service's own
    environment and an absolute home path are not seen; the runner boundary of #9455 is the
    structural answer for those.
    """
    for raw in _strings([step.get("env"), step.get("with"), step.get("run")]):
        text = raw.lower()
        if CONTAINER_SOCKET in text or _home_credential(text):
            return True
        for line in raw.split("\n"):
            words = line.split()
            if _sudo_superuser(words) or _psql_superuser(words):
                return True
    return False


def _env_names(*holders: object) -> set[str]:
    names: set[str] = set()
    for holder in holders:
        if isinstance(holder, dict):
            names.update(str(k) for k in holder)
    return names


def _merged_env(*holders: object) -> dict[str, object]:
    merged: dict[str, object] = {}
    for holder in holders:
        if isinstance(holder, dict):
            merged.update({str(k): v for k, v in holder.items()})
    return merged


def _shell_ctx(env: dict[str, object], job_events: set[str], strict: bool,
               composite: object = None) -> _ShellCtx:
    """The facts a step starts with: base-ref env values and the scanner names env shadows."""
    base: dict[str, int] = {}
    for name, value in env.items():
        if not isinstance(value, str) or not NAME_RE.fullmatch(name):
            continue
        events = BASE_REF_EXPRS.get(value.strip())
        if events is not None:
            base[name] = STRICT_BASE if job_events and job_events <= events else MAYBE_EMPTY_BASE
    shadowed = frozenset(name for name in env if name in SCANNER_NAMES)
    action_dir = f"{WS}/{composite}" if isinstance(composite, str) and composite else None
    return _ShellCtx(strict=strict, base=base, shadowed=shadowed, action_dir=action_dir)


@dataclass
class _StepFacts:
    runs_pr_code: bool = False
    event_text: bool = False
    tree_change: bool = False
    pr_fetch: bool = False


def _analyse_step(step: _Step, job: dict[str, object], doc: dict[str, object], job_events: set[str],
                  windows: bool, strict: bool) -> _StepFacts:
    """Classify one step on its own (I-2): every form on a closed list, or Unclassifiable."""
    body = step.body
    for key in body:
        if key not in STEP_KEYS and key != COMPOSITE_MARK:
            raise Unclassifiable(f"step key {key!r} is not on the closed list")
    _check_shell(step, job, doc, windows)
    facts = _StepFacts()
    for part in (body.get("env"), body.get("with")):
        for text in _strings(part):
            _text_refs(text)
    _text_refs(_if_text(body.get("if")))
    env = _merged_env(doc.get("env"), job.get("env"), body.get("env"))
    uses = body.get("uses")
    if isinstance(uses, str):
        if uses.startswith(LOCAL_PREFIX):
            facts.runs_pr_code = True
            return facts
        name = _action_name(uses)
        known = KNOWN_ACTIONS.get(name)
        if known is None:
            raise Unclassifiable(f"unknown action {name!r}")
        with_ = body.get("with") if isinstance(body.get("with"), dict) else {}
        if known.script_input and with_.get(known.script_input) is not None:
            script = str(with_[known.script_input])
            facts.event_text = any(_is_event_text(p) for p in _text_refs(script)[0])
            ctx = _shell_ctx(env, job_events, strict, body.get(COMPOSITE_MARK))
            facts.runs_pr_code = _shell_runs_pr_code(_joined(script, MARK), ctx)
            facts.tree_change, facts.pr_fetch = ctx.tree_change, ctx.pr_fetch
            return facts
        if known.pr_code:
            facts.runs_pr_code = not known.pr_code_unless or \
                not all(str(with_.get(k)) == v for k, v in known.pr_code_unless)
        return facts
    run = body.get("run")
    if not isinstance(run, str):
        raise Unclassifiable("run is not text")
    paths, _ = _text_refs(run)
    declared = _env_names(doc.get("env"), job.get("env"), body.get("env"))
    for path in paths:
        if path[0] == "env" and (len(path) < 2 or path[1] not in declared):
            shown = ".".join(path)
            raise Unclassifiable(f"expression `{shown}` names no env value declared in the workflow")
    facts.event_text = any(_is_event_text(p) for p in paths)
    ctx = _shell_ctx(env, job_events, strict, body.get(COMPOSITE_MARK))
    facts.runs_pr_code = _shell_runs_pr_code(_joined(run, MARK), ctx)
    facts.tree_change, facts.pr_fetch = ctx.tree_change, ctx.pr_fetch
    return facts


def _pre_scan_fetch(steps: list[_Step], job: dict[str, object], doc: dict[str, object]) -> bool:
    """A job with no pull-request trigger: does any run step fetch a pull-request tree?"""
    env_job = (doc.get("env"), job.get("env"))
    for step in steps:
        run = step.body.get("run")
        if not isinstance(run, str):
            continue
        ctx = _shell_ctx(_merged_env(*env_job, step.body.get("env")), set(), strict=False,
                         composite=step.body.get(COMPOSITE_MARK))
        try:
            _shell_runs_pr_code(_joined(run, MARK), ctx)
        except Unclassifiable:
            pass
        if ctx.pr_fetch:
            return True
    return False


def _check_labels(steps: list[_Step], label: str) -> None:
    """I-3: an allow row names one step, so two steps of a job never share a label."""
    seen: set[str] = set()
    for step in steps:
        if step.label in seen:
            raise Unclassifiable(f"{label}: two steps share the label {step.label!r}")
        seen.add(step.label)


def _windows_job(legs: list[tuple[str, ...]]) -> bool:
    return any(WINDOWS_LABEL_WORD in lab.lower() for leg in legs for lab in leg)


def _analyse_job(wf: str, job_id: str, job: dict[str, object], doc: dict[str, object], events: set[str],
                 actions: dict[str, str], downloads: bool, result: ScanResult) -> str:
    label = f"{wf}/{job_id}"
    _check_job_form(job, label)
    job_events = _job_events(job, events)
    # R2 holds for every job, trusted-only and base-tree jobs included; the runs-on form is
    # parsed first so an unknown form is a failure whatever the triggers.
    legs = _runs_on_legs(job, label)
    r2_events = _r2_trusted(legs, job_events)
    r2 = Violation(wf, job_id, R2_STEP_LABEL, CLASS_PERSISTENT_STATE,
                   R2_DETAIL.format(events=", ".join(r2_events))) if r2_events else None
    steps = _flatten_steps(job.get("steps"), actions, label)
    _check_labels(steps, label)
    strict = bool(job_events & (PR_EVENTS | {CALL_EVENT}))
    if not strict and not _pre_scan_fetch(steps, job, doc):
        if r2 is None:
            return "trusted-only"
        result.violations.append(r2)
        return CLASS_PERSISTENT_STATE
    perms = _permissions(job, doc, label)
    windows = _windows_job(legs)
    pr_tree = False
    taint: _Step | None = None
    leaky_checkouts: list[_Step] = []
    for step in steps:
        body = step.body
        try:
            facts = _analyse_step(step, job, doc, job_events, windows, strict)
        except Unclassifiable as exc:
            raise Unclassifiable(f"{label}: step {step.label!r}: {exc}") from exc
        uses = body.get("uses")
        if isinstance(uses, str) and _action_name(uses) == CHECKOUT_ACTION:
            if _checkout_tree(body, job_events) == "pr":
                pr_tree = True
            with_ = body.get("with") if isinstance(body.get("with"), dict) else {}
            if with_.get("persist-credentials") is not False:
                leaky_checkouts.append(step)
            continue
        if taint is None:
            event_text = facts.event_text and bool(job_events & (PR_EVENTS | {CALL_EVENT}))
            env_write = ENV_FILE_WRITE_RE.search(_dump([body.get("run"), body.get("with")])) is not None
            if event_text or (pr_tree and (env_write or facts.runs_pr_code)):
                taint = step
        if facts.pr_fetch or (facts.tree_change and job_events & PR_EVENTS):
            pr_tree = True
    if taint is None:
        if r2 is None:
            return "no-pr-code"
        result.violations.append(r2)
        return CLASS_PERSISTENT_STATE
    result.taint_steps[(wf, job_id)] = taint.label
    after = [s for s in steps if s.index >= taint.index]
    found: list[Violation] = [r2] if r2 is not None else []

    def add(step: _Step, klass: str, detail: str) -> None:
        v = Violation(wf, job_id, step.label, klass, detail)
        if v not in found:
            found.append(v)

    def holds_token(step: _Step) -> bool:
        uses = step.body.get("uses")
        default_token = isinstance(uses, str) and not uses.startswith(LOCAL_PREFIX) and \
            KNOWN_ACTIONS.get(_action_name(uses), ActionFacts()).default_token
        return _secret_in(step.body) or default_token

    # (i) a secret held by any carrier at, before or after the taint point.
    if _has_secret_ref(_dump([job.get("env"), doc.get("env")])):
        add(taint, CLASS_SECRET, "job or workflow env holds a secret for a tainted job")
    if _has_secret_ref(_dump([job.get("container"), job.get("services")])):
        add(taint, CLASS_SECRET, CONTAINER_DETAIL)
    for step in steps:
        if step.index >= taint.index:
            break
        if holds_token(step):
            add(step, CLASS_SECRET, EARLY_SECRET_DETAIL)
    for step in leaky_checkouts:
        add(step, CLASS_SECRET, "checkout keeps the token in the workspace for later pull-request code")
    token_users: list[_Step] = []
    host_resident = not all(_leg_hosted(leg) for leg in legs)
    for step in after:
        uses = step.body.get("uses")
        # A checkout after the taint point hands its token to git inside a workspace that
        # pull-request code has already run in, whatever `persist-credentials` says.
        late_checkout = step is not taint and isinstance(uses, str) and _action_name(uses) == CHECKOUT_ACTION
        if holds_token(step) or late_checkout:
            add(step, CLASS_SECRET, "secret or token used after pull-request code ran")
            token_users.append(step)
        # A GitHub-hosted VM is fresh per job and holds no resident credential; any other
        # leg is a host that may.
        if host_resident and _host_credential_in(step.body):
            add(step, CLASS_SECRET, HOST_CREDENTIAL_DETAIL)
    # (ii) a write token in a tainted job.
    if _has_write(perms):
        add(token_users[0] if token_users else taint, CLASS_WRITE_TOKEN, "job token has a write scope")
    # (iii) a job output fed by anything at or after the taint point.
    outputs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
    by_id = {s.body.get("id"): s for s in steps if isinstance(s.body.get("id"), str) and " > " not in s.label}
    for value in outputs.values():
        paths, funcs = _text_refs(str(value))
        if "hashFiles" in funcs:
            add(taint, CLASS_GATE_OUTPUT, "job output hashes the workspace of a tainted job")
        for path in paths:
            if path[0] == "steps":
                if len(path) < 2 or path[1] == "*":
                    add(taint, CLASS_GATE_OUTPUT, "job output reads every step of a tainted job")
                    continue
                ref = by_id.get(path[1])
                if ref is None:
                    raise Unclassifiable(f"{label}: output names unknown step {path[1]!r}")
                if ref.index >= taint.index:
                    add(ref, CLASS_GATE_OUTPUT, "job output set at or after pull-request code ran")
            elif path[0] == "env":
                add(taint, CLASS_GATE_OUTPUT, "job output read from the environment of a tainted job")
            elif path[0] == "job":
                add(taint, CLASS_GATE_OUTPUT, "job output reads the state of a tainted job")
    # (iv) persistent state a trusted run later reads: R2 (added above) and artifacts.
    if downloads:
        for step in after:
            uses = step.body.get("uses")
            if isinstance(uses, str) and _action_name(uses) == UPLOAD_ACTION:
                add(step, CLASS_PERSISTENT_STATE, "artifact uploaded after pull-request code ran")
    result.violations.extend(found)
    return ",".join(sorted({v.klass for v in found}, key=CLASSES.index)) if found else "clean"


def _local_workflow(uses: str, workflows: dict[str, str]) -> str | None:
    """`./.github/workflows/<file>` naming a workflow of this repository, else None."""
    if not uses.startswith(LOCAL_WORKFLOW_PREFIX):
        return None
    name = uses[len(LOCAL_WORKFLOW_PREFIX):]
    if not name or "/" in name or "@" in name or not name.endswith(WORKFLOW_SUFFIXES):
        return None
    return name if name in workflows else None


def _has_caller(name: str, workflows: dict[str, str]) -> bool:
    ref = LOCAL_WORKFLOW_PREFIX + name
    return any(ref in text for other, text in workflows.items() if other != name)


def _analyse_workflow(name: str, text: str, workflows: dict[str, str], actions: dict[str, str],
                      downloads: bool, result: ScanResult,
                      caller_events: set[str] | None = None, prefix: str = "", depth: int = 0) -> None:
    if depth > MAX_INDIRECTION_DEPTH:
        raise Unclassifiable(f"{name}: reusable workflow nesting deeper than {MAX_INDIRECTION_DEPTH}")
    doc = parse_yaml(text, name)
    if not isinstance(doc, dict):
        raise Unclassifiable(f"{name}: top level is not a mapping")
    events = _workflow_events(doc, name)
    if caller_events is not None:
        events = set(caller_events)
    elif events == {CALL_EVENT} and not _has_caller(name, workflows):
        raise Unclassifiable(f"{name}: workflow_call-only workflow has no caller in this repository")
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
                _check_job_form(job, f"{name}/{job_id}")
                target = _local_workflow(uses, workflows)
                if target is None:
                    raise Unclassifiable(f"{name}/{job_id}: reusable workflow {uses!r} not found in this repository")
                inner_prefix = f"{key[0]}/{key[1]} > "
                _analyse_workflow(target, workflows[target], workflows, actions, downloads,
                                  result, _job_events(job, events), inner_prefix, depth + 1)
                result.verdicts[key] = "reusable"
                continue
            result.verdicts[key] = _analyse_job(key[0], key[1], job, doc, events, actions, downloads, result)
        except Unclassifiable as exc:
            result.unclassifiable.append(str(exc))
            result.verdicts[key] = UNCLASSIFIABLE


def scan_texts(workflows: dict[str, str], actions: dict[str, str] | None = None,
               repo_files: frozenset[str] | set[str] | None = None) -> ScanResult:
    """Classify every job of every workflow given as text (name -> YAML); actions: dir -> YAML.

    ``repo_files`` is accepted for the callers and decides no verdict: R2 reads the workflow
    files only (ruling 8b8cede8).
    """
    actions = actions or {}
    del repo_files
    result = ScanResult()
    downloads = any(marker in text for text in workflows.values() for marker in DOWNLOAD_MARKERS)
    for name in sorted(workflows):
        try:
            _analyse_workflow(name, workflows[name], workflows, actions, downloads, result)
        except Unclassifiable as exc:
            result.unclassifiable.append(str(exc))
            result.verdicts[(name, "*")] = UNCLASSIFIABLE
    return result


class _FsPath:
    """A real path for the loader: lstat-based checks and a bounded, no-follow read."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self.name = path.name
        self.suffix = path.suffix

    def is_symlink(self) -> bool:
        return self._path.is_symlink()

    def is_file(self) -> bool:
        return self._path.is_file()

    def lstat(self) -> os.stat_result:
        return self._path.lstat()

    def read_bytes_bounded(self, limit: int) -> bytes:
        # O_NOFOLLOW and the fstat check close the window between the checks and the read.
        fd = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("not a regular file")
            chunks: list[bytes] = []
            left = limit
            while left > 0:
                chunk = os.read(fd, min(left, READ_CHUNK_BYTES))
                if not chunk:
                    break
                chunks.append(chunk)
                left -= len(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)


def _refused(reason: str) -> str:
    return REFUSED_MARKER + reason


def _load_one(path: object, workflow: bool) -> str:
    """The text of one workflow or action file, or a refusal the parser reports with its reason."""
    if path.is_symlink():
        return _refused("is a symbolic link")
    if not path.is_file():
        return _refused("is not a regular file")
    if workflow and path.suffix not in WORKFLOW_SUFFIXES:
        return _refused(f"workflow suffix {path.suffix!r} is not on the closed suffix list")
    if path.lstat().st_size > MAX_YAML_BYTES:
        return _refused(f"larger than {MAX_YAML_BYTES} bytes")
    try:
        data = path.read_bytes_bounded(MAX_YAML_BYTES + 1)
    except OSError:
        return _refused("cannot be read as a regular file")
    if len(data) > MAX_YAML_BYTES:
        return _refused(f"larger than {MAX_YAML_BYTES} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return _refused("not UTF-8")


def _load_dir(repo_root: Path | None) -> tuple[dict[str, str], dict[str, str], frozenset[str]]:
    """Read every workflow and local action of a checkout into memory; a refusal is kept, never skipped."""
    wf_dir = repo_root / WORKFLOW_DIR if repo_root is not None else None
    if wf_dir is None or wf_dir.is_symlink() or not wf_dir.is_dir():
        return {WORKFLOW_DIR: _refused(f"no {WORKFLOW_DIR} directory")}, {}, frozenset()
    workflows = {path.name: _load_one(_FsPath(path), workflow=True) for path in sorted(wf_dir.iterdir())}
    actions: dict[str, str] = {}
    gh_dir = repo_root / ".github"
    for path in sorted(gh_dir.rglob("*")):
        if path.name in ACTION_FILE_NAMES:
            actions[path.parent.relative_to(repo_root).as_posix()] = _load_one(_FsPath(path), workflow=False)
    files = frozenset(p.relative_to(repo_root).as_posix() for p in (repo_root / "scripts").rglob("*.py"))
    return workflows, actions, files


def load_repo(repo_root: Path) -> tuple[dict[str, str], dict[str, str], frozenset[str]]:
    """Read every workflow and local action of a checkout into memory."""
    return _load_dir(repo_root)


def check(result: ScanResult, allow: tuple[AllowRow, ...] = TAINT_ALLOW, pin: int = TAINT_ALLOW_PIN) -> list[str]:
    """Every problem: unclassifiable forms, violations without a row, stale rows, rows without an issue."""
    problems = [f"unclassifiable: {msg}" for msg in result.unclassifiable]
    if len(allow) != pin:
        problems.append(f"allow table has {len(allow)} rows, pin is {pin}")
    counts: dict[tuple[str, str, str], int] = {}
    for row in allow:
        key = (row.workflow, row.job, row.step)
        counts[key] = counts.get(key, 0) + 1
    for dup in sorted(k for k, c in counts.items() if c > 1):
        problems.append(f"duplicate allow row {dup}")
    violated = {(v.workflow, v.job, v.step, v.klass) for v in result.violations}
    allowed: set[tuple[str, str, str, str]] = set()
    for row in allow:
        # bool is an int subclass: only a plain int naming an open fix issue counts.
        if type(row.issue) is not int or row.issue not in FIX_ISSUES:
            problems.append(f"allow row without an open fix issue: {row.workflow}/{row.job}/{row.step}")
        if not row.classes or any(k not in CLASSES for k in row.classes):
            problems.append(f"allow row with an unknown class: {row.workflow}/{row.job}/{row.step}")
        # A row of an unclassifiable job is not stale: its verdict is unknown and the
        # unclassifiable line above already fails the check.
        unknown = UNCLASSIFIABLE in (result.verdicts.get((row.workflow, row.job)),
                                     result.verdicts.get((row.workflow, "*")))
        for klass in row.classes:
            key = (row.workflow, row.job, row.step, klass)
            allowed.add(key)
            if key not in violated and not unknown:
                problems.append(f"stale allow row (no longer violates class {klass}): "
                                f"{row.workflow}/{row.job}/{row.step}")
    for v in sorted(result.violations, key=lambda x: (x.workflow, x.job, x.step, x.klass)):
        if (v.workflow, v.job, v.step, v.klass) not in allowed:
            problems.append(f"violation class ({v.klass}) without an allow row: {v.workflow}/{v.job}/{v.step}: {v.detail}")
    return problems


def scan(repo_root: Path) -> ScanResult:
    workflows, actions, files = load_repo(repo_root)
    return scan_texts(workflows, actions, files)


def _escape(text: str) -> str:
    """Workflow text on stdout: no line break, no tab and no leading `:` reach the log."""
    out = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace("\t", "%09")
    return "%3A" + out[1:] if out.startswith(":") else out


def _line(*fields: str) -> str:
    return "\t".join(_escape(f) for f in fields)


def emit(result: ScanResult, problems: list[str], verdicts: bool = False) -> None:
    """Print the verdict table (optional) and every problem, each field escaped (I-5)."""
    if verdicts:
        for (wf, job), verdict in sorted(result.verdicts.items()):
            print(_line(wf, job, verdict, result.taint_steps.get((wf, job), "-")))
        for v in result.violations:
            print(_line("violation", v.workflow, v.job, v.step, f"({v.klass})"))
    for problem in problems:
        print(_line(problem))
    print(f"problems={len(problems)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--verdicts", action="store_true", help="print the per-job verdict table")
    args = parser.parse_args(argv)
    result = scan(args.repo)
    problems = check(result)
    emit(result, problems, verdicts=args.verdicts)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
