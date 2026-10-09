#!/usr/bin/env python3
"""claude-md-rule-compare.py - issue #4507 (PR #4508 review R3-F3): make a CLAUDE.md rule change loud.

Run by .github/workflows/claude-md-rule-compare.yml from the BASE branch (pull_request_target). The pull request head is
DATA: with --pr-number this base script fetches `refs/pull/<N>/head` as git objects (no workflow step fetches or checks
out the head, #6163), and its CLAUDE.md and the two docs/reference files are read out of git objects with `git ls-tree`
and `git cat-file` into a scratch directory. Nothing from the head is executed, imported or checked out, and a symlink
blob (mode 120000) at any of the three paths is refused. Credential-shaped head text is masked in the summary where it
enters the report (#6163): a `name=value` / `name: value` whose name holds a password, passphrase, secret, token, API
key, access key, private key or credential word (quoted, multi-word and JSON-quoted forms included, past an escaped
quote and to the end of the line when the quote is never closed; a count of at most 9 digits or a switch word is shown,
and an UPPER_SNAKE value only as an environment variable name, unless the name is a password or passphrase; a later word
that is neither plain nor short prose masks the whole value, #6209; an emphasised or code-quoted name, a backtick-quoted
value and the cells after a credential-name cell of a Markdown table row, #6210), URL userinfo (an empty user name
included), an Authorization Bearer/Basic value, a GitHub, AWS access key id, Slack or `sk-` provider token, a GitLab
personal access, Google API or npm token, a JSON Web Token, a PEM, PGP or PuTTY private key block, and the value on the
line after a credential name that has none on its own line (#6211). A diff line inside a private key block is masked by
its index on its own side, so it is masked even when the BEGIN line lies outside its hunk. Lines this script writes are
never masked, and the verdict is computed on the unmasked text. Control and format characters of head text (ESC, CSI,
BEL, a bidirectional override) are written as escapes before they reach the summary (#6212).

The BASE guard (scripts/check-claude-md-size.py of the base checkout) and the BASE manifest
(scripts/qc-allowlists/claude-md-rule-sections.sha256) then judge the head copies:

  * every rule section whose raw text no longer hashes to the BASE manifest (changed, added, removed) is
    written to the step summary with the section name and a unified diff, headed "RULE TEXT CHANGED";
  * if the only differences are ASCII digit runs of the generated census (a number before its unit words)
    inside a section whose heading starts with `## Prime directive` (the real heading carries a date), the
    heading is "COUNT CHANGED" instead;
  * any OTHER error the base guard reports about the head copies (a lowered floor, a deleted pinned
    heading, a broken index) is "BASE GUARD REFUSES THE HEAD" and counts as a rule change;
  * a rule change fails the job unless a commit in base..head carries a trailer line
    `Rule-Change-Approved-By: <who>`; a count-only change passes but is still printed.

This is TAMPERING EVIDENCE, not authority. The trailer is data an agent can also write, and the head also
carries its own manifest, so the comparison deliberately uses the base one. What enforces is the two
independent reviews and the sole merger. Fail closed: a missing, unreadable or symlinked base guard, base
manifest or base CLAUDE.md is a failure. The comparison runs only in isolated mode (`python3 -I`); the self-test
runs a non-isolated copy beside planted files named like every module this script imports, under several interpreter
flag sets, and fails if one runs (#5163). The base guard is compiled from its source bytes; the self-test plants a
weakened cached .pyc beside it and fails if it is used (#5163). Bootstrap: pull_request_target
runs only once this workflow is on the base branch, so the PR that introduces it is judged by review.

Python 3.9 standard library only.

Usage (the comparison refuses to run without -I):
  python3 -I scripts/claude-md-rule-compare.py --base-root DIR --repo DIR --base-sha SHA --head-sha SHA
      --scratch DIR [--pr-number N] [--summary FILE]
  python3 -I scripts/claude-md-rule-compare.py --self-test
"""
import sys

if __name__ == "__main__" and not sys.flags.isolated:
    # R6 (#5163): checked before any other import. The self-test plants a file named like each imported module
    # beside a non-isolated copy and fails if one runs.
    print("## CLAUDE.md rule-change comparison\n\nRESULT: FAIL (closed) - run the comparison as "
          "`python3 -I scripts/claude-md-rule-compare.py` (isolated mode)")
    sys.exit(1)

import argparse  # noqa: E402 - after the isolated-mode refusal on purpose (#5163)
import ast
import difflib
import importlib.machinery
import importlib.util
import os
import py_compile
import re
import shutil
import stat
import subprocess
import tokenize
import unicodedata
from pathlib import Path
from typing import NamedTuple

GUARD_REL = "scripts/check-claude-md-size.py"
MANIFEST_REL = "scripts/qc-allowlists/claude-md-rule-sections.sha256"
DATA_PATHS = ("CLAUDE.md", "docs/reference/ARCHITECTURE_REFERENCE.md", "docs/reference/CODE_STYLE.md")
TRAILER = re.compile(r"^Rule-Change-Approved-By: (\S.*)$", re.MULTILINE)
SHA = re.compile(r"^[0-9a-f]{40}$")
# R4 (#4507): a digit is rule text (a vote size, a file threshold, a release branch). Only a digit run that is a
# public-surface census count INSIDE a section whose heading STARTS WITH CENSUS_SECTION (the real heading carries a
# date, so the match is a prefix; #5375) may change without the trailer; the same words in any other section are rule
# text. Fail closed, the precedent of root issue #4869.
CENSUS_SECTION = "## Prime directive"
CENSUS_DIGITS = re.compile(
    r"\b\d+(?=\s+(?:MCP tools|production HTTP route registrations|unique URL paths|CLI subcommands|"
    r"in the default build)\b)", re.ASCII)  # R5 (#5165): ASCII digits only; any other digit is rule text
# R4 (#4507): the code and configuration that judge a rule change. A change to any of them is reported and needs
# the trailer, so a guard weakened in one PR cannot silently judge the next one. The manifest is not listed: the
# section comparison above already judges it against the base.
GUARD_PATHS = ("scripts/check-claude-md-size.py", "scripts/claude-md-rule-compare.py",
                 ".github/workflows/claude-md-guard.yml", ".github/workflows/claude-md-rule-compare.yml",
                 ".github/CODEOWNERS")
DIFF_LINE_CAP = 200
# #6163: the pull request number that names the head refspec; a decimal with no leading zero, ASCII only, at most ten
# digits, so nothing but `refs/pull/<N>/head` can reach the fetch.
PR_NUMBER = re.compile(r"[1-9][0-9]{0,9}", re.ASCII)
# #6163: credential-shaped head text. The summary is a public job log; the masked value is still a rule change (the
# verdict is computed before masking). The separator is an optional closing quote, backtick or emphasis, then `:` or
# `=`; an unquoted value is the run of words up to a quote, a backtick or the end of the line, so `password = a b`
# masks both words.
CREDENTIAL_NAME = (r"[\w-]*(?:passw(?:or)?d|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
                   r"credential)[\w-]*")
# #6210: the name may be emphasised or code-quoted (`**password**: v`, `password:** v`, `` `token`: v ``) and the
# value may be backtick-quoted; groups: 1 name, 2 separator, 3 "...", 4 '...', 5 `...`, 6 unquoted.
CREDENTIAL_VALUE = re.compile(
    r"(?i)(?<![\w-])(" + CREDENTIAL_NAME + r")((?:[*_]{1,2}|[\"'`])?\s*[:=]\s*(?:[*_]{1,2}\s*)?)"
    r"(?:\"((?:[^\"\\\n]|\\.?)*)(?:\"|$)|'((?:[^'\\\n]|\\.?)*)(?:'|$)|`([^`\n]*)(?:`|$)|"
    r"([^\s\"'`]+(?:[ \t]+[^\s\"'`]+)*))")
# #6210: a Markdown table row whose cell is a credential name (`| password | v |`); the cells after it are values.
# A line that starts with `|` (after a diff prefix) is a table row; elsewhere a `|` inside a code span (a regex
# alternation such as `password|secret|token` in rule prose) separates no cells.
TABLE_ROW_START = re.compile(r"[+ -]?\s*\|")
CODE_SPAN = re.compile(r"(`+).*?\1")
TABLE_NAME_CELL = re.compile(r"(?i)\|\s*[*_`]{0,2}(" + CREDENTIAL_NAME + r")[*_`]{0,2}\s*(?=\|)")
# #6163 round 3 (review G3): a quoted value runs to its closing quote past `\"` escapes, or to the end of the line when
# the quote is never closed, so neither an escaped quote nor a missing one leaves the rest of the value visible.
# #6163 round 2/3: a value that is a count or a switch word is configuration, not a credential (a ceiling change in rule
# text must stay readable). A count is at most 9 digits with up to three 1-3 digit groups (review G4); a longer number
# is masked. A password or passphrase is masked regardless.
PLAIN_VALUE = re.compile(r"(?:\d{1,9}(?:[.,_]\d{1,3}){0,3}|true|false|yes|no|on|off|enabled|disabled|none|null)"
                         r"[.,;:)\]}]*", re.ASCII)
# #6163 round 3 (review G4): an UPPER_SNAKE value is shown only as the NAME of an environment variable: under a name
# ending in env/var/name, or when the value itself ends in a credential word (`api_key: OPENAI_API_KEY`), and never
# when it holds a run of 4 or more digits. Any other upper-case value (`token=AB_CD_EF12`) is masked.
ENV_NAME_VALUE = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+[.,;:)\]}]*", re.ASCII)
ENV_NAME_KEY = re.compile(r"(?i)[_-](?:env|var|name)$")
ENV_NAME_TAIL = re.compile(r"_(?:KEY|TOKEN|SECRET|PASSWORD|PASSPHRASE|CREDENTIALS?)[.,;:)\]}]*$")
LONG_DIGITS = re.compile(r"\d{4}")
# #6209: an unquoted multi-word value is shown only when its first word is plain and every later word is plain too or
# a short prose word (`max_tokens: 20000 per request`); `token: on <secret>` or `secret: yes, it is <secret>`
# masks the whole value. A prose word may start with a capital (a table cell `The budget for one call`) or be an
# acronym of 2-5 capitals (`CLI`, `HTTP`).
PROSE_WORD = re.compile(r"(?:[A-Za-z][a-z]{0,11}|[A-Z]{2,5})[.,;:)\]}]*", re.ASCII)
ALWAYS_MASK_NAME = re.compile(r"(?i)passw(?:or)?d|passphrase")
# #6163 round 3 (review G2): the user name is optional (`redis://:<password>@host`).
URL_USERINFO = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]*:([^@\s/]+)@")
BEARER_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/-]{8,}=*)")
PROVIDER_KEY_SHAPE = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|(?:AKIA|ASIA)[0-9A-Z]{16}|"
                                r"xox[abposr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|"
                                # #6211: GitLab personal access, Google API and npm tokens carry no name either.
                                r"glpat-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{35,}|npm_[A-Za-z0-9]{36,})\b")
# #6211: a JSON Web Token (header.payload.signature, both JSON parts base64url `{"` = `eyJ`).
JWT_SHAPE = re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})")
# A PEM or PGP private key block; #6211: a PuTTY private key file runs from its header to its Private-MAC line.
PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-\d+:")
PRIVATE_KEY_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|Private-MAC:")
# #6211: a credential name with no value on its line (`api_key:`); the value is on the next line that is not blank.
NAME_ONLY = re.compile(r"(?i)(?<![\w-])(" + CREDENTIAL_NAME + r")(?:[*_]{1,2}|[\"'`])?\s*[:=]\s*(?:[*_]{1,2})?\s*$")
# A next line that is a heading, a table row or a nested `key:` of its own is structure, not the value.
STRUCTURE_LINE = re.compile(r"(?:#|\||[\w-]+:(?:\s|$))")
MASK = "[MASKED]"
# #6212: Unicode categories of head text that are escaped before they reach the summary (see printable).
UNPRINTABLE_CATEGORIES = ("Cc", "Cf", "Cs", "Zl", "Zp")
MAX_BLOB_BYTES = 2 * 1024 * 1024  # far above any legitimate file; refuses a memory-exhaustion blob
# Messages of the base guard that the section comparison already reports in its own words.
DRIFT_MARKERS = ("changed: sha256", "is not pinned in", "is missing from CLAUDE.md")


def git(repo: Path, *args: str) -> bytes:
    """Run git in `repo` and return stdout bytes; a non-zero exit raises RuntimeError (fail closed)."""
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout


def regular_file(path: Path, label: str) -> None:
    """Raise unless `path` is a regular, non-symlink file (every level below its checkout is not checked: the
    base checkout is the trusted workflow checkout)."""
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        raise RuntimeError(f"cannot stat {label}: {exc}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise RuntimeError(f"{label} is a symlink or not a regular file")


def load_source_module(name: str, path: Path):
    """R5 (#5163): execute `path` compiled from its source bytes with compile(); no cached bytecode file is
    read. The self-test plants a weakened unchecked-hash .pyc beside the guard and fails if it is used."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    code = compile(path.read_bytes(), str(path), "exec", dont_inherit=True)
    exec(code, module.__dict__)  # noqa: S102 - trusted base code, compiled from source on purpose
    return module


def load_base_guard(base_root: Path):
    """Import the BASE guard module (trusted code of the base commit), compiled from its source."""
    guard = base_root / GUARD_REL
    regular_file(guard, f"base guard {GUARD_REL}")
    regular_file(base_root / MANIFEST_REL, f"base manifest {MANIFEST_REL}")
    regular_file(base_root / "CLAUDE.md", "base CLAUDE.md")
    module = load_source_module("base_claude_md_guard", guard)
    for name in ("rule_section_hashes", "load_manifest", "check", "read_utf8", "fence_scan"):
        if not hasattr(module, name):
            raise RuntimeError(f"the base guard has no {name}; it cannot judge this pull request")
    return module


def extract_head(repo: Path, head_sha: str, dest: Path) -> None:
    """Copy the three data files of `head_sha` into `dest` as plain files. A symlink or non-blob is refused."""
    for rel in DATA_PATHS:
        listing = git(repo, "ls-tree", "-z", head_sha, "--", rel)
        entries = [entry for entry in listing.split(b"\0") if entry]
        if len(entries) != 1:
            raise RuntimeError(f"{rel} is absent from the head commit")
        meta, _tab, name = entries[0].partition(b"\t")
        mode, kind, blob = meta.decode("ascii").split(" ")
        if name.decode("utf-8") != rel or kind != "blob" or mode not in ("100644", "100755"):
            raise RuntimeError(f"{rel} is not a regular file blob in the head (mode {mode}, type {kind})")
        if int(git(repo, "cat-file", "-s", blob).decode("ascii").strip()) > MAX_BLOB_BYTES:
            raise RuntimeError(f"{rel} in the head is larger than {MAX_BLOB_BYTES} bytes")
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git(repo, "cat-file", "blob", blob))


def section_texts(guard, text: str) -> dict:
    """Return {key: raw section text} using the same split the guard hashes."""
    bodies = {guard.PREAMBLE_KEY: []}
    current = guard.PREAMBLE_KEY
    for line, in_code in guard.fence_scan(text):
        if not in_code and line.startswith("## "):
            current = line.rstrip()
            bodies.setdefault(current, [])
            continue
        bodies[current].append(line)
    return {key: "\n".join(lines) for key, lines in bodies.items()}


def printable(text: str) -> str:
    """#6212: `text` with every control, format, surrogate or line/paragraph separator character except newline and
    tab written as a `\\xHH` / `\\uHHHH` / `\\UHHHHHHHH` escape, so head text can never send a terminal escape
    sequence (ESC, CSI, BEL) or a bidirectional override to whoever reads the summary or the job log."""
    out = []
    for char in text:
        if char in "\n\t" or unicodedata.category(char) not in UNPRINTABLE_CATEGORIES:
            out.append(char)
            continue
        code = ord(char)
        out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}")
    return "".join(out)


def fenced(body: str, info: str = "diff") -> list:
    """R4 (#4507): a code fence one backtick longer than the longest backtick run in `body`, so head text can
    never close the block early and render as Markdown in the job summary. #6212: `body` is made printable first."""
    body = printable(body)
    longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + info, body, fence]


def span(text: str) -> str:
    """R5 (#5166): head-controlled text outside a fence (a heading, a guard message, a trailer value) as one
    inline code span, longer than any backtick run inside it, on one line, so it never renders as Markdown.
    #6212: line breaks become spaces first (R5), then the rest is made printable."""
    flat = printable(" ".join(text.splitlines()))
    ticks = "`" * (max((len(run) for run in re.findall(r"`+", flat)), default=0) + 1)
    return f"{ticks} {flat} {ticks}"


def guard_path_changes(repo: Path, base_sha: str, head_sha: str) -> list:
    """The GUARD_PATHS the head changes relative to its merge base with the base (fail closed on git error)."""
    merge_base = git(repo, "merge-base", base_sha, head_sha).decode("ascii").strip()
    out = git(repo, "diff", "--name-only", "-z", "--no-renames", merge_base, head_sha, "--", *GUARD_PATHS)
    return sorted(name.decode("utf-8", "replace") for name in out.split(b"\0") if name)


def head_fetch_args(pr_number: str) -> tuple:
    """#6163: the git arguments that fetch the pull request head as objects into the base clone (never checked out).
    Anything but a plain decimal pull request number raises ValueError (fail closed)."""
    if not PR_NUMBER.fullmatch(pr_number):
        raise ValueError(f"--pr-number must be a decimal pull request number, got {pr_number!r}")
    return ("fetch", "--no-tags", "origin", f"+refs/pull/{pr_number}/head:refs/remotes/pull/head")


def plain_word(name: str, word: str) -> bool:
    """#6163: True when `word`, the value of credential name `name`, is configuration (a count, a switch word, or an
    environment variable name per ENV_NAME_VALUE) rather than a credential. A password or passphrase is never plain."""
    if ALWAYS_MASK_NAME.search(name):
        return False
    if PLAIN_VALUE.fullmatch(word):
        return True
    return bool(ENV_NAME_VALUE.fullmatch(word)) and not LONG_DIGITS.search(word) and bool(
        ENV_NAME_KEY.search(name) or ENV_NAME_TAIL.search(word))


def plain_text(name: str, value: str) -> bool:
    """#6209: True when the unquoted `value` of credential name `name` is empty, or its first word is plain and every
    later word is plain or a short prose word (PROSE_WORD)."""
    words = value.split()
    return not words or (plain_word(name, words[0]) and all(
        plain_word(name, word) or PROSE_WORD.fullmatch(word) for word in words[1:]))


def prose_cell(name: str, value: str) -> bool:
    """#6210 / #6211: True when `value`, a table cell after credential name `name` or the line after a bare `name:`, is
    plain_text, or a description of two or more words that are all plain or prose words (PROSE_WORD) under a name that
    is not a password or passphrase."""
    words = value.split()
    return plain_text(name, value) or (len(words) > 1 and not ALWAYS_MASK_NAME.search(name) and all(
        plain_word(name, word) or PROSE_WORD.fullmatch(word) for word in words))


def mask_table_cells(line: str) -> tuple:
    """#6210: in a Markdown table row with a credential-name cell, mask every later cell that is not prose_cell
    (Markdown emphasis and code quotes around the cell ignored); returns (line, count). A `|` inside a code span of a
    line that does not start with `|` is not a cell separator (TABLE_ROW_START, CODE_SPAN)."""
    scan = line if TABLE_ROW_START.match(line) else CODE_SPAN.sub(lambda span_match: span_match.group(0).replace(
        "|", " "), line)
    match = TABLE_NAME_CELL.search(scan)
    if match is None:
        return line, 0
    texts, count, start = [], 0, match.end()
    for index, cell in enumerate(scan[match.end():].split("|")):
        text, start = line[start:start + len(cell)], start + len(cell) + 1
        value = text.strip().strip("*_`")
        if index and value != MASK and not prose_cell(match.group(1), value):
            text, count = f" {MASK} ", count + 1
        texts.append(text)
    return line[:match.end()] + "|".join(texts), count


def mask_named_values(line: str) -> tuple:
    """#6163: mask the value of every credential-named `name=value` / `name: value` in one line; returns (line, count).
    A plain value (plain_word) is left visible unless the name is a password or passphrase; an unquoted value of several
    words only when every later word is plain or short prose (#6209)."""
    out, pos, count = [], 0, 0
    while True:
        match = CREDENTIAL_VALUE.search(line, pos)
        if match is None:
            break
        group = next(index for index in (3, 4, 5, 6) if match.group(index) is not None)
        value = match.group(group)
        first = value.split()[0] if value.split() else ""
        if plain_text(match.group(1), value) if group == 6 else not value.strip() or plain_word(match.group(1),
                                                                                              value.strip()):
            stop = match.start(group) + (len(first) if group == 6 else len(value) + 1)
            out.append(line[pos:stop])
            pos = stop
            continue
        out.append(line[pos:match.start(group)] + MASK)
        pos = match.end(group)
        count += 1
    out.append(line[pos:])
    return "".join(out), count


def mask_group(pattern, line: str) -> tuple:
    """Replace group 1 of every `pattern` match in `line` with MASK; returns (line, count)."""
    def replace(match):
        start, stop = match.span(1)
        return match.group(0)[:start - match.start()] + MASK + match.group(0)[stop - match.start():]
    return pattern.subn(replace, line)


def key_line_indexes(lines: list, in_key: bool = False) -> set:
    """#6163 round 3 (review G1): the indexes of `lines` inside a private key block, BEGIN and END lines included; an
    unterminated BEGIN runs to the end. `in_key` starts inside a block (a section whose heading is a BEGIN line)."""
    inside = set()
    for index, line in enumerate(lines):
        if in_key or PRIVATE_KEY_BEGIN.search(line):
            inside.add(index)
            in_key = not PRIVATE_KEY_END.search(line)
    return inside


class Redactor:
    """#6163: masks credential-shaped HEAD text at the point it enters the report (one diff block or one inline span
    per call) and counts what it masked. The private key state never outlives one call, so an unterminated BEGIN line
    masks the rest of its own block only; lines the script writes itself never pass through here."""

    def __init__(self) -> None:
        self.count = 0

    def mask_rows(self, rows: list, prefixed: bool = False) -> list:
        """Mask `rows` of (text, kind): kind "meta" is a diff header line the script writes (shown as is), "key" is a
        line inside a private key block (masked whole, its diff prefix kept), "text" is masked shape by shape.
        `prefixed`: every non-meta row starts with a one-character diff prefix. #6211: the first non-blank text row
        after a credential name with no value (`api_key:`) is masked unless it is structure (STRUCTURE_LINE) or a
        prose_cell; a meta or key row ends the wait."""
        out, pending = [], None
        for line, kind in rows:
            if kind == "meta":
                out.append(line)
                pending = None
                continue
            if kind == "key":
                self.count += 1
                out.append(line[:1] + MASK if line[:1] in "+- " else MASK)
                pending = None
                continue
            body = line[1:] if prefixed else line
            content = body.strip()
            if pending is not None and content:
                if not (STRUCTURE_LINE.match(content) or prose_cell(pending, content)):
                    self.count += 1
                    out.append(line[:len(line) - len(body.lstrip())] + MASK)
                    pending = None
                    continue
                pending = None
            name_only = NAME_ONLY.search(line)
            if name_only is not None:
                pending = name_only.group(1)
            line, found = mask_named_values(line)
            self.count += found
            line, found = mask_table_cells(line)
            self.count += found
            for pattern in (URL_USERINFO, BEARER_VALUE, PROVIDER_KEY_SHAPE, JWT_SHAPE):
                line, found = mask_group(pattern, line)
                self.count += found
            out.append(line)
        return out

    def mask(self, text: str, in_key: bool = False) -> str:
        """Mask `text`; `in_key` starts the block inside a private key (a section whose heading is a BEGIN line)."""
        lines = text.split("\n")
        inside = key_line_indexes(lines, in_key)
        return "\n".join(self.mask_rows([(line, "key" if index in inside else "text")
                                         for index, line in enumerate(lines)]))

    def note(self) -> list:
        if not self.count:
            return []
        return [f"NOTE: {self.count} credential-shaped value(s) masked in this summary (#6163); the pull request "
                "diff shows the raw text and the verdict was computed on it."]


def unified_range(start: int, stop: int) -> str:
    """The `start,length` of a unified diff hunk header for the 0-based range [start, stop) (difflib's format)."""
    length = stop - start
    if length == 1:
        return str(start + 1)
    return f"{start + 1 if length else start},{length}"


def unified(old: str, new: str, key: str, redactor=None) -> str:
    """A unified diff (2 context lines, the same text difflib.unified_diff gives) of one section, capped at
    DIFF_LINE_CAP lines. #6163 round 3 (review G1): every `-`, `+` or context line whose index on its own side lies in a
    private key block of that side is masked, so a key line prints masked even when its BEGIN line is outside the
    hunk; a context line is masked when it lies in a block on either side."""
    old_lines, new_lines = old.split("\n"), new.split("\n")
    heading_key = bool(PRIVATE_KEY_BEGIN.search(key)) and not PRIVATE_KEY_END.search(key)
    old_key, new_key = key_line_indexes(old_lines, heading_key), key_line_indexes(new_lines, heading_key)
    rows = []
    for group in difflib.SequenceMatcher(None, old_lines, new_lines).get_grouped_opcodes(2):
        if not rows:
            rows += [("--- base", "meta"), ("+++ head", "meta")]
        rows.append((f"@@ -{unified_range(group[0][1], group[-1][2])} "
                     f"+{unified_range(group[0][3], group[-1][4])} @@", "meta"))
        for tag, old_start, old_stop, new_start, new_stop in group:
            if tag == "equal":
                rows += [(" " + old_lines[index], "key" if index in old_key or new_index in new_key else "text")
                         for index, new_index in zip(range(old_start, old_stop), range(new_start, new_stop))]
                continue
            rows += [("-" + old_lines[index], "key" if index in old_key else "text")
                     for index in range(old_start, old_stop)]
            rows += [("+" + new_lines[index], "key" if index in new_key else "text")
                     for index in range(new_start, new_stop)]
    truncated = len(rows) > DIFF_LINE_CAP
    rows = rows[:DIFF_LINE_CAP]
    lines = redactor.mask_rows(rows, True) if redactor is not None else [line for line, _kind in rows]
    return "\n".join(lines) + (f"\n... diff truncated at {DIFF_LINE_CAP} lines" if truncated else "")


def approvals(repo: Path, base_sha: str, head_sha: str) -> list:
    """The `Rule-Change-Approved-By` trailer values in base..head (commit messages are data)."""
    out = git(repo, "log", "--format=%B%x00", f"{base_sha}..{head_sha}").decode("utf-8", "replace")
    found = []
    for message in out.split("\0"):
        found += [match.group(1).strip() for match in TRAILER.finditer(message)]
    return found


def compare(base_root: Path, repo: Path, base_sha: str, head_sha: str, scratch: Path, index_pins=None):
    """Return (report_text, failed). Raises RuntimeError for a fail-closed precondition."""
    for sha in (base_sha, head_sha):
        if not SHA.fullmatch(sha):
            raise RuntimeError(f"{sha!r} is not a 40-hex commit id")
    guard = load_base_guard(base_root)
    head_root = scratch / "head"
    if head_root.exists():
        shutil.rmtree(head_root)
    head_root.mkdir(parents=True)
    extract_head(repo, head_sha, head_root)
    manifest_dest = head_root / MANIFEST_REL
    manifest_dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(base_root / MANIFEST_REL, manifest_dest)

    manifest_errors, pinned = guard.load_manifest(base_root)
    if manifest_errors:
        raise RuntimeError("the base manifest is unusable: " + "; ".join(manifest_errors))
    head_text = guard.read_utf8(head_root / "CLAUDE.md")
    base_text = guard.read_utf8(base_root / "CLAUDE.md")
    head_hashes, duplicates = guard.rule_section_hashes(head_text)
    head_bodies = section_texts(guard, head_text)
    base_bodies = section_texts(guard, base_text)

    lines = ["## CLAUDE.md rule-change comparison (base manifest vs pull request head)", ""]
    redactor = Redactor()
    rule_changed = False
    count_changed = False
    for key in sorted(set(pinned) | set(head_hashes)):
        if key in pinned and head_hashes.get(key) == pinned[key]:
            continue
        old = base_bodies.get(key)
        new = head_bodies.get(key)
        # #5404: split on the census digit runs and compare the text BETWEEN them; no stand-in character is
        # substituted, so no byte the head holds (U+0000 included) can imitate a number.
        if old is not None and new is not None and key.startswith(CENSUS_SECTION) and (
                CENSUS_DIGITS.split(old) == CENSUS_DIGITS.split(new)):
            count_changed = True
            lines += [f"### COUNT CHANGED: {span(redactor.mask(key))}", "", "Only census counts differ.", ""] + fenced(
                unified(old, new, key, redactor)) + [""]
        else:
            rule_changed = True
            state = "removed" if new is None else ("added" if old is None else "changed")
            lines += [f"### RULE TEXT CHANGED ({state}): {span(redactor.mask(key))}", ""] + fenced(
                unified(old or "", new or "", key, redactor)) + [""]
    for key in duplicates:
        rule_changed = True
        lines += [f"### RULE TEXT CHANGED (duplicated heading): {span(redactor.mask(key))}", ""]
    residual = [error for error in guard.check(head_root, index_pins) if not any(marker in error for marker in DRIFT_MARKERS)]
    for error in residual:
        rule_changed = True
        lines.append(f"- BASE GUARD REFUSES THE HEAD: {span(redactor.mask(error))}")
    if residual:
        lines.append("")
    for rel in guard_path_changes(repo, base_sha, head_sha):
        rule_changed = True
        lines.append(f"- GUARD CHANGED: {rel} (the code that judges rule changes; needs the trailer)")
    approved = approvals(repo, base_sha, head_sha)
    failed = False
    if rule_changed and not approved:
        failed = True
        lines.append("RESULT: FAIL - the rule text changed and no commit in the range carries a "
                     "`Rule-Change-Approved-By: <who>` trailer.")
    elif rule_changed:
        lines.append("RESULT: PASS - rule text changed; approval trailer(s): "
                     + "; ".join(span(redactor.mask(value)) for value in approved)
                     + ". This is tamper-evidence: the trailer is data, and review plus the sole merger enforce.")
    elif count_changed:
        lines.append("RESULT: PASS - only counts changed (printed above for review).")
    else:
        lines.append("RESULT: PASS - no rule section differs from the base manifest.")
    return "\n".join(lines + redactor.note()) + "\n", failed


def closed_failure(exc: Exception) -> str:
    """The report of a comparison that failed closed on `exc`. #6212: the message may quote head data, so it is
    masked, put on one line and made printable like any other head text."""
    message = printable(" ".join(Redactor().mask(str(exc)).splitlines()))
    return f"## CLAUDE.md rule-change comparison\n\nRESULT: FAIL (closed) - {message}\n"


def run(args) -> int:
    if not sys.flags.isolated:
        # R5 (#5163): second line of defence for a caller that imports this module; the refusal that
        # stops a sibling module is the one above the imports.
        print("## CLAUDE.md rule-change comparison\n\nRESULT: FAIL (closed) - run the comparison as "
              "`python3 -I scripts/claude-md-rule-compare.py` (isolated mode)")
        return 1
    scratch = Path(args.scratch)
    try:
        scratch.mkdir(parents=True, exist_ok=True)
        if args.pr_number is not None:
            git(Path(args.repo), *head_fetch_args(args.pr_number))
        report, failed = compare(Path(args.base_root), Path(args.repo), args.base_sha, args.head_sha, scratch)
    except (RuntimeError, OSError, UnicodeDecodeError, ValueError, SyntaxError) as exc:
        report, failed = closed_failure(exc), True
    print(report)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(report)
    return 1 if failed else 0


# --------------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------------
IDENT = ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false")


def make_repo(guard, root: Path):
    """A git repo whose first commit is a valid tree (CLAUDE.md, references, manifest). Returns the base sha."""
    root.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    guard.build_fixture(root)
    path = root / "CLAUDE.md"
    heading = guard.CLAUDE_MD_REQUIRED_HEADINGS[2]
    census = next(h for h in guard.CLAUDE_MD_REQUIRED_HEADINGS if h.startswith(CENSUS_SECTION))
    text = path.read_text(encoding="utf-8").replace(
        heading + "\n", heading + "\nThe tool limit is 103 tools.\nThe vote needs 5 MCP tools.\n", 1)
    path.write_text(text.replace(
        census + "\n", census + "\nThe surface has 103 MCP tools and 99 CLI subcommands (97 in the default build). A vote needs 5 agents.\n",
        1), encoding="utf-8")
    guard.update_manifest_quiet(root)
    for rel in GUARD_PATHS:
        stub = root / rel
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text("# stub\n", encoding="utf-8")
    return commit_all(root, "base")


def commit_all(root: Path, message: str) -> str:
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), *IDENT, "commit", "-q", "--allow-empty", "-m", message], check=True)
    return git(root, "rev-parse", "HEAD").decode().strip()


CHILD_ENV_KEEP = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT")


def child_env(extra=None) -> dict:
    """#5508: the environment of every Python child the self-test starts. Built explicitly: only the names in
    CHILD_ENV_KEEP are copied from this process (a child needs a PATH and a locale; SYSTEMROOT is for Windows), plus
    `extra`. Nothing else is inherited, so PYTHONPATH, PYTHONHOME, PYTHONSAFEPATH, PYTHONSTARTUP, PYTHONINSPECT and the
    like set by an operator cannot change what a child measures."""
    env = {key: os.environ[key] for key in CHILD_ENV_KEEP if key in os.environ}
    env.update(extra or {})
    return env


REFUSAL_ISOLATION_SETS = ([], ["-E"], ["-s"], ["-E", "-s"], ["-E", "-s", "-S", "-B", "-O"], ["-S", "-E"])


def refusal_flag_sets() -> list:
    """#5507: the interpreter flag sets the non-isolated refusal is run under: every -X frozen_modules option (none,
    off, on) in front of every isolation set of REFUSAL_ISOLATION_SETS."""
    return [xopt + isolation for xopt in ([], ["-X", "frozen_modules=off"], ["-X", "frozen_modules=on"])
            for isolation in REFUSAL_ISOLATION_SETS]


def non_isolated_child(script: Path, flags: list, scratch: Path):
    """#5380: run `script` with the interpreter flags `flags` (never -I) and the comparison arguments. Returns None
    without starting anything when `script` is inside the real scripts/ directory: there a merged sibling named
    like a standard module would run inside the trusted job, so the child must start from a scratch copy."""
    if Path(script).resolve().parent == Path(__file__).resolve().parent:
        return None
    return subprocess.run([sys.executable, *flags, str(script), "--base-root", ".", "--repo", ".",
                           "--base-sha", "0" * 40, "--head-sha", "0" * 40, "--scratch", str(scratch)],
                          capture_output=True, text=True, check=False, env=child_env(), stdin=subprocess.DEVNULL)


class Plant(NamedTuple):
    """#5473: what plant_probe measured. `ok` is False when the child did not report, the planted file ran and was not
    expected to (or the reverse), or the flags the child reports differ from the flags plant_probe passed it."""
    shadowable: bool
    preloaded: bool
    planted_ran: bool
    ok: bool
    no_site: int
    ignore_env: int
    safe_path: int
    frozen_xopt: str


def plant_probe(name: str, probe: Path, xopts: list, env=None, isolate=("-S", "-E"), exit_code: int = 0) -> Plant:
    """#5441: plant `name`.py beside a child that imports `name`, run with the isolation flags `isolate` (default
    -S -E) plus the interpreter options `xopts`; `env` (None: child_env(), never the inherited environment) is the child's environment. Before importing,
    the CHILD prints its own verdict (through _frozen_importlib): whether `name` is already loaded, and whether it is
    loaded, built-in or frozen, together with the flags it was started with (#5473: sys.flags.no_site,
    sys.flags.ignore_environment, sys.flags.safe_path where the interpreter has it, and the frozen_modules -X
    option). Nothing is assumed about the interpreter: the callers compare these reports with what they require."""
    probe.mkdir(parents=True, exist_ok=True)
    (probe / f"{name}.py").write_text(f"print('PLANTED')\nraise SystemExit({exit_code})\n", encoding="utf-8")
    (probe / "probe.py").write_text(
        "import sys, _frozen_importlib as fi\n"
        f"name = {name!r}\n"
        "pre = name in sys.modules\n"
        "print('VERDICT', int(pre), int(pre or name in sys.builtin_module_names "
        "or fi.FrozenImporter.find_spec(name) is not None), sys.flags.no_site, sys.flags.ignore_environment, "
        "int(getattr(sys.flags, 'safe_path', 0)), sys._xoptions.get('frozen_modules') or '-')\n"
        "__import__(name)\n"
        "print('REAL')\n", encoding="utf-8")
    result = subprocess.run([sys.executable, *xopts, *isolate, str(probe / "probe.py")],
                            capture_output=True, text=True, check=False, cwd=str(probe),
                            env=child_env() if env is None else env, stdin=subprocess.DEVNULL)
    return parse_plant(result.stdout, xopts, isolate, result.returncode)


VERDICT_LINE = re.compile(r"VERDICT ([01]) ([01]) ([01]) ([01]) ([01]) (-|on|off)")


def parse_plant(stdout: str, xopts: list, isolate, returncode: int = 0) -> Plant:
    """#5473/#5509: turn the output of a probe child into a Plant. Pure (no process), so the self-test feeds it
    synthetic output. Exactly one line whose text starts with VERDICT (after stripping blanks) must exist, and it must
    match VERDICT_LINE exactly (five fields in {0,1}, then -, on or off; a preloaded module is also built-in or
    frozen). The child must have exited 0. `ok` needs, as WHOLE lines: PLANTED exactly once and no REAL when the
    module is not loaded, built-in or frozen; REAL exactly once and no PLANTED when it is; and the reported flags to
    equal the requested ones."""
    lines = stdout.splitlines()
    verdict = [VERDICT_LINE.fullmatch(line) for line in lines if line.strip().startswith("VERDICT")]
    if returncode != 0 or len(verdict) != 1 or verdict[0] is None:
        return Plant(False, False, False, False, -1, -1, -1, "?")
    preloaded, inert, no_site, ignore_env, safe_path, frozen_xopt = verdict[0].groups()
    if preloaded == "1" and inert != "1":
        return Plant(False, False, False, False, -1, -1, -1, "?")
    shadowable = inert == "0"
    want_frozen = next((xopts[i + 1].split("=", 1)[1] for i in range(len(xopts) - 1)
                        if xopts[i] == "-X" and xopts[i + 1].startswith("frozen_modules=")), "-")
    flags_ok = (int(no_site), int(ignore_env), frozen_xopt) == (int("-S" in isolate), int("-E" in isolate), want_frozen)
    planted, real = lines.count("PLANTED"), lines.count("REAL")
    outcome_ok = (planted, real) == ((1, 0) if shadowable else (0, 1))
    return Plant(shadowable, preloaded == "1", planted > 0, outcome_ok and flags_ok, int(no_site), int(ignore_env),
                 int(safe_path), frozen_xopt)


def safe_path_probe_bad(plant: Plant) -> bool:
    """#5511: True when a probe child started with -E and PYTHONSAFEPATH=1 in its environment either did not behave as
    its own verdict says or reports a non-zero safe_path flag, that is, it honoured the environment variable."""
    return (not plant.ok) or plant.safe_path != 0


def safe_path_measurement_gap(has_flag: bool, honours: bool) -> bool:
    """#5511: True when the interpreter has sys.flags.safe_path but a bare child did not report it from
    PYTHONSAFEPATH, which means the measurement of PYTHONSAFEPATH support is itself broken."""
    return has_flag and not honours


def plant_coverage_gap(probed: list, names: list, rounds: int) -> bool:
    """#5443: True when `probed` is not exactly `names` once per round."""
    return probed != names * rounds


# #5472: the top-level modules this script imports (except sys), pinned as a literal so the self-test has a source of
# truth that does not come from imported_modules() itself. Adding or removing an import without updating this tuple
# makes the self-test red.
EXPECTED_IMPORTS = ("argparse", "ast", "difflib", "importlib", "os", "pathlib", "py_compile", "re", "shutil", "stat",
                    "subprocess", "tokenize", "typing", "unicodedata")


def import_pin_gap(found: list, pinned) -> tuple:
    """#5472: (missing, extra): the pinned names `found` lacks, and the names in `found` that are not pinned."""
    return (sorted(set(pinned) - set(found)), sorted(set(found) - set(pinned)))


def imported_modules(path: Path) -> list:
    """#5379: the top-level names of every module `path` imports (parsed with ast, never executed), except `sys`.
    The self-test plants one file per name beside its non-isolated child. What a planted file does on a given
    interpreter is not stated here: plant_probe has the child report whether each name is loaded, built-in or
    frozen, and the self-test requires the planted file to run exactly when the child says it is not (#5441).
    EXPECTED_IMPORTS pins the set (#5472). Dynamic imports (importlib.import_module, __import__) are not found by
    this ast scan (#5405). They cannot run before the refusal: refusal_prefix_gap (#5510) requires the code above it to
    be the docstring and `import sys`; the self-test applies it to this file."""
    names = set()
    for node in ast.walk(ast.parse(path.read_bytes())):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    names.discard("sys")
    return sorted(names)


CONTROL_BYTES = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)")


def refusal_prefix_gap(source: bytes) -> str:
    """#5510/#5560: "" when `source` (the file BYTES, never a str) is plain strict utf-8 and the only statements that
    execute above the isolation refusal are the docstring and `import sys`, and the refusal is exactly
    `if __name__ == "__main__" and not sys.flags.isolated:` whose body is calls to print and sys.exit with constant
    arguments; otherwise why not. Parsed with ast from the bytes, never executed, so the check reads the file the way
    the interpreter does. It is closed-world and fails closed: it refuses a non-bytes argument; any coding cookie or
    BOM other than plain utf-8 spelled utf-8 or utf8 (tokenize.detect_encoding follows the PEP 263 rule the
    interpreter uses, so a cookie in any spelling on line 1 or 2 is covered); bytes that are not strict utf-8; any
    control byte other than tab, LF and CRLF line ends (NUL, form feed, a lone CR and the rest) anywhere in the file;
    and a line ending in a line-continuation backslash above the refusal. Module level statements are the only code
    that runs when the file is started, so a dynamic import, eval, exec, a branch, a class body or a decorator above
    the refusal cannot hide: any statement outside this whitelist is refused."""
    if not isinstance(source, (bytes, bytearray)):
        return "the source is not bytes"
    source = bytes(source)
    try:
        encoding = tokenize.detect_encoding(iter(source.splitlines(keepends=True)).__next__)[0]
    except (SyntaxError, StopIteration, LookupError) as exc:
        return f"the source encoding cannot be determined: {exc}"
    if encoding not in ("utf-8", "utf8"):
        return f"the source declares the encoding {encoding}, not plain utf-8 (a BOM or a coding cookie)"
    try:
        source.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        return f"the source is not strict utf-8: {exc}"
    if CONTROL_BYTES.search(source):
        return "the source has a control byte other than tab, LF and CRLF line ends"
    try:
        body = ast.parse(source).body
    except (SyntaxError, ValueError) as exc:
        return f"the source does not parse: {exc}"
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    if not body or not isinstance(body[0], ast.Import) or [(a.name, a.asname) for a in body[0].names] != [("sys", None)]:
        return "the first statement after the docstring is not `import sys`"
    if len(body) < 2 or not isinstance(body[1], ast.If) or body[1].orelse:
        return "the statement after `import sys` is not the refusal if"
    refusal = body[1]
    if any(line.rstrip(b"\r").endswith(b"\\") for line in source.split(b"\n")[:refusal.lineno - 1]):
        return "a line above the refusal ends with a line-continuation backslash"
    want = ast.dump(ast.parse('__name__ == "__main__" and not sys.flags.isolated', mode="eval").body)
    if ast.dump(refusal.test) != want:
        return "the refusal test is not `__name__ == \"__main__\" and not sys.flags.isolated`"
    for stmt in refusal.body:
        call = stmt.value if isinstance(stmt, ast.Expr) else None
        name = ast.unparse(call.func) if isinstance(call, ast.Call) else ""
        if name not in ("print", "sys.exit") or call.keywords or not all(isinstance(a, ast.Constant) for a in call.args):
            return "the refusal body is not print and sys.exit calls with constant arguments"
    return ""


def selftest_dir() -> Path:
    """#5384: the scratch directory of this process's self-test, under the repo's .local-runs (never /tmp)."""
    return Path(__file__).resolve().parent.parent / ".local-runs" / f"rule-compare-selftest-{os.getpid()}"


def self_test() -> int:
    try:
        return _self_test_cases()
    finally:
        shutil.rmtree(selftest_dir(), ignore_errors=True)  # a case that raises must not leave scratch behind


def _self_test_cases() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    guard_path = repo_root / GUARD_REL
    try:
        guard = load_source_module("sibling_guard", guard_path)
    except (RuntimeError, OSError, SyntaxError, ValueError) as exc:
        print(f"FAIL: self-test - cannot load the sibling guard: {exc}", file=sys.stderr)
        return 1
    refusal = guard.scratch_base_error(repo_root)
    if refusal:
        print(refusal, file=sys.stderr)
        return 1
    base_dir = selftest_dir()
    shutil.rmtree(base_dir, ignore_errors=True)
    base_dir.mkdir(parents=True)
    failures = []

    counter = [0]

    def case(name, mutate, want_fail, needle, trailer=None, base_mutate=None, message=None, absent=None, needles=()):
        counter[0] += 1
        work = base_dir / f"c{counter[0]}"
        base_sha = make_repo(guard, work / "repo")
        base_root = work / "baseroot"
        shutil.copytree(work / "repo", base_root, ignore=shutil.ignore_patterns(".git"))
        shutil.copyfile(guard_path, base_root / GUARD_REL)
        if base_mutate:
            base_mutate(base_root)
        mutate(work / "repo")
        if message is None:
            message = "head change" + (f"\n\nRule-Change-Approved-By: {trailer}" if trailer else "")
        head_sha = commit_all(work / "repo", message)
        try:
            report, failed = compare(base_root, work / "repo", base_sha, head_sha, work / "scratch", guard.fixture_index_pins())
        except RuntimeError as exc:
            report, failed = f"RESULT: FAIL (closed) - {exc}", True
        missing = [want for want in (needle, *needles) if want not in report]
        if failed != want_fail or missing or (absent is not None and absent in report):
            failures.append(name)
            print(f"FAIL: self-test - {name}: failed={failed} (wanted {want_fail}), missing {missing!r}, "
                  f"absent {absent!r}\n{report}", file=sys.stderr)
        else:
            print(f"PASS: self-test - {name}")

    heading = guard.CLAUDE_MD_REQUIRED_HEADINGS[2]

    def edit(old, new):
        def apply(root):
            target = root / "CLAUDE.md"
            target.write_text(target.read_text(encoding="utf-8").replace(old, new, 1), encoding="utf-8")
        return apply

    def reseal(root):
        guard.update_manifest_quiet(root)

    def reword(root):
        edit("tool limit is 103 tools", "tool limit is NOT 103 tools")(root)
        reseal(root)

    case("reworded section without a trailer fails with the diff", reword, True, "RULE TEXT CHANGED")
    case("the diff names the section and shows the change", reword, True, "+The tool limit is NOT 103 tools.")
    case("reworded section with the trailer passes", reword, False, "approval trailer(s): ` Justin `", trailer="Justin")
    case("a trailer value with a backtick is one code span (#5378)", reword, False,
         "approval trailer(s): `` Jus`tin ``", trailer="Jus`tin")
    case("a trailer quoted mid-line does not count", reword, True, "RESULT: FAIL",
         message="head change Rule-Change-Approved-By: Justin")
    case("an empty trailer value does not count", reword, True, "RESULT: FAIL",
         message="head change\n\nRule-Change-Approved-By: ")

    def filler(root):
        edit("section body x", "section body y")(root)
        reseal(root)

    case("same-size filler swap is a rule change", filler, True, "RULE TEXT CHANGED")

    def census_edit(old, new):
        def apply(root):
            edit(old, new)(root)
            reseal(root)
        return apply

    case("a census-count change prints COUNT CHANGED and passes", census_edit("103 MCP tools", "104 MCP tools"),
         False, "COUNT CHANGED")
    case("every census phrase may change together (R4)", census_edit(
        "103 MCP tools and 99 CLI subcommands (97 in the default build)",
        "110 MCP tools and 101 CLI subcommands (98 in the default build)"), False, "COUNT CHANGED")
    case("a digit change in prose outside the census is a rule change (R4)",
         census_edit("tool limit is 103 tools", "tool limit is 1 tools"), True, "RULE TEXT CHANGED")
    case("a vote size next to census words outside the prime directive is a rule change (R4)",
         census_edit("The vote needs 5 MCP tools.", "The vote needs 1 MCP tools."), True, "RULE TEXT CHANGED")
    case("a prose digit in the census section is a rule change (R4)",
         census_edit("A vote needs 5 agents.", "A vote needs 1 agents."), True, "RULE TEXT CHANGED")
    case("a census digit plus a prose digit together is a rule change (R4)", census_edit(
        "The surface has 103 MCP tools and 99 CLI subcommands (97 in the default build). A vote needs 5 agents.",
        "The surface has 104 MCP tools and 99 CLI subcommands (97 in the default build). A vote needs 1 agents."),
        True, "RULE TEXT CHANGED")
    case("a census unit word changed with the same digits is a rule change (R4)",
         census_edit("103 MCP tools and", "103 MCP toolz and"), True, "RULE TEXT CHANGED")
    case("a census digit changed without its unit word is a rule change (R4)",
         census_edit("(97 in the default build)", "(97 in the default build) 12"), True, "RULE TEXT CHANGED")
    case("a census count in non-ASCII digits is a rule change (R5, #5165)",
         census_edit("103 MCP tools", "\u0661\u0660\u0664 MCP tools"), True, "RULE TEXT CHANGED")

    def link_heading(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## [ok](https://e.invalid/x)\n\nbody\n",
                          encoding="utf-8")

    case("a head heading is a code span in the summary (R5, #5166)", link_heading, True,
         "RULE TEXT CHANGED (added): ` ## [ok](https://e.invalid/x) `")

    def guard_file_write(rel, data=b"# weakened\n"):
        def apply(root):
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return apply

    guard_edit = guard_file_write(GUARD_REL)
    case("a change to the guard code is reported and needs the trailer (R4)", guard_edit, True, "GUARD CHANGED")
    case("a guard change with the trailer passes (R4)", guard_edit, False, "approval trailer(s)", trailer="Justin")
    # R5 (#5164): the trusted set is pinned to a literal, and the per-path cases loop over that literal, so
    # dropping an entry from GUARD_PATHS fails here instead of silently dropping its own case.
    pinned_guard_paths = ("scripts/check-claude-md-size.py", "scripts/claude-md-rule-compare.py",
                      ".github/workflows/claude-md-guard.yml", ".github/workflows/claude-md-rule-compare.yml",
                      ".github/CODEOWNERS")
    if GUARD_PATHS != pinned_guard_paths:
        failures.append("GUARD_PATHS pin")
        print(f"FAIL: self-test - GUARD_PATHS {GUARD_PATHS} differs from the pinned set (R5, #5164)",
              file=sys.stderr)
    else:
        print("PASS: self-test - GUARD_PATHS equals the pinned set (R5, #5164)")
    for rel in pinned_guard_paths:
        case(f"a change to {rel} is reported and needs the trailer (R4)", guard_file_write(rel), True,
             f"GUARD CHANGED: {rel}")

    def weakened_pyc(root):
        # #5163: an unchecked-hash .pyc of a guard that reports every section as pinned; the source is untouched.
        source = (root / GUARD_REL).read_text(encoding="utf-8") + (
            "\n_real_hashes = rule_section_hashes\n\n\n"
            "def rule_section_hashes(text):\n"
            "    hashes, dups = _real_hashes(text)\n"
            "    pins = load_manifest(Path(__file__).resolve().parent.parent)[1]\n"
            "    return {k: pins.get(k, v) for k, v in hashes.items()}, dups\n")
        weak = root / "weak-guard-source.py"
        weak.write_text(source, encoding="utf-8")
        cfile = Path(importlib.util.cache_from_source(str(root / GUARD_REL)))
        cfile.parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(str(weak), cfile=str(cfile), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        weak.unlink()

    case("a cached .pyc beside the base guard is never loaded (R5, #5163)", reword, True, "RULE TEXT CHANGED",
         base_mutate=weakened_pyc)

    def isolated_refusal():
        # #5163/#5313/#5474: the comparison must refuse to run without -I. The non-isolated child is started from a
        # COPY of the script in an empty scratch directory (never from the real scripts/ directory, #5380), with a file
        # planted beside the copy for every imported name; none may run before the refusal, under each flag set below.
        iso = base_dir / "iso"
        iso.mkdir(parents=True, exist_ok=True)
        copy = iso / "claude-md-rule-compare.py"
        shutil.copyfile(Path(__file__).resolve(), copy)
        for name in sorted(set(EXPECTED_IMPORTS) | set(imported_modules(Path(__file__).resolve()))):
            (iso / f"{name}.py").write_text("print('PLANTED')\nraise SystemExit(0)\n", encoding="utf-8")
        # #5507: the set covers every frozen_modules option, alone and with every isolation set.
        flag_sets = refusal_flag_sets()
        for xopt in ([], ["-X", "frozen_modules=off"], ["-X", "frozen_modules=on"]):
            for isolation in ([], ["-E"], ["-s"], ["-E", "-s"], ["-E", "-s", "-S", "-B", "-O"], ["-S", "-E"]):
                if xopt + isolation not in flag_sets:
                    return False
        # #5283/#5373/#5474/#5507: the refusal is pinned for every flag set in refusal_flag_sets(): each of no -X option,
        # -X frozen_modules=off and -X frozen_modules=on, alone and crossed with each isolation set in
        # REFUSAL_ISOLATION_SETS (partial isolation -E, -s, both, plus -S -B -O, and -S -E). -P is not pinned here.
        for flags in flag_sets:
            result = non_isolated_child(copy, flags, iso / "s")
            if result is None or not (result.returncode == 1 and "isolated mode" in result.stdout
                                      and "PLANTED" not in result.stdout + result.stderr):
                return False
        # #5380: the helper refuses to start a child from the real scripts/ directory; pin that refusal.
        return non_isolated_child(Path(__file__).resolve(), [], iso / "s") is None

    if isolated_refusal():
        print("PASS: self-test - a comparison run without -I fails closed (R5, #5163)")
    else:
        failures.append("non-isolated run")
        print("FAIL: self-test - a comparison run without -I did not fail closed (R5, #5163)", file=sys.stderr)

    def importlib_plant():
        # #5424/#5441/#5442/#5443/#5473: importlib is in the plant set, the imported set equals the pin, and for EVERY
        # pinned name a planted file runs exactly when the child finds the module neither preloaded, built-in nor
        # frozen, under default interpreter options and under -X frozen_modules=off, with the child's own flag report
        # equal to what is required. Returns "" or why.
        found = imported_modules(Path(__file__).resolve())
        missing, extra = import_pin_gap(found, EXPECTED_IMPORTS)
        if missing or extra:
            return f"imported_modules() and EXPECTED_IMPORTS disagree: missing {missing}, extra {extra} (#5472)"
        if not import_pin_gap(found[1:], EXPECTED_IMPORTS)[0] or not import_pin_gap(found + ["zz_unpinned"],
                                                                                     EXPECTED_IMPORTS)[1] \
                or any(import_pin_gap(list(EXPECTED_IMPORTS), EXPECTED_IMPORTS)):
            return "the import pin check does not tell a narrowed or widened list from the pin (#5472)"
        # #5473: parse_plant on synthetic child output: ok needs a matching planted/shadowable pair AND matching flags.
        synth = [("VERDICT 0 0 1 1 0 -\nPLANTED\n", [], True), ("VERDICT 0 0 0 1 0 -\nPLANTED\n", [], False),
                 ("VERDICT 0 0 1 0 0 -\nPLANTED\n", [], False), ("VERDICT 0 0 1 1 0 off\nPLANTED\n", [], False),
                 ("VERDICT 0 0 1 1 0 off\nPLANTED\n", ["-X", "frozen_modules=off"], True),
                 ("VERDICT 0 0 1 1 0 -\nPLANTED\n", ["-X", "frozen_modules=off"], False),
                 ("VERDICT 0 1 1 1 0 -\nREAL\n", [], True), ("VERDICT 0 1 1 1 0 -\nPLANTED\n", [], False),
                 ("VERDICT 0 0 1 1 0 -\nREAL\n", [], False), ("PLANTED\n", [], False),
                 ("VERDICT 0 0 1 1 0 -\nVERDICT 0 0 1 1 0 -\nPLANTED\n", [], False),
                 ("VERDICT 0 0 1 1 x -\nPLANTED\n", [], False),
                 # #5509: the loose cases measured at 8328fbb65, each now refused
                 ("VERDICT 0 7 1 1 0 -\nPLANTED\n", [], False), ("VERDICT 0 1 1 1 0 -\nTraceback\nImportError\n", [], False),
                 ("VERDICT 0 0 1 1 0 -\nxPLANTEDx\n", [], False),
                 ("VERDICT 0 0 1 1 0 -\n VERDICT 0 0 1 1 0 -\nPLANTED\n", [], False),
                 ("VERDICT 0 1 1 1 0 -\nREAL\nREAL\n", [], False), ("VERDICT 0 0 1 1 0 -\nPLANTED\nREAL\n", [], False),
                 ("VERDICT 1 0 1 1 0 -\nREAL\n", [], False), ("VERDICT 0 1 1 1 0 - \nREAL\n", [], False),
                 ("VERDICT 0 1 1 1 0 bad\nREAL\n", [], False),
                 ("VERDICT 7 0 1 1 0 -\nPLANTED\n", [], False), ("VERDICT 1 0 1 1 0 -\nPLANTED\n", [], False), ("VERDICT 0 1 1 1 0 -\nREAL\n", [], True)]
        for out, xo, want in synth:
            if parse_plant(out, xo, ("-S", "-E")).ok != want:
                return f"parse_plant gave the wrong ok for {out!r} with options {xo} (#5473)"
        # #5561: every numeric field of the VERDICT row is 0 or 1. A 2 in field 2, 3, 4 or 5 must give the all-failed
        # Plant, compared as a whole: fields 3 to 5 are not all part of `ok`, so comparing ok alone cannot see them.
        failed_plant = Plant(False, False, False, False, -1, -1, -1, "?")
        for row in ("VERDICT 0 2 1 1 0 -\nREAL\n", "VERDICT 0 0 2 1 0 -\nPLANTED\n", "VERDICT 0 0 1 2 0 -\nPLANTED\n",
                    "VERDICT 0 0 1 1 2 -\nPLANTED\n", "VERDICT 0 1 2 1 0 -\nREAL\n", "VERDICT 0 1 1 2 0 -\nREAL\n",
                    "VERDICT 0 1 1 1 2 -\nREAL\n", "VERDICT 2 1 1 1 0 -\nREAL\n", "VERDICT 0 1 1 1 10 -\nREAL\n"):
            if parse_plant(row, [], ("-S", "-E")) != failed_plant:
                return f"parse_plant accepted a VERDICT field outside 0 and 1: {row!r} (#5561)"
        # #5509: a child that exited non-zero is never ok, even when its output reads as a pass.
        if parse_plant("VERDICT 0 1 1 1 0 -\nREAL\n", [], ("-S", "-E"), 1).ok \
                or parse_plant("VERDICT 0 0 1 1 0 -\nPLANTED\n", [], ("-S", "-E"), 1).ok:
            return "parse_plant accepted a probe child that exited non-zero (#5509)"
        if not parse_plant("VERDICT 0 0 1 1 0 -\nPLANTED\n", [], ("-S", "-E")).planted_ran:
            return "parse_plant did not read the planted marker (#5473)"
        # #5510: nothing may execute above the refusal except `import sys`. The real source must pass; each synthetic
        # source (mutant M05b and siblings: a dynamic import, an eval, an import in a branch, a class body, a decorator,
        # a second imported name, a call inside the refusal, a weakened refusal test) must be refused.
        raw = Path(__file__).read_bytes()
        source = raw.decode("utf-8")

        def gap(text: str) -> str:
            return refusal_prefix_gap(text.encode("utf-8"))

        if refusal_prefix_gap(raw):
            return f"the source has code above the isolation refusal: {refusal_prefix_gap(raw)} (#5510)"
        marker = "if __name__ == \"__main__\" and not sys.flags.isolated:"
        before = {"__import__('colorsys')\n", "import json\n", "if False:\n    import json\n", "x = eval('1')\n",
                  "class C:\n    import json\n", "@(lambda f: f)\ndef g():\n    pass\n", "exec('pass')\n",
                  "import importlib\nimportlib.import_module('colorsys')\n", "x = 1\n", "from os import path\n"}
        for inserted in sorted(before):
            if not gap(source.replace(marker, inserted + marker, 1)):
                return f"code above the isolation refusal was not refused: {inserted!r} (#5510)"
        for old, new in (("import sys\n\nif __name__", "import sys, json\n\nif __name__"),
                         ("import sys\n\nif __name__", "import sys as s\nimport sys\n\nif __name__"),
                         ("sys.exit(1)", "sys.exit(__import__('colorsys'))"), ("    print(\"## CLAUDE.md rule-change", "    __import__('colorsys')\n    print(\"## CLAUDE.md rule-change"),
                         ("not sys.flags.isolated:", "not sys.flags.isolated or True:"),
                         ("import sys\n\nif __name__", "import sys as s\n\nif __name__"), ("sys.exit(1)", "sys.exit(1, **{})"),
                         ("    sys.exit(1)\n", "    sys.exit(1)\nelse:\n    x = 1\n"), ("not sys.flags.isolated:", "not sys.flags.isolated or __import__('colorsys'):"),
                         (marker, "if True:"), ("import sys\n\nif __name__", "import sys\n\nx = 1\nif __name__")):
            if old not in source or not gap(source.replace(old, new, 1)):
                return f"a changed refusal or import line was not refused: {new!r} (#5510)"
        if not gap("") or not gap("import sys\n"):
            return "a source without the refusal was not refused (#5510)"
        # #5560: the check works on the BYTES and is closed-world about encoding and control bytes. Each source below
        # was accepted by the text based check of f95e295a0 (the utf-7 spellings even ran hidden code) or only
        # refused by accident; each must be refused with a stated reason.
        refusal = 'import sys\nif __name__ == "__main__" and not sys.flags.isolated:\n    print("refused")\n    sys.exit(1)\n'
        hidden = 'import sys\n#+AAo-print("hidden")\nif __name__ == "__main__" and not sys.flags.isolated:\n    print("refused")\n    sys.exit(1)\n'
        plain = ('"""doc"""\n' + refusal).encode("utf-8")
        if refusal_prefix_gap(plain) or refusal_prefix_gap(b"#!/usr/bin/env python3\n# coding: utf-8\n" + plain) \
                or refusal_prefix_gap(b"# -*- coding: utf8 -*-\n" + plain) or refusal_prefix_gap(b'"""doc"""\r\n' + refusal.encode().replace(b"\n", b"\r\n")):
            return "a plain utf-8 source (shebang, utf-8 cookie, CRLF) was refused (#5560)"
        encodings = {
            "utf-7 cookie on line 1": b"# coding: utf-7\n" + b'"""doc"""\n' + hidden.encode(),
            "utf-7 cookie on line 2 under a shebang": b"#!/usr/bin/env python3\n# coding: utf-7\n" + b'"""doc"""\n' + hidden.encode(),
            "utf-16 with BOM": ('"""doc"""\n' + refusal).encode("utf-16"),
            "utf-8 BOM and a latin-1 cookie": b"\xef\xbb\xbf# coding: latin-1\n" + plain,
            "utf-8 BOM alone": b"\xef\xbb\xbf" + plain,
            "vim style utf-7 cookie": b"# vim: set fileencoding=utf-7 :\n" + b'"""doc"""\n' + hidden.encode(),
            "emacs style utf-7 cookie": b"# -*- coding: utf-7 -*-\n" + b'"""doc"""\n' + hidden.encode(),
            "latin-1 cookie with a latin-1 byte": b"# coding: latin-1\n" + '"""d\xe9"""\n'.encode("latin-1") + refusal.encode(),
            "unknown cookie": b"# coding: no-such-codec\n" + plain,
            "bytes that are not utf-8": b'"""d\xff"""\n' + refusal.encode(),
            "CR-only line ends": ('"""doc"""\rimport sys\r# note\rimport json\r' + refusal.split("import sys\n", 1)[1]).replace("\n", "\r").encode(),
            "a lone CR inside a comment": b'"""doc"""\nimport sys\n# note\rimport json\n' + refusal.split("import sys\n", 1)[1].encode(),
            "form feed": b'"""doc"""\nimport sys\n\x0c\n' + refusal.split("import sys\n", 1)[1].encode(),
            "NUL": b'"""doc"""\nimport sys\n#\x00\n' + refusal.split("import sys\n", 1)[1].encode(),
            "vertical tab": b'"""doc"""\nimport sys\n\x0b\n' + refusal.split("import sys\n", 1)[1].encode(),
            "DEL": b'"""doc"""\nimport sys\n#\x7f\n' + refusal.split("import sys\n", 1)[1].encode(),
            "line continuation backslash": b'"""doc"""\nimport sys\n\\\n' + refusal.split("import sys\n", 1)[1].encode(),
            "backslash in the docstring slot": b'"""doc \\\nmore"""\n' + refusal.encode(),
            "a str instead of bytes": '"""doc"""\n' + refusal,
        }
        # The structure check also sees most of these, because ast.parse of the bytes honours the cookie. Each gate is
        # therefore also pinned on a source that is structurally valid, so no gate is carried by another one.
        benign = {
            "a benign utf-7 cookie": b"# coding: utf-7\n" + plain,
            "a benign utf-7 cookie on line 2 under a shebang": b"#!/usr/bin/env python3\n# coding: utf-7\n" + plain,
            "a benign vim style cookie": b"# vim: set fileencoding=utf-7 :\n" + plain,
            "a benign emacs style cookie": b"# -*- coding: utf-7 -*-\n" + plain,
            "a benign latin-1 cookie": b"# coding: latin-1\n" + plain,
            "a benign latin-1 cookie on line 2": b"#!/usr/bin/env python3\n# coding: iso-8859-1\n" + plain,
            "all CR line ends": ('"""doc"""\n' + refusal).replace("\n", "\r").encode("utf-8"),
            "an invalid utf-8 byte after line 2": b'"""doc"""\n# note\n# \xff\n' + refusal.encode(),
            "a CRLF line continuation backslash": b'"""doc"""\r\nimport sys\r\n\\\r\n' + refusal.split("import sys\n", 1)[1].replace("\n", "\r\n").encode(),
        }
        for byte in [*range(0, 9), 11, 12, *range(14, 32), 127]:
            benign[f"control byte {byte:#04x} in a comment"] = b'"""doc"""\nimport sys\n#' + bytes([byte]) + b"\n" + refusal.split("import sys\n", 1)[1].encode()
        for label, data in {**encodings, **benign}.items():
            if not refusal_prefix_gap(data):
                return f"a source with {label} was not refused (#5560)"
        # imported_modules reads the bytes the way the interpreter does: a utf-7 comment that hides an import is seen.
        hidden_import = base_dir / "hidden-import.py"
        hidden_import.write_bytes(b"# coding: utf-7\n#+AAo-import colorsys\nimport sys\n")
        if "colorsys" not in imported_modules(hidden_import):
            return "imported_modules did not see an import hidden behind a coding cookie (#5560)"
        # #5562: only a real docstring (a str constant) is stripped from the front. Any other first statement must be
        # refused, however harmless it looks, so it cannot be mistaken for the docstring.
        tail = refusal
        for label, first in (("a call", "__import__('colorsys')\n"), ("a number", "1\n"), ("a bytes literal", "b'doc'\n"),
                             ("an f-string", "f'{__import__(\"colorsys\")}'\n"), ("a name", "x\n"),
                             ("a docstring-like call", "str('doc')\n"), ("an ellipsis", "...\n"), ("None", "None\n")):
            if not gap(first + tail):
                return f"{label} in the docstring slot was not refused (#5562)"
        if gap('"""doc"""\n' + tail) or gap(tail):
            return "a plain docstring or no docstring was refused (#5562)"
        # #5563: the refusal body may call only print and sys.exit. Each other callable, with constant arguments and
        # followed by the valid print and sys.exit, must be refused, so the whitelist cannot grow unseen.
        head = 'import sys\nif __name__ == "__main__" and not sys.flags.isolated:\n'
        for callee in ("exec", "eval", "compile", "getattr", "setattr", "open", "globals", "vars", "input", "breakpoint",
                       "type", "os._exit", "sys.exit.__call__", "print.__call__"):
            if not gap(f'{head}    {callee}("import colorsys")\n    print("refused")\n    sys.exit(1)\n'):
                return f"a refusal body that calls {callee} was not refused (#5563)"
        if gap(f'{head}    print("refused")\n    sys.exit(1)\n') or gap(f'{head}    print("a", "b")\n    sys.exit(2)\n'):
            return "a refusal body of print and sys.exit calls was refused (#5563)"
        names = list(EXPECTED_IMPORTS)  # the probe set is the pin, never the output of imported_modules (#5472)
        if "importlib" not in names:
            return "importlib is not in the plant set"
        probed = []
        for xopts in ([], ["-X", "frozen_modules=off"]):
            live = []
            for name in names:
                plant = plant_probe(name, base_dir / "implant", xopts)
                # #5473: the flags the CHILD reports must be the ones this check relies on (-S -E, no safe path, and
                # the frozen_modules option asked for), whatever the interpreter or its site start-up does.
                if (plant.no_site, plant.ignore_env, plant.safe_path) != (1, 1, 0) \
                        or plant.frozen_xopt != ("off" if xopts else "-"):
                    return (f"the probe child reported no_site/ignore_environment/safe_path/frozen_modules "
                            f"{(plant.no_site, plant.ignore_env, plant.safe_path, plant.frozen_xopt)} for {name} "
                            f"(xopts {xopts}), not (1, 1, 0, {'off' if xopts else '-'}) (#5473)")
                if name == "importlib" and plant.preloaded:
                    return "importlib was already loaded under -S -E, so the probe is not independent of site (#5442)"
                if not plant.ok:
                    return f"the planted {name}.py behaved differently from the child's own verdict (xopts {xopts})"
                probed.append(name)
                if plant.planted_ran:
                    live.append(name)
            print(f"INFO: self-test - planted file ran (measured) for {live} with options {xopts}")
        # #5509: the child's exit code reaches parse_plant: a planted file that ran and exited 3 is never ok.
        # #5565: run on a module name no interpreter provides, so the planted file always runs and the pin cannot be
        # skipped on an interpreter where every probed name is inert. exit_code 0 is the positive control.
        fake = "zz_rule_compare_5565_absent"
        control_ok = plant_probe(fake, base_dir / "implant-fake", [])
        exit_three = plant_probe(fake, base_dir / "implant-fake-exit", [], exit_code=3)
        if not (control_ok.ok and control_ok.shadowable):  # ok already requires PLANTED exactly once
            return "the planted file of an absent module did not run cleanly (#5565)"
        if exit_three.ok:
            return "a probe child that exited non-zero was accepted (#5509, #5565)"
        if plant_coverage_gap(probed, names, 2):
            return "not every imported name was probed"
        if plant_coverage_gap(names + names, names, 2) or not plant_coverage_gap(names[:1], names, 1) \
                or not plant_coverage_gap(names + names, names, 1):
            return "the coverage check does not tell a narrowed probe from a full one"
        # #5441: measured, not assumed: the child must report encodings as already loaded and the planted file must
        # stay inert; this fails on an interpreter where that is not the case, which would leave the preloaded
        # branch of the probe unexercised.
        enc = plant_probe("encodings", base_dir / "implant", [])
        if not (enc.preloaded and not enc.planted_ran and enc.ok):
            return "a preloaded module's planted file ran, or the child did not report it preloaded"
        # #5441/#5475: with PYTHONSAFEPATH=1 in the environment the child, started with -E, must report safe_path 0
        # and the planted file must behave as the child's verdict says.
        # #5511: the two conditions below are pure functions, pinned on synthetic input so that deleting or weakening one is red.
        good, wrong_flag = parse_plant("VERDICT 0 1 1 1 0 -\nREAL\n", [], ("-S", "-E")), \
            parse_plant("VERDICT 0 1 1 1 1 -\nREAL\n", [], ("-S", "-E"))
        if safe_path_probe_bad(good) or not safe_path_probe_bad(wrong_flag) \
                or not safe_path_probe_bad(parse_plant("", [], ("-S", "-E"))) \
                or safe_path_measurement_gap(False, False) or safe_path_measurement_gap(True, True) \
                or safe_path_measurement_gap(False, True) or not safe_path_measurement_gap(True, False):
            return "the PYTHONSAFEPATH probe conditions are not pinned (#5511)"
        safe = plant_probe("importlib", base_dir / "implant", [], child_env({"PYTHONSAFEPATH": "1"}))
        if safe_path_probe_bad(safe):
            return "the probe child honours PYTHONSAFEPATH, so its result depends on the environment"
        # Negative control (#5475): whether this interpreter honours PYTHONSAFEPATH is MEASURED by a bare child,
        # not read from sys.version_info. When it does, a child started without -E must report safe_path 1 and the
        # probe must say ok False (the planted file is inert while the verdict says shadowable); this shows the
        # check above can fail and that ok is not always True. When it does not, the control is skipped and said so.
        honours = subprocess.run([sys.executable, "-S", "-c", "import sys; print(int(getattr(sys.flags, 'safe_path', 0)))"],
                                 capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL,
                                 env=child_env({"PYTHONSAFEPATH": "1"})).stdout.strip() == "1"
        if safe_path_measurement_gap(hasattr(sys.flags, "safe_path"), honours):
            return "this interpreter has sys.flags.safe_path but a bare child did not report it from PYTHONSAFEPATH (#5475)"
        if honours:
            control = plant_probe("importlib", base_dir / "implant", [], child_env({"PYTHONSAFEPATH": "1"}), ("-S",))
            if control.safe_path != 1 or control.ok:
                return "the probe cannot tell an inert planted file from a live one"
        print(f"INFO: self-test - this interpreter honours PYTHONSAFEPATH: {honours} (measured; the control runs only then)")
        # #5473: the flag report can say 0. A child started without -S must report no_site 0 (and -E still 1), and a
        # child started without -E must report ignore_environment 0; an always-1 report is red.
        no_s = plant_probe("importlib", base_dir / "implant", [], isolate=("-E",))
        no_e = plant_probe("importlib", base_dir / "implant", [], isolate=("-S",))
        if (no_s.no_site, no_s.ignore_env, no_e.no_site, no_e.ignore_env) != (0, 1, 1, 0) or not (no_s.ok and no_e.ok):
            return "the probe child's flag report does not follow the flags it was started with (#5473)"
        print(f"INFO: self-test - importlib already loaded without -S: {no_s.preloaded} (measured, not assumed)")
        return ""

    plant_failure = importlib_plant()
    if not plant_failure:
        print("PASS: self-test - the plant set equals the pinned imports and every planted file ran as the child reported (#5424)")
    else:
        failures.append("importlib plant")
        print(f"FAIL: self-test - the importlib plant check failed: {plant_failure} (#5424, #5441)", file=sys.stderr)

    def importer_refusal():
        # #5377: a caller that imports the module skips the module-top refusal (it is gated on __name__ ==
        # "__main__"), so run() is its only refusal. Load the file as a module in a child without -I and call run().
        imp = base_dir / "imp"
        imp.mkdir(parents=True, exist_ok=True)
        code = ("import argparse, importlib.util, sys\n"
                "spec = importlib.util.spec_from_file_location('rc_importer', sys.argv[1])\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(module)\n"
                "sys.exit(module.run(argparse.Namespace(base_root='.', repo='.', base_sha='0' * 40, "
                "head_sha='0' * 40, scratch=sys.argv[2], summary=None)))\n")
        result = subprocess.run([sys.executable, "-c", code, str(Path(__file__).resolve()), str(imp / "s")],
                                capture_output=True, text=True, check=False, cwd=str(imp), env=child_env(),
                                stdin=subprocess.DEVNULL)
        return result.returncode == 1 and "isolated mode" in result.stdout

    if importer_refusal():
        print("PASS: self-test - run() refuses a non-isolated caller that imports the module (#5377)")
    else:
        failures.append("importer refusal")
        print("FAIL: self-test - run() did not refuse a non-isolated caller that imports the module (#5377)",
              file=sys.stderr)

    def hostile_parent_env():
        # #5508: the self-test children get a controlled environment (child_env), so a parent that exports the variables
        # below must not change any result. Rerun the three child-spawning checks with those variables set in THIS
        # process; each must still pass. PYTHONINSPECT, PYTHONUSERBASE and PYTHONUTF8 are in the set too (#5564):
        # every child has stdin=DEVNULL, so a child that honoured PYTHONINSPECT would read EOF and exit, not hang; the
        # pin below therefore does not rely on a hang, it checks that child_env passes no PYTHON* name and that a bare
        # child reports sys.flags.inspect 0 and the default user base.
        hostile_dir = base_dir / "hostile"
        hostile_dir.mkdir(parents=True, exist_ok=True)
        for name in EXPECTED_IMPORTS:
            (hostile_dir / f"{name}.py").write_text("print('PLANTED')\nraise SystemExit(0)\n", encoding="utf-8")
        startup = hostile_dir / "startup.py"
        startup.write_text("print('PLANTED')\n", encoding="utf-8")
        hostile = {"PYTHONPATH": str(hostile_dir), "PYTHONHOME": str(hostile_dir / "no-home"), "PYTHONSAFEPATH": "1",
                   "PYTHONSTARTUP": str(startup), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONWARNINGS": "error",
                   "PYTHONINSPECT": "1", "PYTHONUSERBASE": str(hostile_dir / "userbase"), "PYTHONUTF8": "1"}
        saved = {key: os.environ.get(key) for key in hostile}
        os.environ.update(hostile)
        try:
            refusal_ok = isolated_refusal()
            plant_why = importlib_plant()
            importer_ok = importer_refusal()
            leaked = sorted(key for key in child_env() if key.startswith("PYTHON"))
            bare = subprocess.run([sys.executable, "-c", "import site, sys; print(sys.flags.inspect, site.getuserbase())"],
                                  capture_output=True, text=True, check=False, env=child_env(), stdin=subprocess.DEVNULL)
            env_ok = not leaked and bare.returncode == 0 and bare.stdout.startswith("0 ") \
                and str(hostile_dir) not in bare.stdout
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        return refusal_ok and not plant_why and importer_ok and env_ok

    if hostile_parent_env():
        print("PASS: self-test - the probe, refusal and importer checks are green under a hostile parent environment (#5508)")
    else:
        failures.append("hostile parent environment")
        print("FAIL: self-test - the probe, refusal and importer checks depend on the parent environment (#5508)",
              file=sys.stderr)

    def crash_cleanup():
        # #5384: a self-test whose case raises still removes its scratch directory. The child loads this file as
        # a module (so the module-top refusal does not apply), makes its first case raise, and prints its pid.
        code = ("import importlib.util, os, sys\n"
                "spec = importlib.util.spec_from_file_location('rc_crash', sys.argv[1])\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(module)\n"
                "def boom(*args, **kwargs):\n"
                "    raise RuntimeError('boom')\n"
                "module.make_repo = boom\n"
                "print(os.getpid(), flush=True)\n"
                "try:\n"
                "    module.self_test()\n"
                "except RuntimeError:\n"
                "    print('crashed')\n")
        result = subprocess.run([sys.executable, "-I", "-c", code, str(Path(__file__).resolve())],
                                capture_output=True, text=True, check=False, env=child_env(), stdin=subprocess.DEVNULL)
        lines = result.stdout.split()
        if len(lines) != 2 or lines[1] != "crashed" or not lines[0].isdigit():
            return False
        left = repo_root / ".local-runs" / f"rule-compare-selftest-{lines[0]}"
        survived = left.exists()
        shutil.rmtree(left, ignore_errors=True)
        return not survived

    if crash_cleanup():
        print("PASS: self-test - a self-test whose case raises removes its scratch directory (#5384)")
    else:
        failures.append("crash cleanup")
        print("FAIL: self-test - a self-test whose case raises left its scratch directory behind (#5384)",
              file=sys.stderr)

    def rename_guard(root):
        subprocess.run(["git", "-C", str(root), "mv", GUARD_REL, GUARD_REL + ".old"], check=True)

    case("a renamed trusted file is reported (R4)", rename_guard, True, f"GUARD CHANGED: {GUARD_REL}")

    def delete_compare_workflow(root):
        (root / ".github/workflows/claude-md-rule-compare.yml").unlink()

    case("a deleted trusted workflow is reported (R4)", delete_compare_workflow, True,
         "GUARD CHANGED: .github/workflows/claude-md-rule-compare.yml")
    case("a workflow trigger block removed is reported (R4)", guard_file_write(
        ".github/workflows/claude-md-guard.yml", b"name: stub\n"), True,
        "GUARD CHANGED: .github/workflows/claude-md-guard.yml")
    case("a trusted workflow that is not UTF-8 is reported, not a crash (R4)", guard_file_write(
        ".github/workflows/claude-md-guard.yml", b"\xff\xfe\x00"), True,
        "GUARD CHANGED: .github/workflows/claude-md-guard.yml")

    def chmod_guard(root):
        (root / GUARD_REL).chmod(0o755)

    case("a mode change of a trusted file is reported (R4)", chmod_guard, True, f"GUARD CHANGED: {GUARD_REL}")

    def symlink_guard(root):
        target = root / GUARD_REL
        target.unlink()
        target.symlink_to("claude-md-rule-compare.py")

    case("a trusted file replaced by a symlink is reported (R4)", symlink_guard, True, f"GUARD CHANGED: {GUARD_REL}")
    case("a change to an untrusted file is not a guard change (R4)", guard_file_write("README.md", b"hi\n"), False,
         "no rule section differs")

    def fence_check(root):
        edit("tool limit is 103 tools", "tool limit is 103 tools\n```\n[link](https://e.invalid)")(root)
        reseal(root)

    case("head backticks cannot close the summary fence (R4)", fence_check, True, "````diff")

    def long_fence(root):
        edit("tool limit is 103 tools", "tool limit is 103 tools\n``````\n[link](https://e.invalid)")(root)
        reseal(root)

    case("a long head backtick run gets a longer fence (R4)", long_fence, True, "```````diff")

    def reseal_only(root):
        manifest = root / MANIFEST_REL
        manifest.write_text(manifest.read_text(encoding="utf-8") + "# resealed, text unchanged\n", encoding="utf-8")

    case("a manifest edit with unchanged text passes", reseal_only, False, "no rule section differs")

    def hash_forge(root):
        edit("tool limit is 103 tools", "tool limit is NOT 103 tools")(root)  # head manifest left stale: base used

    case("a head that edits text but not its manifest is still a rule change", hash_forge, True,
         "RULE TEXT CHANGED")

    def remove_section(root):
        target = root / "CLAUDE.md"
        text = target.read_text(encoding="utf-8")
        start = text.index(heading)
        end = text.index("\n## ", start) + 1
        target.write_text(text[:start] + text[end:], encoding="utf-8")
        reseal(root)

    case("a removed section fails", remove_section, True, "RULE TEXT CHANGED (removed)")

    def add_section(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## New rule\nNever do X.\n", encoding="utf-8")
        reseal(root)

    case("an added section fails", add_section, True, "RULE TEXT CHANGED (added)")

    def weaken_floor(root):
        (root / "docs/reference/CODE_STYLE.md").write_text("# gone\n", encoding="utf-8")

    case("a head the base guard refuses (reference emptied) fails", weaken_floor, True, "BASE GUARD REFUSES THE HEAD")
    case("a head the base guard refuses passes only with the trailer", weaken_floor, False, "approval trailer(s)",
         trailer="Justin")

    def missing_manifest(root):
        pass

    def drop_base_manifest(root):
        (root / MANIFEST_REL).unlink()

    case("a missing base manifest fails closed", missing_manifest, True, "cannot stat base manifest",
         base_mutate=drop_base_manifest)

    def symlink_blob(root):
        target = root / "docs/reference/CODE_STYLE.md"
        target.unlink()
        target.symlink_to("ARCHITECTURE_REFERENCE.md")

    case("a symlink blob in the head fails closed", symlink_blob, True, "is not a regular file blob")

    def claude_symlink(root):
        target = root / "CLAUDE.md"
        target.unlink()
        target.symlink_to("docs/reference/CODE_STYLE.md")

    case("a symlinked CLAUDE.md in the head fails closed", claude_symlink, True, "is not a regular file blob")

    def huge(root):
        with open(root / "docs/reference/CODE_STYLE.md", "a", encoding="utf-8") as handle:
            handle.write("x" * (MAX_BLOB_BYTES + 1))

    case("an oversize head blob fails closed", huge, True, "larger than")

    def invisible(root):
        edit("tool limit is 103 tools", "tool limit is 103\u202e tools")(root)
        reseal(root)

    case("an invisible-character edit is a rule change", invisible, True, "RULE TEXT CHANGED")

    def drop_guard(root):
        (root / GUARD_REL).unlink()

    case("a missing base guard fails closed", missing_manifest, True, "cannot stat base guard", base_mutate=drop_guard)

    def fresh_pair(name):
        work = base_dir / name
        base_sha = make_repo(guard, work / "repo")
        base_root = work / "baseroot"
        shutil.copytree(work / "repo", base_root, ignore=shutil.ignore_patterns(".git"))
        shutil.copyfile(guard_path, base_root / GUARD_REL)
        return work, base_sha, base_root

    def refused(label, base_root, repo, base_sha, head_sha, scratch, needle):
        try:
            compare(base_root, repo, base_sha, head_sha, scratch, guard.fixture_index_pins())
        except RuntimeError as exc:
            if needle in str(exc):
                print(f"PASS: self-test - {label}")
                return
            print(f"FAIL: self-test - {label}: refused with {exc} (wanted {needle!r})", file=sys.stderr)
        else:
            print(f"FAIL: self-test - {label}: not refused", file=sys.stderr)
        failures.append(label)

    work, base_sha, base_root = fresh_pair("sym")
    refused("R4 a symbolic ref instead of a commit id fails closed", base_root, work / "repo", "HEAD", base_sha,
            work / "scratch", "40-hex")
    refused("R5 an abbreviated commit id fails closed", base_root, work / "repo", base_sha, base_sha[:12],
            work / "scratch", "40-hex")
    refused("R5 an upper-case commit id fails closed", base_root, work / "repo", base_sha, base_sha.upper(),
            work / "scratch", "40-hex")
    refused("R5 a commit id with a trailing newline fails closed", base_root, work / "repo", base_sha,
            base_sha + "\n", work / "scratch", "40-hex")

    for label, body, want in (
            ("no backticks keep the plain three-backtick fence", "plain text", "```diff"),
            ("a three-backtick run gets a four-backtick fence", "a\n```\nb", "````diff"),
            ("a five-backtick run gets a six-backtick fence", "a\n`````\nb", "``````diff"),
            ("a tilde run does not lengthen the backtick fence", "~~~~~~~~\nb", "```diff")):
        got = fenced(body)
        closes = got[2]
        if got[0] != want or closes != want[:-len("diff")] or got[1] != body:
            print(f"FAIL: self-test - R5 fenced(): {label}: {got!r}", file=sys.stderr)
            failures.append(label)
        else:
            print(f"PASS: self-test - R5 fenced(): {label}")

    # #5179: the trusted-path diff starts at the merge base, so a trusted change that landed on the base after
    # the head forked is not charged to the head (every other fixture is linear).
    work, fork_sha, base_root = fresh_pair("mergebase")
    repo = work / "repo"
    (repo / GUARD_REL).write_text("# the base moved on\n", encoding="utf-8")
    moved_sha = commit_all(repo, "base moves on")
    subprocess.run(["git", "-C", str(repo), "checkout", "-q", fork_sha], check=True)
    (repo / "docs").mkdir(parents=True, exist_ok=True)
    (repo / "docs" / "untrusted-note.md").write_text("x\n", encoding="utf-8")
    head_sha = commit_all(repo, "head change")
    try:
        report, failed = compare(base_root, repo, moved_sha, head_sha, work / "scratch", guard.fixture_index_pins())
    except RuntimeError as exc:
        report, failed = f"RESULT: FAIL (closed) - {exc}", True
    if failed or "GUARD CHANGED" in report:
        print(f"FAIL: self-test - R6 a base-side trusted change after the fork is charged to the head\n{report}",
              file=sys.stderr)
        failures.append("merge base")
    else:
        print("PASS: self-test - R6 a base-side trusted change after the fork is not charged to the head (#5179)")

    # #5180: the COUNT CHANGED branch uses the same dynamic fence as the rule branch; no other census diff carries
    # a backtick run, so a static fence there was never caught.
    work, _, _ = fresh_pair("countfence")
    repo = work / "repo"
    claude = repo / "CLAUDE.md"
    census_line = "The surface has 103 MCP tools"
    claude.write_text(claude.read_text(encoding="utf-8").replace(
        census_line, "````\n````\n" + census_line, 1), encoding="utf-8")
    guard.update_manifest_quiet(repo)
    fence_base = commit_all(repo, "base with a backtick run next to the census")
    base_root = work / "baseroot2"
    shutil.copytree(repo, base_root, ignore=shutil.ignore_patterns(".git"))
    shutil.copyfile(guard_path, base_root / GUARD_REL)
    claude.write_text(claude.read_text(encoding="utf-8").replace(census_line, "The surface has 104 MCP tools", 1),
                      encoding="utf-8")
    guard.update_manifest_quiet(repo)
    head_sha = commit_all(repo, "head change")
    try:
        report, failed = compare(base_root, repo, fence_base, head_sha, work / "scratch", guard.fixture_index_pins())
    except RuntimeError as exc:
        report, failed = f"RESULT: FAIL (closed) - {exc}", True
    if failed or "COUNT CHANGED" not in report or not re.search(r"\n`````diff\n.*?\n`````\n", report, re.S):
        print(f"FAIL: self-test - R6 the COUNT CHANGED fence is not longer than a backtick run\n{report}",
              file=sys.stderr)
        failures.append("count fence")
    else:
        print("PASS: self-test - R6 the COUNT CHANGED fence is longer than a backtick run in the census section "
              "(#5180)")

    # #5282: every head-controlled string printed outside a fence goes through span(), including text that holds a
    # backtick run; the cases below carry backticks in head headings and in the guard message that quotes them.
    for raw, want in (("a", "` a `"), ("a ``` b", "```` a ``` b ````"), ("a\nb", "` a b `"),
                      ("`", "`` ` ``"), ("a`b", "`` a`b ``"),
                      ("a\rb", "` a b `"), ("a\u2028b", "` a b `")):  # #5381: CR and U+2028 break lines too
        if span(raw) == want:
            print(f"PASS: self-test - span({raw!r}) is one code span (#5282)")
        else:
            failures.append(f"span {raw!r}")
            print(f"FAIL: self-test - span({raw!r}) = {span(raw)!r}, wanted {want!r} (#5282)", file=sys.stderr)

    # #6212: a fail-closed message is printed on one line, masked and with its control characters escaped.
    closed = closed_failure(RuntimeError("bad head\x1b[2K\nsecond line password=6163-canary-closed"))
    if ("\x1b" not in closed and "bad head\\x1b[2K second line password=[MASKED]" in closed
            and "6163-canary-closed" not in closed):
        print("PASS: self-test - #6212 a fail-closed message is masked, on one line and escaped")
    else:
        failures.append("closed_failure")
        print(f"FAIL: self-test - #6212 closed_failure gave {closed!r}", file=sys.stderr)

    # #6211 (final mutants N27, N36): a diff header row is shown as is and ends the wait after a bare credential name,
    # so the first line of the next hunk is not taken for that name's value.
    header_rows = Redactor().mask_rows([("+api_key:", "text"), ("@@ -9 +9 @@", "meta"), (" visible-6163", "text")],
                                       True)
    if header_rows == ["+api_key:", "@@ -9 +9 @@", " visible-6163"]:
        print("PASS: self-test - #6211 a hunk header is shown as is and ends the wait for a value")
    else:
        failures.append("mask_rows meta")
        print(f"FAIL: self-test - #6211 mask_rows over a hunk header gave {header_rows!r}", file=sys.stderr)

    def tick_heading(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## added `x` heading\n\nbody\n", encoding="utf-8")

    case("a head heading with a backtick is one code span (#5282)", tick_heading, True,
         "RULE TEXT CHANGED (added): `` ## added `x` heading ``")

    def duplicated_tick_heading(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## dup `y`\n\nbody\n\n## dup `y`\n\nbody\n",
                          encoding="utf-8")

    case("a duplicated head heading with a backtick is one code span (#5282)", duplicated_tick_heading, True,
         "RULE TEXT CHANGED (duplicated heading): `` ## dup `y` ``")
    case("a base-guard refusal quoting a head heading with a backtick is one code span (#5282)",
         duplicated_tick_heading, True, "- BASE GUARD REFUSES THE HEAD: `` FAIL: CLAUDE.md has the heading '## dup `y`' more than once")

    work, _, _ = fresh_pair("countkey")
    repo = work / "repo"
    claude = repo / "CLAUDE.md"
    claude.write_text(claude.read_text(encoding="utf-8")
                      + "\n## Prime directive census `z` addendum\n\nThe addendum has 103 MCP tools\n", encoding="utf-8")
    guard.update_manifest_quiet(repo)
    key_base = commit_all(repo, "base with a census section whose heading holds a backtick")
    base_root = work / "baseroot3"
    shutil.copytree(repo, base_root, ignore=shutil.ignore_patterns(".git"))
    shutil.copyfile(guard_path, base_root / GUARD_REL)
    claude.write_text(claude.read_text(encoding="utf-8").replace("addendum has 103 MCP tools", "addendum has 104 MCP tools", 1),
                      encoding="utf-8")
    guard.update_manifest_quiet(repo)
    head_sha = commit_all(repo, "head change")
    try:
        report, failed = compare(base_root, repo, key_base, head_sha, work / "scratch", guard.fixture_index_pins())
    except RuntimeError as exc:
        report, failed = f"RESULT: FAIL (closed) - {exc}", True
    needle = "### COUNT CHANGED: `` ## Prime directive census `z` addendum ``"
    if failed or needle not in report:
        print(f"FAIL: self-test - the COUNT CHANGED heading is not one code span (#5282)\n{report}", file=sys.stderr)
        failures.append("count key span")
    else:
        print("PASS: self-test - the COUNT CHANGED heading with a backtick is one code span (#5282)")

    # #5376: a head census line that holds a literal "#" where the base had a number is a rule change, not a count.
    def hash_for_count(root):
        edit("The surface has 103 MCP tools", "The surface has # MCP tools")(root)
        reseal(root)

    case("a census number replaced by a literal # is a rule change, not COUNT CHANGED (#5376)", hash_for_count,
         True, "RULE TEXT CHANGED")

    # #5404: a head census line that holds U+0000 where the base had a number is a rule change, not a count.
    def hash_for_nul(root):
        edit("The surface has 103 MCP tools", "The surface has \x00 MCP tools")(root)
        reseal(root)

    case("a census number replaced by U+0000 is a rule change, not COUNT CHANGED (#5404)", hash_for_nul,
         True, "RULE TEXT CHANGED")

    # #5425: the CENSUS_DIGITS split comparison is pinned against every weakening of its pattern. Each case is a
    # head (or base and head) change that must be a rule change; the comment names the mutant it kills.
    def census_case(name, old, new, base_old=None, base_new=None, want_fail=True):
        base_edit = None
        if base_old is not None:
            def base_edit(root):
                edit(base_old, base_new)(root)
                reseal(root)
        case(name, census_edit(old, new), want_fail, "RULE TEXT CHANGED" if want_fail else "COUNT CHANGED",
             base_mutate=base_edit)

    # M4 (join the pieces): a census number deleted while its spaces stay.
    census_case("a census number deleted with its spaces kept is a rule change (#5425)",
                "has 103 MCP tools", "has  MCP tools")
    # M5 (drop the first piece): text before the first census number edited.
    census_case("text before the first census number edited is a rule change (#5425)",
                "The surface has 103 MCP", "The surface lacks 103 MCP")
    # M8 (drop the word boundary): a base number glued to a letter changes with the letter kept.
    census_case("a census number glued to a letter v103 to v104 is a rule change (#5425)",
                "has 103 MCP tools", "has v104 MCP tools", "has 103 MCP tools", "has v103 MCP tools")
    # M9 (lookahead whitespace optional): a base number glued to the census words.
    census_case("a census number glued to the census words 103MCP to 104MCP is a rule change (#5425)",
                "has 103 MCP tools", "has 104MCP tools", "has 103 MCP tools", "has 103MCP tools")
    # M12 (any non-space run instead of digits): a number replaced by a word.
    census_case("a census number replaced by a word is a rule change (#5425)",
                "has 103 MCP tools", "has many MCP tools")
    # M10 (digit class widened with NUL and #): the byte follows a digit, where the word boundary does not block it.
    census_case("a census number followed by a literal # is a rule change (#5425)",
                "has 103 MCP tools", "has 10# MCP tools")
    census_case("a census number followed by U+0000 is a rule change (#5425)",
                "has 103 MCP tools", "has 10\x00 MCP tools")

    # Further mutants of the same lines (round 10): a pattern or comparison weakened in a way no case above caught.
    # N2 (one whitespace, not a run): a census number followed by two spaces is still a census number.
    census_case("a census count change across a double space is still COUNT CHANGED (#5426)",
                "has 103 MCP tools", "has 104  MCP tools", "has 103 MCP tools", "has 103  MCP tools", want_fail=False)
    # N8 (digit run capped at three): a four-digit count is a census number too.
    census_case("a four-digit census count change is still COUNT CHANGED (#5426)",
                "has 103 MCP tools", "has 1040 MCP tools", "has 103 MCP tools", "has 1030 MCP tools",
                want_fail=False)
    # N3 (a census phrase dropped from the alternation): the route and URL-path phrases are census counts.
    census_case("route and URL-path census counts change as COUNT CHANGED (#5426)",
                "has 103 MCP tools", "has 104 MCP tools, 104 production HTTP route registrations, 90 unique URL paths",
                "has 103 MCP tools", "has 103 MCP tools, 103 production HTTP route registrations, 89 unique URL paths",
                want_fail=False)
    # N6 (case-insensitive census words): a lower-case words run is not a census phrase.
    census_case("a count before lower-case census words is a rule change (#5426)",
                "has 103 MCP tools", "has 104 mcp tools", "has 103 MCP tools", "has 103 mcp tools")
    # N7 (no word boundary after the census words): a census word glued to more letters is not a census phrase.
    census_case("a count before census words with a glued suffix is a rule change (#5426)",
                "has 103 MCP tools", "has 104 MCP toolsX", "has 103 MCP tools", "has 103 MCP toolsX")
    # N11 (compare the pieces sorted): the text between the numbers moved to another place is a rule change.
    census_case("census text between the numbers reordered is a rule change (#5426)",
                "103 MCP tools and 99 CLI subcommands (97 in the default build)",
                "103 CLI subcommands (99 MCP tools and 97 in the default build)")
    # N12/N13 (strip or collapse the pieces): whitespace between a number and its words is rule text.
    census_case("extra whitespace between a census number and its words is a rule change (#5426)",
                "has 103 MCP tools", "has 103   MCP tools")
    # N14 (case-fold the pieces): a case change in the text between the numbers is a rule change.
    census_case("a case change in census prose is a rule change (#5426)",
                "A vote needs 5 agents.", "a vote needs 5 agents.")

    # #5375: the docstring says what the code does: the census exemption is a heading PREFIX match.
    doc_words = " ".join((__doc__ or "").split())
    if f"inside a section whose heading starts with `{CENSUS_SECTION}`" in doc_words:
        print("PASS: self-test - the docstring states the COUNT CHANGED section rule as a heading prefix (#5375)")
    else:
        failures.append("docstring prefix")
        print("FAIL: self-test - the docstring does not state that COUNT CHANGED applies to a heading prefix "
              "(#5375)", file=sys.stderr)

    # #5383: the changelog states the guarantee the code gives: a program-level refusal under -I, not "never runs".
    changelog = repo_root / "changelog.d" / "4507.fixed.md"
    if not changelog.is_file():
        print("PASS: self-test - changelog.d/4507.fixed.md is consumed; the #5383 wording pin does not apply")
    elif "when the script is run as a program" in changelog.read_text(encoding="utf-8"):
        print("PASS: self-test - the changelog scopes the sibling-module refusal to a program run (#5383)")
    else:
        failures.append("changelog wording")
        print("FAIL: self-test - changelog.d/4507.fixed.md does not scope the sibling-module refusal to a program "
              "run (#5383)", file=sys.stderr)

    def base_claude_symlink(root):
        target = root / "CLAUDE.md"
        target.rename(root / "CLAUDE.real.md")
        target.symlink_to("CLAUDE.real.md")

    case("R4 a symlinked base CLAUDE.md fails closed", missing_manifest, True, "not a regular file",
         base_mutate=base_claude_symlink)

    def base_guard_symlink(root):
        target = root / GUARD_REL
        target.unlink()
        target.symlink_to("/dev/null")

    case("R5 a symlinked base guard fails closed", missing_manifest, True, "not a regular file",
         base_mutate=base_guard_symlink)

    def base_manifest_symlink(root):
        target = root / MANIFEST_REL
        target.rename(root / "manifest.real")
        target.symlink_to("../../manifest.real")

    case("R5 a symlinked base manifest fails closed", missing_manifest, True, "not a regular file",
         base_mutate=base_manifest_symlink)

    def base_manifest_garbage(root):
        with open(root / MANIFEST_REL, "a", encoding="utf-8") as handle:
            handle.write("not a manifest line\n")

    case("R4 a malformed base manifest fails closed even with the trailer", reword, True, "unusable",
         trailer="Justin", base_mutate=base_manifest_garbage)
    case("R5 a malformed base manifest fails closed without the trailer", reword, True, "unusable",
         base_mutate=base_manifest_garbage)

    # #6163 (CodeQL py/clear-text-logging-sensitive-data): a credential-shaped value in head rule text never reaches
    # the summary, stdout or the step-summary file; the verdict is still computed on the unmasked text, and the
    # report says that it masked something, so a masked rule change stays loud.
    canary = "hunter2-6163-canary"

    def credential_reword(root):
        edit("tool limit is 103 tools", f"tool limit is 103 tools; password={canary}")(root)
        reseal(root)

    case("#6163 a password= value in changed rule text is masked in the report", credential_reword, True,
         "RULE TEXT CHANGED", absent=canary)
    case("#6163 the report says a value was masked", credential_reword, True, "masked", absent=canary)

    def pem_reword(root):
        edit("tool limit is 103 tools", "tool limit is 103 tools\n-----BEGIN PRIVATE KEY-----\n"
             f"{canary}\n-----END PRIVATE KEY-----")(root)
        reseal(root)

    case("#6163 a private key block in changed rule text is masked in the report", pem_reword, True,
         "RULE TEXT CHANGED", absent=canary, needles=("credential-shaped value(s) masked",))

    # #6163 round 2 (review F1): masking applies to head text where it enters the report, one diff block or one span
    # at a time. A private key BEGIN line with no END line masks the rest of ITS block only; the lines this script
    # writes (GUARD CHANGED, the approval list, RESULT) always stay visible.
    guard_line = f"- GUARD CHANGED: {GUARD_REL} (the code"
    open_canary = "6163-canary-unterminated"

    def unterminated_begin(root):
        edit("tool limit is 103 tools", f"tool limit is 103 tools\n-----BEGIN PRIVATE KEY-----\n{open_canary}")(root)
        reseal(root)
        guard_file_write(GUARD_REL)(root)

    case("#6163 an unterminated private key BEGIN masks only its block; GUARD CHANGED and RESULT survive",
         unterminated_begin, False, guard_line, trailer="Justin", absent=open_canary,
         needles=("RESULT: PASS - rule text changed; approval trailer(s): ` Justin `",))
    case("#6163 an unterminated private key BEGIN without the trailer still shows GUARD CHANGED and RESULT: FAIL",
         unterminated_begin, True, guard_line, absent=open_canary,
         needles=("RESULT: FAIL - the rule text changed and no commit",))
    heading_canary = "6163-canary-heading-key"

    def begin_heading(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## -----BEGIN RSA PRIVATE KEY-----\n\n"
                          f"{heading_canary}\n", encoding="utf-8")
        guard_file_write(GUARD_REL)(root)

    case("#6163 a private key BEGIN in an added heading masks only its block; GUARD CHANGED and RESULT survive",
         begin_heading, False, guard_line, trailer="Justin", absent=heading_canary,
         needles=("RESULT: PASS - rule text changed; approval trailer(s): ` Justin `", "RULE TEXT CHANGED (added)"))

    # #6163 round 2 (review F2): each credential shape the docstring names is masked.
    def head_line(extra):
        def apply(root):
            edit("tool limit is 103 tools", f"tool limit is 103 tools; {extra}")(root)
            reseal(root)
        return apply

    provider_canaries = ("gh" + "p_" + "6163canary" + "Q" * 26, "AK" + "IA" + "6163CANARYQQQQQQ")
    shapes = (
        ("a quoted multi-word password", 'password="hunter2 6163-canary-qb 6163-canary-qc"', "6163-canary-qc"),
        ("an unquoted multi-word password", "password = s1x 6163-canary-s2", "6163-canary-s2"),
        ("a JSON-quoted password key", '{"password": "6163-canary-json"}', "6163-canary-json"),
        ("URL userinfo", "postgres://dbuser:6163-canary-url@db.example.invalid/x", "6163-canary-url"),
        ("an Authorization Bearer value", "Authorization: Bearer 6163-canary-bearer-token", "6163-canary-bearer"),
        ("a bare provider token", f"use {provider_canaries[0]} here", provider_canaries[0]),
        ("a bare access key id", f"use {provider_canaries[1]} here", provider_canaries[1]),
        ("a numeric password", "password=8675309", "8675309"),
    )
    for label, extra, hidden in shapes:
        case(f"#6163 {label} in changed rule text is masked", head_line(extra), True, "RULE TEXT CHANGED",
             absent=hidden, needles=("credential-shaped value(s) masked",))

    pgp_canary = "6163-canary-pgp"

    def pgp_block(root):
        edit("tool limit is 103 tools", "tool limit is 103 tools\n-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
             f"{pgp_canary}\n-----END PGP PRIVATE KEY BLOCK-----\nafter-the-key-6163")(root)
        reseal(root)

    case("#6163 a PGP private key block is masked and the text after its END stays visible", pgp_block, True,
         "+after-the-key-6163", absent=pgp_canary, needles=("credential-shaped value(s) masked",))

    # #6163 round 2 (review F4): a count, a switch word or an environment variable name is not a credential, so a
    # ceiling change in rule text stays readable in the summary.
    for visible in ("X_TOKENS=20000", "max_tokens: 20000", "secret_scanning: enabled",
                    "AI_MEMORY_API_KEY_ENV: AI_MEMORY_API_KEY", "token_budget = 3500"):
        case(f"#6163 {visible!r} is not masked", head_line(visible), True, visible)

    # #6163 round 3 (review G2, G3, G4, S1): further credential shapes in changed rule text are masked.
    round3_shapes = (
        ("URL userinfo with an empty user name (G2)", "redis://:6163-canary-redis@db.example.invalid:6379",
         "6163-canary-redis"),
        ("a JSON password with an escaped quote (G3)", '{"password": "ab\\"6163-canary-escaped"}',
         "6163-canary-escaped"),
        ("a password with an unterminated quote (G3)", 'password="6163-canary-unclosed', "6163-canary-unclosed"),
        ("a long numeric secret (G4)", "secret=616312345678901234567890", "616312345678901234567890"),
        ("an upper-case value with no env-name shape (G4)", "token=AB_CD_EF12", "AB_CD_EF12"),
        ("a word after an exempted count (G4)", "api_key = 12345 realtailsecret", "realtailsecret"),
        ("an upper-case PASSWORD name (S1, O4)", "PASSWORD=6163-canary-upper", "6163-canary-upper"),
        ("a prefixed db_password name (S1, O5)", "db_password=6163-canary-prefixed", "6163-canary-prefixed"),
        ("a numeric passphrase (S1, O12)", "passphrase=6163555", "6163555"),
    )
    for label, extra, hidden in round3_shapes:
        case(f"#6163 {label} in changed rule text is masked", head_line(extra), True, "RULE TEXT CHANGED",
             absent=hidden, needles=("credential-shaped value(s) masked",))
    for visible in ("max_tokens: 20000 per request", "api_key: OPENAI_API_KEY", "token_count = 1,500"):
        case(f"#6163 {visible!r} is not masked (round 3)", head_line(visible), True, visible)
    # #6163 round 3 (final mutants SR3, N9): the env-name exemption is upper case only and refuses a run of 4 digits,
    # so under an `_env` name a lower-case snake value or a value with a digit run is still masked.
    for label, extra, hidden in (("a lower-case snake value under an _env name", "token_env: canary_lower_snake",
                                  "canary_lower_snake"),
                                 ("an env-name value with a 4-digit run", "API_TOKEN_ENV: SK_6163_9999_LIVE",
                                  "SK_6163_9999_LIVE")):
        case(f"#6163 {label} in changed rule text is masked", head_line(extra), True, "RULE TEXT CHANGED",
             absent=hidden, needles=("credential-shaped value(s) masked",))

    # #6209 #6210 #6211 (security review round 2): a leading count or switch word does not exempt the words after
    # it; Markdown forms (a backtick-quoted value, an emphasised name, a table row) and unlabelled token shapes (a
    # JWT, GitLab, Google API and npm tokens, a value on the line after its name, a PuTTY private key) are masked.
    sec_canaries = ("gl" + "pat-" + "6163canaryGLPATqqqqqq", "AI" + "za" + "6163CanaryGoogleKeyQQQQQQQQQQQQQQQQ",
                    "np" + "m_" + "6163canaryNPMqqqqqqqqqqqqqqqqqqqqqqqq",
                    "gith" + "ub_pat_" + "6163canaryFINEGRAINED" + "q" * 19)
    security_shapes = (
        ("a switch word then a token (#6209)", "token: on 6163-Canary-SW", "6163-Canary-SW"),
        ("a count then a secret (#6209)", "secret_key: 20000 6163CanaryCT", "6163CanaryCT"),
        ("a yes then prose then a secret (#6209)", "secret: yes, it is hunter6163", "hunter6163"),
        ("a backtick-quoted password (#6210)", "password: `6163-canary-bt`", "6163-canary-bt"),
        ("an emphasised password name (#6210)", "**password**: 6163-canary-em", "6163-canary-em"),
        ("a Markdown table row (#6210)", "| password | 6163-canary-table |", "6163-canary-table"),
        ("a JWT (#6211)", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2MTYzIn0.c2lnbmF0dXJlNjE2M2NhbmFyeQ",
         "eyJzdWIiOiI2MTYzIn0"),
        ("a GitLab token (#6211)", f"use {sec_canaries[0]} here", sec_canaries[0]),
        ("a Google API key (#6211)", f"use {sec_canaries[1]} here", sec_canaries[1]),
        ("an npm token (#6211)", f"use {sec_canaries[2]} here", sec_canaries[2]),
        ("a value on the line after its name (#6211)", "api_key:\n  c2VjcmV0LTYxNjMtbmV4dGxpbmU=",
         "c2VjcmV0LTYxNjMtbmV4dGxpbmU"),
        ("a PuTTY private key (#6211)", "\nPuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPublic-Lines: 1\n"
         "AAAAC3pub\nPrivate-Lines: 1\nAAAA6163canaryputty\nPrivate-MAC: 6163abcdef\nafter-putty-6163",
         "6163canaryputty"),
        ("a lowercase snake api_key value (security R3)", "api_key: my_real_key_6163", "my_real_key_6163"),
        ("a quoted secret starting with a count (security R4)", 'secret="20000 6163-canary-q4"', "6163-canary-q4"),
        ("a numeric passphrase (security R5)", "passphrase: 86753096163", "86753096163"),
        ("percent-encoded URL userinfo (security R7)", "postgres://u%40x:6163%40canary@db.example.invalid/x",
         "6163%40canary"),
        ("a fine-grained GitHub token (security R8)", f"use {sec_canaries[3]} here", sec_canaries[3]),
    )
    for label, extra, hidden in security_shapes:
        case(f"#6163 {label} in changed rule text is masked", head_line(extra), True, "RULE TEXT CHANGED",
             absent=hidden, needles=("credential-shaped value(s) masked",))
    case("#6211 the line after a PuTTY key's Private-MAC stays visible", head_line(security_shapes[11][1]), True,
         "+after-putty-6163", absent="6163canaryputty")
    # #6211 (final mutant O1b): the Private-MAC line ends a PuTTY key and carries a value; it is masked with the block.
    case("#6211 a PuTTY key's Private-MAC value is masked", head_line(security_shapes[11][1]), True,
         "+after-putty-6163", absent="6163abcdef")
    for visible in ("token_budget = 3500 tokens per call", "secret_scanning: enabled for every repository"):
        case(f"#6209 {visible!r} is not masked", head_line(visible), True, visible)
    # #6210: a `|` inside a code span (a regex alternation in rule prose) is not a Markdown table row.
    case("#6210 a regex alternation of credential words in a code span is not masked",
         head_line("`password|secret|key|token|cred` patterns in the diff"), True,
         "`password|secret|key|token|cred` patterns in the diff")
    # #6210 / #6211: a prose table cell and a prose line after a bare name are descriptions, not values.
    case("#6210 a prose table cell after a credential name is not masked",
         head_line("\n| token_budget | The budget for one call |"), True, "| token_budget | The budget for one call |")
    case("#6211 a prose line after a bare credential name is not masked",
         head_line("\napi_key:\n  The key used by the CLI"), True, "+  The key used by the CLI")
    # #6210 (final mutants N18, N33): a one-word cell is a value, not a description, and a table row is split at every
    # `|` (Markdown splits the cells before it reads code spans), so a code span across cells does not hide the value.
    for label, extra, hidden in (("a one-word table cell after a token name", "\n| api_token | swordfish |",
                                  "swordfish"),
                                 ("a table value inside a code span that crosses cells",
                                  "\n| `x | api_token | 6163-canary-span | y` |", "6163-canary-span")):
        case(f"#6210 {label} is masked", head_line(extra), True, "RULE TEXT CHANGED", absent=hidden,
             needles=("credential-shaped value(s) masked",))
    case("#6210 a prose table cell after a password name is masked",
         head_line("\n| password | correct horse battery |"), True, "RULE TEXT CHANGED",
         absent="correct horse battery", needles=("credential-shaped value(s) masked",))

    def named_heading(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## password: 6163-canary-heading2\n\nbody\n",
                          encoding="utf-8")

    case("#6163 a password in an added heading is masked (security R11)", named_heading, True,
         "RULE TEXT CHANGED (added)", absent="6163-canary-heading2")
    case("#6163 a password approval trailer is masked and RESULT: PASS stays (security R9)", reword, False,
         "RESULT: PASS - rule text changed", trailer="password=6163-canary-trailer9", absent="6163-canary-trailer9",
         needles=("credential-shaped value(s) masked",))

    # #6212: a control character in head text or a trailer value is shown escaped, never raw, in the summary.
    case("#6212 an ESC in an approval trailer is shown escaped", reword, False, "approval trailer(s): ` Justin\\x1b[2K",
         trailer="Justin\x1b[2K", absent="\x1b")

    def control_text(root):
        edit("tool limit is 103 tools", "tool limit is 103 tools \x1b[31mred6212 \x9b2J \x07bell")(root)
        reseal(root)

    case("#6212 control characters in changed rule text are shown escaped", control_text, True,
         "\\x1b[31mred6212", needles=("\\x9b2J", "\\x07bell"), absent="\x1b")
    case("#6212 no C1 or BEL control character reaches the summary", control_text, True, "RULE TEXT CHANGED",
         absent="\x9b")

    def bidi_text(root):
        edit("tool limit is 103 tools", "tool limit is 103 tools \u202ebidi6212\u202c")(root)
        reseal(root)

    case("#6212 a bidirectional override in changed rule text is shown escaped (final mutant N30)", bidi_text, True,
         "\\u202ebidi6212\\u202c", absent="\u202e")

    # #6163 round 3 (review G1): a key line is masked by its position inside a BEGIN..END range of its own side, so a
    # changed body line whose BEGIN line is outside the hunk (or on the other side only) never prints.
    split_body = [f"6163-canary-split-b{index}" for index in range(1, 10)]
    split_key = ["-----BEGIN PRIVATE KEY-----", *split_body, "-----END PRIVATE KEY-----"]
    split_pad = [f"unchanged line {index}" for index in range(4)]

    def base_key(root):
        edit("tool limit is 103 tools", "tool limit is 103 tools\n" + "\n".join(split_pad + split_key))(root)
        reseal(root)

    def head_key_body_changed(root):
        changed = [line.replace("-b5", "-b5-new") for line in split_key]
        filler = [f"filler line {index}" for index in range(20)]
        edit("tool limit is 103 tools", "tool limit is 103 tools\n" + "\n".join(filler + split_pad + changed))(root)
        reseal(root)

    case("#6163 a changed key body line whose BEGIN is outside the hunk is masked (G1)", head_key_body_changed,
         True, "RULE TEXT CHANGED", base_mutate=base_key, absent="6163-canary-split",
         needles=("+filler line 19", "credential-shaped value(s) masked"))

    def head_key_begin_removed(root):
        edit("tool limit is 103 tools", "tool limit is 103 tools\n" + "\n".join(split_pad + split_key[1:]))(root)
        reseal(root)

    case("#6163 key body context lines are masked when the head drops the BEGIN line (G1)", head_key_begin_removed,
         True, "RULE TEXT CHANGED", base_mutate=base_key, absent="6163-canary-split",
         needles=("credential-shaped value(s) masked",))

    # #6163 round 3 (S1, O9 O10 O11): head text in a heading, an approval trailer and a base-guard refusal is masked.
    def credential_heading(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## api_key=6163-canary-heading\n\nbody\n",
                          encoding="utf-8")

    case("#6163 a credential in an added heading is masked (S1, O9)", credential_heading, True,
         "RULE TEXT CHANGED (added): ` ## api_key=[MASKED] `", absent="6163-canary-heading")

    def credential_duplicate(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## api_key=6163-canary-dup\n\nbody\n\n"
                          "## api_key=6163-canary-dup\n\nbody\n", encoding="utf-8")

    case("#6163 a credential in a base-guard refusal is masked (S1, O11)", credential_duplicate, True,
         "- BASE GUARD REFUSES THE HEAD: ` FAIL: CLAUDE.md has the heading '## api_key=[MASKED]'",
         absent="6163-canary-dup", needles=("RULE TEXT CHANGED (duplicated heading)",))
    case("#6163 a credential in an approval trailer is masked (S1, O10)", reword, False,
         "approval trailer(s): ` password=[MASKED] `", trailer="password=6163-canary-trailer",
         absent="6163-canary-trailer")

    # #6163 round 3: unit cells on unified() itself (the diff shape, the line cap and CRLF lines).
    def unit(label, ok, detail):
        if ok:
            print(f"PASS: self-test - #6163 {label}")
        else:
            failures.append(label)
            print(f"FAIL: self-test - #6163 {label}\n{detail}", file=sys.stderr)

    shape_pairs = (
        ("a\nb\nc\nd\ne\nf\ng\nh\ni\nj", "a\nB\nc\nd\ne\nf\ng\nh\nI\nj"),
        ("", "one\ntwo"),
        ("one\ntwo", ""),
        ("x1\nx2\nx3", "x0\nx1\nx2\nx3\nx4"),
        ("k1\nk2\nk3\nk4\nk5\nk6\nk7", "k1\nk2\nk4\nk5\nk6\nk7"),
    )
    for number, (old_text, new_text) in enumerate(shape_pairs, 1):
        want = "\n".join(difflib.unified_diff(old_text.split("\n"), new_text.split("\n"), "base", "head",
                                              lineterm="", n=2))
        got = unified(old_text, new_text, "## Sec", Redactor())
        unit(f"unified() matches a unified diff with 2 context lines (shape {number})", got == want,
             f"got:\n{got}\nwant:\n{want}")
    cap_old = "\n".join(f"row{index}" for index in range(300))
    cap_new = "\n".join(f"ROW{index}" for index in range(300))
    cap_lines = unified(cap_old, cap_new, "## Sec", Redactor()).split("\n")
    unit("a diff longer than the cap keeps exactly 200 lines, then the truncation note (S1, O1c)",
         len(cap_lines) == 201 and cap_lines[199] == "-row196" and cap_lines[200] == "... diff truncated at 200 lines",
         "\n".join(cap_lines[-3:]))
    crlf_new = ("intro\r\n-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n6163-canary-crlf\r\n"
                "-----END PGP PRIVATE KEY BLOCK-----\r\nafter-crlf-6163\r")
    crlf_report = unified("intro\r", crlf_new, "## Sec", Redactor())
    unit("a CRLF private key block is masked and the line after its END stays visible (S1, O6)",
         "6163-canary-crlf" not in crlf_report and "+after-crlf-6163\r" in crlf_report, crlf_report)

    # #6163 round 4: unit cells on Redactor().mask() and unified() for the round-3 review findings. Each names the
    # finding it pins; `hidden` must not appear in the output, `shown` must.
    def masks(label, text, hidden=(), shown=(), count=None):
        redactor = Redactor()
        got = redactor.mask(text)
        unit(label, all(item not in got for item in hidden) and all(item in got for item in shown)
             and (count is None or redactor.count == count), f"count={redactor.count}\n{got}")

    def diff_masks(label, old_text, new_text, hidden=(), shown=(), count=None):
        redactor = Redactor()
        got = unified(old_text, new_text, "## Sec", redactor)
        unit(label, all(item not in got for item in hidden) and all(item in got for item in shown)
             and (count is None or redactor.count == count), f"count={redactor.count}\n{got}")

    # #6211 round 4 (security F1, code F1): the value on the line after a bare credential name is found on each side
    # of the diff, so a rotated value under an unchanged name line is masked on both its `-` and its `+` row, at the
    # end of a hunk too, and when blank lines put the name line outside the hunk.
    diff_masks("#6211 R4 a rotated api_key value under a context name is masked on both sides",
               "intro\napi_key:\n  6163OldCanaryValueAAAA\nafter\nend",
               "intro\napi_key:\n  6163NewCanaryValueBBBB\nafter\nend",
               hidden=("6163OldCanary", "6163NewCanary"), shown=(" api_key:", "-  [MASKED]", "+  [MASKED]"), count=2)
    diff_masks("#6211 R4 a rotated password value under a context name is masked on both sides",
               "intro\npassword:\n  6163OldCanaryPw\nend", "intro\npassword:\n  6163NewCanaryPw\nend",
               hidden=("6163OldCanaryPw", "6163NewCanaryPw"), count=2)
    diff_masks("#6211 R4 a rotated value at the end of a hunk is masked on both sides",
               "intro\napi_key:\n  6163OldCanaryEnd", "intro\napi_key:\n  6163NewCanaryEnd",
               hidden=("6163OldCanaryEnd", "6163NewCanaryEnd"), count=2)
    diff_masks("#6211 R4 a rotated value whose name line is outside the hunk is masked",
               "intro\napi_key:\n\n\n\n  6163OldCanaryFar\nend",
               "intro\napi_key:\n\n\n\n  6163NewCanaryFar\nend",
               hidden=("6163OldCanaryFar", "6163NewCanaryFar"), count=2)
    # #6211 round 4 (security F1): a YAML block scalar under a credential name masks every line more indented than
    # the name; the first line back at the name's indentation is shown.
    masks("#6211 R4 a YAML literal block under private_key is masked",
          "private_key: |\n  6163CanaryBlockLineOne\n\n  6163CanaryBlockLineTwo\nafter-block-6163",
          hidden=("6163CanaryBlock",), shown=("private_key: |", "after-block-6163"), count=2)
    masks("#6211 R4 a YAML folded block with chomping under secret is masked",
          "  secret: >-\n      6163CanaryFoldedOne\n      6163CanaryFoldedTwo\n  next: shown-6163",
          hidden=("6163CanaryFolded",), shown=("  secret: >-", "  next: shown-6163"), count=2)
    diff_masks("#6211 R4 a changed line inside a YAML block whose name line is unchanged is masked",
               "x\nsecret: |\n  6163OldCanaryInBlock\n  keep\ny", "x\nsecret: |\n  6163NewCanaryInBlock\n  keep\ny",
               hidden=("6163OldCanaryInBlock", "6163NewCanaryInBlock", "  keep"), count=3)
    # #6211 round 4 (code F4): a JSON Web Token is matched on its header alone; the payload need not start with `eyJ`.
    masks("#6211 R4 a JWT whose payload does not start with eyJ is masked",
          "jwt eyJhbGciOiJIUzI1NiJ9.eyAgInN1YiI6IjYxNjMifQ.c2lnbmF0dXJlNjE2M2NhbmFyeQ here",
          hidden=("eyAgInN1YiI6IjYxNjMifQ",), shown=("here",), count=1)
    # #6163 round 4 (security F2, code F2; mutant O1a): a private key written on one line, as a JSON or environment
    # string with `\n` escapes or with its body on the BEGIN line, is masked whole; the BEGIN line is key material.
    one_line_pem = "-----BEGIN PRIVATE KEY-----\\nMIIEvQ6163canaryO1a\\n-----END PRIVATE KEY-----\\n"
    masks("#6163 R4 a one-line PEM private key with escaped newlines is masked", f'key material "{one_line_pem}"',
          hidden=("6163canaryO1a",), count=1)
    masks("#6163 R4 a one-line PEM private key inside a service-account JSON is masked",
          f'{{"type": "service_account", "private_key": "{one_line_pem}", "client_id": "6163"}}',
          hidden=("6163canaryO1a",))
    masks("#6163 R4 a PEM BEGIN line with its body and END on the same line is masked",
          "-----BEGIN PRIVATE KEY----- MIIEvQ6163canarySameLine -----END PRIVATE KEY-----\nafter-same-line-6163",
          hidden=("6163canarySameLine",), shown=("after-same-line-6163",))
    # #6163 round 4 (code F5): an unquoted value runs to whitespace past a quote inside the word.
    masks("#6163 R4 an unquoted password with a double quote inside is masked to the end of the word",
          'password=abc"def6163CanaryInnerDq rest', hidden=("def6163CanaryInnerDq",))
    masks("#6163 R4 an unquoted token with a single quote inside is masked to the end of the word",
          "token: abc'def6163CanaryInnerSq", hidden=("def6163CanaryInnerSq",))
    # #6163 round 4 (security F6): a doubled quote inside a quoted value is an escaped quote, not its end.
    masks("#6163 R4 a single-quoted password with a doubled single quote is masked to its closing quote",
          "password: 'ab''6163CanaryDoubledSq' tail", hidden=("6163CanaryDoubledSq",), shown=("tail",))
    masks("#6163 R4 a double-quoted password with a doubled double quote is masked to its closing quote",
          'password: "ab""6163CanaryDoubledDq" tail', hidden=("6163CanaryDoubledDq",), shown=("tail",))
    # #6163 round 4 (code F6): a nested `key: value` line under a bare credential name is judged by its value.
    masks("#6163 R4 a nested YAML value under a bare api_key is masked",
          "api_key:\n  value: 6163CanaryNestedValue", hidden=("6163CanaryNestedValue",))
    masks("#6163 R4 a nested prose description under a bare api_key stays visible",
          "api_key:\n  description: The key used by the CLI", shown=("description: The key used by the CLI",),
          count=0)

    # #6163 round 2 (review F2 of the code review): run() itself fetches the pull request head with --pr-number. A
    # scratch origin holds refs/pull/7/head; the base clone has no head objects until the script fetches them.
    fetch_root = base_dir / "pr-fetch"
    origin = fetch_root / "origin"
    fetch_base = make_repo(guard, origin)
    git(origin, "branch", "basebr", fetch_base)
    reword(origin)
    fetch_head = commit_all(origin, "head change\n\nRule-Change-Approved-By: Justin")
    git(origin, "update-ref", "refs/pull/7/head", fetch_head)
    git(origin, "reset", "-q", "--hard", fetch_base)
    clone = fetch_root / "clone"
    subprocess.run(["git", "clone", "-q", "--no-local", "--single-branch", "--branch", "basebr", "--no-tags",
                    origin.resolve().as_uri(), str(clone)], check=True, capture_output=True)
    fetch_base_root = fetch_root / "baseroot"
    shutil.copytree(clone, fetch_base_root, ignore=shutil.ignore_patterns(".git"))
    shutil.copyfile(guard_path, fetch_base_root / GUARD_REL)

    def head_ref() -> str:
        probe = subprocess.run(["git", "-C", str(clone), "rev-parse", "-q", "--verify", "refs/remotes/pull/head"],
                               capture_output=True, text=True, check=False)
        return probe.stdout.strip()

    def run_cli(pr_number):
        summary = fetch_root / f"summary-{counter[0]}.md"
        counter[0] += 1
        argv = [sys.executable, "-I", str(Path(__file__).resolve()), "--base-root", str(fetch_base_root),
                "--repo", str(clone), "--base-sha", fetch_base, "--head-sha", fetch_head,
                "--scratch", str(fetch_root / "scratch"), "--summary", str(summary)]
        if pr_number is not None:
            argv += ["--pr-number", pr_number]
        result = subprocess.run(argv, capture_output=True, text=True, check=False, env=child_env(),
                                stdin=subprocess.DEVNULL)
        written = summary.read_text(encoding="utf-8") if summary.is_file() else ""
        return result.returncode, result.stdout, written

    head_missing = subprocess.run(["git", "-C", str(clone), "cat-file", "-e", fetch_head], capture_output=True,
                                  check=False).returncode != 0
    fetch_checks = [("the base clone starts without the head objects", head_missing)]
    rc, out, written = run_cli("07")
    fetch_checks.append(("--pr-number 07 fails closed and creates no ref",
                         rc == 1 and "RESULT: FAIL (closed) - --pr-number must be" in out and head_ref() == ""))
    rc, out, written = run_cli("7")
    fetch_checks.append(("--pr-number 7 fetches refs/pull/7/head and the comparison passes with the trailer",
                         rc == 0 and head_ref() == fetch_head and "RESULT: PASS - rule text changed" in out
                         and "RESULT: PASS - rule text changed" in written))
    for label, ok in fetch_checks:
        if ok:
            print(f"PASS: self-test - #6163 run(): {label}")
        else:
            failures.append(f"run() fetch: {label}")
            print(f"FAIL: self-test - #6163 run(): {label} (rc={rc})\n{out}", file=sys.stderr)

    # #6163 (CodeQL py/clear-text-*-sensitive-data, SensitiveDataHeuristics.qll): an identifier whose name falls in
    # the heuristic's secret, password or private-data class marks every value derived from it as sensitive (the
    # Python clear-text queries ignore its id and certificate classes). The values this script names are repository
    # paths and report lines, so no identifier may fall in those classes. Round 2 (review F3): the three classes are
    # written out in full here, plus "trusted", the name CodeQL traced in alerts 403-409. A name is exempt when it
    # matches the heuristic's not-sensitive list, ends in a path/file/url word (a repository path), or is a module this
    # script imports (a module object is not a datum).
    class_one = r"(?<!is)(?<!is_)secret|(?<!un)(?<!un_)(?<!is)(?<!is_)token|(?<!un)(?<!un_)(?<!is)(?<!is_)trusted"
    class_two = (r"pass(wd|word|code|.?phrase)(?!.*question)|(auth(entication|ori[sz]ation)?).?key|oauth|"
                      r"api.?(key|tok)|([_-]|\b)mfa([_-]|\b)")
    class_three = (r"social.?security|employer.?identification|national.?insurance|resident.?id|"
                     r"passport.?(num|no)|([_-]|\b)ssn([_-]|\b)|post.?code|zip.?code|home.?addr|"
                     r"(mob(ile)?|home).?(num|no|tel|phone)|(tel|fax|phone).?(num|no)|telephone|"
                     r"emergency.?contact|latitude|longitude|nationality|(credit|debit|bank|visa).?(card|num|no|"
                     r"acc(ou)?nt)|acc(ou)?nt.?(no|num|credit)|salary|billing|credit.?(rating|score)|"
                     r"([_-]|\b)ccn([_-]|\b)|birth.?da(te|y)|da(te|y).?(of.?)?birth|medical|(health|care).?plan|"
                     r"healthkit|appointment|prescription|blood.?(type|alcohol|glucose|pressure)|"
                     r"heart.?(rate|rhythm)|body.?(mass|fat)|menstrua|pregnan|insulin|inhaler|insurance|private.?data")
    sensitive_name = re.compile(f"(?is)({class_one}|{class_two}|{class_three})")
    not_sensitive = re.compile(r"(?is)([^\w$.-]|redact|censor|obfuscate|hash|md5|sha|random|((?<!un)(en))?(crypt|"
                               r"(?<!pass)code)|certain|concert|secretar|accountant|accountab|(path|paths|file|url)$)")
    heuristic_samples = ("auth_key", "authorization_key", "oauth_state", "mfa_code", "salary_line", "api_token",
                         "session_secret", "trusted_write", "zip_code", "passphrase")
    missed = [name for name in heuristic_samples if not sensitive_name.search(name)]
    if missed:
        failures.append("sensitive-name classes")
        print(f"FAIL: self-test - #6163 the sensitive-name classes miss {missed}", file=sys.stderr)
    else:
        print("PASS: self-test - #6163 the sensitive-name classes cover the secret, password and private-data names")
    own_tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    own_names = set()
    imported = set()
    for node in ast.walk(own_tree):
        if isinstance(node, ast.Name):
            own_names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            own_names.add(node.name)
        elif isinstance(node, ast.arg):
            own_names.add(node.arg)
        elif isinstance(node, ast.Attribute):
            own_names.add(node.attr)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            imported.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
    flagged = sorted(name for name in own_names - imported
                     if sensitive_name.search(name) and not not_sensitive.search(name))
    if flagged:
        failures.append("sensitive identifier names")
        print(f"FAIL: self-test - #6163 identifiers CodeQL reads as credentials: {flagged}", file=sys.stderr)
    else:
        print("PASS: self-test - #6163 no identifier reads as a credential to the sensitive-data heuristic")
    # Round 2 (review F3): the changelog states exactly what the identifier cell checks.
    fragment = repo_root / "changelog.d" / "6163.fixed.md"
    fragment_words = " ".join(fragment.read_text(encoding="utf-8").split()) if fragment.is_file() else ""
    if "refuses any identifier that matches the heuristic" in fragment_words or (
            "secret, password and private-data name classes" not in fragment_words):
        failures.append("6163 changelog wording")
        print("FAIL: self-test - #6163 changelog.d/6163.fixed.md does not name the checked sensitive-name classes",
              file=sys.stderr)
    else:
        print("PASS: self-test - #6163 the changelog names the sensitive-name classes the self-test checks")

    # #6163 (CodeQL actions/untrusted-checkout): the pull request head is fetched by this base script, never by a
    # workflow step; the refspec is built from a validated decimal number only.
    fetch_args = globals().get("head_fetch_args")
    if fetch_args is None:
        failures.append("head_fetch_args")
        print("FAIL: self-test - #6163 head_fetch_args is not defined (the workflow fetches the head itself)",
              file=sys.stderr)
    else:
        want_args = ("fetch", "--no-tags", "origin", "+refs/pull/6163/head:refs/remotes/pull/head")
        if tuple(fetch_args("6163")) != want_args:
            failures.append("head_fetch_args shape")
            print(f"FAIL: self-test - #6163 head_fetch_args('6163') = {fetch_args('6163')!r}", file=sys.stderr)
        else:
            print("PASS: self-test - #6163 head_fetch_args builds the one pull request head refspec")
        for bad in ("", "0", "06163", "-1", "1 2", "12/../x", "+refs/heads/main", "\uff11\uff12", "1\n",
                    "9" * 11):
            try:
                fetch_args(bad)
            except ValueError:
                print(f"PASS: self-test - #6163 head_fetch_args refuses {bad!r}")
            else:
                failures.append(f"head_fetch_args {bad!r}")
                print(f"FAIL: self-test - #6163 head_fetch_args accepted {bad!r}", file=sys.stderr)

    shutil.rmtree(base_dir, ignore_errors=True)
    if failures:
        print(f"FAIL: self-test - {len(failures)} case(s) failed", file=sys.stderr)
        return 1
    print("PASS: self-test #4507 R3-F3 - rule changes are reported, need the trailer, counts only print, "
          "and every fail-closed path refuses")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--base-root")
    parser.add_argument("--repo")
    parser.add_argument("--base-sha")
    parser.add_argument("--head-sha")
    parser.add_argument("--scratch")
    parser.add_argument("--pr-number", help="fetch refs/pull/<N>/head as git objects before comparing (#6163)")
    parser.add_argument("--summary")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not all((args.base_root, args.repo, args.base_sha, args.head_sha, args.scratch)):
        parser.error("--base-root, --repo, --base-sha, --head-sha and --scratch are required")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
