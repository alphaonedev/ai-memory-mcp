#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""CI gate for the enterprise-federation certification section 7 expiry trigger.

Ported from scripts/check-cert-expiry.sh (#6137, per the operator's standing
Python-not-shell rule). F7 / 2026-08-12 ratification caveat, #3556, #6137.

THE DEFECT CLASS THIS CLOSES. docs/compliance/ENTERPRISE-FEDERATION-
CERTIFICATION.md section 7 states that the certification "expires on any
change to the federation wire path (`src/federation/**`,
`src/handlers/federation_receive.rs`,
`src/handlers/federation_signing_check.rs`) or the `AI_MEMORY_FED_*`
env surface" and that any such change "requires re-running 5.4(2)-(5) and
re-issuing this document against the new SHA." Until this gate that sentence
was prose-only: a federation-wire change could merge through green CI while
the cert kept being cited (the #2444 "reports success while doing nothing"
shape applied to a certification expiry trigger).

THE RULE (TASK C, verbatim, no extra escape hatches). The change under test is
the standard PR diff (push / local: `merge-base(PR-base, HEAD)..HEAD`;
pull_request: first parent..merge commit, see RANGE RESOLUTION), NEVER a diff
against the cert's pinned SHA (unrelated later PRs must not fail forever). The gate
FAILS when that diff touches ANY of:

  * src/federation/**  (the directory itself or any path under it)
  * src/handlers/federation_receive.rs
  * src/handlers/federation_signing_check.rs
  * added / removed / renamed `AI_MEMORY_FED_[A-Z0-9_]+` identifiers anywhere
    in src/  (set-diff of identifiers at merge-base vs the judged commit)

UNLESS the same change also modifies
`docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md` (a re-issue or voiding
record in the same change satisfies the gate).

Failure message (required wording):
  federation-wire surface changed -> the enterprise-federation certification
  expires per its section 7 -> re-issue or void the cert doc in this same change.

RANGE RESOLUTION.
  pull_request     (#6137) The job checks out the pull_request MERGE commit
                   (GITHUB_SHA). The gate judges (B) and (C) at that merge
                   commit, never at the PR head in isolation, so a branch cut
                   before the carrier's banner fix is judged on the tree that
                   would actually merge. NO merge-base is computed on a
                   pull_request: the range starts at the merge commit's FIRST
                   PARENT. A PR's change is its effect on the merged result, so
                   (A) drift and (B) the banner flip are measured from the first
                   parent to the merge commit; base-side changes since the fork
                   point were judged when they landed on the base. (Conductor
                   decision, no vote: precedent = every other CI job tests the
                   merge ref.) The first parent must be ON the live base branch
                   (`git merge-base --is-ancestor <first parent>
                   origin/$GITHUB_BASE_REF`, the ref fetched explicitly when
                   absent), not necessarily its tip: a landing on the base
                   after the merge ref was built does not change what the PR
                   contributes. The event payload's PR_BASE_SHA, which can be
                   stale, is report-only. Fail-closed (the remedy is to push a
                   new commit or sync the branch with the base; a re-run reuses
                   the same GITHUB_SHA) when GITHUB_BASE_REF / PR_HEAD_SHA are
                   unset, a sha taken from the environment is not exactly
                   40 (or 64) hex characters, the base ref cannot be fetched, a sha does not
                   resolve, the merge commit does not have exactly two parents,
                   its second parent is not PR_HEAD_SHA, its first parent is the
                   PR head (reversed parents), or its first parent is not on the
                   live base. (#6138: first parent on the base; strictly tighter
                   than the landed gate; no vote.)
  push             github.event.before .. GITHUB_SHA. An all-zero `before`
                   (new branch / first push) is N/A-skip, never a false-fail.
  workflow_dispatch / other / empty
                   CERT_EXPIRY_BASE[/HEAD] override if set (outside CI only;
                   refused under GitHub Actions, #5970); else (local
                   convenience) merge-base with @{upstream} or
                   origin/release/v1.0.0; else N/A-skip.
  GitHub Actions   (GITHUB_ACTIONS set, #5970) the event payload range is
                   authoritative: CERT_EXPIRY_BASE / CERT_EXPIRY_HEAD set in
                   the environment are refused (rc 1), as is an empty event
                   name. Outside CI the overrides stay honoured for local use.
  Shallow checkout if merge-base fails and the repo is shallow, unshallow /
                   deepen + fetch the missing tip, then retry.

THE TWO PREDICATES #3556 ADDS (2026-09-21).
  (B) a cert-doc edit satisfies the hatch ONLY if the STATUS line or the
      Binds-to line changed between the range start (merge-base; on a
      pull_request the merge commit's first parent) and the judged commit (a
      re-issue rebinds; a voiding record flips STATUS; prose does neither).
  (C) at the judged commit, a banner that says LIVE bound to <sha> must have
      NO wire-surface drift between <sha> and that commit (paths and
      AI_MEMORY_FED_* identifiers); STATUS VOID or EXPIRED makes no live claim
      and is never failed by (C). Drift is a TREE comparison (`git diff <sha>
      <commit>`), so ancestry is not required; an unparseable banner or a
      bound SHA absent from the repository is fail-closed.

THE AMENDMENT LEDGER (#6124, 2026-11-13). While STATUS is VOID or EXPIRED at
both ends, (B) has one more honest pass: the change appends NEW dated records
to the ledger under LEDGER_MARKER at the end of the cert doc, and those records
together name exactly every changed watched path and every added or removed
AI_MEMORY_FED_* identifier (a missing or an extra name fails). The ledger is
append-only (an edited, reordered or removed base record fails), dated within
[LEDGER_DATE_FLOOR, runner UTC date + LEDGER_DATE_SKEW_DAYS] with dates that never
decrease, and parsed as a canonical Markdown subset: anything unrecognised in or
before the region is a refusal (default deny). An amendment never discharges the
cert: the STATUS word stays VOID/EXPIRED (a VOID <-> EXPIRED flip is routed here,
never to the re-issue path), the STATUS line is frozen byte for byte except that
token (3-agent vote 71472661, v9274-status), LIVE behaviour is unchanged, and any
change of Binds-to while both ends are VOID/EXPIRED, a drop to `-` included, is
refused (#6774 option B narrowed). Before ANY pass decision one clean-banner
precondition (clean_banner) proves both ends carry exactly one strict STATUS line,
at most one strict Binds-to line and no banner-like line the strict grammar did not
consume.

WHAT THIS DOES NOT CLAIM. A value-only edit of an existing AI_MEMORY_FED_*
identifier in a file outside the three path watches does not trip the
identifier check. This gate does not re-run 5.4(2)-(5); it only forces the
cert-doc to be touched so a human/re-issue cannot be skipped.

Usage:
  scripts/check_cert_expiry.py              # against the resolved range
  scripts/check_cert_expiry.py --self-test  # runs the external corpus (below)

External corpus and ratchet (#6445). The plant-a-violation cells and one
case per member of the cert-expiry defect class live OUTSIDE this gate, in
scripts/ci/tests/test_check_cert_expiry_corpus.py. Every case builds its own
scratch git repository, so no case can depend on another, and a crash in one is
a named failure while the rest still run. `--self-test` is a thin runner over
that corpus. scripts/qc-allowlists/cert-expiry-corpus-manifest.txt records each
case as GREEN (must pass) or RED (known gap, expectedFailure); the corpus's
ratchet test fails when a case name is deleted or a GREEN case is flipped to RED.

Exit codes: 0 clean / N/A-skip, 1 violation, 2 usage / self-test failure.
"""

import argparse
import ast
import contextlib
import datetime
import errno
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from collections import namedtuple
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CERT_DOC = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
FED_ID_PATTERN = "AI_MEMORY_FED_[A-Z0-9_]+"
FED_ID_RE = re.compile(FED_ID_PATTERN)
ZERO_SHA_RE = re.compile(r"^0+$")
PREFIX = "check-cert-expiry"
# Every sha taken from the environment is exactly 40 (SHA-1) or 64 (SHA-256)
# hex chars (#6138 S-F2, R2-1), matched with `fullmatch` so a trailing newline
# or an abbreviation (which git would resolve as a ref name) is refused before
# any git call, and an option-shaped value can never reach a git argv.
ENV_SHA_RE = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?")
# `--end-of-options` is passed ahead of positional refs. `git rev-parse`
# learned it only in git 2.30 (git RelNotes/2.30.0.txt:74-76); fetch,
# merge-base, diff, show and rev-list had it since 2.24. The floor is the
# newest of those, because the gate calls `rev-parse --verify` throughout.
MIN_GIT_VERSION = (2, 30)
REGULAR_FILE_MODES = ("100644", "100755")  # ls-tree modes read_blob accepts as a file

# POSIX [[:space:]] spelled out so a Unicode space cannot widen the match.
_S = r"[ \t\r\n\f\v]"
# The banner patterns are TOLERANT of formatting (#3556 ruling, fix 3):
# optional blockquote, one to three '#', flexible whitespace, em dash / en dash
# / hyphen, optional backticks, case-insensitive hex. They are anchored at line
# start and require the heading marker / the bold "Binds to", so the section 7
# history records that QUOTE these words in prose do not match.
#
# #6124 round 1 (3-agent vote 71472661, v9274-status): both patterns run on the raw BYTES
# of one line, and only on a line of at most BANNER_MAX_LINE_BYTES, so no input reaches a
# regex unbounded (the old Binds pattern was quadratic on a long whitespace run). The
# STATUS token is case-sensitive from the fixed set with the fixed terminator " as of ",
# so VOIDED, VOID-LIVE, VOIDLIVE and void never read as VOID. The Binds pattern has no
# two adjacent optional whitespace runs (each ':' carries its own trailing run).
_SB = rb"[ \t\r\n\f\v]"
STATUS_LINE_RE = re.compile(
    rb"^>?" + _SB + rb"*#{1,3}" + _SB + rb"*(?i:STATUS)" + _SB
    + "*(?:—|–|-)".encode("utf-8") + _SB + rb"*\*\*" + _SB
    + rb"*(LIVE|VOID|EXPIRED)(?= as of )"
)
BINDS_LINE_RE = re.compile(
    rb"^>?" + _SB + rb"*\*\*" + _SB + rb"*Binds" + _SB + rb"+to" + _SB + rb"*(?::" + _SB
    + rb"*)?\*\*" + _SB + rb"*(?::" + _SB + rb"*)?`?([0-9a-fA-F]{40})`?",
    re.IGNORECASE,
)
BANNER_MAX_LINE_BYTES = 4096
STATUS_TOKENS = (b"LIVE", b"VOID", b"EXPIRED")
# The looser detector (I1): after case-folding (format characters removed, every Unicode
# space read as a space), a line that names "status" followed only by these separators and
# then a status word or an emphasis star, or names "bind(s) to" followed by ':', '*', '`'
# or a run of LOOSE_HEX_RUN hex digits, is banner-like. Any such line the strict grammar
# did not consume is a decoy and a refusal.
LOOSE_STATUS_WORDS = ("live", "void", "expired")
LOOSE_STATUS_SEP = frozenset(" :=—–-*_~`>|#")
LOOSE_BINDS_SEP = frozenset(" -_*~`")
LOOSE_BINDS_AFTER = frozenset(":*`")
LOOSE_HEX = frozenset("0123456789abcdef")
LOOSE_HEX_RUN = 7
Banner = namedtuple("Banner", "status bound status_raw status_line token_span binds_raw problems")
ABSENT_BANNER = Banner("ABSENT", "-", None, None, None, (), ())

EXPIRY_SENTENCE = (
    "federation-wire surface changed → the enterprise-federation certification "
    "expires per its §7 → re-issue or void the cert doc in this same change."
)

# Rule (B) amendment ledger (#6124). While the certification is VOID or EXPIRED at both
# ends of the range, a federation-wire change passes only when the head doc appends new
# dated records, under this exact marker line at the end of the doc, that name exactly the
# changed watched paths and AI_MEMORY_FED_* identifiers. The ledger is a canonical subset
# of Markdown: anything the parser does not positively recognise is a refusal (design B,
# 3-agent vote 71472661).
LEDGER_MARKER = "## Amendment ledger (rule B, append-only)"
LEDGER_RECORD_RE = re.compile(r"### Amendment ([0-9]{4}-[0-9]{2}-[0-9]{2})")
LEDGER_ITEM_RE = re.compile(r"- (?:id: (" + FED_ID_PATTERN + r")|path: ([!-~]+))")
LEDGER_DATE_FLOOR = datetime.date(2026, 11, 13)
LEDGER_DATE_SKEW_DAYS = 1  # a record may carry the runner's UTC date plus this
LEDGER_MAX_DOC_BYTES = 8 * 1024 * 1024
LEDGER_MAX_LINE_BYTES = 256
LEDGER_STATUSES = ("VOID", "EXPIRED")
# Unicode categories refused anywhere in the doc: controls (LF excepted), format
# characters (zero-width, bidi, BOM), line/paragraph separators, private use, unassigned.
LEDGER_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cn", "Cs"})
LEDGER_SUSPECT_RE = re.compile(r"[^\n\x20-\x7e]")
# Leading blockquote markers, list markers and spaces: what a line is nested in.
LEDGER_CONTAINER_RE = re.compile(r"(?:[ >]|[-*+](?=[ ]|$)|[0-9]{1,9}[.)](?=[ ]|$))*")
LEDGER_FENCE_RE = re.compile(r"(`{3,}|~{3,})(.*)")
LEDGER_HTML_START_RE = re.compile(r"<[A-Za-z!?/]")
LEDGER_FRONT_MATTER = ("---", "+++")
LedgerRecord = namedtuple("LedgerRecord", "line lines names")
# The canonical item order the parser enforces, named in the refusal and in the cert doc (I5).
LEDGER_ITEM_ORDER = (
    "'- id:' lines before '- path:' lines, each group in ascending byte order, no duplicates")
# F3: the path item grammar is printable ASCII without spaces; the cert doc states it.
LEDGER_PATH_RESTRICTION = (
    "A '- path:' item names one section 7 watched path spelled in printable ASCII "
    "with no space; a watched path outside that form cannot be named and needs a re-issue.")
# I4: tokens refused inside a construct above the marker that could render as a record or
# a banner, and the constructs' shapes (each applied only to a line already under the cap).
PRE_REGION_TOKENS = ("amendment", "status")
PRE_SETEXT_RE = re.compile(r" {0,3}(?:=+|-+) *")
PRE_LINK_REF_RE = re.compile(r" {0,3}\[[^\]]*\]:")
# A line's container prefix above the ledger: block-quote marks, indentation and list
# bullets (nested in any order); it is blanked before the emphasis scan.
PRE_CONTAINER_RE = re.compile(r"(?:[ \t>]|[*+-][ \t]|[0-9]{1,9}[.)][ \t])+")
PRE_TOKEN_RE = re.compile(r"amendment|status", re.IGNORECASE)


class GateError(Exception):
    """Evidence is missing or ambiguous: the gate fails closed."""


class LedgerError(GateError):
    """The amendment ledger on one side of the range is not in the canonical form."""

    def __init__(self, reason, line, side):
        self.reason = reason
        self.line = line
        self.side = side
        where = f"at {CERT_DOC}:{line}" if line else f"in {CERT_DOC}"
        super().__init__(f"amendment ledger ({side}): {reason} {where}")


# ---------------------------------------------------------------------------
# git plumbing
# ---------------------------------------------------------------------------


def _git_env():
    # Resolve the requested repository, not an inherited worktree/index override.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    return env


def run_git(repo, *args, timeout=120):
    """Run git in `repo`; returns CompletedProcess with bytes output."""
    try:
        return subprocess.run(
            ["git", "-c", "core.quotePath=false", "-C", str(repo), *args],
            capture_output=True, env=_git_env(), timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"git {args[0] if args else ''} could not complete: {exc}") from exc


def git_text(repo, *args):
    """Stdout of a git command that must succeed, as stripped text."""
    proc = run_git(repo, *args)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git {args[0]} exited {proc.returncode}: {err}")
    return proc.stdout.decode("utf-8", "replace").strip()


def require_git_version(repo):
    """Fail closed unless `git rev-parse` understands `--end-of-options` (>= 2.30)."""
    text = git_text(repo, "--version")
    m = re.match(r"git version (\d+)\.(\d+)", text)
    if not m or (int(m.group(1)), int(m.group(2))) < MIN_GIT_VERSION:
        need = ".".join(str(n) for n in MIN_GIT_VERSION)
        raise GateError(f"git >= {need} is required for --end-of-options (got {text!r})")


def env_sha(env, key):
    """The sha in env[key], exactly 40 or 64 hex chars (S-F2, R2-1, fail-closed)."""
    val = env.get(key, "")
    if not ENV_SHA_RE.fullmatch(val):
        raise GateError(f"{key} {val!r} is not exactly 40 or 64 hex characters (fail-closed)")
    return val


def is_commit(repo, ref):
    return run_git(
        repo, "rev-parse", "--verify", "--quiet", "--end-of-options", ref + "^{commit}",
    ).returncode == 0


def ensure_commit(repo, sha):
    """Fetch SHA if it is not yet a local commit; True iff it resolves."""
    if is_commit(repo, sha):
        return True
    run_git(repo, "fetch", "--no-tags", "--quiet", "--end-of-options", "origin", sha)
    return is_commit(repo, sha)


def resolve_merge_base(repo, a, b):
    """merge-base of a and b; deepen a shallow clone once. None if unresolvable."""
    proc = run_git(repo, "merge-base", "--end-of-options", a, b)
    if proc.returncode == 0:
        return proc.stdout.decode().strip()
    shallow = run_git(repo, "rev-parse", "--is-shallow-repository")
    if shallow.stdout.decode().strip() == "true":
        if run_git(repo, "fetch", "--unshallow", "--quiet").returncode != 0:
            run_git(repo, "fetch", "--deepen=2147483647", "--quiet")
        ensure_commit(repo, a)
        ensure_commit(repo, b)
        proc = run_git(repo, "merge-base", "--end-of-options", a, b)
        if proc.returncode == 0:
            return proc.stdout.decode().strip()
    return None


# ---------------------------------------------------------------------------
# Path / identifier classifiers
# ---------------------------------------------------------------------------


def is_watched_path(path):
    """True iff `path` is on the section 7 federation-wire surface."""
    return (
        path == "src/federation"
        or path.startswith("src/federation/")
        or path == "src/handlers/federation_receive.rs"
        or path == "src/handlers/federation_signing_check.rs"
    )


def changed_paths(repo, frm, to):
    """Raw NUL-delimited changed paths. --no-renames so a move of a watched
    file cannot hide as an unwatched destination-only name; -z so a non-ASCII
    or newline-bearing name cannot be C-quoted past the path globs."""
    proc = run_git(repo, "diff", "--name-only", "-z", "--no-renames", "--end-of-options", frm, to)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git diff {frm} {to} exited {proc.returncode}: {err}")
    return [p.decode("utf-8", "replace") for p in proc.stdout.split(b"\0") if p]


def extract_fed_ids(repo, tree):
    """Unique AI_MEMORY_FED_* identifiers in src/ at TREE (set of str)."""
    # -a scans every blob as text: -I would take its binary/text decision from
    # attributes (a head's .gitattributes `binary` line could hide a new id,
    # #6174). The attributes file is also neutralised and textconv is off, so
    # the match is on the raw tree-object bytes only.
    proc = run_git(
        repo, "-c", "core.attributesFile=/dev/null", "grep", "-h", "-a", "--no-textconv",
        "-E", FED_ID_PATTERN, tree, "--", "src",
    )
    if proc.returncode == 1:  # no match
        return set()
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git grep at {tree} exited {proc.returncode}: {err}")
    return set(FED_ID_RE.findall(proc.stdout.decode("utf-8", "replace")))


def wire_drift(repo, frm, to):
    """Section 7 surface that differs between two trees: watched paths, then
    +added / -removed AI_MEMORY_FED_* identifiers. Empty list = no drift."""
    out = [p for p in changed_paths(repo, frm, to) if is_watched_path(p)]
    from_ids = extract_fed_ids(repo, frm)
    to_ids = extract_fed_ids(repo, to)
    out.extend("+" + i for i in sorted(to_ids - from_ids))
    out.extend("-" + i for i in sorted(from_ids - to_ids))
    return out


def read_blob(repo, tree, path):
    """The bytes of the regular file PATH at TREE, or None when PATH is provably absent
    there (#6977). Fail-closed: `git ls-tree` exiting 0 with empty output is the ONLY
    proof of absence. Any git failure (unresolvable tree, missing or corrupt object,
    timeout), a non-file entry (directory, symlink, submodule) or an unreadable blob
    raises GateError, so a read error can never be mistaken for a missing file."""
    listed = run_git(repo, "ls-tree", "-z", "--full-tree", "--end-of-options", tree, path)
    if listed.returncode != 0:
        err = listed.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git ls-tree {tree} {path} exited {listed.returncode}: {err}")
    entries = [e for e in listed.stdout.split(b"\0") if e]
    if not entries:
        return None
    if len(entries) != 1:
        raise GateError(f"git ls-tree {tree} {path} listed {len(entries)} entries, expected one")
    meta, _, name = entries[0].partition(b"\t")
    fields = meta.decode("ascii", "replace").split(" ")
    if len(fields) != 3 or name.decode("utf-8", "replace") != path:
        raise GateError(f"git ls-tree {tree} {path} returned an unparseable entry")
    mode, kind, sha = fields
    if kind != "blob" or mode not in REGULAR_FILE_MODES:
        raise GateError(f"{path} at {tree} is a {kind} (mode {mode}), not a regular file")
    blob = run_git(repo, "cat-file", "blob", sha)
    if blob.returncode != 0:
        err = blob.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git cat-file blob {sha} ({path} at {tree}) exited {blob.returncode}: {err}")
    return blob.stdout


def loose_fold(text):
    """TEXT case-folded for the looser detector: format characters (zero-width, bidi)
    removed and every Unicode space read as one ASCII space."""
    kept = []
    for ch in text:
        if ch.isspace():
            kept.append(" ")
        elif unicodedata.category(ch) != "Cf":
            kept.append(ch)
    return "".join(kept).casefold()


def status_like(folded):
    """True iff FOLDED names 'status' followed only by separators and then a status word
    or an emphasis star. Linear: each scan step moves past the previous match."""
    at = folded.find("status")
    while at != -1:
        i = at + len("status")
        star = False
        while i < len(folded) and folded[i] in LOOSE_STATUS_SEP:
            star = star or folded[i] == "*"
            i += 1
        if star or folded.startswith(LOOSE_STATUS_WORDS, i):
            return True
        at = folded.find("status", i)
    return False


def binds_like(folded):
    """True iff FOLDED names 'bind' or 'binds', separators, 'to', then ':', '*', '`' or a
    run of LOOSE_HEX_RUN hex digits. Linear."""
    at = folded.find("bind")
    while at != -1:
        i = at + len("bind")
        if i < len(folded) and folded[i] == "s":
            i += 1
        while i < len(folded) and folded[i] in LOOSE_BINDS_SEP:
            i += 1
        if folded.startswith("to", i):
            j = i + 2
            while j < len(folded) and folded[j] == " ":
                j += 1
            if j < len(folded) and folded[j] in LOOSE_BINDS_AFTER:
                return True
            k = j
            while k < len(folded) and k - j < LOOSE_HEX_RUN and folded[k] in LOOSE_HEX:
                k += 1
            if k - j >= LOOSE_HEX_RUN:
                return True
        at = folded.find("bind", at + len("bind"))
    return False


def banner_scan(blob, capped):
    """The Banner of the cert doc BLOB (bytes, or None when absent). Every line is read as
    raw bytes; the strict patterns run only on a line within BANNER_MAX_LINE_BYTES, and the
    looser detector runs on what the strict grammar did not consume. PROBLEMS lists
    (reason, line) for every form the precondition refuses; the size cap applies when
    CAPPED (the head), before the split."""
    if blob is None:
        return ABSENT_BANNER
    if capped and len(blob) > LEDGER_MAX_DOC_BYTES:
        reason = f"the document is {len(blob)} bytes, over the {LEDGER_MAX_DOC_BYTES}-byte limit"
        return Banner("UNPARSEABLE", "-", None, None, None, (), ((reason, None),))
    statuses = []
    binds = []
    loose_status = []
    loose_binds = []
    for number, line in enumerate(blob.split(b"\n"), 1):
        rest = line
        if len(line) <= BANNER_MAX_LINE_BYTES:
            found = STATUS_LINE_RE.match(line)
            if found:
                statuses.append((number, line, found.span(1)))
                rest = line[found.end():]
            else:
                found = BINDS_LINE_RE.match(line)
                if found:
                    binds.append((number, line, found.group(1).decode("ascii").lower()))
                    rest = line[found.end():]
        folded = loose_fold(rest.decode("utf-8", "replace"))
        if status_like(folded):
            loose_status.append(number)
        if binds_like(folded):
            loose_binds.append(number)
    problems = []
    if len(statuses) > 1:
        problems.append(("a second STATUS line under the strict grammar", statuses[1][0]))
    if len(binds) > 1:
        problems.append(("a second Binds-to line under the strict grammar", binds[1][0]))
    problems.extend(("a STATUS-like line the strict grammar does not read", n) for n in loose_status)
    problems.extend(("a Binds-like line the strict grammar does not read", n) for n in loose_binds)
    problems.sort(key=lambda p: p[1])
    if not statuses:
        problems.append(("no STATUS line under the strict grammar", None))
    if len(statuses) + len(loose_status) > 1:
        status = "DUPLICATE"
    elif statuses:
        status = statuses[0][1][slice(*statuses[0][2])].decode("ascii")
    else:
        status = "UNPARSEABLE"
    if len(binds) + len(loose_binds) > 1:
        bound = "DUPLICATE"
    elif binds and not loose_binds:
        bound = binds[0][2]
    else:
        bound = "-"
    first = statuses[0] if statuses else (None, None, None)
    return Banner(status, bound, first[1], first[0], first[2],
                  tuple(b[1] for b in binds), tuple(problems))


def scan_banner(repo, tree, capped):
    return banner_scan(read_blob(repo, tree, CERT_DOC), capped)


def cert_banner(repo, tree):
    """(STATUS, BINDS) of the cert doc at TREE.

    STATUS: LIVE | VOID | EXPIRED | UNPARSEABLE (doc present, no strict STATUS line)
    | DUPLICATE (two or more STATUS lines, a STATUS-like decoy included: a decoy above the
    real banner must not be read as the banner) | ABSENT (no doc at TREE).
    BINDS: the lowercase 40-hex bound SHA, "-" when no strict Binds-to line matches,
    "DUPLICATE" when two or more Binds-to or Binds-like lines do.
    """
    found = scan_banner(repo, tree, capped=True)
    return (found.status, found.bound)


BANNER_UNPARSEABLE_TEXT = (
    "{PREFIX}: ERROR — {CERT_DOC} at {where} has no parseable STATUS line. "
    "Expected a line shaped like '> ## STATUS — **LIVE as of …**' "
    "(blockquote, heading level, dash style, spacing and hex case are "
    "tolerated). If this change reformatted the banner, restore that "
    "shape; if it removed the banner, the document must say LIVE, VOID "
    "or EXPIRED. Fail-closed, #3556."
)
BANNER_DUPLICATE_TEXT = (
    "{PREFIX}: ERROR — {CERT_DOC} at {where} has two or more STATUS banner "
    "lines; the gate reads exactly one and will not guess which is the "
    "banner (a decoy line above the real banner is how a stale LIVE "
    "could be read as VOID). Remove the duplicate. Fail-closed, #3556."
)
BINDS_DUPLICATE_TEXT = (
    "{PREFIX}: ERROR — {CERT_DOC} at {where} has two or more Binds-to "
    "lines; the gate reads exactly one and will not guess which SHA the "
    "LIVE claim binds to. Remove the duplicate. Fail-closed, #3556."
)
BANNER_MALFORMED_TEXT = (
    "The cert doc at {where} does not carry exactly one STATUS banner line "
    "and at most one Binds-to line (parsed: {parsed}) — "
    "the gate reads one banner and will not guess; a duplicated, look-alike or "
    "unparseable banner is not a re-issue, not a voiding record and not an "
    "amendment (#3556)."
)


def banner_text(template, where):
    return template.format(PREFIX=PREFIX, CERT_DOC=CERT_DOC, where=where)


class BannerError(GateError):
    """I1: the banner at one end of the range is not exactly one clean STATUS line and
    at most one clean Binds-to line."""

    def __init__(self, reason, line, side, banner):
        self.reason = reason
        self.line = line
        self.side = side
        self.banner = banner
        where = f"at {CERT_DOC}:{line}" if line else f"in {CERT_DOC}"
        super().__init__(f"banner ({side}): {reason} {where}")

    def lines(self):
        where = "HEAD" if self.side == "head" else "the range start"
        out = [f"{PREFIX}: ERROR — {self}" + " (fail-closed)"]
        # The #3556 text follows the parsed status, so a lone decoy line (no strict line
        # at all) reads UNPARSEABLE, never "two or more STATUS banner lines".
        if self.banner.status == "UNPARSEABLE":
            out.append(banner_text(BANNER_UNPARSEABLE_TEXT, where))
        elif self.banner.status == "DUPLICATE":
            out.append(banner_text(BANNER_DUPLICATE_TEXT, where))
        elif "Binds" in self.reason:
            out.append(banner_text(BINDS_DUPLICATE_TEXT, where))
        out.append(BANNER_MALFORMED_TEXT.format(
            where=where, parsed=fmt_banner((self.banner.status, self.banner.bound))))
        return out


def clean_banner(banner_mb, banner_head):
    """I1, the ONE clean-banner precondition: at both ends the doc is absent or carries
    exactly one strict STATUS line, at most one strict Binds-to line and no banner-like
    line the strict grammar did not consume. Raises BannerError for the first problem."""
    for side, banner in (("base", banner_mb), ("head", banner_head)):
        if banner.problems:
            reason, line = banner.problems[0]
            raise BannerError(reason, line, side, banner)


def frozen_status(banner_mb, banner_head):
    """B-1 / B-2: while both ends are VOID or EXPIRED the STATUS line is frozen. It is
    byte-identical at both ends, or only the status token differs (VOID <-> EXPIRED)."""
    if banner_mb.status_raw == banner_head.status_raw:
        return
    if banner_mb.status != banner_head.status:
        lo, hi = banner_mb.token_span
        token = banner_head.status.encode("ascii")
        if banner_mb.status_raw[:lo] + token + banner_mb.status_raw[hi:] == banner_head.status_raw:
            return
    raise GateError(
        f"the STATUS line at {CERT_DOC}:{banner_head.status_line} is frozen while the "
        "certification is not LIVE: on an amendment pass it must be byte-identical to the "
        "range start (only the status word may change, between VOID and EXPIRED); put the "
        "reason for the change in the amendment ledger record (#6124, 3-agent vote 71472661)"
    )


def fmt_banner(banner):
    return f"{banner[0]} {banner[1]}"


# ---------------------------------------------------------------------------
# Rule (B) amendment ledger (#6124)
# ---------------------------------------------------------------------------


def _strip_container(line):
    """(prefix, rest): the leading quote/list/space markers and what follows them."""
    end = LEDGER_CONTAINER_RE.match(line).end()
    return line[:end], line[end:]


def _names_amendment(rest):
    return rest.startswith("#") and "amendment" in rest.casefold()


def ledger_present(blob, capped=True):
    """True iff any line of BLOB (bytes) looks like a heading naming an amendment, so
    the doc must be parsed as carrying a ledger. A doc without one has no records. When
    CAPPED (the head), a doc over LEDGER_MAX_DOC_BYTES is present, so parse_ledger refuses
    it on its size before any split (F4)."""
    if capped and len(blob) > LEDGER_MAX_DOC_BYTES:
        return True
    for line in blob.split(b"\n"):
        rest = line.lstrip(b" >*+-0123456789.)")
        if rest.startswith(b"#") and b"amendment" in rest.lower():
            return True
    return False


def _names_token(text):
    folded = text.casefold()
    return any(token in folded for token in PRE_REGION_TOKENS)


def _blank_code_spans(line):
    """LINE with every inline code span (a backtick run up to the next run of the same
    length) replaced by spaces. Linear: each run is visited once per length bucket."""
    runs = [(m.start(), m.end()) for m in re.finditer(r"`+", line)]
    by_length = {}
    for index, (lo, hi) in enumerate(runs):
        by_length.setdefault(hi - lo, []).append(index)
    cursor = dict.fromkeys(by_length, 0)
    out = list(line)
    index = 0
    while index < len(runs):
        lo, hi = runs[index]
        bucket = by_length[hi - lo]
        while cursor[hi - lo] < len(bucket) and bucket[cursor[hi - lo]] <= index:
            cursor[hi - lo] += 1
        if cursor[hi - lo] == len(bucket):
            index += 1
            continue
        close = bucket[cursor[hi - lo]]
        for k in range(lo, runs[close][1]):
            out[k] = " "
        index = close + 1
    return "".join(out)


def _is_punct(ch):
    return unicodedata.category(ch)[0] in "PS"


def _delimiter_runs(text):
    """The emphasis delimiter runs of TEXT as [char, start, end, can_open, can_close]:
    maximal runs of '*' or '_' that are not backslash-escaped, with the CommonMark
    left/right-flanking rules ('_' may not open or close inside a word). Linear."""
    runs = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch not in "*_" or (i > 0 and text[i - 1] == "\\"):
            i += 1
            continue
        j = i
        while j < len(text) and text[j] == ch:
            j += 1
        before = text[i - 1] if i > 0 else " "
        after = text[j] if j < len(text) else " "
        left = not after.isspace() and (
            not _is_punct(after) or before.isspace() or _is_punct(before))
        right = not before.isspace() and (
            not _is_punct(before) or after.isspace() or _is_punct(after))
        if ch == "*":
            can_open, can_close = left, right
        else:
            can_open = left and (not right or _is_punct(before))
            can_close = right and (not left or _is_punct(after))
        runs.append([ch, i, j, can_open, can_close])
        i = j
    return runs


def _emphasis_hit(paragraph):
    """The line number of the first emphasis span in PARAGRAPH ((number, line) pairs)
    that names an amendment or a status, or None. Container prefixes ('>', a list bullet)
    are blanked and a line left empty by that ends the paragraph; code spans are blanked.
    Delimiter runs pair as in the CommonMark process-emphasis step (nearest opener of the
    same character, the rule of 3, partial consumption of a run, openers between a pair
    dropped, a per-key bottom so a failed look-back is never repeated): linear in the
    paragraph. Every byte between a paired opener and closer is emphasis; a token that
    starts inside any such span is a hit."""
    for pieces in _emphasis_blocks(paragraph):
        hit = _emphasis_hit_flat(pieces)
        if hit:
            return hit
    return None


def _emphasis_blocks(paragraph):
    """The inline blocks of PARAGRAPH as lists of (number, prepared text): code spans and
    the container prefix blanked to spaces (same length), split where a line is empty
    after that."""
    blocks = []
    pieces = []
    for number, line in paragraph:
        text = _blank_code_spans(line)
        container = PRE_CONTAINER_RE.match(text)
        if container:
            text = " " * container.end() + text[container.end():]
        if not text.strip():
            if pieces:
                blocks.append(pieces)
            pieces = []
            continue
        pieces.append((number, text))
    if pieces:
        blocks.append(pieces)
    return blocks


def _emphasis_spans(pieces):
    """(joined text, [(offset, line number)], [(opener lo, opener hi, closer lo, closer hi)])
    for PIECES ((number, prepared text) pairs), offsets in the joined text."""
    flat = []
    owner = []
    runs = []
    offset = 0
    for number, text in pieces:
        for run in _delimiter_runs(text):
            run[1] += offset
            run[2] += offset
            runs.append(run)
        flat.append(text)
        owner.append((offset, number))
        offset += len(text) + 1
    joined = "\n".join(flat)
    spans = []
    # Each run: [char, start, end, can_open, can_close, remaining, original, sequence].
    stack = []
    bottom = {}
    for sequence, run in enumerate(runs):
        run.extend([run[2] - run[1], run[2] - run[1], sequence])
        ch, _, _, can_open, can_close = run[:5]
        if can_close:
            key = (ch, can_open, run[6] % 3)
            floor = bottom.get(key, -1)
            k = len(stack) - 1
            while run[5] > 0 and k >= 0 and stack[k][7] > floor:
                opener = stack[k]
                if opener[0] != ch:
                    k -= 1
                    continue
                both = (opener[3] and opener[4]) or (can_open and can_close)
                if both and (opener[6] + run[6]) % 3 == 0 and not (
                        opener[6] % 3 == 0 and run[6] % 3 == 0):
                    k -= 1
                    continue
                used = min(2 if opener[5] >= 2 and run[5] >= 2 else 1, opener[5], run[5])
                lo = opener[1] + opener[5] - used
                hi = run[1] + (run[6] - run[5]) + used
                spans.append((lo, lo + used, hi - used, hi))
                opener[5] -= used
                run[5] -= used
                del stack[k + 1:]
                if opener[5] == 0:
                    del stack[k]
                k = len(stack) - 1
            if run[5] > 0:
                bottom[key] = sequence - 1
        if can_open and run[5] > 0:
            stack.append(run)
    return joined, owner, spans


def _emphasis_hit_flat(pieces):
    if not pieces:
        return None
    joined, owner, spans = _emphasis_spans(pieces)
    cover = [0] * (len(joined) + 1)
    for lo, _, _, hi in spans:
        cover[lo] += 1
        cover[hi] -= 1
    depth = 0
    covered = [0]  # covered[i]: how many of the first i characters are inside emphasis
    for i in range(len(joined)):
        depth += cover[i]
        covered.append(covered[-1] + (depth > 0))
    for found in PRE_TOKEN_RE.finditer(joined):
        if covered[found.end()] > covered[found.start()]:
            at = found.start()
            number = pieces[0][0]
            for start, owner_number in owner:
                if start <= at:
                    number = owner_number
            return number
    return None


def _check_pre_region(lines, side):
    """Refuse every construct above the marker that could hide or fake a record or a
    banner (I4): default deny over a fixed safe subset. The per-line byte cap is checked
    before any regex touches the line."""
    if lines and lines[0] in LEDGER_FRONT_MATTER:
        raise LedgerError("front matter on line 1 is not supported", 1, side)
    for number, line in enumerate(lines, 1):
        if len(line.encode("utf-8")) > BANNER_MAX_LINE_BYTES:
            raise LedgerError(
                f"line longer than {BANNER_MAX_LINE_BYTES} bytes above the ledger", number, side)
    fence = None  # (char, length, opener line number) while a fence is open
    paragraph = []
    for number, line in enumerate(lines, 1):
        if line.count("<!--") > 1:
            raise LedgerError("a second '<!--' on one line above the ledger", number, side)
        prefix, rest = _strip_container(line)
        found = LEDGER_FENCE_RE.fullmatch(rest)
        if found and prefix:
            raise LedgerError(
                "a fence-like line inside a container or indented is not supported", number, side)
        if fence is not None:
            run, info = found.groups() if found else ("", "")
            if run and run[0] == fence[0] and len(run) >= fence[1] and not info.strip(" "):
                fence = None
            elif _names_token(line):
                raise LedgerError(
                    "a fence body naming an amendment or a status above the ledger", number, side)
            continue
        if found:
            run, info = found.groups()
            if run[0] == "`" and "`" in info:
                raise LedgerError(
                    "a fence opener with a backtick in its info string is not supported", number, side)
            fence = (run[0], len(run), number)
            hit = _emphasis_hit(paragraph)
            if hit:
                raise LedgerError(
                    "emphasis naming an amendment or a status above the ledger", hit, side)
            paragraph = []
            continue
        if LEDGER_HTML_START_RE.match(rest) and not (
                rest.startswith("<!--") and rest.find("-->", 4) != -1):
            raise LedgerError(
                "an HTML block start is not supported (only a one-line <!-- ... --> comment)",
                number, side)
        if "<!--" in line and line.rfind("-->") < line.rfind("<!--"):
            raise LedgerError("an HTML comment not closed on its line above the ledger", number, side)
        if LEDGER_HTML_START_RE.search(_blank_code_spans(line)) and _names_token(line):
            raise LedgerError("inline HTML naming an amendment or a status above the ledger",
                              number, side)
        if PRE_LINK_REF_RE.match(rest) and _names_token(line):
            raise LedgerError(
                "a link reference definition naming an amendment or a status above the ledger",
                number, side)
        if (number < len(lines) and line.strip() and PRE_SETEXT_RE.fullmatch(lines[number])
                and _names_token(line)):
            raise LedgerError(
                "a setext heading naming an amendment or a status above the ledger", number, side)
        if _names_amendment(rest):
            raise LedgerError("a heading-like line naming an amendment outside the ledger", number, side)
        if line.strip():
            paragraph.append((number, line))
        else:
            hit = _emphasis_hit(paragraph)
            if hit:
                raise LedgerError(
                    "emphasis naming an amendment or a status above the ledger", hit, side)
            paragraph = []
    if fence is not None:
        raise LedgerError("a fence opened here is still open at the ledger marker", fence[2], side)
    hit = _emphasis_hit(paragraph)
    if hit:
        raise LedgerError("emphasis naming an amendment or a status above the ledger", hit, side)
    if not lines or lines[-1] != "":
        raise LedgerError("the ledger marker must follow a blank line", len(lines) + 1, side)
    found = sum(1 for line in lines if STATUS_LINE_RE.match(line.encode("utf-8")))
    if found != 1:
        raise LedgerError(
            f"the STATUS banner must appear exactly once, above the ledger (found {found})", None, side)


def _parse_region(lines, first, side, watched_from):
    """Records of the ledger region LINES (the lines after the marker; FIRST is the
    1-based number of LINES[0]). The grammar, with no other form accepted:
        "" then zero or more records separated by one "" line;
        record = "### Amendment YYYY-MM-DD", "", one or more sorted unique items;
        item = "- id: AI_MEMORY_FED_*" or "- path: <section 7 watched path>".
    Record dates never decrease (equal days allowed). A path item of record index
    WATCHED_FROM or later must be a watched path (None: no record is checked, the base)."""
    records = []
    state = "blank"
    heading = None
    items = []
    previous_day = None
    for number, line in enumerate(lines, first):
        if len(line.encode("utf-8")) > LEDGER_MAX_LINE_BYTES:
            raise LedgerError(f"line longer than {LEDGER_MAX_LINE_BYTES} bytes", number, side)
        if not line.isascii():
            raise LedgerError("character outside printable ASCII in the ledger", number, side)
        if state in ("blank", "hblank"):
            if line != "":
                raise LedgerError("expected a blank line", number, side)
            state = "head" if state == "blank" else "item1"
        elif state == "head":
            found = LEDGER_RECORD_RE.fullmatch(line)
            if not found:
                raise LedgerError("expected '### Amendment YYYY-MM-DD'", number, side)
            try:
                day = datetime.date.fromisoformat(found.group(1))
            except ValueError:
                raise LedgerError(f"date {found.group(1)} is not a calendar date", number, side) from None
            if day < LEDGER_DATE_FLOOR:
                raise LedgerError(
                    f"date {found.group(1)} is before the ledger floor {LEDGER_DATE_FLOOR.isoformat()}",
                    number, side)
            if previous_day is not None and day < previous_day:
                raise LedgerError(
                    f"record dated {day.isoformat()} is before the previous record dated "
                    f"{previous_day.isoformat()}; record dates must not decrease", number, side)
            previous_day = day
            heading = (number, line, day)
            items = []
            state = "hblank"
        else:  # "item1" or "items"
            if line == "" and state == "items":
                records.append(_record(heading, items))
                state = "head"
                continue
            found = LEDGER_ITEM_RE.fullmatch(line)
            if not found:
                raise LedgerError(
                    "expected an item line '- id: AI_MEMORY_FED_*' or '- path: <watched path>'",
                    number, side)
            path = found.group(2)
            checked = watched_from is not None and len(records) >= watched_from
            if path is not None and checked and not is_watched_path(path):
                raise LedgerError(f"path {path} is not a section 7 watched path", number, side)
            if items and line <= items[-1]:
                raise LedgerError(
                    f"item lines must be sorted and unique ({LEDGER_ITEM_ORDER}; "
                    "this line is not after the previous one)", number, side)
            items.append(line)
            state = "items"
    if state == "items":
        records.append(_record(heading, items))
    elif state == "head":
        raise LedgerError("trailing blank line at the end of the ledger", first + len(lines) - 1, side)
    elif state in ("hblank", "item1"):
        raise LedgerError("the record is incomplete at the end of the file", heading[0], side)
    return records


def _record(heading, items):
    names = tuple(item.split(": ", 1)[1] for item in items)
    return LedgerRecord(heading[0], (heading[1], *items), names)


def record_day(rec):
    return datetime.date.fromisoformat(LEDGER_RECORD_RE.fullmatch(rec.lines[0]).group(1))


def parse_ledger(blob, side, inherited=0):
    """The records (list of LedgerRecord) of the cert doc BLOB (bytes). Every form the
    parser does not positively recognise raises LedgerError with a reason and, where one
    applies, a 1-based line number. Linear in the size of BLOB. The base (F5) is judged
    for grammar only: no size cap and no watched-path check; the head checks the
    watched-ness of the records after the INHERITED base records only."""
    if side == "head" and len(blob) > LEDGER_MAX_DOC_BYTES:
        raise LedgerError(
            f"the document is {len(blob)} bytes, over the {LEDGER_MAX_DOC_BYTES}-byte limit", None, side)
    try:
        text = blob.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise LedgerError(f"not strict UTF-8 (invalid byte at offset {exc.start})", None, side) from None
    if not text.endswith("\n"):
        raise LedgerError("the document does not end with a line feed", None, side)
    for suspect in LEDGER_SUSPECT_RE.finditer(text):
        category = unicodedata.category(suspect.group())
        if category in LEDGER_FORBIDDEN_CATEGORIES:
            number = text.count("\n", 0, suspect.start()) + 1
            raise LedgerError(
                f"forbidden character U+{ord(suspect.group()):04X} ({category})", number, side)
    lines = text.split("\n")[:-1]
    markers = lines.count(LEDGER_MARKER)
    if markers != 1:
        raise LedgerError(
            f"the ledger marker line appears {markers} times, expected exactly once", None, side)
    at = lines.index(LEDGER_MARKER)
    _check_pre_region(lines[:at], side)
    return _parse_region(lines[at + 1:], at + 2, side, inherited if side == "head" else None)


def utc_today():
    """The runner's UTC date: the record date ceiling (L-1). A commit date is author-set,
    so it is never the clock. Tests replace this function."""
    return datetime.datetime.now(datetime.timezone.utc).date()


def judge_ledger(repo, mb, judged):
    """The NEW records (list) the change appends to the ledger, after proving the ledger
    append-only and every new record dated within [floor, runner UTC date + 1]."""
    base_blob = read_blob(repo, mb, CERT_DOC)
    head_blob = read_blob(repo, judged, CERT_DOC)
    base_on = base_blob is not None and ledger_present(base_blob, capped=False)
    head_on = head_blob is not None and ledger_present(head_blob)
    if not base_on and not head_on:
        return []
    base_records = parse_ledger(base_blob, "base") if base_on else []
    if not head_on:
        raise LedgerError("the ledger present at the range start is missing", None, "head")
    head_records = parse_ledger(head_blob, "head", inherited=len(base_records))
    for k, old in enumerate(base_records, 1):
        if k > len(head_records) or head_records[k - 1].lines != old.lines:
            raise LedgerError(
                f"record {k} of the base ledger ({old.lines[0]}) is edited, reordered or removed",
                old.line, "head")
    new = head_records[len(base_records):]
    if new:
        today = utc_today()
        ceiling = today + datetime.timedelta(days=LEDGER_DATE_SKEW_DAYS)
        for rec in new:
            day = record_day(rec)
            if day > ceiling:
                raise LedgerError(
                    f"record dated {day.isoformat()} is after the runner's UTC date "
                    f"{today.isoformat()} plus {LEDGER_DATE_SKEW_DAYS} day", rec.line, "head")
    return new


def check_amendment_names(new_records, changed):
    """The union of names in the new records must equal CHANGED exactly."""
    named = {name for rec in new_records for name in rec.names}
    missing = sorted(changed - named)
    if missing:
        raise LedgerError(
            f"the new amendment records do not name changed {', '.join(missing)}", None, "head")
    extra = sorted(named - changed)
    if extra:
        raise LedgerError(
            f"a new amendment record names {', '.join(extra)}, which this change did not touch",
            None, "head")


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


def check_banner_consistency(repo, judged):
    """(C) #3556: the doc's own claim at `judged` must be true. STATUS LIVE
    bound to <sha> means no section 7 wire-surface drift between <sha> and
    `judged`. Returns (ok, lines)."""
    status, binds = cert_banner(repo, judged)
    if status == "ABSENT":
        return True, [f"{PREFIX}: banner — {CERT_DOC} absent at HEAD; no live claim to check"]
    if status == "UNPARSEABLE":
        return False, [banner_text(BANNER_UNPARSEABLE_TEXT, "HEAD")]
    if status == "DUPLICATE":
        return False, [banner_text(BANNER_DUPLICATE_TEXT, "HEAD")]
    if status in ("VOID", "EXPIRED"):
        return True, [
            f"{PREFIX}: banner STATUS={status} — the doc makes no live claim; "
            "nothing to hold it to"
        ]
    # LIVE
    if binds == "-":
        return False, [
            f"{PREFIX}: ERROR — {CERT_DOC} at HEAD says STATUS LIVE but has no "
            "parseable Binds-to line. Expected a line shaped like "
            "'**Binds to:** `<40-hex sha>`' (spacing, backticks and hex case are "
            "tolerated). Fail-closed, #3556."
        ]
    if binds == "DUPLICATE":
        return False, [banner_text(BINDS_DUPLICATE_TEXT, "HEAD")]
    if not ensure_commit(repo, binds):
        return False, [
            f"{PREFIX}: ERROR — banner is LIVE bound to {binds} but that commit "
            "is not in this repository, so the claim cannot be checked "
            "(fail-closed, #3556)"
        ]
    # Ancestry is deliberately NOT required: `git diff <binds> <judged>` is a
    # tree-to-tree comparison, so a squash-merge whose watched surface equals
    # the bound tree passes on zero drift, and a bind pointed at some
    # unrelated commit (an evasion) reds on the drift it carries.
    drift = wire_drift(repo, binds, judged)
    if not drift:
        return True, [
            f"{PREFIX}: PASS — banner LIVE bound to {binds}; federation-wire "
            "surface unchanged since the bind (#3556)"
        ]
    lines = [
        f"the enterprise-federation certification claims LIVE bound to {binds} "
        f"but {len(drift)} federation-wire change(s) landed since → the "
        "certification expired per its §7 while its banner still says LIVE → "
        f"re-issue it at HEAD or record VOID/EXPIRED in {CERT_DOC}.",
        "",
        f"Bound: {binds}  HEAD: {judged}",
        ("Federation-wire drift since the bind (paths; +added / -removed "
         "AI_MEMORY_FED_* identifiers):"),
    ]
    lines.extend("  " + d for d in drift)
    lines.append("")
    lines.append(
        f"Remedy: re-run §5.4(2)–(5) at HEAD and rebind {CERT_DOC}, or set its "
        "STATUS line to VOID/EXPIRED (#3556)."
    )
    return False, lines


def pr_base_tip(repo, base, head, tip, base_name=None):
    """Validate the pull_request merge commit and return its first parent.

    The merge commit must have exactly two parents; its second parent must be
    PR_HEAD_SHA (#6138 S-F7); its first parent must be on the live base branch
    (an ancestor of, or equal to, the live tip). The first parent need not be
    the live tip: a landing on the base after the merge ref was built does not
    change what the PR contributes, so the gate stays green and measures
    first parent..merge commit (#6138 F1; strictly tighter than the landed
    gate, no vote). Anything else is not the PR's merge result (fail-closed).
    `base_name` (origin/<GITHUB_BASE_REF>) only labels the messages.
    """
    parents = git_text(repo, "rev-list", "--parents", "-n", "1", "--end-of-options", tip).split()
    if len(parents) != 3:
        raise GateError(
            f"merge commit {tip} does not have exactly two parents "
            "(not a pull_request merge result)"
        )
    first, second = parents[1], parents[2]
    head_full = git_text(repo, "rev-parse", "--verify", "--end-of-options", f"{head}^{{commit}}")
    if first == head_full:
        raise GateError(
            f"merge commit {tip} has the PR head {head_full} as its FIRST parent "
            "(reversed parents: the base branch must be the first parent); "
            "push a new commit or sync the branch with the base so GitHub rebuilds "
            "the merge ref"
        )
    if second != head_full:
        raise GateError(
            f"merge commit {tip} second parent {second} is not PR_HEAD_SHA "
            f"{head_full} (not this PR's merge result)"
        )
    live = git_text(repo, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}")
    anc = run_git(repo, "merge-base", "--is-ancestor", "--end-of-options", first, live)
    if anc.returncode == 1:
        raise GateError(
            f"merge commit {tip} first parent {first} is not on the live base "
            f"{base_name or 'branch'} (tip {live}); the merge ref was not built from this base: "
            "push a new commit or sync the branch with the base so GitHub "
            "rebuilds the merge ref (a re-run reuses the same GITHUB_SHA)"
        )
    if anc.returncode != 0:
        err = anc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git merge-base --is-ancestor exited {anc.returncode}: {err}")
    return first


def check_change(repo, base, head, tip=None, base_name=None):
    """Judge the change. Without `tip` it is merge-base(base, head)..head. With
    `tip` (the pull_request merge commit, #6137) it is tip^1..tip, tip^1 being
    verified to lie on the live base and tip^2 to be the PR head. Returns
    (ok, text)."""
    judged = tip if tip else head
    refs = [base, head] + ([tip] if tip else [])
    if not all(is_commit(repo, r) for r in refs):
        return False, f"{PREFIX}: ERROR — cannot resolve range {base}..{judged} (fail-closed)"
    if tip:
        # #6137 (conductor decision): a pull_request's change is its effect on
        # the merged result, so (A)/(B) compare the merge commit's first parent
        # (on the base branch) with the merge commit. Base-side changes since
        # the fork point were judged when they landed on the base.
        try:
            mb = pr_base_tip(repo, base, head, tip, base_name)
        except GateError as exc:
            return False, f"{PREFIX}: ERROR — {exc} (fail-closed)"
    else:
        mb = resolve_merge_base(repo, base, head)
    if mb is None:
        return False, (
            f"{PREFIX}: ERROR — no merge-base for {base}..{head} "
            "(fail-closed; shallow checkout?)"
        )
    try:
        return _judge(repo, base, head, judged, mb, tip)
    except GateError as exc:
        return False, f"{PREFIX}: ERROR — {exc} (fail-closed)"


def _judge(repo, base, head, judged, mb, tip):
    watched = []
    cert_touched = False
    for p in changed_paths(repo, mb, judged):
        if p == CERT_DOC:
            cert_touched = True
        if is_watched_path(p):
            watched.append(p)
    base_ids = extract_fed_ids(repo, mb)
    head_ids = extract_fed_ids(repo, judged)
    added = sorted(head_ids - base_ids)
    removed = sorted(base_ids - head_ids)
    id_changed = bool(added or removed)

    # I1 (#6124 round 1): ONE clean-banner precondition, before ANY pass decision, while a
    # wire change, a strict banner line change, a new ledger record or a banner-like line at
    # the head is in the range. No pass path below re-checks the banner on its own.
    banner_mb = scan_banner(repo, mb, capped=False)
    banner_head = scan_banner(repo, judged, capped=True)
    strict_changed = (banner_mb.status_raw, banner_mb.binds_raw) != (
        banner_head.status_raw, banner_head.binds_raw)
    # The banner is judged BEFORE the ledger, so a malformed STATUS token (B-3) is refused
    # with the #3556 malformed reason, never with a ledger reason that hides it.
    banner_due = watched or id_changed or (cert_touched and (
        strict_changed or banner_head.problems))
    new_records = []
    try:
        if banner_due:
            clean_banner(banner_mb, banner_head)
        if cert_touched:
            new_records = judge_ledger(repo, mb, judged)
        if new_records and not banner_due:
            clean_banner(banner_mb, banner_head)
    except BannerError as exc:
        return False, "\n".join(exc.lines())
    if new_records:
        check_amendment_names(new_records, set(watched) | set(added) | set(removed))
    # I2 / I3: while both ends are VOID or EXPIRED, the bind never changes (a drop to "-"
    # included) and the STATUS line is frozen (B-1, B-2); a word flip is not a re-issue.
    both_ls = banner_mb.status in LEDGER_STATUSES and banner_head.status in LEDGER_STATUSES
    flip = both_ls and banner_mb.status != banner_head.status
    status_words = (f"goes {banner_mb.status} → {banner_head.status}" if flip
                    else f"stays {banner_head.status}")
    if cert_touched and both_ls:
        if banner_mb.bound != banner_head.bound:
            verb = ("set" if banner_mb.bound == "-" else
                    "dropped" if banner_head.bound == "-" else "changed")
            raise GateError(
                f"Binds-to {verb} ({banner_mb.bound} → {banner_head.bound}) while STATUS "
                f"{status_words}: an amendment never rebinds; re-issue as LIVE "
                "(#6774 option B narrowed)"
            )
        frozen_status(banner_mb, banner_head)

    if not watched and not id_changed:
        ok, more = check_banner_consistency(repo, judged)
        lines = [f"{PREFIX}: PASS — federation-wire surface unchanged in {mb}..{judged}"]
        return ok, "\n".join(lines + more)

    pair_mb = (banner_mb.status, banner_mb.bound)
    pair_head = (banner_head.status, banner_head.bound)
    # (B) #3556: the hatch is a REAL re-issue/voiding only if the banner
    # (STATUS line or Binds-to line) differs between merge-base and judged.
    incidental = cert_touched and pair_mb == pair_head
    # #3556 ruling, fix 2: a DELETED cert doc is not a voiding record.
    deleted = cert_touched and banner_head.status == "ABSENT"

    if both_ls and cert_touched and new_records:
        # #6124: the names match exactly, the bind is unchanged and the STATUS line is
        # frozen, so the certification stays non-LIVE (a VOID <-> EXPIRED flip included).
        ok, more = check_banner_consistency(repo, judged)
        head_line = (
            f"{PREFIX}: PASS — federation-wire surface changed AND a new amendment record "
            f"names every change ({mb}..{judged}); the certification {status_words} "
            "(an amendment never discharges it, #6124)"
        )
        return ok, "\n".join([head_line] + more)

    if cert_touched and not both_ls and not incidental and not deleted:
        ok, more = check_banner_consistency(repo, judged)
        head_line = (
            f"{PREFIX}: PASS — federation-wire surface changed AND cert doc "
            f"re-issued/voided in the same change ({mb}..{judged}; banner "
            f"{fmt_banner(pair_mb)} → {fmt_banner(pair_head)})"
        )
        return ok, "\n".join([head_line] + more)

    out = [EXPIRY_SENTENCE]
    if incidental:
        out.append(
            "The cert doc WAS edited in this change, but neither its STATUS line "
            f"nor its Binds-to line changed (banner {fmt_banner(pair_head)} at "
            "both ends) — an incidental edit is not a re-issue and not a voiding "
            "record (#3556)."
        )
    if flip:
        out.append(
            f"The STATUS word changed {banner_mb.status} → {banner_head.status}; a change "
            "between VOID and EXPIRED is not a re-issue and not a voiding record (#6124)."
        )
    if both_ls:
        out.append(
            "No new dated amendment record names this change; while the "
            "certification stays VOID/EXPIRED, a new '### Amendment YYYY-MM-DD' "
            f"record under the '{LEDGER_MARKER}' line naming every changed path and "
            "identifier is the only honest pass (#6124)."
        )
    if deleted:
        out.append(
            "The cert doc is ABSENT at HEAD (deleted in this change) while the "
            "federation-wire surface changed — deleting the certification is not "
            "a voiding record; record VOID/EXPIRED in the document instead (#3556)."
        )
    out.append("")
    if tip:
        out.append(
            f"Range: {mb}..{judged}  (first parent to the pull_request merge commit; "
            "judged at the pull_request merge commit)"
        )
    else:
        out.append(f"Range: {mb}..{judged}  (merge-base of {base} and {head})")
    if watched:
        out.append("Watched federation-wire paths touched:")
        out.extend("  " + w for w in watched)
    if id_changed:
        out.append("AI_MEMORY_FED_* identifiers added/removed/renamed in src/:")
        out.extend("  + " + a for a in added)
        out.extend("  - " + r for r in removed)
    out.append("")
    out.append(
        f"Remedy: modify {CERT_DOC} in this same change (re-issue against the "
        "new SHA, or record the voiding)."
    )
    return False, "\n".join(out)


# ---------------------------------------------------------------------------
# Range resolution
# ---------------------------------------------------------------------------


class Skip(Exception):
    """N/A: no range to check (not a failure)."""


def _need(env, key, why):
    val = env.get(key, "")
    if not val:
        raise GateError(f"{key} is unset on {why} (fail-closed)")
    return val


def resolve_live_base(repo, base_ref):
    """Sha of the LIVE base ref origin/<base_ref>, fetched explicitly if absent."""
    if base_ref.startswith("-") or ".." in base_ref or any(c.isspace() for c in base_ref):
        raise GateError(f"GITHUB_BASE_REF {base_ref!r} is not a plain branch name (fail-closed)")
    tracking = f"refs/remotes/origin/{base_ref}"
    if not is_commit(repo, tracking):
        run_git(
            repo, "fetch", "--no-tags", "--quiet", "--end-of-options", "origin",
            f"+refs/heads/{base_ref}:{tracking}",
        )
    if not is_commit(repo, tracking):
        raise GateError(
            f"cannot resolve the live base ref origin/{base_ref} (fetch failed; fail-closed)"
        )
    return git_text(repo, "rev-parse", "--verify", "--end-of-options", tracking + "^{commit}")


def resolve_range(repo, env):
    """(base, head, tip) for the change under test. tip is the commit that
    (B)/(C) are judged at (None = judge at head). Raises Skip / GateError."""
    event = env.get("GITHUB_EVENT_NAME", "")
    # #5970 (precedent: PR #5871 head 3be284991): inside GitHub Actions the
    # event payload names the range, so a CERT_EXPIRY_BASE / CERT_EXPIRY_HEAD
    # override is refused (even an empty one); outside CI it is honoured.
    in_ci = "GITHUB_ACTIONS" in env
    if in_ci:
        refused = [k for k in ("CERT_EXPIRY_BASE", "CERT_EXPIRY_HEAD") if k in env]
        if refused:
            raise GateError(
                f"refused (#5970, fail-closed): {', '.join(refused)} set in the gate's "
                "environment under GitHub Actions; the range comes only from the "
                "event payload"
            )
    if env.get("CERT_EXPIRY_BASE"):
        return env["CERT_EXPIRY_BASE"], env.get("CERT_EXPIRY_HEAD") or "HEAD", None

    if event == "pull_request":
        # #6137: judge the merge commit the job checked out, against the LIVE
        # base ref, not the (possibly stale) payload PR_BASE_SHA.
        _need(env, "PR_HEAD_SHA", "a pull_request event")
        head = env_sha(env, "PR_HEAD_SHA")
        base_ref = _need(env, "GITHUB_BASE_REF", "a pull_request event")
        tip = env_sha(env, "GITHUB_SHA") if env.get("GITHUB_SHA") else "HEAD"
        stale = env_sha(env, "PR_BASE_SHA") if env.get("PR_BASE_SHA") else ""
        base = resolve_live_base(repo, base_ref)
        if not is_commit(repo, head):
            ensure_commit(repo, head)
        if not is_commit(repo, head):
            raise GateError(f"PR_HEAD_SHA {head} does not resolve to a commit (fail-closed)")
        if not is_commit(repo, tip):
            raise GateError(f"merge commit {tip} does not resolve to a commit (fail-closed)")
        # The merge commit's parent structure (two parents, second parent ==
        # PR_HEAD_SHA, first parent on the live base) is verified in pr_base_tip.
        if stale and stale != base:
            print(
                f"{PREFIX}: note — payload PR_BASE_SHA {stale} differs from the live "
                f"base origin/{base_ref} {base}; using the live base (#6137)",
                file=sys.stderr,
            )
        return base, head, tip

    if event == "push":
        before = env.get("GITHUB_EVENT_BEFORE", "")
        if not before or ZERO_SHA_RE.match(before):
            raise Skip("push has no previous tip (new branch / first push); skip")
        before = env_sha(env, "GITHUB_EVENT_BEFORE")
        after = env_sha(env, "GITHUB_SHA") if env.get("GITHUB_SHA") else "HEAD"
        return before, after, None
    if event == "workflow_dispatch":
        raise Skip(
            "workflow_dispatch has no PR/push range (outside CI, CERT_EXPIRY_BASE/HEAD "
            "check a range by hand; they are refused under GitHub Actions); skip"
        )
    if event == "":
        if in_ci:
            raise GateError(
                "GITHUB_EVENT_NAME is empty in a CI run; the event payload is the "
                "only range source under GitHub Actions (fail-closed)"
            )
        # Local convenience: standard PR-shaped range vs the tracking branch or
        # origin/release/v1.0.0. Never invent a range against the pinned SHA.
        for ref in ("@{upstream}", "origin/release/v1.0.0"):
            if is_commit(repo, ref):
                return git_text(repo, "rev-parse", "--verify", "--end-of-options", ref), "HEAD", None
        raise Skip(
            "no CERT_EXPIRY_BASE, no @{upstream}, no origin/release/v1.0.0; skip"
        )
    raise Skip(f"event '{event}' has no PR/push range; skip")


def run_gate(repo, env):
    """Returns (rc, stdout_text, stderr_text)."""
    try:
        require_git_version(repo)
        base, head, tip = resolve_range(repo, env)
    except Skip as skip:
        return 0, "", f"{PREFIX}: N/A — {skip}"
    except GateError as exc:
        return 1, "", f"{PREFIX}: ERROR — {exc}"
    base_name = f"origin/{env['GITHUB_BASE_REF']}" if tip is not None else None
    ok, text = check_change(repo, base, head, tip, base_name)
    return (0, text, "") if ok else (1, "", text)


def platform_path_max():
    """The platform's PATH_MAX: 1024 on macOS and the BSDs, 4096 elsewhere (R5-F1)."""
    bsd = ("darwin", "freebsd", "openbsd", "netbsd")
    return 1024 if sys.platform.startswith(bsd) else 4096


def path_max(path):
    """The PATH_MAX of the filesystem holding path (Linux 4096, macOS 1024),
    falling back to the platform's value when os.pathconf cannot say (#6145 R4-F1,
    R5-F1), so the fallback never exceeds the real limit."""
    try:
        limit = os.pathconf(str(path), "PC_PATH_MAX")
    except (OSError, ValueError, AttributeError):
        return platform_path_max()
    return limit if isinstance(limit, int) and limit > 0 else platform_path_max()


@contextlib.contextmanager
def directory_descriptor(path, parent=None):
    """Own one directory descriptor and release it even when traversal fails."""
    descriptor = os.open(path, os.O_RDONLY, dir_fd=parent)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def deep_scratch(tmp, target_len):
    """Build an exact-length path with a lexical owner for every descriptor."""
    base = Path(tempfile.mkdtemp(prefix="gitshim-deep.", dir=str(tmp)))

    def descend(cur, cur_len, component, parent=None):
        """Unwind every directory owner even if an inner traversal or close fails."""
        with directory_descriptor(component, parent) as descriptor:
            if cur_len == target_len:
                return cur
            if cur_len > target_len:
                raise OSError(errno.ENAMETOOLONG,
                              f"the scratch base is {cur_len} bytes, over the {target_len}-byte target")
            room = target_len - cur_len
            step = min(200, room - 1)
            if room - step - 1 == 1:
                step -= 1  # a final component needs 2 bytes ('/' + 1 char)
            if step < 1:
                raise OSError(errno.ENAMETOOLONG,
                              f"cannot land on exactly {target_len} bytes from {cur_len}")
            name = "d" * step
            os.mkdir(name, dir_fd=descriptor)
            return descend(cur / name, cur_len + 1 + step, name, descriptor)

    try:
        return base, descend(base, len(os.fsencode(str(base))), str(base))
    except BaseException:
        shutil.rmtree(base, ignore_errors=True)
        raise


# ---------------------------------------------------------------------------
# Self-test: a thin runner over the external corpus (#6445)
# ---------------------------------------------------------------------------

CORPUS_HARNESS = Path("scripts") / "ci" / "tests" / "test_check_cert_expiry_corpus.py"
CORPUS_TIMEOUT_S = 1800
SELF_TEST_FAIL_RC = 2
CORPUS_FAIL_PREFIX = "CORPUS-FAIL "
CORPUS_SUMMARY_PREFIX = "CORPUS-SUMMARY "
MAX_FAILURES_SHOWN = 20
SELF_TEST_OK = "check-cert-expiry self-test OK: {summary}; corpus {harness}"


CORPUS_ENV_PREFIX = "CERT_CORPUS_"  # the harness's debugging knobs; never inherited by the self-test
CORPUS_FILTER_ENV = "CERT_CORPUS_FILTER"
CORPUS_NESTED_ENV = "CERT_CORPUS_NESTED"
CORPUS_MANIFEST = Path("scripts") / "qc-allowlists" / "cert-expiry-corpus-manifest.txt"
CORPUS_TEST_PREFIX = "test_"  # the harness runs each manifest entry plus every test_ method of its classes
SUBSET_MIN_CASES = 1
SUMMARY_RAN_RE = re.compile(r"\bran=(\d+)\b")
SUMMARY_FAILED_RE = re.compile(r"\bfailed=(\d+)\b")


def corpus_child_env(environ, subset=""):
    """The child's environment: every inherited CERT_CORPUS_* knob is dropped, so an
    ambient filter can never shrink the run (#7975). Only an explicit `subset` (the
    --self-test-subset flag) sets the filter, and it also marks the run nested."""
    env = {k: v for k, v in environ.items() if not k.startswith(CORPUS_ENV_PREFIX)}
    if subset:
        env[CORPUS_FILTER_ENV] = subset
        env[CORPUS_NESTED_ENV] = "1"
    return env


def expected_corpus_cases(repo):
    """(count, problem): the size of a full corpus run, derived from the tree under test as
    the manifest entries plus the test_ methods of the harness classes, so it is never a
    hand-typed floor (#7991). `problem` is set and `count` is None when either file is unreadable."""
    try:
        manifest = (Path(repo) / CORPUS_MANIFEST).read_text(encoding="utf-8").splitlines()
        tree = ast.parse((Path(repo) / CORPUS_HARNESS).read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError) as exc:
        return None, f"expected corpus size cannot be derived ({type(exc).__name__}: {exc})"
    entries = sum(1 for ln in manifest if ln.strip() and not ln.lstrip().startswith("#"))
    tests = sum(1 for cls in tree.body if isinstance(cls, ast.ClassDef)
                for fn in cls.body
                if isinstance(fn, ast.FunctionDef) and fn.name.startswith(CORPUS_TEST_PREFIX))
    return entries + tests, None


def corpus_size_problem(summary, subset="", expected=None):
    """None when the corpus summary shows the right number of executed cases and zero failures,
    else the reason. A full run must execute exactly `expected` cases (manifest entries plus
    test_ methods); a subset run at least SUBSET_MIN_CASES; ran=0 is never a pass (#7975, #7991)."""
    ran = SUMMARY_RAN_RE.search(summary)
    failed = SUMMARY_FAILED_RE.search(summary)
    if ran is None or failed is None:
        return f"unreadable corpus summary {summary!r}"
    if subset:
        if int(ran.group(1)) < SUBSET_MIN_CASES:
            return f"only {ran.group(1)} corpus cases ran, expected at least {SUBSET_MIN_CASES}"
        return None
    if expected is None:
        return "expected corpus size cannot be derived"
    if int(ran.group(1)) != expected:
        return f"{ran.group(1)} corpus cases ran, expected exactly {expected}"
    return None


def self_test(subset=""):
    """Run the external corpus (scripts/ci/tests/test_check_cert_expiry_corpus.py)
    in a child interpreter, one scratch repository per case, and report each failing
    case by name. rc 0 when every case holds, 2 otherwise. The child's traceback is
    never relayed: a crashing case is a named failure and the rest still run. The
    run is fail-closed on size: any count but the derived manifest-plus-tests total is a
    failure, and inherited CERT_CORPUS_* variables are ignored (#7975)."""
    harness = Path(__file__).resolve().parent.parent / CORPUS_HARNESS
    if not harness.is_file():
        print(f"check-cert-expiry self-test FAILED (corpus missing: {CORPUS_HARNESS})",
              file=sys.stderr)
        return SELF_TEST_FAIL_RC
    try:
        proc = subprocess.run(
            [sys.executable, "-I", str(harness), "--machine"],
            capture_output=True, timeout=CORPUS_TIMEOUT_S, check=False,
            env=corpus_child_env(os.environ, subset),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"check-cert-expiry self-test FAILED (corpus could not run: {exc})",
              file=sys.stderr)
        return SELF_TEST_FAIL_RC
    lines = proc.stdout.decode("utf-8", "replace").splitlines()
    failed = [ln[len(CORPUS_FAIL_PREFIX):] for ln in lines if ln.startswith(CORPUS_FAIL_PREFIX)]
    summary = [ln[len(CORPUS_SUMMARY_PREFIX):] for ln in lines
               if ln.startswith(CORPUS_SUMMARY_PREFIX)]
    expected, derive_problem = (None, None) if subset else expected_corpus_cases(harness.parent.parent.parent.parent)
    size_problem = derive_problem or (corpus_size_problem(summary[-1], subset, expected) if summary else None)
    if failed or proc.returncode != 0 or not summary or size_problem:
        if size_problem:
            print(f"self-test FAILED ({size_problem})", file=sys.stderr)
        for entry in failed[:MAX_FAILURES_SHOWN]:
            print(f"self-test FAILED ({entry})", file=sys.stderr)
        if len(failed) > MAX_FAILURES_SHOWN:
            print(f"self-test FAILED (+{len(failed) - MAX_FAILURES_SHOWN} more cases)",
                  file=sys.stderr)
        if not failed and not size_problem:
            print(f"self-test FAILED (corpus exited {proc.returncode} without a summary)",
                  file=sys.stderr)
        print("check-cert-expiry self-test: FAIL", file=sys.stderr)
        return SELF_TEST_FAIL_RC
    print(SELF_TEST_OK.format(summary=summary[-1], harness=CORPUS_HARNESS))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Enterprise-federation certification section 7 expiry gate.")
    parser.add_argument("--self-test", action="store_true",
                        help="run the external corpus (one scratch repository per case)")
    parser.add_argument("--self-test-subset", default="", metavar="PREFIXES",
                        help="run only the corpus cases whose names start with one of the "
                             "comma-separated PREFIXES (used by the corpus's own nested run)")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            # StringIO and closed streams cannot reconfigure; keep their existing encoding.
            continue
    if args.self_test or args.self_test_subset:
        return self_test(args.self_test_subset)
    rc, out, err = run_gate(REPO_ROOT, dict(os.environ))
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
