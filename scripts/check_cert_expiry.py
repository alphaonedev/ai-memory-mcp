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
record in the same change satisfies the gate), OR (#6124) the banner is EXPIRED
or VOID at both ends and the change inserts exactly one non-discharging
amendment record into the cert doc (see amendment_verdict).

Failure message (required wording):
  federation-wire surface changed -> the enterprise-federation certification
  expires per its section 7 -> re-issue or void the cert doc in this same change.
While the banner is already EXPIRED/VOID (#6369) the first clause is kept and
the rest names the route that applies:
  ... expires per its section 7 -> it is already EXPIRED: record a
  non-discharging amendment (#6124); only the WP-B1 re-cert (#6063) re-issues it.

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

WHAT THIS DOES NOT CLAIM. A value-only edit of an existing AI_MEMORY_FED_*
identifier in a file outside the three path watches does not trip the
identifier check. This gate does not re-run 5.4(2)-(5); it only forces the
cert-doc to be touched so a human/re-issue cannot be skipped.

Usage:
  scripts/check_cert_expiry.py              # against the resolved range
  scripts/check_cert_expiry.py --self-test  # plant-a-violation in a scratch
                                            # repository (never a real branch)

Exit codes: 0 clean / N/A-skip, 1 violation, 2 usage / self-test failure.
"""

import argparse
import contextlib
import datetime
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
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

# POSIX [[:space:]] spelled out so a Unicode space cannot widen the match.
_S = r"[ \t\r\n\f\v]"
# The banner patterns are TOLERANT of formatting (#3556 ruling, fix 3):
# optional blockquote, one to three '#', flexible whitespace, em dash / en dash
# / hyphen, optional backticks, case-insensitive hex. They are anchored at line
# start and require the heading marker / the bold "Binds to", so the section 7
# history records that QUOTE these words in prose do not match.
STATUS_LINE_RE = re.compile(
    r"^>?" + _S + r"*#{1,3}" + _S + r"*STATUS" + _S + r"*(?:—|–|-)" + _S
    + r"*\*\*" + _S + r"*(LIVE|VOID|EXPIRED)",
    re.IGNORECASE,
)
BINDS_LINE_RE = re.compile(
    r"^>?" + _S + r"*\*\*" + _S + r"*Binds" + _S + r"+to" + _S + r"*:?" + _S
    + r"*\*\*" + _S + r"*:?" + _S + r"*`?([0-9a-fA-F]{40})`?",
    re.IGNORECASE,
)

EXPIRY_PREFIX = (
    "federation-wire surface changed → the enterprise-federation certification "
    "expires per its §7"
)
EXPIRY_SENTENCE = EXPIRY_PREFIX + " → re-issue or void the cert doc in this same change."
# #6369: an EXPIRED/VOID certification cannot be re-issued by an edit; the
# headline names the route that applies (#6124) and the only way back (#6063).
EXPIRY_AMEND_SENTENCE = (
    EXPIRY_PREFIX + " → it is already {status}: record a non-discharging amendment "
    "(#6124); only the WP-B1 re-cert (#6063) re-issues it."
)


# #6124 (5-agent vote 4d3ea1c5, T3; decision memory 05c39563): while the
# banner is EXPIRED/VOID at both ends, a change that inserts into the cert
# doc exactly ONE new dated amendment record below STATUS (and at most one
# blank separator line, nothing else) that lists exactly the changed watched
# paths / AI_MEMORY_FED_* identifiers and cites only #6063 is a recorded,
# non-discharging pass (R3: #6354..#6359, #6365..#6369). Only a WP-B1
# re-cert (#6063) returns the doc to LIVE.
#
# Any `**Amendment` record opens a ledger entry, whatever its shape (13 of the
# 17 historical ones carry body text on the header line).
AMENDMENT_LEDGER_RE = re.compile(r"^>?[ \t]*\*\*Amendment\b")
# The NEW entry's header stands alone on its line (nothing after the closing
# `**`), inside a blockquote, at most 4 columns after `>` (more is an indented
# code block in CommonMark). Group 1 is the ISO date.
AMENDMENT_HEAD_RE = re.compile(
    r"^>[ ]{0,4}\*\*Amendment \((\d{4}-\d{2}-\d{2})\b(?:(?!\*\*).)*\*\*[ \t\r]*$"
)
AMENDMENT_ITEM_RE = re.compile(r"^>[ ]{0,4}[-*][ \t]+`([^`\n]+)`[ \t\r]*$")
AMENDMENT_BACK_RE = re.compile(r"^>[ ]{0,4}Path back to LIVE:")
# CommonMark fence opener: optional `>`, then a run of >= 3 backticks or
# tildes; a backtick fence's info string carries no backtick. Indentation is
# deliberately NOT capped here: reading an indented code line as a fence only
# hides more text from the ledger, which can only make the gate stricter.
FENCE_OPEN_RE = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
QUOTED_BLANK_RE = re.compile(r"^>[ \t\r]*$")
BLANK_RE = re.compile(r"^[ \t\r]*$")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->")
# #6365: the CommonMark HTML block kinds other than the comment (type 2, kept
# by the anywhere-in-line `<!--` rule). START is matched against the line's
# content (blockquote markers removed) at most 3 columns in; END is the text
# that closes the block (searched after the opener on its own line too), or
# None for types 6/7, which end at a blank line. Types 6 and 7 are matched by
# any tag at line start: reading more lines as HTML only hides more text from
# the ledger, which can only make the gate stricter.
HTML_BLOCK_KINDS = (
    (re.compile(r"^[ ]{0,3}<(?:script|pre|style|textarea)(?:[ \t>]|$)", re.IGNORECASE),
     re.compile(r"</(?:script|pre|style|textarea)>", re.IGNORECASE)),
    (re.compile(r"^[ ]{0,3}<\?"), re.compile(r"\?>")),
    (re.compile(r"^[ ]{0,3}<!\[CDATA\["), re.compile(r"\]\]>")),
    (re.compile(r"^[ ]{0,3}<![A-Za-z]"), re.compile(r">")),
    (re.compile(r"^[ ]{0,3}</?[A-Za-z]"), None),
)
# #6443: one blockquote marker (up to 3 columns of indent, one optional space
# after the '>'; the line's tabs are expanded first) and one list-item marker
# (bullet or ordered; its content starts 1-4 columns after the marker).
QUOTE_MARK_RE = re.compile(r"^[ ]{0,3}>[ ]?")
QUOTE_START_RE = re.compile(r"^[ ]{0,3}>")
LIST_MARK_RE = re.compile(r"^([ ]{0,3})(?:[-*+]|\d{1,9}[.)])(?:([ ]{1,4})(?=[^ ])|[ ]*$)")
# #6354/#6367: the new record's grammar and character set. Every body line is
# a list entry, the back line or plain prose (a letter first); every line
# (header included) is printable ASCII, a tab, or one of a few typographic
# marks, so no bidi control, zero-width, escape or fullwidth lookalike.
AMENDMENT_PROSE_RE = re.compile(r"^>[ ]{0,4}[A-Za-z]")
AMENDMENT_MARKER_RE = re.compile(r"^>[ ]{0,4}")
AMENDMENT_EXTRA_CHARS = frozenset("§—–→’‘“”…·×")
# What may not be left in a record line once its list-entry code span and the
# canonical #6063 link are removed: any other issue / pull / commit reference,
# link, autolink, entity, HTML or code span (GitHub autolinks `#N`, `GH-N`,
# `owner/repo#N`, `owner/repo@sha`, a 7+ hex sha, `www.`, email).
AMENDMENT_BODY_BANNED_RE = re.compile(
    r"[#@/&\[\]<>\\`]|\bGH-\d|www\.|\b[0-9a-f]{7,}\b", re.IGNORECASE)
# The header keeps its `#N` (the issue the change is for); nothing else.
AMENDMENT_HEAD_BANNED_RE = re.compile(
    r"[@/&\[\]<>\\`]|\bGH-\d|www\.|\b[0-9a-f]{7,}\b", re.IGNORECASE)
RE_CERT_ISSUE = "#6063"
RE_CERT_URL = "https://github.com/alphaonedev/ai-memory-mcp/issues/6063"
RE_CERT_LINK = f"[{RE_CERT_ISSUE}]({RE_CERT_URL})"
REGULAR_DOC_MODES = ("100644", "100755")
# Cap on the cert doc the amendment ledger reads whole (#6124; #6140 applies
# the same cap to the banner reader).
CERT_DOC_MAX_BYTES = 2 * 1024 * 1024


class GateError(Exception):
    """Evidence is missing or ambiguous: the gate fails closed."""


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
    proc = run_git(repo, "grep", "-h", "-I", "-E", FED_ID_PATTERN, tree, "--", "src")
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


def cert_banner(repo, tree):
    """(STATUS, BINDS) of the cert doc at TREE.

    STATUS: LIVE | VOID | EXPIRED | UNPARSEABLE (doc present, no STATUS line)
    | DUPLICATE (two or more STATUS lines: a decoy above the real banner must
    not be read as the banner) | ABSENT (no doc at TREE).
    BINDS: the lowercase 40-hex bound SHA, "-" when no Binds-to line matches,
    "DUPLICATE" when two or more do.
    """
    proc = run_git(repo, "show", "--end-of-options", f"{tree}:{CERT_DOC}")
    if proc.returncode != 0:
        return ("ABSENT", "-")
    lines = proc.stdout.decode("utf-8", "replace").split("\n")
    statuses = [m for m in (STATUS_LINE_RE.match(ln) for ln in lines) if m]
    binds = [m for m in (BINDS_LINE_RE.match(ln) for ln in lines) if m]
    if not statuses:
        status = "UNPARSEABLE"
    elif len(statuses) == 1:
        status = statuses[0].group(1).upper()
    else:
        status = "DUPLICATE"
    if not binds:
        bound = "-"
    elif len(binds) == 1:
        bound = binds[0].group(1).lower()
    else:
        bound = "DUPLICATE"
    return (status, bound)


def fmt_banner(banner):
    return f"{banner[0]} {banner[1]}"


def _doc_safe(text):
    """TEXT as shown in gate output: as-is when every character is printable,
    else its escaped `ascii()` form, so a name the change or the doc controls
    cannot inject control characters into the log (#6124; the #6140 rebase
    replaces this with the shared `log_safe`, #6175)."""
    text = str(text)
    return text if text.isprintable() else ascii(text)


def read_cert_doc(repo, tree):
    """Text of the cert doc at TREE for the amendment ledger (#6124). Read
    from the object database only. Fail-closed (GateError) when the entry is
    absent, is not a regular file (a symlink is never followed), exceeds
    CERT_DOC_MAX_BYTES, is not valid UTF-8 (#6368), or git cannot read it: an
    unreadable ledger is never taken as an empty one."""
    proc = run_git(repo, "ls-tree", "-z", "--full-tree", "--end-of-options", tree, CERT_DOC)
    if proc.returncode != 0:
        err = _doc_safe(proc.stderr.decode("utf-8", "replace").strip())
        raise GateError(f"git ls-tree {tree} {CERT_DOC} exited {proc.returncode}: {err}")
    entry = None
    for rec in proc.stdout.split(b"\0"):
        meta, sep, name = rec.partition(b"\t")
        if sep and name.decode("utf-8", "replace") == CERT_DOC:
            entry = meta.decode("ascii", "replace").split(" ")
    if entry is None:
        raise GateError(f"{CERT_DOC} is absent at {tree}; the amendment ledger cannot be read")
    if len(entry) != 3 or entry[1] != "blob" or entry[0] not in REGULAR_DOC_MODES:
        raise GateError(
            f"{CERT_DOC} at {tree} is a symlink or other non-regular entry "
            f"({_doc_safe(' '.join(entry))}); the amendment ledger is not read from it"
        )
    oid = entry[2]
    size = git_text(repo, "cat-file", "-s", "--end-of-options", oid)
    if not size.isdigit() or int(size) > CERT_DOC_MAX_BYTES:
        raise GateError(
            f"{CERT_DOC} at {tree} is {_doc_safe(size)} bytes, above the "
            f"{CERT_DOC_MAX_BYTES}-byte cap of the amendment ledger reader"
        )
    proc = run_git(repo, "cat-file", "blob", "--end-of-options", oid)
    if proc.returncode != 0:
        err = _doc_safe(proc.stderr.decode("utf-8", "replace").strip())
        raise GateError(f"git cat-file blob {oid} ({CERT_DOC}) exited {proc.returncode}: {err}")
    try:
        return proc.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        # #6368: a lossy decode would turn an invalid byte into U+FFFD and let
        # two different documents compare byte-identical; fail closed.
        raise GateError(
            f"{CERT_DOC} at {tree} is not valid UTF-8 (byte offset {exc.start}); the "
            "amendment ledger is not read from it"
        ) from exc


def _containers(ln):
    """(quoted, quote-stripped content, fully stripped content, list pad) of
    LN (#6443, #6365). Tabs are expanded, then every blockquote marker is
    removed (up to 3 columns of indent, one optional space), and inside a
    blockquote every list-item marker too, nested in any order. PAD is the
    columns the list markers took: a fence or HTML block opened in a list
    item ends only with the blockquote or at its own closing text, and a
    reader that did not see the opener would accept a hidden record."""
    text = ln.expandtabs(4)
    quoted = QUOTE_START_RE.match(text) is not None
    if not quoted:
        return False, text, text, 0
    pad = 0
    while True:
        m = QUOTE_MARK_RE.match(text)
        if not m:
            break
        text = text[m.end():]
    plain = text
    while True:
        m = QUOTE_MARK_RE.match(text) or LIST_MARK_RE.match(text)
        if not m:
            break
        if QUOTE_MARK_RE.match(text):
            text = text[m.end():]
            continue
        pad += m.end()
        text = text[m.end():]
    return True, plain, text, pad


def _fence_opener(content, quoted, pad):
    """(quoted, char, run length, pad) when CONTENT (a line with its
    containers removed) opens a CommonMark code fence."""
    m = FENCE_OPEN_RE.match(content)
    if not m or (m.group(1)[0] == "`" and "`" in m.group(2)):
        return None
    return (quoted, m.group(1)[0], len(m.group(1)), pad)


def _fence_closes(plain, fence):
    """True iff PLAIN (a line with its blockquote markers removed) closes
    FENCE: at most 3 columns of indentation past the list item content the
    fence was opened in, the same character, a run at least as long, nothing
    after."""
    _quoted, char, run, pad = fence
    prefix = "^[ ]{0,%d}" % (pad + 3)
    return re.match(prefix + re.escape(char) + "{%d,}[ \\t\\r]*$" % run, plain) is not None


def _ledger_plain(ln):
    """True iff LN continues the new record's paragraph: a non-blank quoted
    line (#6354: whatever it carries, it is part of the record and is held
    to the record grammar)."""
    return ln.startswith(">") and not QUOTED_BLANK_RE.match(ln)


def _html_opener(content):
    """(end regex or None, closed on this line) when CONTENT (a line with its
    blockquote markers removed) opens a CommonMark HTML block (#6365)."""
    for start, end in HTML_BLOCK_KINDS:
        m = start.match(content)
        if m:
            return end, end is not None and end.search(content, m.end()) is not None
    return None


def parse_ledger(lines):
    """The amendment ledger of the cert doc LINES (#6124): one entry per
    `**Amendment` record outside code fences (CommonMark: a fence closes only
    on the same character with a run at least as long), outside HTML
    comments and outside every other CommonMark HTML block kind (#6365: a
    quoted block ends with its blockquote; types 1/3/4/5 end at their closing
    text, types 6/7 at a blank line; an unquoted block swallows '>' lines).
    Returns dicts: start (line index), header, quoted, below_status."""
    entries = []
    fence = None
    in_comment = False
    html = None  # (quoted, end regex or None) of the open HTML block
    seen_status = False
    for idx, ln in enumerate(lines):
        quoted, plain, content, pad = _containers(ln)
        if html is not None:
            if html[0] and not quoted:
                html = None  # the blockquote ended, and its HTML block with it
            else:
                # In an unquoted block a '>' is raw text, so the raw line is read.
                text = plain if html[0] else ln
                if html[1] is None:
                    if BLANK_RE.match(text):
                        html = None
                elif html[1].search(text):
                    html = None
                continue
        if fence is not None:
            if fence[0] and not quoted:
                fence = None  # the blockquote ended, and its fence with it
            else:
                if _fence_closes(plain, fence):
                    fence = None
                continue
        if in_comment:
            if "-->" in ln:
                in_comment = False
            continue
        if "<!--" in ln:
            in_comment = "<!--" in HTML_COMMENT_RE.sub("", ln)
            continue
        opener = _fence_opener(content, quoted, pad)
        if opener is not None:
            fence = opener
            continue
        block = _html_opener(content)
        if block is not None:
            if not block[1]:
                html = (quoted, block[0])
            continue
        if STATUS_LINE_RE.match(ln):
            seen_status = True
            continue
        if AMENDMENT_LEDGER_RE.match(ln):
            entries.append({"start": idx, "header": ln, "quoted": quoted,
                            "below_status": seen_status})
    return entries


def _record_problems(header, body):
    """Why the new record's HEADER and BODY lines are not in the record
    grammar, character set and citation rule ([] when they are; #6354,
    #6367). The whole record is scanned, not only its back line."""
    why = []
    for ln in [header] + body:
        text = ln[:-1] if ln.endswith("\r") else ln
        bad = sorted({ch for ch in text if not (" " <= ch <= "~" or ch == "\t"
                                                or ch in AMENDMENT_EXTRA_CHARS)})
        if bad:
            why.append("a record line carries a character outside printable ASCII "
                       "(control, bidi, zero-width or lookalike): "
                       + ", ".join(f"U+{ord(ch):04X}" for ch in bad))
    if AMENDMENT_HEAD_BANNED_RE.search(AMENDMENT_MARKER_RE.sub("", header, count=1)):
        why.append("its header carries a link, an autolink, an entity, HTML, a code span, "
                   "a commit sha or a cross-repository reference")
    for ln in body:
        if not (AMENDMENT_ITEM_RE.match(ln) or AMENDMENT_BACK_RE.match(ln)
                or AMENDMENT_PROSE_RE.match(ln)):
            why.append(f"record line {_doc_safe(ln)!s} is not a list entry "
                       "('> - `path`'), the 'Path back to LIVE:' line or plain prose")
            continue
        if AMENDMENT_ITEM_RE.match(ln):
            continue
        rest = AMENDMENT_MARKER_RE.sub("", ln, count=1).replace(RE_CERT_LINK, "")
        hit = AMENDMENT_BODY_BANNED_RE.search(rest)
        if hit:
            why.append(f"record line {_doc_safe(ln)!s} cites or links something other than "
                       f"{RE_CERT_LINK} (found {_doc_safe(hit.group(0))!s}); the record "
                       f"cites only {RE_CERT_ISSUE}, by its issue URL")
    if not any(AMENDMENT_BACK_RE.match(ln) and RE_CERT_LINK in ln for ln in body):
        why.append(f"no 'Path back to LIVE:' line citing {RE_CERT_LINK}")
    return why


def _commit_day(repo, sha):
    text = git_text(repo, "show", "-s", "--format=%cs", "--end-of-options", sha)
    try:
        return datetime.date.fromisoformat(text)
    except ValueError as exc:
        raise GateError(f"committer date of {sha} is unreadable: {_doc_safe(text)}") from exc


def _is_sep(lines, i):
    return 0 <= i < len(lines) and (BLANK_RE.match(lines[i]) or QUOTED_BLANK_RE.match(lines[i]))


def ledger_blocks(lines):
    """Every ledger record of LINES as a tuple of its raw lines: the header
    and the unbroken run of '>' lines that follows it (#6423)."""
    blocks = []
    for ent in parse_ledger(lines):
        end = ent["start"] + 1
        while end < len(lines) and _ledger_plain(lines[end]):
            end += 1
        blocks.append(tuple(lines[ent["start"]:end]))
    return blocks


def ledger_append_only(repo, mb, judged):
    """The reason the change breaks the append-only ledger ('' when it keeps
    it), for a change that touches the cert doc while the certification is
    EXPIRED/VOID and is not a re-issue (#6423): every record of the merge-base
    doc stays, byte-identical, in the same order, whatever else the change is.
    A deleted doc loses every record."""
    banner_mb = cert_banner(repo, mb)
    banner_head = cert_banner(repo, judged)
    if banner_mb[0] not in ("EXPIRED", "VOID"):
        return ""
    deleted = banner_head == ("ABSENT", "-")
    malformed = banner_head[0] in ("DUPLICATE", "UNPARSEABLE") or banner_head[1] == "DUPLICATE"
    if banner_mb != banner_head and not deleted and not malformed:
        return ""  # a real re-issue or voiding keeps its own path
    old = ledger_blocks(read_cert_doc(repo, mb).split("\n"))
    new = [] if deleted else ledger_blocks(read_cert_doc(repo, judged).split("\n"))
    at = 0
    for block in new:
        if at < len(old) and block == old[at]:
            at += 1
    if at < len(old):
        return (f"{CERT_DOC} is {banner_mb[0]} and its amendment ledger is append-only: this "
                "change removes, edits, re-dates, moves or reorders an existing record "
                f"(or deletes the document); only a new record may be added (#6124, #6423)")
    return ""


def _in_ledger(lines, known, start, end):
    """True iff the record at LINES[start:end] sits in the ledger (#6420):
    LINES[end] (past at most one blank '>' line) is the header of a KNOWN
    record, or the unbroken '>' run above START holds one."""
    nxt = end + 1 if end < len(lines) and QUOTED_BLANK_RE.match(lines[end]) else end
    if nxt in known and lines[nxt].startswith(">"):
        return True
    i = start - 1
    while i >= 0 and lines[i].startswith(">"):
        if i in known:
            return True
        i -= 1
    return False


def amendment_verdict(repo, mb, judged, required):
    """(ok, why) for the #6124 pass path. The cert doc at JUDGED must be the
    doc at MB with exactly ONE new amendment record inserted (plus at most one
    blank separator line) and no other line changed (#6366), and that record
    must be below STATUS, open its own paragraph with its header alone on its
    line, sit directly above an existing amendment header or close its
    blockquote, be followed by no lazy line (#6354), carry a valid ISO date
    from the merge-base commit day - 1 (#6358) to the judged commit's day (or
    today) + 1, list exactly REQUIRED, keep to the record grammar and cite
    only #6063 by its issue URL (#6367). Doc read failures raise GateError."""
    old_lines = read_cert_doc(repo, mb).split("\n")
    new_lines = read_cert_doc(repo, judged).split("\n")
    # Every header line already in the merge-base doc, wherever it sits (a
    # fenced or hidden copy included), is not a new record.
    old_heads = {ln.rstrip("\r") for ln in old_lines if AMENDMENT_LEDGER_RE.match(ln)}
    fresh = [e for e in parse_ledger(new_lines) if e["header"].rstrip("\r") not in old_heads]
    if not fresh:
        return False, ("no NEW amendment record was added below STATUS (a header that "
                       "already exists in the document is not a new record)")
    if len(fresh) > 1:
        lines = ", ".join(str(e["start"] + 1) for e in fresh)
        return False, (f"exactly one new amendment per change is accepted; this change adds "
                       f"{len(fresh)} (lines {lines})")
    ent = fresh[0]
    at = f"the new amendment at line {ent['start'] + 1}"
    start = ent["start"]
    end = start + 1
    while end < len(new_lines) and _ledger_plain(new_lines[end]):
        end += 1
    para = new_lines[start + 1:end]
    prev = new_lines[start - 1] if start > 0 else ""
    why = []
    # #6366: the change is a pure insertion of the record and at most one
    # blank separator line; every other line of the doc stays byte-identical,
    # so no existing record (or prose, or HTML opener) is edited around it.
    spans = [(start, end)]
    if _is_sep(new_lines, start - 1):
        spans.append((start - 1, end))
    if _is_sep(new_lines, end):
        spans.append((start, end + 1))
    if not any(new_lines[:a] + new_lines[b:] == old_lines for a, b in spans):
        why.append("the cert doc may only gain the new amendment record and one blank "
                   "separator line; every other line must stay byte-identical (existing "
                   "records are append-only: never removed, edited, re-dated, moved or "
                   "reordered, and nothing may be inserted around them)")
    if end < len(new_lines) and not _is_sep(new_lines, end):
        why.append(f"{at}: line {end + 1} continues its last paragraph without a '>' (a lazy "
                   "continuation line renders inside the record); end the record with a "
                   "blank line or a blank '>' line")
    nxt = end
    while nxt < len(new_lines) and QUOTED_BLANK_RE.match(new_lines[nxt]):
        nxt += 1
    if (nxt > end and nxt < len(new_lines) and new_lines[nxt].startswith(">")
            and not AMENDMENT_LEDGER_RE.match(new_lines[nxt])):
        why.append(f"{at}: it would take over the paragraph at line {nxt + 1}, which is not "
                   "an amendment record; place the record directly above an existing "
                   "amendment header or as the last paragraph of its blockquote")
    if not ent["below_status"]:
        why.append(f"{at} is above the STATUS line")
    # #6420: once the doc has a ledger the record belongs inside it: its next
    # line (past at most one blank '>' line) is an existing record's header,
    # or the unbroken blockquote above it holds an existing record's header.
    known = {e["start"] for e in parse_ledger(new_lines) if e is not ent
             and e["header"].rstrip("\r") in old_heads}
    if known and not _in_ledger(new_lines, known, start, end):
        why.append(f"{at} is not adjacent to the amendment ledger: place it directly above "
                   "an existing amendment header (a blank '>' line between them) or as the "
                   "last paragraph of the blockquote that holds one")
    head = AMENDMENT_HEAD_RE.match(ent["header"])
    if not head:
        why.append(f"{at}: its header must stand alone on its line, inside the blockquote, "
                   "shaped '> **Amendment (YYYY-MM-DD, ...).**' with nothing after the "
                   "closing '**'")
    else:
        try:
            day = datetime.date.fromisoformat(head.group(1))
        except ValueError:
            why.append(f"{at}: {head.group(1)} is not a valid ISO date")
        else:
            today = datetime.datetime.now(datetime.timezone.utc).date()
            latest = min(_commit_day(repo, judged), today) + datetime.timedelta(days=1)
            earliest = _commit_day(repo, mb) - datetime.timedelta(days=1)
            if day > latest:
                why.append(f"{at}: {head.group(1)} is in the future (after {latest})")
            if day < earliest:
                why.append(f"{at}: {head.group(1)} is before the merge-base commit day less "
                           f"one ({earliest}); a record is dated when it is written")
    if not _is_sep([prev], 0):
        why.append(f"{at}: its header must open its own paragraph (a blank line or a blank "
                   "'>' line before it)")
    items = [m.group(1) for m in (AMENDMENT_ITEM_RE.match(ln) for ln in para) if m]
    listed = set(items)
    missing = sorted(required - listed)
    extra = sorted(listed - required)
    if len(listed) != len(items):
        why.append(f"{at}: an entry is listed more than once")
    if missing:
        why.append(f"{at}: not listed: {', '.join(_doc_safe(m) for m in missing)}")
    if extra:
        why.append(f"{at}: listed but not changed: {', '.join(_doc_safe(x) for x in extra)}")
    why.extend(f"{at}: {w}" for w in _record_problems(ent["header"], para))
    if why:
        return False, "; ".join(why)
    return True, f"line {ent['start'] + 1}"


def amendment_remedy(status, required):
    """The remedy for a watched change while the banner is EXPIRED/VOID: the
    #6124 amendment record, spelled out, never a bare re-issue (#3899)."""
    lines = [
        f"Remedy: the certification is {status}, so its banner may move only through the "
        f"WP-B1 re-measurement and re-issue ({RE_CERT_ISSUE}); re-binding without "
        "re-measurement is forbidden (#3899). Record this change instead (#6124): insert ONE "
        f"new amendment record below STATUS in {CERT_DOC}, directly above an existing "
        "amendment header (a blank '>' line between them) or as the last paragraph of its "
        "blockquote, as its own paragraph, dated from the merge-base day to today, in plain "
        "text shaped exactly as below, and change no other line of the doc:",
        "  > **Amendment (YYYY-MM-DD, #<issue> - section 7 record, non-discharging).**",
    ]
    lines.extend(f"  > - `{_doc_safe(r)}`" for r in sorted(required))
    lines.append(f"  > Path back to LIVE: WP-B1 re-cert ([{RE_CERT_ISSUE}]({RE_CERT_URL})) only.")
    return lines


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
        return False, [
            f"{PREFIX}: ERROR — {CERT_DOC} at HEAD has no parseable STATUS line. "
            "Expected a line shaped like '> ## STATUS — **LIVE as of …**' "
            "(blockquote, heading level, dash style, spacing and hex case are "
            "tolerated). If this change reformatted the banner, restore that "
            "shape; if it removed the banner, the document must say LIVE, VOID "
            "or EXPIRED. Fail-closed, #3556."
        ]
    if status == "DUPLICATE":
        return False, [
            f"{PREFIX}: ERROR — {CERT_DOC} at HEAD has two or more STATUS banner "
            "lines; the gate reads exactly one and will not guess which is the "
            "banner (a decoy line above the real banner is how a stale LIVE "
            "could be read as VOID). Remove the duplicate. Fail-closed, #3556."
        ]
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
        return False, [
            f"{PREFIX}: ERROR — {CERT_DOC} at HEAD has two or more Binds-to "
            "lines; the gate reads exactly one and will not guess which SHA the "
            "LIVE claim binds to. Remove the duplicate. Fail-closed, #3556."
        ]
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
        "Federation-wire drift since the bind (paths; +added / -removed "
        "AI_MEMORY_FED_* identifiers):",
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

    if not watched and not id_changed:
        if cert_touched:
            problem = ledger_append_only(repo, mb, judged)
            if problem:
                return False, f"{PREFIX}: FAIL — {problem}"
        ok, more = check_banner_consistency(repo, judged)
        lines = [f"{PREFIX}: PASS — federation-wire surface unchanged in {mb}..{judged}"]
        return ok, "\n".join(lines + more)

    # (B) #3556: the hatch is a REAL re-issue/voiding only if the banner
    # (STATUS line or Binds-to line) differs between merge-base and judged.
    incidental = deleted = malformed = False
    banner_mb = banner_head = ("", "")
    if cert_touched:
        banner_mb = cert_banner(repo, mb)
        banner_head = cert_banner(repo, judged)
        incidental = banner_mb == banner_head
        # #3556 ruling, fix 2: a DELETED cert doc is not a voiding record.
        deleted = banner_head == ("ABSENT", "-")
        # #3556 ruling, fix 1: a banner the gate cannot read as exactly one
        # STATUS line and at most one Binds-to line is not a re-issue.
        malformed = banner_head[0] in ("DUPLICATE", "UNPARSEABLE") or banner_head[1] == "DUPLICATE"

    if cert_touched and not incidental and not deleted and not malformed:
        ok, more = check_banner_consistency(repo, judged)
        head_line = (
            f"{PREFIX}: PASS — federation-wire surface changed AND cert doc "
            f"re-issued/voided in the same change ({mb}..{judged}; banner "
            f"{fmt_banner(banner_mb)} → {fmt_banner(banner_head)})"
        )
        return ok, "\n".join([head_line] + more)

    amend_why = ""
    # `incidental` means the banner is identical at both ends, so checking the
    # merge-base STATUS alone also pins the judged one.
    if incidental and not deleted and not malformed and banner_mb[0] in ("EXPIRED", "VOID"):
        amend_ok, amend_why = amendment_verdict(
            repo, mb, judged, set(watched) | set(added) | set(removed)
        )
        if amend_ok:
            ok, more = check_banner_consistency(repo, judged)
            head_line = (
                f"{PREFIX}: PASS — federation-wire surface changed while the certification "
                f"is {banner_head[0]} at both ends ({mb}..{judged}) and this change adds a "
                f"new non-discharging amendment listing exactly its {len(watched)} watched "
                f"path(s) and {len(added) + len(removed)} identifier(s) and citing "
                f"{RE_CERT_ISSUE} (#6124); the certification is NOT re-issued, only the "
                f"WP-B1 re-cert ({RE_CERT_ISSUE}) returns it to LIVE"
            )
            return ok, "\n".join([head_line] + more)

    status_mb = banner_mb[0] if cert_touched else cert_banner(repo, mb)[0]
    amendable = status_mb in ("EXPIRED", "VOID") and not deleted and not malformed
    out = [EXPIRY_AMEND_SENTENCE.format(status=status_mb) if amendable else EXPIRY_SENTENCE]
    if incidental:
        out.append(
            "The cert doc WAS edited in this change, but neither its STATUS line "
            f"nor its Binds-to line changed (banner {fmt_banner(banner_head)} at "
            "both ends) — an incidental edit is not a re-issue and not a voiding "
            "record (#3556)."
        )
    if amend_why:
        out.append(
            f"The certification is {banner_head[0]}; a non-discharging amendment is "
            "accepted only as exactly ONE new record inserted below STATUS, with at most "
            "one blank separator line and no other line of the doc changed (header alone "
            "on its line, opening its own paragraph, directly above an existing amendment "
            "header or closing its blockquote, outside code fences and HTML blocks, dated "
            "from the merge-base commit day less one to today plus one, plain printable "
            "text) that lists exactly the changed watched paths and AI_MEMORY_FED_* "
            f"identifiers and cites only {RE_CERT_ISSUE} by its issue URL (#6124). "
            f"Not satisfied: {amend_why}."
        )
    if deleted:
        out.append(
            "The cert doc is ABSENT at HEAD (deleted in this change) while the "
            "federation-wire surface changed — deleting the certification is not "
            "a voiding record; record VOID/EXPIRED in the document instead (#3556)."
        )
    if malformed:
        out.append(
            "The cert doc at HEAD does not carry exactly one STATUS banner line "
            f"and at most one Binds-to line (parsed: {fmt_banner(banner_head)}) — "
            "the gate reads one banner and will not guess; a duplicated or "
            "unparseable banner is not a re-issue and not a voiding record (#3556)."
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
    if amendable:
        out.extend(amendment_remedy(status_mb, set(watched) | set(added) | set(removed)))
    else:
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


# ---------------------------------------------------------------------------
# Plant-a-violation self-test (scratch repository; never a real branch)
# ---------------------------------------------------------------------------


class Fixture:
    """A throwaway repository the self-test plants violations in."""

    def __init__(self, repo):
        self.repo = repo

    def g(self, *args):
        proc = run_git(self.repo, *args)
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            raise GateError(f"fixture git {args} failed: {err}")
        return proc.stdout.decode("utf-8", "replace").strip()

    def write(self, rel, text, append=False):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a" if append else "w", encoding="utf-8") as fh:
            fh.write(text)

    def commit(self, paths, msg):
        self.g("add", "--", *paths)
        self.g("commit", "-q", "-m", msg)
        return self.g("rev-parse", "HEAD")

    def reset(self, sha):
        self.g("reset", "-q", "--hard", sha)

    def banner(self, status, binds, extra="", quoted=""):
        """The cert doc in its real shape (the gate READS the banner): a
        leading one-line SPDX HTML comment, the STATUS blockquote (QUOTED
        continues it, as the real doc keeps its amendments there), then
        body prose and EXTRA (#6355)."""
        self.write(
            CERT_DOC,
            "<!-- Copyright 2026 fixture / SPDX-License-Identifier: Apache-2.0 -->\n"
            "# Enterprise federation certification (fixture)\n\n"
            f"**Binds to:** `{binds}` (fixture bind)\n\n"
            f"> ## STATUS — **{status} as of 2026-01-01** (fixture)\n{quoted}\n"
            f"Body prose.\n{extra}",
        )

    def prepend(self, rel, line):
        path = self.repo / rel
        path.write_text(line + "\n" + path.read_text(encoding="utf-8"), encoding="utf-8")

    def merge(self, other, msg):
        self.g("merge", "-q", "--no-ff", "-m", msg, other)
        return self.g("rev-parse", "HEAD")


class SelfTest:
    def __init__(self):
        self.failed = False

    def fail(self, msg, out=None):
        print(f"self-test FAILED {msg}", file=sys.stderr)
        if out:
            print(out, file=sys.stderr)
        self.failed = True

    def expect_red(self, label, desc, repo, base, head, needles, tip=None):
        ok, out = check_change(repo, base, head, tip)
        if ok:
            self.fail(f"({label}): {desc} was NOT rejected", out)
            return out
        for needle, why in needles:
            if needle not in out:
                self.fail(f"({label}): rejection {why}:", out)
        return out

    def expect_green(self, label, desc, repo, base, head, needles=(), tip=None):
        ok, out = check_change(repo, base, head, tip)
        if not ok:
            self.fail(f"({label}): {desc} was REJECTED:", out)
            return out
        for needle, why in needles:
            if needle not in out:
                self.fail(f"({label}): pass output {why}:", out)
        return out


    def gate(self, label, why, repo, env, needle=None):
        """Run the whole gate. needle None: it must pass. Else it must fail
        closed (rc 1) AND say `needle` (a fail-closed for the wrong reason, or
        a wrong remedy, is a defect too)."""
        rc, out, err = run_gate(repo, env)
        text = out + err
        if needle is None:
            if rc != 0:
                self.fail(f"({label}): {why} was REJECTED:", text)
        elif rc == 0:
            self.fail(f"({label}): {why} did not fail closed", text)
        elif needle not in text:
            self.fail(f"({label}): {why} failed for the wrong reason (wanted {needle!r}):", text)
        return text


GIT_SHIM = """#!{python}
import os, sys
real, argv = {real!r}, sys.argv[1:]
if "--version" in argv and {version!r}:
    print({version!r})
    sys.exit(0)
if {fail!r} and {fail!r} in argv:
    sys.stderr.write("fatal: shim refuses " + {fail!r} + chr(10))
    sys.exit(128)
os.execv(real, [real] + argv)
"""


def run_gate_shimmed(tmp, repo, env, version="", fail=""):
    """run_gate with a PATH shim `git` that reports `version` for --version
    and exits 128 on any call whose argv contains `fail`, and otherwise
    delegates to the real git (R2-F2: pins the guarded branches)."""
    real = shutil.which("git")
    if real is None:
        raise GateError("git is not on PATH")
    shim_dir = Path(tempfile.mkdtemp(prefix="gitshim.", dir=str(tmp)))
    shim = shim_dir / "git"
    shim.write_text(GIT_SHIM.format(python=sys.executable, real=real, version=version,
                                    fail=fail), encoding="utf-8")
    shim.chmod(0o755)
    saved = os.environ.get("PATH")
    os.environ["PATH"] = f"{shim_dir}{os.pathsep}{saved or ''}"
    try:
        return run_gate(repo, dict(env, PATH=os.environ["PATH"]))
    finally:
        if saved is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = saved
        shutil.rmtree(shim_dir, ignore_errors=True)


def _gate_env(**kw):
    return {k: v for k, v in kw.items() if v is not None}


def self_test():
    try:
        require_git_version(REPO_ROOT)
    except GateError as exc:
        print(f"{PREFIX}: ERROR — {exc}", file=sys.stderr)
        return 2
    scratch_root = REPO_ROOT / ".local-runs"
    scratch_root.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="cert-expiry-selftest.", dir=str(scratch_root)))
    try:
        return _self_test(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _self_test(tmp):  # noqa: C901 - one linear plant-a-violation corpus
    repo = tmp / "repo"
    repo.mkdir()
    t = SelfTest()
    fx = Fixture(repo)
    fx.g("init", "-q", "-b", "main")
    fx.g("config", "user.name", "Cert Expiry Selftest")
    fx.g("config", "user.email", "selftest@invalid.example")
    fx.g("config", "commit.gpgsign", "false")

    fx.write("src/federation/mod.rs", "fn federation_mod() {}\n")
    fx.write("src/handlers/federation_receive.rs", "fn receive() {}\n")
    fx.write("src/handlers/federation_signing_check.rs", "fn signing_check() {}\n")
    fx.write("src/config.rs", 'pub const X: &str = "AI_MEMORY_FED_REQUIRE_SIG";\n')
    fx.write("src/unrelated.rs", "fn other() {}\n")
    genesis = fx.commit(["src"], "genesis")

    # The base fixture is LIVE and bound to the genesis tree, so a range from
    # base carries no wire drift since the bind ((C) is true).
    fx.banner("LIVE", genesis)
    base = fx.commit([CERT_DOC], "base: certification LIVE bound to genesis")

    sentence = "federation-wire surface changed → the enterprise-federation certification expires per its §7"
    mod_rs = "src/federation/mod.rs"

    # (a) RED - watched federation path, no cert-doc touch.
    fx.write(mod_rs, "// mutate\n", append=True)
    viol = fx.commit([mod_rs], "violate: touch src/federation without cert doc")
    t.expect_red("a", "watched-path violation", repo, base, viol, [
        (sentence, "did not carry the required §7 expiry sentence"),
        (mod_rs, "did not name the watched path"),
    ])

    # (b) GREEN - same violation PLUS a REAL re-issue: the doc rebinds to the
    #     wire-change commit.
    fx.banner("LIVE", viol)
    satisfied = fx.commit([CERT_DOC], "satisfy: re-issue cert doc alongside wire change")
    t.expect_green("b", "cert-doc-touching variant", repo, base, satisfied, [
        ("cert doc re-issued/voided", "did not name the cert-doc satisfy path"),
    ])
    fx.reset(base)

    # (c) RED - AI_MEMORY_FED_* identifier added in src/ OUTSIDE the path watches.
    fx.write("src/config.rs", 'pub const X: &str = "AI_MEMORY_FED_REQUIRE_SIG";\n'
             'pub const Y: &str = "AI_MEMORY_FED_NEW_KNOB";\n')
    id_sha = fx.commit(["src/config.rs"], "violate: add AI_MEMORY_FED_* identifier")
    t.expect_red("c", "identifier-add violation", repo, base, id_sha, [
        ("AI_MEMORY_FED_NEW_KNOB", "did not name the added identifier"),
        (sentence, "did not carry the required §7 expiry sentence"),
    ])

    # (d) GREEN - identifier add + a real re-issue (rebind to the add).
    fx.banner("LIVE", id_sha)
    id_ok = fx.commit([CERT_DOC], "satisfy: re-issue cert doc alongside identifier add")
    t.expect_green("d", "identifier-add + cert-doc variant", repo, base, id_ok)
    fx.reset(base)

    # (e) GREEN - unrelated src/ edit.
    fx.write("src/unrelated.rs", "// unrelated\n", append=True)
    clean = fx.commit(["src/unrelated.rs"], "clean: unrelated src edit")
    t.expect_green("e", "unrelated src edit", repo, base, clean, [
        ("federation-wire surface unchanged", "did not say the surface was unchanged"),
    ])
    fx.reset(base)

    # (f) GREEN - cert-doc-only change.
    fx.write(CERT_DOC, "// docs only\n", append=True)
    docs = fx.commit([CERT_DOC], "clean: cert-doc only")
    t.expect_green("f", "cert-doc-only change", repo, base, docs)
    fx.reset(base)

    # (g) RED - federation_receive.rs.
    fx.write("src/handlers/federation_receive.rs", "// mutate receive\n", append=True)
    recv = fx.commit(["src/handlers/federation_receive.rs"], "violate: touch federation_receive.rs")
    t.expect_red("g", "federation_receive.rs violation", repo, base, recv, [
        ("src/handlers/federation_receive.rs", "did not name federation_receive.rs"),
    ])
    fx.reset(base)

    # (h) RED - federation_signing_check.rs.
    fx.write("src/handlers/federation_signing_check.rs", "// mutate signing\n", append=True)
    sign = fx.commit(["src/handlers/federation_signing_check.rs"],
                     "violate: touch federation_signing_check.rs")
    t.expect_red("h", "federation_signing_check.rs violation", repo, base, sign, [
        ("src/handlers/federation_signing_check.rs", "did not name federation_signing_check.rs"),
    ])
    fx.reset(base)

    # (h2) RED - nested path under src/federation/** (a non-recursive glob would
    #      let src/federation/identity/*.rs through).
    fx.write("src/federation/identity/mod.rs", "fn identity() {}\n")
    nested = fx.commit(["src/federation/identity/mod.rs"],
                       "violate: touch nested src/federation/identity")
    t.expect_red("h2", "nested src/federation/identity/mod.rs", repo, base, nested, [
        ("src/federation/identity/mod.rs", "did not name the nested watched path"),
    ])
    fx.reset(base)

    # (i) RED - rename of a watched file (D of the old path must still trip).
    (repo / "src/elsewhere").mkdir(parents=True, exist_ok=True)
    fx.g("mv", mod_rs, "src/elsewhere/mod.rs")
    fx.g("commit", "-q", "-m", "violate: rename watched federation file away")
    rename = fx.g("rev-parse", "HEAD")
    t.expect_red("i", "watched-file rename", repo, base, rename, [
        (mod_rs, "rename rejection did not name the old watched path"),
    ])
    fx.reset(base)

    # (j) RED - identifier RENAME (remove one, add another).
    fx.write("src/config.rs", 'pub const X: &str = "AI_MEMORY_FED_REQUIRE_SIGNATURE";\n')
    idren = fx.commit(["src/config.rs"], "violate: rename AI_MEMORY_FED_* identifier")
    t.expect_red("j", "identifier-rename", repo, base, idren, [
        ("AI_MEMORY_FED_REQUIRE_SIGNATURE", "did not name the added identifier"),
        ("AI_MEMORY_FED_REQUIRE_SIG", "did not name the removed identifier"),
    ])
    fx.reset(base)

    # (p) RED - non-ASCII path under a watched dir. core.quotePath would
    #     C-quote it and the path match would MISS; the gate reads raw -z paths.
    fx.write("src/federation/naïve_wire.rs", "fn wire() {}\n")
    quoted = fx.commit(["src/federation/naïve_wire.rs"], "violate: non-ASCII watched path")
    t.expect_red("p", "non-ASCII watched path (core.quotePath bypass)", repo, base, quoted, [
        ("src/federation/naïve_wire.rs", "did not name the raw (unquoted) non-ASCII path"),
    ])

    # ---- #3556 predicates (B) and (C) ----------------------------------

    # (q) RED - wire change + an INCIDENTAL cert-doc edit (banner untouched).
    fx.write(mod_rs, "// mutate\n", append=True)
    fx.banner("LIVE", genesis, "An incidental prose edit.\n")
    incidental = fx.commit([mod_rs, CERT_DOC], "violate: wire change + incidental doc edit")
    t.expect_red("q", "wire change + incidental cert-doc edit (#3556 hole open)", repo, base,
                 incidental, [
        ("an incidental edit is not a re-issue and not a voiding record",
         "did not name the incidental edit"),
        (sentence, "did not carry the required §7 expiry sentence"),
    ])
    fx.reset(base)

    # (r) GREEN - wire change + the STATUS line flipped to VOID.
    fx.write(mod_rs, "// mutate\n", append=True)
    fx.banner("VOID", genesis)
    void = fx.commit([mod_rs, CERT_DOC], "satisfy: wire change + VOID record")
    t.expect_green("r", "wire change + VOID record", repo, base, void, [
        ("banner STATUS=VOID", "did not report the VOID banner"),
    ])

    # (t) GREEN - an unrelated change ON TOP of the VOID record.
    fx.write("src/unrelated.rs", "// unrelated\n", append=True)
    over_void = fx.commit(["src/unrelated.rs"], "clean: unrelated edit over a VOID record")
    t.expect_green("t", "unrelated change over a VOID banner", repo, void, over_void)
    fx.reset(base)

    # (s) RED - LIVE banner + wire drift since the bind, on a range that touches
    #     NOTHING watched.
    fx.write(mod_rs, "// mutate\n", append=True)
    drifted = fx.commit([mod_rs], "earlier: wire change with no re-issue")
    fx.write("src/unrelated.rs", "// unrelated\n", append=True)
    stale_live = fx.commit(["src/unrelated.rs"], "later: unrelated edit over a stale LIVE banner")
    t.expect_red("s", "LIVE banner over wire drift (#3556 hole open)", repo, drifted, stale_live, [
        (f"claims LIVE bound to {genesis} but 1 federation-wire change(s) landed since",
         "did not name the bound SHA and the drift count"),
        ("while its banner still says LIVE", "did not carry the banner-vs-drift sentence"),
        (mod_rs, "did not list the drifted path"),
    ])

    # (u) GREEN - the same stale state HEALED by a STATUS flip to EXPIRED.
    fx.banner("EXPIRED", genesis)
    healed = fx.commit([CERT_DOC], "heal: record EXPIRED")
    t.expect_green("u", "recording EXPIRED over the stale LIVE banner", repo, stale_live, healed)
    fx.reset(base)

    # (v1) GREEN - LIVE bound to a non-ancestor whose watched tree equals HEAD's
    #      (squash-merge shape): drift is a tree comparison.
    fx.g("checkout", "-q", "-b", "side", genesis)
    fx.write("src/unrelated.rs", "// side\n", append=True)
    side = fx.commit(["src/unrelated.rs"], "side commit (unwatched)")
    fx.g("checkout", "-q", "main")
    fx.banner("LIVE", side)
    nonanc = fx.commit([CERT_DOC], "bind to a non-ancestor with an identical watched tree")
    t.expect_green("v1", "a bind to a non-ancestor with an identical watched tree", repo, base,
                   nonanc, [("federation-wire surface unchanged since the bind",
                             "did not report zero drift since the bind")])
    fx.reset(base)

    # (v2) RED - LIVE bound to a non-ancestor whose watched tree DIFFERS.
    fx.g("checkout", "-q", "-b", "side2", genesis)
    fx.write(mod_rs, "// side wire\n", append=True)
    side2 = fx.commit([mod_rs], "side commit (watched)")
    fx.g("checkout", "-q", "main")
    fx.banner("LIVE", side2)
    evasive = fx.commit([CERT_DOC], "bind to a non-ancestor whose watched tree differs")
    t.expect_red("v2", "a bind to a non-ancestor with a DIFFERENT watched tree (evasion open)",
                 repo, base, evasive, [
        (f"claims LIVE bound to {side2}", "did not name the evasive bound SHA"),
    ])
    fx.reset(base)

    # (w) fail-closed - the doc exists but its STATUS line is unparseable.
    fx.write(CERT_DOC, "# cert\nno banner here\n")
    unparseable = fx.commit([CERT_DOC], "break: banner unparseable")
    t.expect_red("w", "an unparseable STATUS line (not fail-closed)", repo, base, unparseable, [
        ("no parseable STATUS line", "did not name the missing STATUS line"),
    ])
    fx.reset(base)

    # ---- #3556 ruling: the three fixes, a cell each -----------------------

    # (x1) RED - DECOY STATUS line above the real LIVE banner + wire change.
    fx.write(mod_rs, "// mutate\n", append=True)
    fx.banner("LIVE", genesis)
    fx.prepend(CERT_DOC, "> ## STATUS — **VOID as of 2026-01-02** (decoy)")
    decoy_status = fx.commit([mod_rs, CERT_DOC],
                             "violate: decoy STATUS line above the banner + wire change")
    t.expect_red("x1", "a decoy STATUS line above the real banner", repo, base, decoy_status, [
        ("not carry exactly one STATUS banner line", "did not name the duplicated banner"),
    ])
    fx.reset(base)

    # (x2) RED - DECOY on the Binds-to line.
    fx.write(mod_rs, "// mutate\n", append=True)
    wire = fx.commit([mod_rs], "wire change")
    fx.banner("LIVE", genesis)
    fx.prepend(CERT_DOC, f"**Binds to:** `{wire}` (decoy)")
    decoy_binds = fx.commit([CERT_DOC], "violate: decoy Binds-to line above the real one")
    t.expect_red("x2", "a decoy Binds-to line above the real one", repo, base, decoy_binds, [
        ("at most one Binds-to line", "did not name the duplicated Binds-to"),
    ])
    fx.reset(base)

    # (y) RED - the cert doc DELETED in the same change as a wire change.
    fx.write(mod_rs, "// mutate\n", append=True)
    fx.g("rm", "-q", CERT_DOC)
    deleted = fx.commit([mod_rs], "violate: delete the certification + wire change")
    t.expect_red("y", "deleting the cert doc alongside a wire change", repo, base, deleted, [
        ("ABSENT at HEAD (deleted in this change)", "did not name the deletion"),
    ])
    fx.reset(base)

    # (z) GREEN - a PURE REFORMAT of the banner on a docs-only change.
    fx.write(
        CERT_DOC,
        "# Enterprise federation certification (fixture)\n\n"
        f"**Binds  to:**  {genesis.upper()}  (reformatted)\n\n"
        "#  STATUS  -  **LIVE as of 2026-01-01**  (reformatted)\n\nBody prose.\n",
    )
    reformat = fx.commit([CERT_DOC], "docs: reformat the banner")
    t.expect_green("z", "a pure banner reformat (typographic landmine)", repo, base, reformat, [
        (f"banner LIVE bound to {genesis}; federation-wire surface unchanged since the bind",
         "did not parse the reformatted banner to LIVE bound to genesis"),
    ])

    # (z2) RED - the same reformat carried alongside a wire change is INCIDENTAL.
    fx.write(mod_rs, "// mutate\n", append=True)
    reformat_wire = fx.commit([mod_rs], "violate: wire change over the reformatted banner")
    t.expect_red("z2", "reformat + wire change", repo, base, reformat_wire, [
        ("an incidental edit is not a re-issue",
         "did not classify the reformat as incidental (pair unchanged)"),
    ])
    fx.reset(base)

    # ---- #6137: pull_request judged at the merge commit ----------------------
    # History: base (LIVE bound genesis) -> stale_tip (wire change W landed with
    # no re-issue: banner LIVE with drift, the pre-#6121 carrier state). The
    # feature branch is cut at stale_tip. The live base then heals to EXPIRED.
    fx.write(mod_rs, "// W: wire change, banner not re-issued\n", append=True)
    stale_tip = fx.commit([mod_rs], "carrier before the banner fix: wire change, banner still LIVE")
    fx.g("checkout", "-q", "-b", "feature", stale_tip)
    fx.write("src/unrelated.rs", "// feature work\n", append=True)
    feature = fx.commit(["src/unrelated.rs"], "feature: unrelated change on a stale branch")
    fx.g("checkout", "-q", "main")
    fx.banner("EXPIRED", genesis)
    healed_base = fx.commit([CERT_DOC], "carrier banner fix: record EXPIRED (#6121 shape)")
    fx.g("update-ref", "refs/remotes/origin/main", healed_base)
    pr_merge = fx.merge("feature", "Merge feature into main (pull_request merge commit)")

    # (pr1) GREEN at the merge commit; RED if judged at the head in isolation
    #       (the old semantics), proving the two differ on this very history.
    t.expect_green("pr1", "stale-LIVE head banner with base banner EXPIRED, judged at the merge commit",
                   repo, healed_base, feature, [
        ("federation-wire surface unchanged", "did not pass at the merge commit"),
        ("banner STATUS=EXPIRED", "did not read the EXPIRED banner at the merge commit"),
    ], tip=pr_merge)
    t.expect_red("pr1-head", "head-only judgment of the same stale branch (old semantics)", repo,
                 healed_base, feature, [
        ("while its banner still says LIVE", "did not show the stale-LIVE head failure"),
    ])
    pr_env = _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=feature,
                       GITHUB_BASE_REF="main", GITHUB_SHA=pr_merge, PATH=os.environ.get("PATH", ""))
    rc, out, err = run_gate(repo, pr_env)
    if rc != 0:
        t.fail("(pr1-gate): pull_request event on the stale branch did not pass end to end:", out + err)

    # (pr3) the payload PR_BASE_SHA is stale (genesis); the LIVE base ref wins.
    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        rc, out, err = run_gate(repo, dict(pr_env, PR_BASE_SHA=genesis))
    err = err + captured.getvalue()
    if rc != 0:
        t.fail("(pr3): a stale payload PR_BASE_SHA broke the pull_request verdict:", out + err)
    elif f"unchanged in {healed_base}..{pr_merge}" not in out:
        t.fail("(pr3): the live base was NOT used (range should be base tip..merge commit):", out)
    elif "using the live base" not in err:
        t.fail("(pr3): the stale payload base was not reported:", err)

    # (pr3b) the stale payload base would have given a different range: prove
    #        the verdict text changes if the stale sha were honoured.
    stale_ok, stale_text = check_change(repo, genesis, feature, pr_merge)
    if stale_ok or "is not on the live base" not in stale_text:
        t.fail("(pr3b): a base that does not contain the merge commit's first parent did not fail closed", stale_text)

    # (pr2) the head FLIPS the banner (voiding record + wire change) while the
    #       live base has moved on: detected over merge-base..merge-commit.
    fx.reset(base)
    fx.g("checkout", "-q", "-b", "flip", base)
    fx.write(mod_rs, "// flip branch wire change\n", append=True)
    fx.banner("VOID", genesis)
    flip = fx.commit([mod_rs, CERT_DOC], "flip: wire change + VOID record")
    fx.g("checkout", "-q", "main")
    fx.write("src/unrelated.rs", "// base moved\n", append=True)
    moved_base = fx.commit(["src/unrelated.rs"], "base moves on with an unrelated change")
    fx.g("update-ref", "refs/remotes/origin/main", moved_base)
    flip_merge = fx.merge("flip", "Merge flip into main")
    t.expect_green("pr2", "head that flips the banner (VOID) with the base moved on", repo,
                   moved_base, flip, [
        ("cert doc re-issued/voided", "did not detect the banner flip over merge-base..merge-commit"),
        (f"{moved_base}..{flip_merge}", "did not measure base tip..merge-commit"),
    ], tip=flip_merge)
    # (pr2b) the same wire change WITHOUT the banner flip is still RED there.
    fx.reset(moved_base)
    fx.g("checkout", "-q", "-b", "noflip", base)
    fx.write(mod_rs, "// noflip branch wire change\n", append=True)
    noflip = fx.commit([mod_rs], "noflip: wire change, no cert-doc change")
    fx.g("checkout", "-q", "main")
    noflip_merge = fx.merge("noflip", "Merge noflip into main")
    t.expect_red("pr2b", "wire change without a banner flip over a moved base", repo, moved_base,
                 noflip, [
        (sentence, "did not carry the required §7 expiry sentence"),
        (mod_rs, "did not name the watched path"),
        ("judged at the pull_request merge commit", "did not say it judged the merge commit"),
    ], tip=noflip_merge)

    # (pr5) conductor decision (#6137): the banner is already EXPIRED at the
    #       fork point, the base then gained a wire change, and a stale branch
    #       with no wire change of its own must PASS (the base-side change was
    #       judged when it landed; the PR's own effect is nil).
    fx.reset(base)
    fx.banner("EXPIRED", genesis)
    fork5 = fx.commit([CERT_DOC], "base: banner EXPIRED at the fork point")
    fx.g("checkout", "-q", "-b", "stale5", fork5)
    fx.write("src/unrelated.rs", "// stale5 branch work\n", append=True)
    stale5 = fx.commit(["src/unrelated.rs"], "stale5: unrelated change, no wire change")
    fx.g("checkout", "-q", "main")
    fx.write(mod_rs, "// base-side wire change after the fork\n", append=True)
    base5 = fx.commit([mod_rs], "base gains a wire change after the fork (banner already EXPIRED)")
    fx.g("update-ref", "refs/remotes/origin/main", base5)
    merge5 = fx.merge("stale5", "Merge stale5 into main")
    if mod_rs not in changed_paths(repo, fork5, merge5):
        t.fail("(pr5): control: merge-base..merge-commit no longer sees the base-side wire change")
    t.expect_green("pr5", "stale branch with no wire change over a base that gained one", repo,
                   base5, stale5, [
        (f"unchanged in {base5}..{merge5}", "did not measure base tip..merge-commit"),
    ], tip=merge5)
    rc, out, err = run_gate(repo, dict(pr_env, PR_HEAD_SHA=stale5, GITHUB_SHA=merge5))
    if rc != 0:
        t.fail("(pr5-gate): pull_request event on the stale branch did not pass end to end:", out + err)

    # (pr6) the PR itself adds a wire change, does not flip the banner, base
    #       unchanged: still RED under (A)/(B).
    fx.reset(base)
    fx.g("checkout", "-q", "-b", "wire6", base)
    fx.write(mod_rs, "// wire6 branch wire change\n", append=True)
    wire6 = fx.commit([mod_rs], "wire6: wire change, banner untouched")
    fx.g("checkout", "-q", "main")
    fx.g("update-ref", "refs/remotes/origin/main", base)
    merge6 = fx.merge("wire6", "Merge wire6 into main")
    t.expect_red("pr6", "PR wire change without a banner flip, base unchanged", repo, base, wire6, [
        (sentence, "did not carry the required section 7 expiry sentence"),
        (mod_rs, "did not name the watched path"),
        (f"{base}..{merge6}", "did not measure base tip..merge-commit"),
    ], tip=merge6)

    # ---- #6138: merge-commit structure cells ------------------------------
    # main is at `base`; h7 is the PR head, o7 an unrelated branch.
    fx.reset(base)
    fx.g("update-ref", "refs/remotes/origin/main", base)
    fx.g("checkout", "-q", "-b", "h7", base)
    fx.write("src/unrelated.rs", "// h7 PR work\n", append=True)
    head7 = fx.commit(["src/unrelated.rs"], "h7: PR work")
    fx.g("checkout", "-q", "-b", "o7", base)
    fx.write("src/other7.rs", "fn other7() {}\n")
    fx.commit(["src/other7.rs"], "o7: an unrelated branch")
    fx.g("checkout", "-q", "main")
    good7 = fx.merge("h7", "Merge h7 into main")
    fx.reset(base)
    unrel7 = fx.merge("o7", "Merge o7 into main (an unrelated branch, not the PR head)")
    fx.reset(base)
    fx.g("merge", "-q", "--no-ff", "-m", "octopus: h7 and o7 into main", "h7", "o7")
    octo7 = fx.g("rev-parse", "HEAD")
    fx.reset(base)
    env7 = _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=head7,
                     GITHUB_BASE_REF="main", GITHUB_SHA=good7, PATH=os.environ.get("PATH", ""))
    t.gate("pr7-ok", "control: a two-parent merge of the live tip and the PR head", repo, env7)
    # R2-F2: the version guard and the is-ancestor error branch are pinned.
    rc, out, err = run_gate_shimmed(tmp, repo, env7, version="git version 2.29.9")
    if rc != 1 or "git >= 2.30 is required" not in out + err:
        t.fail("(gitver): git 2.29.9 did not fail closed with the version guard:", out + err)
    rc, out, err = run_gate_shimmed(tmp, repo, env7, fail="--is-ancestor")
    if rc != 1 or "merge-base --is-ancestor exited 128" not in out + err:
        t.fail("(anc-error): an is-ancestor error did not fail closed:", out + err)
    rc, out, err = run_gate_shimmed(tmp, repo, env7)
    if rc != 0:
        t.fail("(shim-control): the pass-through git shim was REJECTED:", out + err)
    # Each of the next two cells is rejected by exactly one predicate.
    t.gate("pr7-second", "a two-parent merge whose second parent is an unrelated branch, not "
           "PR_HEAD_SHA", repo, dict(env7, GITHUB_SHA=unrel7), "is not PR_HEAD_SHA")
    t.gate("pr7-octopus", "a three-parent (octopus) merge containing the PR head", repo,
           dict(env7, GITHUB_SHA=octo7), "does not have exactly two parents")
    # The base moves by an unrelated commit after the merge ref was built.
    fx.write("src/main7.rs", "fn main7() {}\n")
    moved7 = fx.commit(["src/main7.rs"], "base moves on with an unrelated commit")
    fx.g("update-ref", "refs/remotes/origin/main", moved7)
    out = t.gate("pr4-moved", "base moved by an unrelated commit (first parent on the base)", repo, env7)
    if f"unchanged in {base}..{good7}" not in out:
        t.fail("(pr4-moved): the range did not start at the merge commit's first parent:", out)
    # Reversed parents: the PR head is the first parent, the base the second.
    fx.g("checkout", "-q", "h7")
    rev7 = fx.merge("main", "Merge main into h7 (reversed parents)")
    fx.g("checkout", "-q", "main")
    t.gate("pr4-reversed", "reversed parents (PR head first)", repo,
           dict(env7, GITHUB_SHA=rev7), "reversed parents")
    # The first parent is not on the live base at all.
    fx.g("update-ref", "refs/remotes/origin/main", side)
    off = t.gate("pr4-offbase", "first parent not on the live base", repo, env7,
                 "is not on the live base")
    if "re-run the job" in off or "push a new commit or sync the branch" not in off:
        t.fail("(pr4-offbase): the remedy must say to push or sync, never re-run:", off)
    if "is not on the live base origin/main (tip " not in off:
        t.fail("(pr4-offbase): the message must name origin/<GITHUB_BASE_REF>:", off)
    for what, sha in (("first parent", fx.g("rev-parse", f"{good7}^1")), ("live tip", side)):
        if off.count(sha) != 1:
            t.fail(f"(pr4-offbase): the {what} sha must be printed exactly once:", off)
    fx.g("update-ref", "refs/remotes/origin/main", base)

    # (pr4) pull_request fail-closed cells; each asserts the reason.
    pr_base_env = _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=feature,
                            GITHUB_BASE_REF="main", GITHUB_SHA=pr_merge,
                            PATH=os.environ.get("PATH", ""))
    hex_msg = "is not exactly 40 or 64 hex characters"
    closed = [
        ("no GITHUB_BASE_REF", {k: v for k, v in pr_base_env.items() if k != "GITHUB_BASE_REF"},
         "GITHUB_BASE_REF is unset"),
        ("no PR_HEAD_SHA", {k: v for k, v in pr_base_env.items() if k != "PR_HEAD_SHA"},
         "PR_HEAD_SHA is unset"),
        ("unresolvable PR_HEAD_SHA", dict(pr_base_env, PR_HEAD_SHA="1" * 40),
         "does not resolve to a commit"),
        ("unresolvable merge commit", dict(pr_base_env, GITHUB_SHA="2" * 40),
         "does not resolve to a commit"),
        ("a GITHUB_SHA that is not a two-parent merge", dict(pr_base_env, GITHUB_SHA=base),
         "does not have exactly two parents"),
        ("base ref neither local nor fetchable", dict(pr_base_env, GITHUB_BASE_REF="no-such-branch"),
         "cannot resolve the live base ref"),
        ("option-shaped base ref", dict(pr_base_env, GITHUB_BASE_REF="--upload-pack=x"),
         "is not a plain branch name"),
        ("option-shaped PR_HEAD_SHA", dict(pr_base_env, PR_HEAD_SHA="--upload-pack=x"), hex_msg),
        ("too-short PR_HEAD_SHA", dict(pr_base_env, PR_HEAD_SHA=feature[:6]), hex_msg),
        ("12-char abbreviated PR_HEAD_SHA", dict(pr_base_env, PR_HEAD_SHA=feature[:12]), hex_msg),
        ("40-hex GITHUB_SHA with a trailing newline",
         dict(pr_base_env, GITHUB_SHA=pr_merge + "\n"), hex_msg),
        ("non-hex GITHUB_SHA", dict(pr_base_env, GITHUB_SHA="zz" + pr_merge[2:]), hex_msg),
        ("non-hex PR_BASE_SHA", dict(pr_base_env, PR_BASE_SHA="--oops"), hex_msg),
        ("option-shaped push GITHUB_EVENT_BEFORE",
         {"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_BEFORE": "--upload-pack=x",
          "GITHUB_SHA": base, "PATH": os.environ.get("PATH", "")}, hex_msg),
    ]
    for why, env, needle in closed:
        t.gate("pr4", f"pull_request with {why}", repo, env, needle)

    # (k) fail-closed - pull_request with nothing set (missing PR head sha / base ref).
    t.gate("k", "pull_request with PR_HEAD_SHA and GITHUB_BASE_REF unset", repo,
           {"GITHUB_EVENT_NAME": "pull_request"}, "PR_HEAD_SHA is unset")

    # ---- #5970 (ported from PR #5871): the event payload is authoritative in CI ----
    push_env = {"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_BEFORE": base, "GITHUB_SHA": docs,
                "PATH": os.environ.get("PATH", "")}
    refuse = "refused (#5970, fail-closed)"
    t.gate("ci1", "control: a push range from the payload under GitHub Actions", repo,
           dict(push_env, GITHUB_ACTIONS="true"))
    t.gate("ci2", "CERT_EXPIRY_BASE/HEAD overrides under GitHub Actions", repo,
           dict(push_env, GITHUB_ACTIONS="true", CERT_EXPIRY_BASE=base, CERT_EXPIRY_HEAD=docs),
           refuse)
    t.gate("ci3", "an empty CERT_EXPIRY_BASE under GitHub Actions", repo,
           dict(push_env, GITHUB_ACTIONS="true", CERT_EXPIRY_BASE=""), refuse)
    t.gate("ci4", "CERT_EXPIRY_HEAD alone under GitHub Actions", repo,
           dict(push_env, GITHUB_ACTIONS="true", CERT_EXPIRY_HEAD=viol), refuse)
    t.gate("ci5", "an empty event name under GitHub Actions", repo,
           {"GITHUB_ACTIONS": "true", "PATH": os.environ.get("PATH", "")},
           "GITHUB_EVENT_NAME is empty in a CI run")
    t.gate("ci6", "the CERT_EXPIRY_BASE override outside CI (honoured, RED range)", repo,
           {"CERT_EXPIRY_BASE": base, "CERT_EXPIRY_HEAD": viol,
            "PATH": os.environ.get("PATH", "")}, sentence)
    t.gate("ci7", "the CERT_EXPIRY_BASE override outside CI (honoured, docs range)", repo,
           {"CERT_EXPIRY_BASE": base, "CERT_EXPIRY_HEAD": docs,
            "PATH": os.environ.get("PATH", "")})

    # (l) N/A-skip - workflow_dispatch with no override (must not false-fail).
    rc, _o, skip_msg = run_gate(repo, {"GITHUB_EVENT_NAME": "workflow_dispatch"})
    if rc != 0:
        t.fail("(l): workflow_dispatch without CERT_EXPIRY_BASE did not skip")
    if "outside CI" not in skip_msg or "refused under GitHub Actions" not in skip_msg:
        t.fail("(l): the skip message must say the overrides work only outside CI:", skip_msg)

    # (m) N/A-skip - push with all-zero before (new branch / first push).
    rc, _o, _e = run_gate(repo, {"GITHUB_EVENT_NAME": "push", "GITHUB_SHA": base,
                                  "GITHUB_EVENT_BEFORE": "0" * 40})
    if rc != 0:
        t.fail("(m): push with zero before-SHA did not skip")

    # (n) fail-closed - unresolvable range.
    if check_change(repo, "0" * 40, base)[0]:
        t.fail("(n): unresolvable base SHA did not fail closed")

    # (o) GREEN - this PR itself (scripts / workflow / allowlist / CHANGELOG
    #     only; must not trip the gate). Runs against the REAL worktree so a
    #     future edit that accidentally touches the watched surface turns the
    #     self-test red before CI does.
    own_base = ""
    for ref in ("origin/release/v1.0.0", "@{upstream}"):
        if is_commit(REPO_ROOT, ref):
            own_base = git_text(REPO_ROOT, "rev-parse", ref)
            break
    if own_base:
        own_head = git_text(REPO_ROOT, "rev-parse", "HEAD")
        ok, out = check_change(REPO_ROOT, own_base, own_head)
        if not ok:
            t.fail("(o): THIS change trips the cert-expiry gate without touching the cert doc:", out)
    else:
        print("self-test NOTE (o): skipped own-PR check (no origin/release/v1.0.0 "
              "and no @{upstream})", file=sys.stderr)

    # ---- #6124: non-discharging amendment while EXPIRED/VOID ---------------
    # 5-agent vote (4d3ea1c5), T3; decision memory 05c39563. Rule B gets a
    # pass path only when STATUS is EXPIRED/VOID at both ends AND the change
    # inserts into the cert doc exactly ONE new amendment record (plus at most
    # one blank separator line) and nothing else: header alone on its line,
    # opening its own paragraph, below STATUS, outside code fences and HTML
    # blocks, dated between the merge-base commit day and today, listing
    # exactly the changed watched paths / identifiers, citing only #6063 by
    # its issue URL, placed directly above an existing amendment header or as
    # the last paragraph of its blockquote (R3: #6354..#6359, #6365..#6369).
    # Container cells keep the container in the merge-base so only the record
    # is inserted, and the container model is the only guard that can refuse
    # them (#6357).
    url6063 = "https://github.com/alphaonedev/ai-memory-mcp/issues/6063"
    cite6063 = f"[#6063]({url6063})"
    back6063 = f"> Path back to LIVE: WP-B1 re-cert ({cite6063}) only."

    recv_rs = "src/handlers/federation_receive.rs"
    new_id = "AI_MEMORY_FED_6124_KNOB"
    green6124 = [("non-discharging", "did not say the amendment is non-discharging"),
                 ("#6063", "did not name #6063 as the way back to LIVE")]

    fx.reset(base)
    fx.banner("EXPIRED", genesis)
    exp6124 = fx.commit([CERT_DOC], "base: banner EXPIRED (#6124)")
    # #6358: the header date is bounded below by the merge-base commit day, so
    # the fixture dates its records from its own commit day, never a constant.
    day6124 = _commit_day(repo, exp6124)
    today6124 = day6124.isoformat()

    def amend(ref, items, cite=True, tag="Amendment", fence=False, date=None, back=None,
              bullet="-", prose="> Changed in this range:"):
        lines = [f"> **{tag} ({date or today6124}, {ref} - section 7 record, non-discharging).**",
                 prose]
        body = [f"> {bullet} `{i}`" for i in items]
        lines.extend(["> ```"] + body + ["> ```"] if fence else body)
        if back is not None:
            lines.append(back)
        elif cite:
            lines.append(back6063)
        return "\n".join(lines) + "\n"

    def edit_range(extra, touch=(mod_rs,), ids=False, label="x", frm=None, quoted=""):
        """From exp6124 (or FRM): edit `touch`, optionally add an identifier,
        rewrite the cert doc (banner unchanged) with `extra` below STATUS and
        `quoted` inside the STATUS blockquote, commit."""
        fx.reset(frm or exp6124)
        paths = []
        for tp in touch:
            fx.write(tp, f"// {label}\n", append=True)
            paths.append(tp)
        if ids:
            fx.write("src/config.rs", f'pub const N: &str = "{new_id}";\n', append=True)
            paths.append("src/config.rs")
        fx.banner("EXPIRED", genesis, extra, quoted)
        return fx.commit(paths + [CERT_DOC], f"6124 cell {label}")

    def doc_only(extra="", quoted="", label="mb"):
        """A merge-base for one cell: exp6124 with the cert doc rewritten."""
        return edit_range(extra, touch=(), label=label, quoted=quoted)

    rec6124 = amend("#6162", [mod_rs])
    red6124 = [(sentence, "did not carry the required section 7 expiry sentence")]

    # (6124-h1) GREEN - EXPIRED both ends + new amendment listing the one path.
    h1 = edit_range("\n" + rec6124, label="h1")
    t.expect_green("6124-h1", "EXPIRED both ends + valid new amendment", repo, exp6124, h1,
                   green6124)
    # (6124-h1b) GREEN (#6355) - the real doc's shape: the new record inside
    # the STATUS blockquote, directly above an existing record, a blank '>'
    # line before and after it.
    old_a = ("> **Amendment (2026-10-07, #6063 WP-B1 - section 7 record).** First old record.\n"
             "> Its body.\n")
    old_b = ("> **Amendment (2026-10-08, #6116 - second section 7 record).**\n"
             "> Second old record.\n")
    mb_h1b = doc_only(quoted=">\n" + old_a + ">\n" + old_b, label="h1b-mb")
    h1b = edit_range("", quoted=">\n" + old_a + ">\n" + rec6124 + ">\n" + old_b, label="h1b",
                     frm=mb_h1b)
    t.expect_green("6124-h1b", "new record between two records of the STATUS blockquote", repo,
                   mb_h1b, h1b, green6124)
    # (6124-h1c) GREEN (#6355) - the new record as the last paragraph of the
    # STATUS blockquote.
    h1c = edit_range("", quoted=">\n" + old_a + ">\n" + old_b + ">\n" + rec6124, label="h1c",
                     frm=mb_h1b)
    t.expect_green("6124-h1c", "new record closing the STATUS blockquote", repo, mb_h1b, h1c,
                   green6124)
    # (6124-h7) GREEN (#6356, X6) - the new record opens a blockquote directly
    # above an existing header: its one separator is the blank '>' AFTER it.
    mb_h7 = doc_only("\n" + old_a, label="h7-mb")
    h7 = edit_range("\n" + rec6124 + ">\n" + old_a, label="h7", frm=mb_h7)
    t.expect_green("6124-h7", "new record opening the blockquote of an existing record", repo,
                   mb_h7, h7, green6124)
    # (6124-h8) GREEN (#6356, S15/X11) - a quoted code fence left open at the
    # end of the STATUS blockquote ends with that blockquote; a record in a
    # later blockquote is rendered and counts.
    mb_h8 = doc_only("\n" + old_a, quoted=">\n> ```\n> open fence\n", label="h8-mb")
    h8 = edit_range("\n" + old_a + ">\n" + rec6124, quoted=">\n> ```\n> open fence\n",
                    label="h8", frm=mb_h8)
    t.expect_green("6124-h8", "record after a blockquote that ended inside a code fence", repo,
                   mb_h8, h8, green6124)
    # (6124-h9) GREEN (#6356, S02) - a backtick run whose info string holds a
    # backtick is inline text, not a fence opener; the record after it counts.
    mb_h9 = doc_only(quoted=">\n> ```x`y\n>\n" + old_a, label="h9-mb")
    h9 = edit_range("", quoted=">\n> ```x`y\n>\n" + rec6124 + ">\n" + old_a, label="h9",
                    frm=mb_h9)
    t.expect_green("6124-h9", "record after a backtick line that is not a fence", repo, mb_h9,
                   h9, green6124)
    # (6124-h2) GREEN - two watched paths + a new identifier, all listed.
    h2 = edit_range("\n" + amend("#6162", [mod_rs, recv_rs, new_id]), touch=(mod_rs, recv_rs),
                    ids=True, label="h2")
    t.expect_green("6124-h2", "paths and identifier all listed", repo, exp6124, h2, green6124)
    # (6124-h3) GREEN - VOID both ends works the same way.
    fx.reset(base)
    fx.banner("VOID", genesis)
    void6124 = fx.commit([CERT_DOC], "base: banner VOID (#6124)")
    fx.write(mod_rs, "// h3\n", append=True)
    fx.banner("VOID", genesis, "\n" + rec6124)
    h3 = fx.commit([mod_rs, CERT_DOC], "6124 cell h3")
    t.expect_green("6124-h3", "VOID both ends + valid new amendment", repo, void6124, h3,
                   green6124)
    # (6124-h4) GREEN - identifier-only change listed exactly.
    fx.reset(exp6124)
    fx.write("src/config.rs", f'pub const N: &str = "{new_id}";\n', append=True)
    fx.banner("EXPIRED", genesis, "\n" + amend("#6162", [new_id]))
    h4 = fx.commit(["src/config.rs", CERT_DOC], "6124 cell h4")
    t.expect_green("6124-h4", "identifier-only change listed exactly", repo, exp6124, h4,
                   green6124)
    # (6124-h5) GREEN (#6365) - HTML blocks that END before the record do not
    # hide it: a closed type-6 block, a one-line type-1 block, and a quoted
    # type-1 block ended by its blockquote.
    html_ok = ("\n<div>\n</div>\n\n<pre>one line</pre>\n\n> <pre>\n> kept as code\n\n")
    mb_h5 = doc_only(html_ok, label="h5-mb")
    h5 = edit_range(html_ok + rec6124, label="h5", frm=mb_h5)
    t.expect_green("6124-h5", "record after HTML blocks that already ended", repo, mb_h5, h5,
                   green6124)
    # (6124-h6) GREEN (#6355) - the date may be the merge-base commit day - 1
    # (time-zone slack) and today + 1.
    h6 = edit_range("\n" + amend("#6162", [mod_rs], date=(
        day6124 - datetime.timedelta(days=1)).isoformat()), label="h6")
    t.expect_green("6124-h6", "record dated the day before the merge-base", repo, exp6124, h6,
                   green6124)

    # (6124-f1) RED - a changed watched file is missing from the list.
    f1 = edit_range("\n" + rec6124, touch=(mod_rs, recv_rs), label="f1")
    t.expect_red("6124-f1", "watched file missing from the amendment list", repo, exp6124, f1,
                 red6124)
    # (6124-f2) RED - the list names a path that did not change.
    f2 = edit_range("\n" + amend("#6162", [mod_rs, recv_rs]), label="f2")
    t.expect_red("6124-f2", "extra path listed", repo, exp6124, f2, red6124)
    # (6124-f3) RED - substring / prose mention is not an exact list entry.
    f3 = edit_range("\n" + amend("#6162", [mod_rs + ".bak"]), label="f3")
    t.expect_red("6124-f3", "list entry that merely contains the path", repo, exp6124, f3, red6124)
    f3b = edit_range("\n" + amend("#6162", [], prose="> This touched the mod file in passing."),
                     label="f3b")
    t.expect_red("6124-f3b", "prose mention instead of a list entry", repo, exp6124, f3b, red6124)
    # (6124-f4) RED - a pre-existing amendment is never reused.
    old6100 = amend("#6100", [mod_rs])
    pre = doc_only("\n" + old6100, label="pre")
    f4 = edit_range("\n" + old6100 + "\nUnrelated prose edit.\n", label="f4", frm=pre)
    t.expect_red("6124-f4", "pre-existing amendment reused", repo, pre, f4, red6124 + [
        ("no NEW amendment record", "did not say no new record was added")])
    # (6124-f4b) RED - an existing amendment re-dated (header edited) is a
    # rewrite of the ledger, not a new record.
    f4b = edit_range("\n" + amend("#6100", [mod_rs], date=(
        day6124 + datetime.timedelta(days=1)).isoformat()), label="f4b", frm=pre)
    t.expect_red("6124-f4b", "pre-existing amendment header re-dated", repo, pre, f4b, red6124)
    # (6124-f4c) RED - an old one-line amendment split so its header stands
    # alone is the old record rewritten, not a new one.
    oneline = (f"> **Amendment ({today6124}, #6100 - record).** Body text on the header line.\n"
               "> More of the old record.\n")
    pre1 = doc_only("\n" + oneline, label="pre1")
    f4c = edit_range(f"\n> **Amendment ({today6124}, #6100 - record).**\n"
                     "> Body text on the header line.\n> More of the old record.\n"
                     f"> - `{mod_rs}`\n{back6063}\n", label="f4c", frm=pre1)
    t.expect_red("6124-f4c", "old one-line amendment split into a new-looking one", repo, pre1,
                 f4c, red6124)
    # (6124-f4d) RED - an old amendment deleted, a valid new one added.
    f4d = edit_range("\n" + rec6124, label="f4d", frm=pre)
    t.expect_red("6124-f4d", "old amendment deleted beside a new one", repo, pre, f4d, red6124)
    # (6124-f4e) RED - an old amendment's body edited beside a valid new one.
    f4e = edit_range("\n" + old6100.replace("Changed in this range:", "Changed (edited):")
                     + "\n" + rec6124, label="f4e", frm=pre)
    t.expect_red("6124-f4e", "old amendment body edited beside a new one", repo, pre, f4e,
                 red6124)
    # (6124-f4f) RED (#6356, S06) - an old record moved from below STATUS to
    # above it, beside a valid new record.
    fx.reset(pre)
    fx.write(mod_rs, "// f4f\n", append=True)
    fx.write(CERT_DOC, "<!-- Copyright 2026 fixture / SPDX-License-Identifier: Apache-2.0 -->\n"
             "# Enterprise federation certification (fixture)\n\n"
             f"**Binds to:** `{genesis}` (fixture bind)\n\n" + old6100 + "\n"
             "> ## STATUS — **EXPIRED as of 2026-01-01** (fixture)\n\nBody prose.\n\n" + rec6124)
    f4f = fx.commit([mod_rs, CERT_DOC], "6124 cell f4f")
    t.expect_red("6124-f4f", "old record moved across STATUS", repo, pre, f4f, red6124)
    # (6124-f4g) RED - a header that already exists ANYWHERE in the merge-base
    # (even inside a code fence) is not a new record.
    fenced_old = "\n```\n" + rec6124 + "```\n"
    mb_f4g = doc_only(fenced_old, label="f4g-mb")
    f4g = edit_range(fenced_old + "\n" + rec6124, label="f4g", frm=mb_f4g)
    t.expect_red("6124-f4g", "copy of a header already present in the merge-base", repo, mb_f4g,
                 f4g, red6124 + [("no NEW amendment record", "did not say no new record")])
    # (6124-f5) RED - LIVE at both ends keeps rule B whatever the doc says.
    fx.reset(base)
    fx.write(mod_rs, "// f5\n", append=True)
    fx.banner("LIVE", genesis, "\n" + rec6124)
    f5 = fx.commit([mod_rs, CERT_DOC], "6124 cell f5")
    t.expect_red("6124-f5", "LIVE at merge-base and judged commit + amendment", repo, base, f5,
                 red6124)
    # (6124-f6) RED - EXPIRED at the merge-base flipped to LIVE (stale bind)
    # beside an amendment. A banner change never enters the amendment route;
    # it is the #3556 re-issue hatch, and rule C must still hold the new LIVE
    # claim to its bind (pins that the hatch out of EXPIRED keeps rule C).
    fx.reset(exp6124)
    fx.write(mod_rs, "// f6\n", append=True)
    fx.banner("LIVE", genesis, "\n" + rec6124)
    f6 = fx.commit([mod_rs, CERT_DOC], "6124 cell f6")
    t.expect_red("6124-f6", "EXPIRED flipped to a stale LIVE + amendment", repo, exp6124, f6,
                 [("claims LIVE bound to", "did not hold the new LIVE claim to its bind")])
    # (6124-f7) RED - decoy: the list inside a code fence in the record.
    f7 = edit_range("\n" + amend("#6162", [mod_rs], fence=True), label="f7")
    t.expect_red("6124-f7", "list inside a code fence", repo, exp6124, f7, red6124)

    def contained(label, before, after="", quoted_before=None, sep=""):
        """#6357: a merge-base whose doc already holds the container
        (BEFORE + AFTER), and a change that inserts only the record (and SEP)
        between them."""
        if quoted_before is not None:
            mb_ = doc_only(quoted=quoted_before, label=label + "-mb")
            hd_ = edit_range("", quoted=quoted_before + sep + rec6124, label=label, frm=mb_)
        else:
            mb_ = doc_only(before + after, label=label + "-mb")
            hd_ = edit_range(before + sep + rec6124 + after, label=label, frm=mb_)
        return mb_, hd_

    # (6124-f7b) RED (#6357) - the whole record inside a pre-existing ``` fence
    # (a blank line after the opener, so only the fence rule hides it).
    mb_, hd_ = contained("f7b", "\n```\n\n", "\n```\n")
    t.expect_red("6124-f7b", "whole amendment inside a code fence", repo, mb_, hd_, red6124)
    # (6124-f7c) RED - a ``` fence is not closed by ~~~.
    mb_, hd_ = contained("f7c", "\n```\n~~~\n\n", "\n```\n")
    t.expect_red("6124-f7c", "amendment inside a ``` fence 'closed' by ~~~", repo, mb_, hd_,
                 red6124)
    # (6124-f7d) RED - a ```` fence is not closed by a shorter ```.
    mb_, hd_ = contained("f7d", "\n````\n```\n\n", "\n````\n")
    t.expect_red("6124-f7d", "amendment inside a 4-backtick fence", repo, mb_, hd_, red6124)
    # (6124-f7e) RED - an amendment in an HTML comment never renders.
    mb_, hd_ = contained("f7e", "\n<!--\n\n", "\n-->\n")
    t.expect_red("6124-f7e", "amendment inside an HTML comment", repo, mb_, hd_, red6124)
    # (6124-f7f) RED - a comment opened on a quoted line, still open when the
    # blockquote ends.
    mb_, hd_ = contained("f7f", "", quoted_before=">\n> <!-- hidden\n", sep=">\n")
    t.expect_red("6124-f7f", "amendment inside a quoted HTML comment", repo, mb_, hd_, red6124)
    # (6124-f7g) RED - a header indented more than 4 columns after '>' is an
    # indented code block, not a header.
    head7g, rest7g = rec6124.split("\n", 1)
    mb_f7g = doc_only("\n> Note.\n", label="f7g-mb")
    f7g = edit_range("\n> Note.\n>\n>     " + head7g[2:] + "\n" + rest7g, label="f7g",
                     frm=mb_f7g)
    t.expect_red("6124-f7g", "amendment inside an indented code block", repo, mb_f7g, f7g,
                 red6124)
    # (6124-f7h..f7n) RED (#6365) - the new record inside a pre-existing HTML
    # block of each CommonMark kind that does not end at a blank '>' line:
    # type 1 (<pre>), 3 (<?), 4 (<!X), 5 (<![CDATA[), all quoted and open to
    # the end of their blockquote; type 6 (<div>) and type 7 (a custom tag
    # alone on its line), unquoted, where a '>' line is not a blank line.
    for lab, opener in (("f7h", "> <pre>"), ("f7i", "> <?php"), ("f7j", "> <!DOCTYPE note"),
                        ("f7k", "> <![CDATA[")):
        mb_, hd_ = contained(lab, "", quoted_before=">\n" + opener + "\n", sep=">\n")
        t.expect_red(f"6124-{lab}", f"amendment inside a quoted HTML block {opener!r}", repo,
                     mb_, hd_, red6124)
    for lab, opener in (("f7m", "<div>"), ("f7n", "<x-note>")):
        mb_, hd_ = contained(lab, "\n" + opener + "\n", sep=">\n")
        t.expect_red(f"6124-{lab}", f"amendment inside an unquoted HTML block {opener!r}", repo,
                     mb_, hd_, red6124)
    # (6124-f7p) RED (#6365) - an HTML opener inserted beside a valid record
    # hides the existing records below it in the rendered doc.
    mb_f7p = doc_only(quoted=">\n" + old_a + ">\n" + old_b, label="f7p-mb")
    f7p = edit_range("", quoted=">\n" + rec6124 + ">\n> <?\n" + old_a + ">\n" + old_b,
                     label="f7p", frm=mb_f7p)
    t.expect_red("6124-f7p", "HTML opener hiding the existing records", repo, mb_f7p, f7p,
                 red6124 + [("may only gain the new amendment record",
                             "did not name the insertion-only rule")])
    # (6124-f8) RED - an identifier changed but is not listed.
    f8 = edit_range("\n" + rec6124, ids=True, label="f8")
    t.expect_red("6124-f8", "identifier changed but not listed", repo, exp6124, f8, red6124)
    # (6124-f9) RED - the amendment sits above the STATUS line.
    fx.reset(exp6124)
    fx.write(mod_rs, "// f9\n", append=True)
    fx.write(CERT_DOC, "<!-- Copyright 2026 fixture / SPDX-License-Identifier: Apache-2.0 -->\n"
             "# Enterprise federation certification (fixture)\n\n"
             f"**Binds to:** `{genesis}` (fixture bind)\n\n" + rec6124 + "\n"
             "> ## STATUS — **EXPIRED as of 2026-01-01** (fixture)\n\nBody prose.\n")
    f9 = fx.commit([mod_rs, CERT_DOC], "6124 cell f9")
    t.expect_red("6124-f9", "amendment above STATUS", repo, exp6124, f9, red6124)
    # (6124-f9a) RED (#6356, S17) - a record glued to the STATUS line below it.
    fx.reset(exp6124)
    fx.write(mod_rs, "// f9a\n", append=True)
    fx.write(CERT_DOC, "<!-- Copyright 2026 fixture / SPDX-License-Identifier: Apache-2.0 -->\n"
             "# Enterprise federation certification (fixture)\n\n"
             f"**Binds to:** `{genesis}` (fixture bind)\n\n" + rec6124
             + "> ## STATUS — **EXPIRED as of 2026-01-01** (fixture)\n\nBody prose.\n")
    f9a = fx.commit([mod_rs, CERT_DOC], "6124 cell f9a")
    t.expect_red("6124-f9a", "record running into the STATUS line", repo, exp6124, f9a, red6124)
    # (6124-f9e) RED (#6356, S16) - an unquoted record header is read as a
    # record and refused for its shape, not missed as "no new record".
    f9e = edit_range("\n" + "\n".join(ln[2:] for ln in rec6124.splitlines()) + "\n",
                     label="f9e")
    t.expect_red("6124-f9e", "unquoted record header", repo, exp6124, f9e,
                 red6124 + [("inside the blockquote", "did not name the header's blockquote")])
    # (6124-f9f) RED (#6356, N28) - a commit sha in the header (a GitHub
    # autolink) is refused like one in the body.
    f9f = edit_range("\n" + amend("#6162 see 02eddc6c6", [mod_rs]), label="f9f")
    t.expect_red("6124-f9f", "commit sha in the header", repo, exp6124, f9f, red6124)
    # (6124-f9b) RED - the header must open its own paragraph; glued under a
    # prose line that already exists it renders inside that paragraph.
    mb_f9b = doc_only("\n> Preceding prose line.\n", label="f9b-mb")
    f9b = edit_range("\n> Preceding prose line.\n" + rec6124, label="f9b", frm=mb_f9b)
    t.expect_red("6124-f9b", "header not opening its own paragraph", repo, mb_f9b, f9b, red6124)
    # (6124-f9c) RED - the header stands alone on its line: body text after
    # the closing ** (even text ending in bold) is refused.
    f9c = edit_range("\n" + rec6124.replace(
        "non-discharging).**", "non-discharging).** Changed in **this range**", 1),
        label="f9c")
    t.expect_red("6124-f9c", "header line carrying body text", repo, exp6124, f9c, red6124)
    # (6124-f9d) RED (#6367) - a link in the header.
    f9d = edit_range("\n" + rec6124.replace(
        "#6162 - section", "[#6162](https://example.invalid/x) - section", 1), label="f9d")
    t.expect_red("6124-f9d", "link in the header", repo, exp6124, f9d, red6124)
    # (6124-f10) RED - no back line at all.
    f10 = edit_range("\n" + amend("#6162", [mod_rs], cite=False), label="f10")
    t.expect_red("6124-f10", "amendment without the #6063 citation", repo, exp6124, f10, red6124)
    # (6124-f10b) RED (#6357) - the canonical #6063 link AND another issue.
    f10b = edit_range("\n" + amend("#6162", [mod_rs], back=(
        f"> Path back to LIVE: WP-B1 re-cert ({cite6063} and #6064) only.")), label="f10b")
    t.expect_red("6124-f10b", "canonical #6063 plus another issue", repo, exp6124, f10b,
                 red6124)
    # (6124-f10c) RED - a second back line citing another issue.
    f10c = edit_range("\n" + rec6124 + "> Path back to LIVE: #6064.\n", label="f10c")
    t.expect_red("6124-f10c", "second back line citing another issue", repo, exp6124, f10c,
                 red6124)
    # (6124-f10d) RED (#6357) - another issue as a bare URL beside the
    # canonical link.
    f10d = edit_range("\n" + amend("#6162", [mod_rs], back=(
        f"> Path back to LIVE: WP-B1 re-cert ({cite6063}) or "
        "https://github.com/alphaonedev/ai-memory-mcp/issues/6064.")), label="f10d")
    t.expect_red("6124-f10d", "back line naming another issue by bare URL", repo, exp6124, f10d,
                 red6124)
    # (6124-f10e) RED - "#6063" linked to another repository's issue.
    f10e = edit_range("\n" + amend("#6162", [mod_rs], back=(
        f"> Path back to LIVE: WP-B1 re-cert ({cite6063}; mirror "
        "[#6063](https://github.com/example-fork/ai-memory-mcp/issues/6063)) only.")),
        label="f10e")
    t.expect_red("6124-f10e", "#6063 linked to another repository", repo, exp6124, f10e,
                 red6124)
    # (6124-f10f) RED - a bare "#6063" without the issue URL the doc uses
    # (double-guarded: the canonical link is absent AND '#' is left over).
    f10f = edit_range("\n" + amend("#6162", [mod_rs], back=(
        "> Path back to LIVE: WP-B1 re-cert (#6063) only.")), label="f10f")
    t.expect_red("6124-f10f", "#6063 cited without its issue URL", repo, exp6124, f10f, red6124)
    # (6124-f10g) RED - a back line with no citation at all; the canonical
    # link in another line does not count.
    f10g = edit_range("\n" + amend("#6162", [mod_rs], prose=(
        f"> Changed in this range, see {cite6063}:"), back="> Path back to LIVE: WP-B1 only."),
        label="f10g")
    t.expect_red("6124-f10g", "back line without the canonical #6063 link", repo, exp6124,
                 f10g, red6124)
    # (6124-f10h..f10n) RED (#6367) - GitHub autolink forms and lookalikes.
    for lab, tail in (("f10h", "not GH-6064"), ("f10i", "see example-org/other-repo#6064"),
                      ("f10j", "see alphaonedev/ai-memory-mcp@02eddc6c6"),
                      ("f10k", "see ＃6064"), ("f10l", "see #6063x"),
                      ("f10m", "see 02eddc6c6"), ("f10n", "see www.example.invalid"),
                      ("f10o", "ask ops@example.invalid"), ("f10p", "see &num;6064")):
        cell = edit_range("\n" + amend("#6162", [mod_rs], back=(
            f"> Path back to LIVE: WP-B1 re-cert ({cite6063}) only, {tail}.")), label=lab)
        t.expect_red(f"6124-{lab}", f"back line carrying {tail!r}", repo, exp6124, cell, red6124)
    # (6124-f10q) RED - a reference-style link to #6063 on the back line.
    f10q = edit_range("\n" + amend("#6162", [mod_rs], back=(
        "> Path back to LIVE: WP-B1 re-cert ([#6063][c]) only.")), label="f10q")
    t.expect_red("6124-f10q", "reference-style link on the back line", repo, exp6124, f10q,
                 red6124)
    # (6124-f10r) RED (#6356, X8/S08) - a shortcut reference link whose
    # definition already sits in the doc: only its brackets show in the record.
    def_6064 = "\n[x]: https://github.com/alphaonedev/ai-memory-mcp/issues/6064\n"
    mb_f10r = doc_only(def_6064, label="f10r-mb")
    f10r = edit_range(def_6064 + "\n" + amend("#6162", [mod_rs], back=(
        f"> Path back to LIVE: WP-B1 re-cert ({cite6063}) only, see [x].")), label="f10r",
        frm=mb_f10r)
    t.expect_red("6124-f10r", "shortcut reference link in the record", repo, mb_f10r, f10r,
                 red6124)
    # (6124-f11) RED - list lines after the block ended (a new blockquote
    # after a blank line) do not count.
    mb_f11 = doc_only("\n\n> - `" + mod_rs + "`\n", label="f11-mb")
    f11 = edit_range("\n" + amend("#6162", []) + "\n> - `" + mod_rs + "`\n", label="f11",
                     frm=mb_f11)
    t.expect_red("6124-f11", "list outside the amendment block", repo, mb_f11, f11, red6124)
    # (6124-f11b) RED (#6354) - a later '>' paragraph of the same blockquote
    # (here naming another issue) would be read as part of the new record.
    mb_f11b = doc_only("\n> Path back to LIVE: #6064.\n", label="f11b-mb")
    f11b = edit_range("\n" + rec6124 + ">\n> Path back to LIVE: #6064.\n", label="f11b",
                      frm=mb_f11b)
    t.expect_red("6124-f11b", "record taking over a later paragraph", repo, mb_f11b, f11b,
                 red6124)
    # (6124-f11c) RED (#6354) - a lazy-continuation line (no '>') joins the
    # record's last paragraph when rendered.
    mb_f11c = doc_only("\nPath back to LIVE: GH-6064.\n", label="f11c-mb")
    f11c = edit_range("\n" + rec6124 + "Path back to LIVE: GH-6064.\n", label="f11c",
                      frm=mb_f11c)
    t.expect_red("6124-f11c", "lazy continuation after the record", repo, mb_f11c, f11c,
                 red6124)
    # (6124-f11d) RED (#6366) - the new record spliced between two paragraphs
    # of one existing record.
    old_multi = ("> **Amendment (2026-10-08, #6100 - record).** Old body.\n>\n"
                 "> Second paragraph of the old record.\n")
    mb_f11d = doc_only(quoted=">\n" + old_multi, label="f11d-mb")
    f11d = edit_range("", quoted=">\n" + old_multi.replace(
        ">\n> Second", ">\n" + rec6124 + ">\n> Second"), label="f11d", frm=mb_f11d)
    t.expect_red("6124-f11d", "new record spliced inside an old record", repo, mb_f11d, f11d,
                 red6124)
    # (6124-f11e..f11i) RED - record grammar: every line is prose, a list
    # entry or the back line; printable ASCII (and a few typographic marks)
    # only; no HTML in the record.
    for lab, line in (("f11e", "> 1. Step one."), ("f11f", "> Changed‮ here."),
                      ("f11g", "> Changed\x1b here."), ("f11h", "> Changed <b>here</b>."),
                      ("f11i", "> > nested quote")):
        cell = edit_range("\n" + rec6124.replace(back6063, line + "\n" + back6063), label=lab)
        t.expect_red(f"6124-{lab}", f"record line {line!r}", repo, exp6124, cell, red6124)
    # (6124-f11j) RED (#6356, X4) - a list entry hidden in an HTML comment
    # inside the record.
    f11j = edit_range("\n" + amend("#6162", []).replace(
        back6063, f"> <!--\n> - `{mod_rs}`\n> -->\n" + back6063), label="f11j")
    t.expect_red("6124-f11j", "list entry inside a comment in the record", repo, exp6124, f11j,
                 red6124)
    # (6124-f11k) RED - a '+' bullet is not a list entry.
    f11k = edit_range("\n" + amend("#6162", [mod_rs], bullet="+"), label="f11k")
    t.expect_red("6124-f11k", "'+' bullet entry", repo, exp6124, f11k, red6124)
    # (6124-f11l) RED (#6356, X12) - a list entry given twice.
    f11l = edit_range("\n" + amend("#6162", [mod_rs, mod_rs]), label="f11l")
    t.expect_red("6124-f11l", "list entry given twice", repo, exp6124, f11l, red6124)
    # (6124-f12a) RED - the cert doc cannot be read at the merge-base for the
    # ledger: fail closed, never "no prior amendments".
    real_run_git = globals()["run_git"]
    reads = {"n": 0}

    def flaky_run_git(repo_, *args, **kw):
        joined = " ".join(str(a) for a in args)
        if CERT_DOC in joined and pre in joined:
            reads["n"] += 1
            if reads["n"] > 1:
                return subprocess.CompletedProcess(list(args), 128, b"",
                                                   b"injected read failure (self-test)")
        return real_run_git(repo_, *args, **kw)

    globals()["run_git"] = flaky_run_git
    try:
        t.expect_red("6124-f12a", "cert doc unreadable at the merge-base", repo, pre, f4,
                     [("fail-closed", "did not fail closed on the unreadable cert doc")])
    finally:
        globals()["run_git"] = real_run_git
    # (6124-f12b) RED (#6359: the production reader, called directly) - a
    # symlink at the cert-doc path is never read as the ledger.
    fx.reset(exp6124)
    (repo / CERT_DOC).unlink()
    os.symlink("../../README.md", str(repo / CERT_DOC))
    link6124 = fx.commit([CERT_DOC], "6124 cell f12b: symlinked cert doc")
    try:
        read_cert_doc(repo, link6124)
        t.fail("(6124-f12b): a symlinked cert doc was read as the amendment ledger")
    except GateError:
        pass
    # (6124-f12c) RED (#6359) - an oversized cert doc is refused, not read whole.
    saved_cap = globals().get("CERT_DOC_MAX_BYTES")
    globals()["CERT_DOC_MAX_BYTES"] = 16
    try:
        read_cert_doc(repo, exp6124)
        t.fail("(6124-f12c): a cert doc above the size cap was read")
    except GateError:
        pass
    finally:
        if saved_cap is None:
            globals().pop("CERT_DOC_MAX_BYTES", None)
        else:
            globals()["CERT_DOC_MAX_BYTES"] = saved_cap
    # (6124-f12e) RED (#6356, S13; the production reader, called directly) -
    # a tree without the cert doc is refused, never read as an empty ledger.
    fx.reset(exp6124)
    fx.g("rm", "-q", "--", CERT_DOC)
    fx.g("commit", "-q", "-m", "6124 cell f12e: cert doc absent")
    gone6124 = fx.g("rev-parse", "HEAD")
    try:
        read_cert_doc(repo, gone6124)
        t.fail("(6124-f12e): a tree without the cert doc was read as an empty ledger")
    except GateError as exc:
        if "is absent" not in str(exc):
            t.fail("(6124-f12e): the absent cert doc was refused for another reason", str(exc))
    # (6124-f12f) RED (#6356, S14) - git failing to read the blob fails closed.
    def catfile_fails(repo_, *args, **kw):
        if "cat-file" in args and "blob" in args:
            return subprocess.CompletedProcess(list(args), 128, b"",
                                               b"injected cat-file failure (self-test)")
        return real_run_git(repo_, *args, **kw)

    globals()["run_git"] = catfile_fails
    try:
        read_cert_doc(repo, exp6124)
        t.fail("(6124-f12f): a failed blob read was taken as the cert doc")
    except GateError as exc:
        if "cat-file blob" not in str(exc):
            t.fail("(6124-f12f): the failed blob read was refused for another reason", str(exc))
    finally:
        globals()["run_git"] = real_run_git
    # (6124-f12d) RED (#6368) - invalid UTF-8 in the cert doc fails closed: a
    # U+FFFD in an old record swapped for an invalid byte beside a valid new
    # record is not "byte-identical" text.
    mb_f12d = doc_only("\n> **Amendment (2026-10-08, #6100 - record).** Old � body.\n",
                       label="f12d-mb")
    fx.reset(mb_f12d)
    fx.write(mod_rs, "// f12d\n", append=True)
    raw = (repo / CERT_DOC).read_bytes().replace("�".encode("utf-8"), b"\xff")
    (repo / CERT_DOC).write_bytes(raw + b"\n" + rec6124.encode("utf-8"))
    f12d = fx.commit([mod_rs, CERT_DOC], "6124 cell f12d")
    t.expect_red("6124-f12d", "invalid UTF-8 in the cert doc", repo, mb_f12d, f12d,
                 [("not valid UTF-8", "did not fail closed on the undecodable cert doc")])
    # (6124-f13) RED - the #6162 shape (EXPIRED, cert doc not touched): the
    # headline and the remedy name the amendment route, never "re-issue or
    # void" (#6369), and the remedy names where the record may go (#6366).
    fx.reset(exp6124)
    fx.write(mod_rs, "// f13\n", append=True)
    f13 = fx.commit([mod_rs], "6124 cell f13")
    out13 = t.expect_red("6124-f13", "EXPIRED + watched change without the cert doc", repo,
                         exp6124, f13, red6124 + [
                             ("> **Amendment (YYYY-MM-DD", "did not name the amendment header form"),
                             (f"> - `{mod_rs}`", "did not name the exact list entry"),
                             ("Path back to LIVE:", "did not name the #6063 back line"),
                             ("#3899", "did not warn that a re-bind without re-measurement is forbidden"),
                             ("directly above an existing amendment header",
                              "did not name where the record may be placed"),
                         ])
    head13 = out13.split("\n", 1)[0]
    if "re-issue or void" in head13 or "non-discharging amendment" not in head13:
        t.fail("(6124-f13): the EXPIRED headline must name the non-discharging amendment, "
               "not 're-issue or void' (#6369):", out13)
    # (6124-f14) RED - exactly ONE new amendment.
    f14 = edit_range("\n" + rec6124 + "\n" + amend("#6199", ["src/unrelated.rs"], cite=False),
                     label="f14")
    t.expect_red("6124-f14", "a second, unrelated new amendment", repo, exp6124, f14,
                 red6124 + [("exactly one new amendment", "did not name the one-record rule")])
    # (6124-f15a..d) RED - the header date is a real ISO date, not in the
    # future (#6356, X9: two days past the commit day), not back-dated before
    # the merge-base commit day (#6358).
    f15a = edit_range("\n" + amend("#6162", [mod_rs], date="2026-13-45"), label="f15a")
    t.expect_red("6124-f15a", "impossible header date", repo, exp6124, f15a, red6124)
    f15b = edit_range("\n" + amend("#6162", [mod_rs], date="9999-12-31"), label="f15b")
    t.expect_red("6124-f15b", "far-future header date", repo, exp6124, f15b, red6124)
    utc_today = datetime.datetime.now(datetime.timezone.utc).date()
    f15c = edit_range("\n" + amend("#6162", [mod_rs], date=(
        max(day6124, utc_today) + datetime.timedelta(days=2)).isoformat()), label="f15c")
    t.expect_red("6124-f15c", "header dated two days ahead", repo, exp6124, f15c, red6124)
    f15d = edit_range("\n" + amend("#6162", [mod_rs], date=(
        day6124 - datetime.timedelta(days=3)).isoformat()), label="f15d")
    t.expect_red("6124-f15d", "header back-dated before the merge-base day", repo, exp6124,
                 f15d, red6124 + [("before the merge-base", "did not name the date floor")])

    # (6124-l*) RED (R3-F1 #6365 residual, #6443): an HTML block or a fence
    # opened inside a LIST ITEM of the ledger blockquote (`> - ` and `> 1. `
    # items, the record indented into the item) hides the record from the
    # rendered doc, and an opener behind an indented `>` or a `>` + tab does
    # the same. The opener is already in the merge-base so only the record is
    # inserted; the container model is the only guard that can refuse it.
    # Offline cells only, one per HTML block kind 1-7 and per fence kind.
    def indented(rec, n):
        return "".join("> " + " " * n + ln[2:] + "\n" for ln in rec.rstrip("\n").split("\n"))

    gone6124 = [("no NEW amendment record", "did not report the hidden record as not added")]
    for oname, op in (("script", "<script>"), ("style", "<style>"), ("pre", "<pre>"),
                      ("textarea", "<textarea>"), ("comment", "<!-- x"), ("pi", "<?x"),
                      ("decl", "<!X"), ("cdata", "<![CDATA["), ("div", "<div>"),
                      ("custom", "<x-y>"), ("fence", "```"), ("tilde", "~~~")):
        for lname, mark, ind in (("ul", "- ", 2), ("ol", "1. ", 3)):
            tag = f"l-{oname}-{lname}"
            pre = f">\n> {mark}{op}\n"
            mb_l = doc_only(quoted=pre + ">\n" + old_b, label=f"{tag}-mb")
            cell_l = edit_range("", quoted=pre + indented(rec6124, ind) + ">\n" + old_b,
                                label=tag, frm=mb_l)
            t.expect_red(f"6124-{tag}", f"record behind a {oname} opener in a {lname} item", repo,
                         mb_l, cell_l, red6124 + gone6124)
    # (6124-l-ctl) GREEN - a list item whose HTML block ended before the record
    # (types 6/7 end at a blank line) and a plain list item hide nothing.
    pre_l = ">\n> - <div>\n>\n"
    mb_lc = doc_only(quoted=pre_l + ">\n" + old_b, label="l-ctl-mb")
    l_ctl = edit_range("", quoted=pre_l + indented(rec6124, 2) + ">\n" + old_b, label="l-ctl",
                       frm=mb_lc)
    t.expect_green("6124-l-ctl", "record after a list item HTML block that already ended",
                   repo, mb_lc, l_ctl, green6124)
    # (6124-q1..q5) RED (#6443, T1/T2/T3/T11/T12): the opener behind a tab
    # after '>' or behind an indented '>' (up to three columns) is an opener.
    for tag, opener in (("q1", ">\t<pre>"), ("q2", "  > <pre>"), ("q3", "  > ```"),
                        ("q4", ">\t<![CDATA["), ("q5", "   > <?x")):
        pre = f">\n{opener}\n"
        mb_q = doc_only(quoted=pre + ">\n" + old_b, label=f"{tag}-mb")
        cell_q = edit_range("", quoted=pre + rec6124 + ">\n" + old_b, label=tag, frm=mb_q)
        t.expect_red(f"6124-{tag}", f"record behind the opener {opener!r}", repo, mb_q, cell_q,
                     red6124 + gone6124)
    # (6124-q-ctl) GREEN - a tab-indented plain line is not an opener.
    mb_qc = doc_only(quoted=">\n>\tplain\n>\n" + old_b, label="q-ctl-mb")
    q_ctl = edit_range("", quoted=">\n>\tplain\n>\n" + rec6124 + ">\n" + old_b, label="q-ctl",
                       frm=mb_qc)
    t.expect_green("6124-q-ctl", "record after a tab-indented plain line", repo, mb_qc, q_ctl,
                   green6124)

    # (6124-p1..p4) RED (R3-F3, #6420) - once the doc has an amendment ledger,
    # a new record is accepted only inside it: directly above an existing
    # record (the only gap a '>' blank line) or as the last paragraph of the
    # blockquote that holds one. A standalone blockquote elsewhere below
    # STATUS (prose, end of document, a collapsible block) is refused.
    placed6124 = [("not adjacent to the amendment ledger",
                   "did not refuse a record placed away from the ledger")]
    for tag, label, extra in (
            ("p1", "standalone quote in section 8 prose",
             "\n" + old_a + "\nSection 8 prose.\n\n" + rec6124),
            ("p2", "standalone quote at the end of the document", "\n" + old_a + "\n" + rec6124),
            ("p3", "standalone quote after a plain blank line below the ledger",
             "\n" + old_a + "\n\n\n" + rec6124),
            ("p4", "standalone quote inside a collapsible block",
             "\n" + old_a + "\n<details>\n<summary>x</summary>\n\n" + rec6124)):
        pre = extra[:extra.index(rec6124)]
        mb_p = doc_only(pre, label=f"{tag}-mb")
        cell_p = edit_range(extra, label=tag, frm=mb_p)
        t.expect_red(f"6124-{tag}", label, repo, mb_p, cell_p, red6124 + placed6124)
    # (6124-p5) RED - above an existing record but separated by a PLAIN blank
    # line: two blockquotes, so not inside the ledger.
    mb_p5 = doc_only("\n" + old_a, label="p5-mb")
    p5 = edit_range("\n" + rec6124 + "\n" + old_a, label="p5", frm=mb_p5)
    t.expect_red("6124-p5", "record above a record across a plain blank line", repo, mb_p5, p5,
                 red6124 + placed6124)

    # (6124-d1..d5) RED (R3-F6, #6423) - append-only holds for EVERY change
    # that touches the cert doc while it is EXPIRED/VOID, not only for the
    # wire-change pass path: a doc-only change may not delete, re-date, edit,
    # reorder or remove the records. d6 is the GREEN control (prose outside
    # the ledger; a new record on its own).
    append6124 = [("append-only", "did not say the ledger is append-only")]
    led_ab = ">\n" + old_a + ">\n" + old_b
    mb_d = doc_only(quoted=led_ab, label="d-mb")
    for tag, label, doc in (
            ("d1", "a record deleted by a doc-only change", ">\n" + old_b),
            ("d2", "a record re-dated by a doc-only change",
             ">\n" + old_a.replace("2026-10-07", "2026-10-09") + ">\n" + old_b),
            ("d3", "a record's citation edited by a doc-only change",
             ">\n" + old_a.replace("#6063", "#6064") + ">\n" + old_b),
            ("d4", "records reordered by a doc-only change", ">\n" + old_b + ">\n" + old_a)):
        cell_d = edit_range("", touch=(), label=tag, frm=mb_d, quoted=doc)
        t.expect_red(f"6124-{tag}", label, repo, mb_d, cell_d, append6124)
    fx.reset(mb_d)
    fx.g("rm", "-q", CERT_DOC)
    d5 = fx.commit([], "6124 cell d5: cert doc deleted, no wire change")
    t.expect_red("6124-d5", "the cert doc deleted by a doc-only change", repo, mb_d, d5,
                 append6124)
    d6 = edit_range("\nOther prose.\n", touch=(), label="d6", frm=mb_d, quoted=led_ab)
    t.expect_green("6124-d6", "doc-only prose edit beside an untouched ledger", repo, mb_d, d6)
    d7 = edit_range("", touch=(), label="d7", frm=mb_d, quoted=led_ab + ">\n" + rec6124)
    t.expect_green("6124-d7", "doc-only change that only appends a record", repo, mb_d, d7)

    # (6124-r1..r4) #6355: the COMMITTED cert doc of this checkout, as the
    # merge-base, with a record inserted at each legal spot (GREEN), behind an
    # inserted HTML opener (RED), and above non-record prose that would then
    # read as part of it (RED). Skipped with a NOTE when this checkout has no
    # readable cert doc or its banner is not EXPIRED/VOID with a record.
    real_doc = None
    proc_rd = real_run_git(REPO_ROOT, "show", f"HEAD:{CERT_DOC}")
    if proc_rd.returncode == 0:
        real_doc = proc_rd.stdout.decode("utf-8", "replace")
    elif (REPO_ROOT / CERT_DOC).is_file():
        real_doc = (REPO_ROOT / CERT_DOC).read_text(encoding="utf-8", errors="replace")
    rl = real_doc.split("\n") if real_doc is not None else []
    st_i = next((i for i, ln in enumerate(rl) if STATUS_LINE_RE.match(ln)), None)
    st_m = STATUS_LINE_RE.match(rl[st_i]) if st_i is not None else None
    hd_i = next((i for i in range((st_i or 0) + 1, len(rl))
                 if AMENDMENT_LEDGER_RE.match(rl[i])), None) if st_m else None
    bq_end = next((i for i in range((st_i or 0) + 1, len(rl)) if not rl[i].startswith(">")),
                  len(rl)) if st_m else None
    if (st_m is None or st_m.group(1).upper() not in ("EXPIRED", "VOID") or hd_i is None
            or hd_i >= bq_end or not QUOTED_BLANK_RE.match(rl[hd_i - 1])):
        print("self-test NOTE (6124-r1..r4): skipped the committed-doc cells (no readable "
              f"{CERT_DOC} with an EXPIRED/VOID STATUS blockquote holding a record)",
              file=sys.stderr)
    else:
        rec_l = rec6124.rstrip("\n").split("\n")
        fx.reset(exp6124)
        fx.write(CERT_DOC, real_doc)
        mb_r = fx.commit([CERT_DOC], "base: the committed cert doc (#6355)")

        def real_cell(label, doc_lines):
            fx.reset(mb_r)
            fx.write(mod_rs, f"// {label}\n", append=True)
            fx.write(CERT_DOC, "\n".join(doc_lines))
            return fx.commit([mod_rs, CERT_DOC], f"6124 cell {label}")

        r1 = real_cell("r1", rl[:hd_i] + rec_l + [">"] + rl[hd_i:])
        t.expect_green("6124-r1", "committed doc + record above its first amendment", repo,
                       mb_r, r1, green6124)
        r2 = real_cell("r2", rl[:bq_end] + [">"] + rec_l + rl[bq_end:])
        t.expect_green("6124-r2", "committed doc + record closing the STATUS blockquote",
                       repo, mb_r, r2, green6124)
        r3 = real_cell("r3", rl[:hd_i] + rec_l + [">", "> <pre>"] + rl[hd_i:])
        t.expect_red("6124-r3", "committed doc + record + an opener hiding the records",
                     repo, mb_r, r3, red6124)
        sp_i = next((i for i in range(hd_i + 1, bq_end - 1)
                     if QUOTED_BLANK_RE.match(rl[i]) and not QUOTED_BLANK_RE.match(rl[i + 1])
                     and not AMENDMENT_LEDGER_RE.match(rl[i + 1])), None)
        if sp_i is None:
            print("self-test NOTE (6124-r4): the committed STATUS blockquote has no "
                  "non-record paragraph after a record", file=sys.stderr)
        else:
            r4 = real_cell("r4", rl[:sp_i + 1] + rec_l + [">"] + rl[sp_i + 1:])
            t.expect_red("6124-r4", "committed doc + record above non-record prose", repo,
                         mb_r, r4, red6124)
    fx.reset(base)

    if t.failed:
        print("check-cert-expiry self-test: FAIL", file=sys.stderr)
        return 2
    print(SELF_TEST_OK)
    return 0


SELF_TEST_OK = (
    "check-cert-expiry self-test OK: (a) watched-path violation RED with the §7 expiry "
    "sentence; (b) same change + cert-doc GREEN; (c) AI_MEMORY_FED_* identifier-add outside "
    "the path watches RED; (d) identifier-add + cert-doc GREEN; (e) unrelated src/ edit GREEN; "
    "(f) cert-doc-only GREEN; (g) federation_receive.rs RED; (h) federation_signing_check.rs "
    "RED; (h2) nested src/federation/identity/** RED; (i) watched-file rename RED (old path "
    "still named); (j) identifier-rename RED (both names listed); (k) pull_request missing "
    "PR_HEAD_SHA / GITHUB_BASE_REF fail-closed with its reason; (l) workflow_dispatch skip naming the outside-CI-only overrides; (m) push with zero before-SHA skip; "
    "(n) unresolvable range fail-closed; (o) this checkout vs origin/release/v1.0.0 GREEN; "
    "(p) non-ASCII watched path RED (core.quotePath bypass closed); (q) wire change + "
    "incidental cert-doc edit RED (#3556 B); (r) wire change + VOID record GREEN; (s) unrelated "
    "change over a LIVE banner with wire drift since the bind RED (#3556 C, names the bound SHA "
    "and the drift); (t) unrelated change over a VOID banner GREEN; (u) stale LIVE healed by "
    "recording EXPIRED GREEN; (v1) LIVE bound to a non-ancestor with an identical watched tree "
    "GREEN (squash-merge shape, tree diff); (v2) LIVE bound to a non-ancestor whose watched "
    "tree differs RED (the ancestry hatch would have silenced it); (w) unparseable STATUS line "
    "fail-closed; (x1) decoy STATUS line above the banner RED (exactly-one rule); (x2) decoy "
    "Binds-to line RED; (y) cert doc deleted alongside a wire change RED (ABSENT fails closed); "
    "(z) pure banner reformat on a docs-only change GREEN (tolerant parse); (z2) reformat + "
    "wire change RED as incidental, not unparseable; (pr1) #6137 stale-LIVE head banner with "
    "the base EXPIRED GREEN at the merge commit (and RED if judged at the head alone); (pr2) "
    "head that flips the banner detected over base-tip..merge-commit, and a wire change "
    "without the flip RED; (pr3) stale payload PR_BASE_SHA ignored, the live base ref used; "
    "(pr4) pull_request fail-closed, each with its reason, on missing/unresolvable base ref, "
    "head or merge commit and on non-hex, abbreviated or newline-suffixed shas; (pr4-moved) base moved by an unrelated commit "
    "GREEN; (pr4-offbase) first parent not on the base RED naming origin/<base ref>, each sha once, "
    "with the push-or-sync remedy; (gitver) git below 2.30 fail-closed; (anc-error) an is-ancestor "
    "error fail-closed; "
    "(pr4-reversed) reversed parents RED; (pr5) stale branch without a wire change "
    "over a base that gained one GREEN; (pr6) PR wire change without a banner flip RED; "
    "(pr7) merge with an unrelated branch (second parent is not the PR head) RED and an "
    "octopus merge RED; (ci1-ci7, #5970) the event payload range is authoritative under "
    "GitHub Actions and CERT_EXPIRY_BASE/HEAD overrides are refused there but honoured "
    "outside CI; (6124-h1..h9, #6124) EXPIRED/VOID at both ends plus exactly ONE inserted "
    "amendment record (and one blank separator) below STATUS, directly above an existing "
    "record (also opening its blockquote) or closing its blockquote, after HTML blocks, "
    "code fences and blockquotes that already ended and after a backtick line that is not "
    "a fence, dated from the "
    "merge-base day - 1 to today + 1, listing exactly the changed watched paths and "
    "identifiers and citing only #6063 by its issue URL GREEN; (6124-f1..f15d) missing, "
    "extra, substring, prose-only, reused, re-dated, split, deleted, edited or moved prior "
    "records, a copy of an existing header, LIVE at the merge-base, EXPIRED flipped to a "
    "stale LIVE (rule C), fenced (CommonMark), HTML-commented, inside an HTML block of "
    "each kind (#6365) or behind an inserted opener, indented-code, unlisted-identifier, "
    "above or glued to STATUS, mid-paragraph, header with body text, a link or a commit "
    "sha, unquoted header, uncited, "
    "other-issue, bare-URL, foreign-link, URL-less, reference-link, shortcut-reference, "
    "GitHub autolink and "
    "lookalike citations (#6367), a taken-over later paragraph, a lazy line (#6354), a "
    "splice inside an old record (#6366), non-grammar, control or bidi lines, a duplicate "
    "entry, two new records, and invalid, future or back-dated dates (#6358) RED; an "
    "absent, unreadable, symlinked, oversized or non-UTF-8 (#6368) cert doc and a failed "
    "blob read fail-closed; the "
    "EXPIRED headline names the non-discharging amendment, not re-issue (#6369), and the "
    "remedy names the record, its legal spots and #3899; (6124-r1..r4, #6355) the "
    "committed cert doc with a record at each legal spot GREEN and behind an opener or "
    "above non-record prose RED."
)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Enterprise-federation certification section 7 expiry gate.")
    parser.add_argument("--self-test", action="store_true",
                        help="plant-a-violation corpus in a scratch repository")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if args.self_test:
        return self_test()
    rc, out, err = run_gate(REPO_ROOT, dict(os.environ))
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
