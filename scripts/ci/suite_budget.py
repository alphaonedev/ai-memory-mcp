#!/usr/bin/env python3
"""Suite margin gate and per-binary profile for the sqlite full test suite (#9229).

Class invariant (ruling b29 17183e98): a full-suite invocation ends with at least
``MARGIN_PCT`` percent of its per-invocation watchdog budget left. A suite that
loses the margin is a named red even when every test passed, and the in-flight
case is a named red at the margin deadline, BEFORE the watchdog kills the suite.

Subcommands:

* ``gate --label L --elapsed S --budget B --rc RC [--log F]``: after the cargo
  invocation. Exit 0 when the margin holds (or the suite failed inside the
  margin: that red is the suite's own), ``EXIT_MARGIN_LOST`` when the wall used
  more than ``100 - MARGIN_PCT`` percent of the budget (passed or killed).
* ``timer --label L --budget B [--log F]``: started next to the cargo
  invocation; sleeps to the margin deadline and, if still alive there, prints
  the in-flight ``::error::`` (the caller kills it when the suite ends first).
* ``profile --log F [--top N]``: per-binary seconds of a cargo test log, ranked.
* ``shard-args --metadata F [--features LIST] [--part K/N]``: the second shard of the full suite.
  The full ``cargo test`` runs as sequential invocations, each under its own watchdog budget and this
  gate: ``--lib``, then the arguments printed here (one per line: every non-lib target cargo's
  default selection runs, i.e. ``test = true`` and its required features enabled), then ``--doc``.
  ``--part K/N`` prints the K-th of N round-robin parts of that list (manifest order), so N
  invocations together run every target exactly once.
  Anything the derivation cannot judge (no single default package, a lib without ``test`` or
  ``doctest``, a target name outside ``[A-Za-z0-9_-]``, a required feature of another package) is
  exit 2, and the step then runs the unsharded suite instead (fail closed to full coverage).

* ``suite-plan --workflow F --job J --node N --tier T``: before the first invocation of the full suite. The
  whole-suite ceiling ``WHOLE_SUITE_CEILING_SECS`` plus the same ``MARGIN_PCT`` margin must fit the timeout of
  job J as the workflow F states it (``timeout-minutes``, or the ``timeout`` of the matrix leg N, T when the
  job reads ``${{ matrix.timeout }}``). A ceiling that cannot fit is ``EXIT_MARGIN_LOST`` at derivation, so
  the suite is red before it runs, never killed by the job cap.
* ``suite-sum --seconds F``: after the last invocation. F holds one ``<seconds><TAB><label>`` line per
  invocation (the step appends them); their sum over ``WHOLE_SUITE_CEILING_SECS`` is ``EXIT_MARGIN_LOST``
  with every invocation's seconds printed (ruling b29 cdfe800f: four budgets of 2100 s must not become a
  silent 8400 s suite).

``--log-offset N`` (gate, timer) reads the log from byte N: the step appends every invocation to one
log, so each gate profiles only its own invocation.

Every margin red names issue #9229 and the slowest binaries, so a lane does not read it as its own defect.

Exit codes: 0 ok, 2 malformed input (argparse usage too), 3 margin lost (an invocation, the whole suite, or
a whole-suite plan that cannot fit the job), 4 the shared workflow_annotation.py next to this file cannot be
loaded.
Malformed input is always red with a named error, never a silent pass.

Python 3.12+, standard library only.
"""
import argparse
import datetime
import json
import re
import sys
import time


def _load_workflow_annotation():
    """The shared module at WA_RELATIVE_PATH from this file's real directory, by path only, never through
    sys.path; every name in WA_REQUIRED must be a callable of it (#9365, one shape in every script)."""
    import importlib.util
    import os
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), WA_RELATIVE_PATH))
    loaded = sys.modules.get("workflow_annotation")
    if loaded is not None and os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
        module = loaded
    else:
        spec = importlib.util.spec_from_file_location("workflow_annotation", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # absent, unreadable or broken: it raises here, the try below catches it
    missing = [name for name in WA_REQUIRED if not callable(getattr(module, name, None))]
    if missing:
        raise AttributeError("workflow_annotation.py lacks " + ", ".join(missing))
    if loaded is None:
        sys.modules["workflow_annotation"] = module
    return module


EXIT_OK = 0
EXIT_MALFORMED = 2  # argparse uses 2 as well: a bad argument is malformed input
EXIT_MARGIN_LOST = 3
EXIT_LOAD_REFUSED = 4  # the shared module cannot be loaded

# The one shared-module load shape of scripts/ (#9365, ruling bcd0a15c; LoaderShape pins it).
WA_PROG = "suite_budget"
WA_RELATIVE_PATH = "workflow_annotation.py"
WA_REQUIRED = ("annotation", "log_line", "safe_value")
WA_EXIT_LOAD_REFUSED = EXIT_LOAD_REFUSED
WA_ERROR_TO_STDERR = False

try:
    wa = _load_workflow_annotation()
except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
    wa_cause = type(exc).__name__
    print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
          % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
    print("::error title=suite_budget refused::suite_budget: refused: shared module workflow_annotation.py"
          " next to the script cannot be loaded",
          file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
    sys.exit(WA_EXIT_LOAD_REFUSED)

TAG = "[#9229 margin]"
# Required margin, percent of the per-invocation watchdog budget (ruling b29 17183e98 proposes 20). The
# measured hosted-runner variance between two runs of one suite is about 30 % (1593 s green vs a kill at
# 2100 s), so 20 % is the floor, never a target: re-derive the suite cost, not this number.
MARGIN_PCT = 20
MIN_MARGIN_PCT = 1
MAX_MARGIN_PCT = 99
WATCHDOG_KILL_CODES = (124, 137)  # GNU timeout: TERM fired / KILL after --kill-after
# The most seconds the invocations of the sqlite full suite may sum to (ruling b29 cdfe800f). It fits both
# sqlite legs with the margin: 80 % of the 80-minute macos-fed job is 3840 s, of the 95-minute ubuntu-latest
# job 4560 s (suite-plan checks the running leg). The measured unsharded suite is about 2000 s on ubuntu-latest.
WHOLE_SUITE_CEILING_SECS = 3600
# Carried by every margin red, so another lane reads it as the suite's cost, not as its own failure.
ISSUE_NOTE = "this red is issue #9229 (the cost of the sqlite suite), not a failure of the change under test"
NO_PROFILE = "slowest binaries: none profiled"
_SECONDS_RE = re.compile(r"[0-9]{1,9}")
_NEGATIVE_RE = re.compile(r"-[0-9]{1,9}")
_MINUTES_RE = re.compile(r"[1-9][0-9]{0,3}")
_MATRIX_TIMEOUT_RE = re.compile(r"\$\{\{\s*matrix\.timeout\s*\}\}")
_KEY_RE = re.compile(r"^( *)(- )?([A-Za-z_][A-Za-z0-9_-]*):(?: +(.*?))?\s*$")
# Binaries named in a red message: enough to point at the cost, bounded so the annotation stays one line.
SLOWEST_NAMED = 5
PROFILE_TOP_DEFAULT = 25
# A log is read up to this many bytes from its end (a full sqlite suite log is about 60 MB at most).
MAX_LOG_BYTES = 256 * 1024 * 1024

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?Z ")
_RUNNING_RE = re.compile(r"^\s*Running (.+?) \(")
_DOCTESTS_RE = re.compile(r"^\s*Doc-tests (\S+)")
_END_RE = re.compile(r"\[#1492\] '[^']*' ran \d+s of the \d+s per-invocation watchdog budget")
_RESULT_RE = re.compile(r"^test result: (ok|FAILED)\..*finished in ([0-9]+(?:\.[0-9]+)?)s")
# Cargo target names reach cargo as option values; anything else is refused, never quoted.
_TARGET_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,199}")  # no leading dash: a name is never read as a flag
_FEATURE_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,200}")
# Target kinds the second shard selects, with the cargo flag that names one target of the kind.
_SHARD_KIND_FLAGS = {"bin": "--bin", "test": "--test", "example": "--example", "bench": "--bench"}
# Parts the second shard can be cut into (--part K/N); more is never needed for one package.
MAX_PARTS = 16
_PART_RE = re.compile(r"([0-9]{1,2})/([0-9]{1,2})")
_LIB_KINDS = frozenset(("lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"))


class MalformedInput(ValueError):
    """Input the gate cannot judge; always red, never a pass."""


def margin_deadline(budget, margin_pct=MARGIN_PCT):
    """Seconds of wall after which the margin is lost: floor(budget * (100 - margin) / 100)."""
    _check_budget(budget, margin_pct)
    return budget * (100 - margin_pct) // 100


def _check_budget(budget, margin_pct):
    if not isinstance(budget, int) or isinstance(budget, bool) or budget <= 0:
        raise MalformedInput("budget must be a positive integer of seconds, got %r" % (budget,))
    if not isinstance(margin_pct, int) or isinstance(margin_pct, bool) \
            or not MIN_MARGIN_PCT <= margin_pct <= MAX_MARGIN_PCT:
        raise MalformedInput("margin must be an integer percent in [%d, %d], got %r"
                             % (MIN_MARGIN_PCT, MAX_MARGIN_PCT, margin_pct))


def judge(elapsed, budget, rc, margin_pct=MARGIN_PCT):
    """(verdict, message): verdict is "ok" or "margin-lost". Raises MalformedInput on bad input.

    The margin holds when ``elapsed <= margin_deadline(budget)``; exactly at the deadline passes. A watchdog
    kill (rc 124/137) is always margin-lost: the suite reached the whole budget.
    """
    for name, value in (("elapsed", elapsed), ("rc", rc)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise MalformedInput("%s must be a non-negative integer, got %r" % (name, value))
    deadline = margin_deadline(budget, margin_pct)
    left = budget - elapsed
    pct_used = elapsed * 100 // budget
    if rc in WATCHDOG_KILL_CODES:
        return "margin-lost", (
            "killed by the watchdog (rc %d) after %ds of the %ds budget: the suite needs at least %d%% (%ds) "
            "of margin and had none; cut the suite cost or shard it, do not raise the budget"
            % (rc, elapsed, budget, margin_pct, budget - deadline))
    if elapsed > deadline:
        state = "passed" if rc == 0 else "failed (rc %d)" % rc
        return "margin-lost", (
            "%s but used %ds of the %ds budget (%d%%, %ds left); the required margin is %d%% (%ds, so at most "
            "%ds of wall); cut the suite cost or shard it, do not raise the budget"
            % (state, elapsed, budget, pct_used, left, margin_pct, budget - deadline, deadline))
    return "ok", ("wall %ds of the %ds budget (%d%% used, %ds left; required margin %d%% = %ds)"
                  % (elapsed, budget, pct_used, left, margin_pct, budget - deadline))


def _parse_ts(line):
    m = _TS_RE.match(line)
    if not m:
        return None, line
    frac = (m.group(2) or ".0")[1:7].ljust(6, "0")
    ts = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(microsecond=int(frac))
    return ts.timestamp(), line[m.end():]


def _close(row, end_ts):
    """Finish a row: wall from its start to ``end_ts`` when both are known, else libtest's own figure."""
    if row["start"] is not None and end_ts is not None:
        row["secs"] = max(0.0, end_ts - row["start"])
    elif row["libtest_secs"] is not None:
        row["secs"] = row["libtest_secs"]
    else:
        row["secs"] = 0.0
    del row["start"]
    return row


def profile_lines(lines, now=None):
    """Per-binary rows from cargo test output lines (GitHub job log or a plain tee log).

    Each row: dict(name, secs, libtest_secs, status). ``secs`` is the wall from the binary's ``Running`` line
    to the next binary's ``Running`` line (or the invocation end) when the lines carry timestamps, else
    libtest's own ``finished in``. The LAST result line inside a binary is its own: a lib test that re-runs
    the binary as a child (env-isolated tests) prints the child's result line earlier. A binary with no
    result line is ``running`` (the kill or the in-flight point). The ``[#1492] ... watchdog budget`` notice
    after a binary started ends the invocation (one before any binary is the previous invocation's, still in
    the pipe when the caller measured the log offset), so job-teardown lines after a kill are not charged to the last binary.
    """
    rows, current, last_ts = [], None, None
    for raw in lines:
        ts, text = _parse_ts(raw.rstrip("\n"))
        text = _ANSI_RE.sub("", text)
        if _END_RE.search(text) and current is not None:  # an earlier invocation's notice before any binary
            if ts is not None:
                last_ts = ts
            break
        if ts is not None:
            last_ts = ts
        start = _RUNNING_RE.match(text) or _DOCTESTS_RE.match(text)
        if start:
            if current is not None:
                rows.append(_close(current, ts))
            current = {"name": start.group(1), "start": ts, "secs": None, "libtest_secs": None,
                       "status": "running"}
            continue
        result = _RESULT_RE.match(text.strip())
        if result and current is not None:
            current["libtest_secs"] = float(result.group(2))
            current["status"] = result.group(1)
    if current is not None:
        rows.append(_close(current, now if now is not None and current["status"] == "running" else last_ts))
    return rows


def read_log(path, offset=0):
    """Lines of a log file from byte ``offset``, at most MAX_LOG_BYTES from its end.

    MalformedInput when unreadable, or when ``offset`` is negative or past the end (the log only grows
    while the step runs, so an offset past the end means the caller measured another file).
    """
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise MalformedInput("log offset must be a non-negative integer, got %r" % (offset,))
    try:
        with open(path, "rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            if offset > size:
                raise MalformedInput("log offset %d is past the end of %s (%d bytes)" % (offset, path, size))
            handle.seek(max(offset, size - MAX_LOG_BYTES))
            data = handle.read()
    except OSError as exc:
        raise MalformedInput("log %s cannot be read (%s)" % (path, type(exc).__name__)) from None
    return data.decode("utf-8", "replace").splitlines()


def _enabled_features(features, requested):
    """The closure of ``default`` plus ``requested`` over the package's own feature table."""
    if not isinstance(features, dict):
        raise MalformedInput("package features is not an object")
    todo = ["default"] + list(requested)
    enabled = set()
    while todo:
        name = todo.pop()
        if name in enabled:
            continue
        if name not in features:
            if name == "default":
                continue
            raise MalformedInput("requested feature %r is not a feature of the package" % (name,))
        enabled.add(name)
        entries = features[name]
        if not isinstance(entries, list):
            raise MalformedInput("feature %r is not a list" % (name,))
        for entry in entries:
            if not isinstance(entry, str):
                raise MalformedInput("feature %r has a non-string entry" % (name,))
            if "/" in entry or entry.startswith("dep:"):
                continue  # a dependency or a dependency's feature: never one of this package's names
            todo.append(entry)
    return enabled


def parse_part(text):
    """``K/N`` with 1 <= K <= N <= MAX_PARTS, as a tuple; anything else is MalformedInput."""
    m = _PART_RE.fullmatch(text) if isinstance(text, str) else None
    if m is None:
        raise MalformedInput("part %r is not K/N" % (text[:40] if isinstance(text, str) else text,))
    k, n = int(m.group(1)), int(m.group(2))
    if not 1 <= k <= n <= MAX_PARTS:
        raise MalformedInput("part %r is outside 1..N with N at most %d" % (text, MAX_PARTS))
    return k, n


def shard_args(metadata, requested_features=(), part=(1, 1)):
    """Cargo target arguments of the second shard: every non-lib target cargo's default selection runs.

    ``metadata`` is the parsed ``cargo metadata --no-deps --format-version 1``. The partition is exact by
    construction: the default ``cargo test`` runs the lib unit tests (shard 1, ``--lib``), each bin,
    test, example and bench whose manifest ``test`` flag is true and whose required features are enabled
    (this shard) and the lib doc tests (shard 3, ``--doc``). Raises MalformedInput for anything else.
    """
    if not isinstance(metadata, dict):
        raise MalformedInput("cargo metadata is not a JSON object")
    members = metadata.get("workspace_default_members") or metadata.get("workspace_members")
    packages = metadata.get("packages")
    if not isinstance(members, list) or len(members) != 1 or not isinstance(packages, list):
        raise MalformedInput("cargo metadata must name exactly one default workspace member")
    package = next((p for p in packages if isinstance(p, dict) and p.get("id") == members[0]), None)
    if package is None or not isinstance(package.get("targets"), list):
        raise MalformedInput("the default workspace member has no target list")
    for name in requested_features:
        if not _FEATURE_NAME_RE.fullmatch(name):
            raise MalformedInput("feature name %r is outside the allowed set" % (name,))
    enabled = _enabled_features(package.get("features", {}), requested_features)
    libs, args = 0, []
    for target in package["targets"]:
        if not isinstance(target, dict) or not isinstance(target.get("kind"), list):
            raise MalformedInput("a target has no kind list")
        kinds = target["kind"]
        name = target.get("name")
        if not isinstance(name, str) or not _TARGET_NAME_RE.fullmatch(name):
            raise MalformedInput("target name %r is outside [A-Za-z0-9_-] (no leading dash)" % (name,))
        if any(k in _LIB_KINDS for k in kinds):
            libs += 1
            if target.get("test") is not True or target.get("doctest") is not True:
                raise MalformedInput("lib target %s must have test and doctest on for the lib and doc shards"
                                     % name)
            continue
        if len(kinds) != 1 or kinds[0] not in _SHARD_KIND_FLAGS and kinds[0] != "custom-build":
            raise MalformedInput("target %s has an unknown kind %r" % (name, kinds))
        if kinds[0] == "custom-build" or target.get("test") is not True:
            continue
        required = target.get("required-features") or []
        if not isinstance(required, list) or not all(isinstance(f, str) for f in required):
            raise MalformedInput("target %s has a malformed required-features list" % name)
        if any("/" in f for f in required):
            raise MalformedInput("target %s requires a dependency feature this gate cannot judge" % name)
        if not set(required) <= enabled:
            continue  # cargo's default selection skips it the same way
        args.extend((_SHARD_KIND_FLAGS[kinds[0]], name))
    if libs != 1:
        raise MalformedInput("the package must have exactly one lib target, found %d" % libs)
    k, n = part
    pairs = list(zip(args[0::2], args[1::2]))[k - 1::n]  # round-robin: parts are disjoint and complete
    if not pairs:
        raise MalformedInput("the second shard selects no target" if n == 1
                             else "the second shard part %d/%d selects no target" % (k, n))
    return [item for pair in pairs for item in pair]


def run_shard_args(metadata_path, features, part_text="1/1"):
    requested = [f for f in re.split(r"[ ,]+", features.strip()) if f] if features else []
    try:
        try:
            with open(metadata_path, encoding="utf-8") as handle:
                metadata = json.load(handle)
        except (OSError, ValueError) as exc:
            raise MalformedInput("cargo metadata %s cannot be read as JSON (%s)"
                                 % (metadata_path, type(exc).__name__)) from None
        args = shard_args(metadata, requested, parse_part(part_text))
    except MalformedInput as exc:
        print(wa.annotation("warning", "%s shard-args: %s; the full suite runs unsharded (#9229)" % (TAG, exc)),
              file=sys.stderr, flush=True)
        return EXIT_MALFORMED
    for arg in args:  # flags and [A-Za-z0-9_-] names, so safe_value is the identity on them
        print(wa.safe_value(arg))
    return EXIT_OK


def slowest_summary(rows, count=SLOWEST_NAMED):
    """'still running X; slowest binaries: a 120s, b 90s' from profile rows (NO_PROFILE when no rows)."""
    if not rows:
        return NO_PROFILE
    parts = []
    running = [r for r in rows if r["status"] == "running"]
    if running:
        parts.append("still running %s" % running[-1]["name"])
    ranked = sorted(rows, key=lambda r: r["secs"], reverse=True)[:count]
    parts.append("slowest binaries: " + ", ".join("%s %ds" % (r["name"], int(r["secs"])) for r in ranked))
    return "; ".join(parts)


def run_gate(label, elapsed, budget, rc, margin_pct, log, log_offset=0):
    try:
        verdict, message = judge(elapsed, budget, rc, margin_pct)
        detail = NO_PROFILE
        if verdict != "ok" and log:
            detail = slowest_summary(profile_lines(read_log(log, log_offset)))
    except MalformedInput as exc:
        print(wa.annotation("error", "%s '%s': malformed gate input: %s; refusing to pass (#9229)"
                            % (TAG, label, exc)), flush=True)
        return EXIT_MALFORMED
    if verdict == "ok":
        print(wa.annotation("notice", "%s '%s': margin held: %s" % (TAG, label, message)), flush=True)
        return EXIT_OK
    print(wa.annotation("error", "%s '%s' lost the suite margin: %s; %s; %s"
                        % (TAG, label, message, ISSUE_NOTE, detail)), flush=True)
    return EXIT_MARGIN_LOST


def run_timer(label, budget, margin_pct, log, log_offset=0, sleep_fn=time.sleep, clock=time.time):
    """Sleep to the margin deadline, then print the in-flight red. The caller kills this when the suite ends."""
    try:
        deadline = margin_deadline(budget, margin_pct)
    except MalformedInput as exc:
        print(wa.annotation("error", "%s '%s': malformed timer input: %s; refusing to arm (#9229)"
                            % (TAG, label, exc)), flush=True)
        return EXIT_MALFORMED
    started = clock()
    while True:
        left = deadline - (clock() - started)
        if left <= 0:
            break
        sleep_fn(min(left, 60))
    detail = NO_PROFILE
    if log:
        try:
            detail = slowest_summary(profile_lines(read_log(log, log_offset), now=clock()))
        except MalformedInput:
            detail = "the suite log cannot be read; " + NO_PROFILE
    print(wa.annotation("error", "%s '%s' lost the suite margin while still running: %ds of the %ds budget used, "
                        "the required margin is %d%% (%ds); the watchdog kills it at %ds unless it ends first; "
                        "%s; %s" % (TAG, label, deadline, budget, margin_pct, budget - deadline, budget,
                                    ISSUE_NOTE, detail)), flush=True)
    return EXIT_MARGIN_LOST


def _read_text(path, what):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, ValueError) as exc:  # UnicodeDecodeError is a ValueError
        raise MalformedInput("the %s cannot be read (%s)" % (what, type(exc).__name__)) from None


def _job_block(text, job):
    """The lines of job ``job`` under the top-level ``jobs:`` key (two-space indent, as ci.yml writes it)."""
    lines = text.splitlines()
    try:
        start = lines.index("jobs:")
    except ValueError:
        raise MalformedInput("the workflow has no job %r" % (job,)) from None
    header = "  %s:" % job
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if line and not line.startswith(" ") and not line.startswith("#"):
            break  # left the jobs: mapping
        if line.rstrip() == header:
            block = []
            for nxt in lines[i + 1:]:
                if nxt and not nxt.startswith("   ") and not nxt.lstrip().startswith("#"):
                    break
                block.append(nxt)
            return block
    raise MalformedInput("the workflow has no job %r" % (job,))


def _value(raw):
    """A plain YAML scalar as ci.yml writes it: trailing comment and one pair of quotes stripped."""
    raw = re.sub(r"\s+#.*$", "", raw or "").strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        raw = raw[1:-1]
    return raw


def _matrix_legs(block):
    """The mappings of ``strategy.matrix.include`` in a job block, each as {key: value}."""
    legs, inside, include_indent, item_indent = [], False, 0, None
    for line in block:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _KEY_RE.match(line)
        indent = len(line) - len(line.lstrip(" "))
        if not inside:
            if m and not m.group(2) and m.group(3) == "include" and not m.group(4):
                inside, include_indent = True, indent
            continue
        if indent <= include_indent and not line.lstrip().startswith("- "):
            break
        if not m:
            continue
        if m.group(2):
            item_indent = indent + 2
            legs.append({m.group(3): _value(m.group(4))})
        elif legs and indent == item_indent:
            legs[-1][m.group(3)] = _value(m.group(4))
    return legs


def job_timeout_secs(text, job, node, tier):
    """Seconds of the timeout of ``job`` in the workflow ``text`` for the matrix leg (node, tier)."""
    block = _job_block(text, job)
    stated = [m for m in (_KEY_RE.match(line) for line in block)
              if m and not m.group(2) and len(m.group(1)) == 4 and m.group(3) == "timeout-minutes"]
    if not stated:
        raise MalformedInput("job %r has no timeout-minutes" % (job,))
    value = _value(stated[0].group(4))
    if _MINUTES_RE.fullmatch(value):
        return int(value) * 60
    if not _MATRIX_TIMEOUT_RE.fullmatch(value):
        raise MalformedInput("job %r timeout-minutes %r is neither an integer of minutes nor ${{ matrix.timeout }}"
                             % (job, value))
    where = "node=%s tier=%s" % (node, tier)
    legs = [leg for leg in _matrix_legs(block) if leg.get("node") == node and leg.get("tier") == tier]
    if not legs:
        raise MalformedInput("job %r has no matrix leg %s" % (job, where))
    if len(legs) > 1:
        raise MalformedInput("job %r has %d matrix legs %s" % (job, len(legs), where))
    minutes = legs[0].get("timeout")
    if minutes is None:
        raise MalformedInput("matrix leg %s of job %r has no timeout" % (where, job))
    if not _MINUTES_RE.fullmatch(minutes):
        raise MalformedInput("matrix leg %s of job %r timeout %r is not a positive integer of minutes"
                             % (where, job, minutes))
    return int(minutes) * 60


def run_suite_plan(workflow_path, job, node, tier, ceiling=WHOLE_SUITE_CEILING_SECS, margin_pct=MARGIN_PCT):
    try:
        secs = job_timeout_secs(_read_text(workflow_path, "workflow file"), job, node, tier)
        room = margin_deadline(secs, margin_pct)
    except MalformedInput as exc:
        print(wa.annotation("error", "%s whole-suite plan: malformed input: %s; refusing to pass (#9229)"
                            % (TAG, exc)), flush=True)
        return EXIT_MALFORMED
    where = "the %d-minute timeout of job '%s' (node=%s tier=%s) with the required %d%% margin (at most %ds)" \
        % (secs // 60, job, node, tier, margin_pct, room)
    if ceiling > room:
        print(wa.annotation("error", "%s whole-suite plan refused: the %ds whole-suite ceiling "
                            "(WHOLE_SUITE_CEILING_SECS) does not fit %s; %s; cut the suite cost or shard it, do not "
                            "raise the ceiling" % (TAG, ceiling, where, ISSUE_NOTE)), flush=True)
        return EXIT_MARGIN_LOST
    print(wa.annotation("notice", "%s whole-suite plan: the %ds whole-suite ceiling fits %s"
                        % (TAG, ceiling, where)), flush=True)
    return EXIT_OK


def parse_seconds(text):
    """[(label, seconds)] from '<seconds><TAB><label>' lines, in order; anything else is MalformedInput."""
    rows, seen = [], set()
    lines = text.split("\n") if text else []
    if lines and not lines[-1]:
        lines.pop()  # the newline that ends the last line
    for number, line in enumerate(lines, 1):
        secs, tab, label = line.partition("\t")
        if not tab or not label:
            raise MalformedInput("invocation seconds line %d is not '<seconds><TAB><label>'" % number)
        if _NEGATIVE_RE.fullmatch(secs):
            raise MalformedInput("invocation seconds line %d has a negative seconds value %s" % (number, secs))
        if not _SECONDS_RE.fullmatch(secs):
            raise MalformedInput("invocation seconds line %d has a non-numeric seconds value %r"
                                 % (number, secs[:40]))
        if label in seen:
            raise MalformedInput("invocation seconds line %d repeats the invocation %r" % (number, label))
        seen.add(label)
        rows.append((label, int(secs)))
    if not rows:
        raise MalformedInput("the invocation seconds file records no invocation")
    return rows


def run_suite_sum(seconds_path, ceiling=WHOLE_SUITE_CEILING_SECS):
    try:
        rows = parse_seconds(_read_text(seconds_path, "invocation seconds file"))
    except MalformedInput as exc:
        print(wa.annotation("error", "%s whole sqlite suite: malformed input: %s; refusing to pass (#9229)"
                            % (TAG, exc)), flush=True)
        return EXIT_MALFORMED
    total = sum(secs for _, secs in rows)
    each = ", ".join("%s %ds" % (label, secs) for label, secs in rows)
    if total > ceiling:
        print(wa.annotation("error", "%s whole sqlite suite lost its ceiling: %d invocations ran %ds, over the %ds "
                            "whole-suite ceiling (WHOLE_SUITE_CEILING_SECS); per invocation: %s; %s; cut the suite "
                            "cost or shard it, do not raise the ceiling" % (TAG, len(rows), total, ceiling, each,
                                                                             ISSUE_NOTE)), flush=True)
        return EXIT_MARGIN_LOST
    print(wa.annotation("notice", "%s whole sqlite suite: %d invocations ran %ds of the %ds whole-suite ceiling "
                        "(WHOLE_SUITE_CEILING_SECS); per invocation: %s" % (TAG, len(rows), total, ceiling, each)),
          flush=True)
    return EXIT_OK


def run_profile(log, top):
    try:
        rows = profile_lines(read_log(log))
    except MalformedInput as exc:
        print(wa.log_line("%s profile: %s" % (TAG, exc)), file=sys.stderr, flush=True)
        return EXIT_MALFORMED
    ranked = sorted(rows, key=lambda r: r["secs"], reverse=True)
    total = sum(r["secs"] for r in rows)
    print(wa.log_line("binaries %d, summed wall %.1fs" % (len(rows), total)))
    for rank, row in enumerate(ranked[:top], 1):
        libtest = "-" if row["libtest_secs"] is None else "%.2f" % row["libtest_secs"]
        print(wa.log_line("%3d %8.1fs  libtest %8ss  %-9s %s" % (rank, row["secs"], libtest, row["status"],
                                                                 row["name"])))
    return EXIT_OK


def _int_arg(text):
    try:
        return int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not an integer: %r" % (text,)) from None


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gate")
    g.add_argument("--label", required=True)
    g.add_argument("--elapsed", type=_int_arg, required=True)
    g.add_argument("--budget", type=_int_arg, required=True)
    g.add_argument("--rc", type=_int_arg, required=True)
    g.add_argument("--margin-pct", type=_int_arg, default=MARGIN_PCT)
    g.add_argument("--log", default="")
    g.add_argument("--log-offset", type=_int_arg, default=0)
    t = sub.add_parser("timer")
    t.add_argument("--label", required=True)
    t.add_argument("--budget", type=_int_arg, required=True)
    t.add_argument("--margin-pct", type=_int_arg, default=MARGIN_PCT)
    t.add_argument("--log", default="")
    t.add_argument("--log-offset", type=_int_arg, default=0)
    r = sub.add_parser("profile")
    r.add_argument("--log", required=True)
    r.add_argument("--top", type=_int_arg, default=PROFILE_TOP_DEFAULT)
    s = sub.add_parser("shard-args")
    s.add_argument("--metadata", required=True)
    s.add_argument("--features", default="")
    s.add_argument("--part", default="1/1")
    w = sub.add_parser("suite-plan")
    w.add_argument("--workflow", required=True)
    w.add_argument("--job", required=True)
    w.add_argument("--node", required=True)
    w.add_argument("--tier", required=True)
    u = sub.add_parser("suite-sum")
    u.add_argument("--seconds", required=True)
    args = p.parse_args(argv)
    if args.cmd == "gate":
        return run_gate(args.label, args.elapsed, args.budget, args.rc, args.margin_pct, args.log,
                        args.log_offset)
    if args.cmd == "timer":
        return run_timer(args.label, args.budget, args.margin_pct, args.log, args.log_offset)
    if args.cmd == "shard-args":
        return run_shard_args(args.metadata, args.features, args.part)
    if args.cmd == "suite-plan":
        return run_suite_plan(args.workflow, args.job, args.node, args.tier)
    if args.cmd == "suite-sum":
        return run_suite_sum(args.seconds)
    return run_profile(args.log, args.top)


if __name__ == "__main__":
    sys.exit(main())
