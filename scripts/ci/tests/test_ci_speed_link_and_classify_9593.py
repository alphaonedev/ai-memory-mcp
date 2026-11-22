#!/usr/bin/env python3
"""Workflow wiring invariants for the CI speed change of #9593.

Class: the changes that must leave the set of tests and the set of reported check names
unchanged (invariant for every push):
  (a) debuginfo (#8216, widening the #9593 pin): for EVERY cargo job on a SELF-HOSTED runner, in
      every workflow, the effective CARGO_PROFILE_DEV_DEBUG and CARGO_PROFILE_TEST_DEBUG are
      declared, equal and 0 on every leg, whatever the form that sets them (workflow env, job env,
      step env, a write to GITHUB_ENV by echo quoted or unquoted, printf, tee, here-document, a
      composed variable name, RUSTFLAGS, a cargo --config). This is fail closed BY CONSTRUCTION:
      ALLOWED_SETTING_SITES is an allowlist of the exact lines (workflow, job, indent, text) that
      may mention a debuginfo setting, and every write to GITHUB_ENV is either a literal
      `echo "NAME=value"` (alone or in a `{ ...; } >> "$GITHUB_ENV"` group) or listed in
      ALLOWED_DYNAMIC_ENV_WRITERS; a line the test cannot classify is a problem, never a pass.
      The domain is read from the workflow files; the expected runner kind and values per job and
      leg are the hand table EXPECTED_CARGO_DEBUG;
  (c) the scripts/ci unit-test step lives in exactly one job that is no `needs` ancestor of any
      Check leg, runs on every push and carries no path filter or job-level `if:`.
  (d) the job ids and names of ci.yml equal the list pinned from the base (6c67b17b7).
  (e) what the moved unit-test step needs holds in its new job: the checkout keeps
      `fetch-depth: 2` (a push anchors the corpus ratchet on HEAD^), the 7987, 7988 and 9303
      preparation steps run right before it in that order with their load-bearing lines,
      and the job timeout stays above the measured step time with headroom.

Every check is a pure function over workflow TEXT that returns the problem lines; the cells
assert an empty list on the real files and an exact message on a deliberately broken copy.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.12+, standard library only (the workflows are read as text).
"""
import re
import unittest
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORKFLOWS = REPO / ".github" / "workflows"

CI = "ci.yml"
SELF_HOSTED = "self-hosted"
DEBUG_KEY = "cargo_debug"
DEBUG_EXPR = "${{ matrix.cargo_debug || 'line-tables-only' }}"
DEBUG_VARS = ("CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG")
DEBUG_WORKFLOW_VALUE = "line-tables-only"
SELF_HOSTED_VALUE = "0"
# The `cargo` subcommands that make a job a cargo job (a `name:` line is not a command).
CARGO_CMD_RE = re.compile(
    r"(?:^|[\s;&|(`\"'])cargo\s+(?:\+\S+\s+)?(?:build|test|check|clippy|fmt|run|llvm-cov|bench|doc|install|"
    r"fetch|metadata|audit|rustc|nextest|miri|fuzz|clean|tree|vet|deny|publish|package|search|update|"
    r"generate-lockfile|login|yank|nm|ndk|xtask|rustdoc|tarpaulin|hack|machete|udeps|about|cyclonedx|sbom)\b")
# Hand table (written from the workflow files at 5955a3e1d, never derived): (workflow, job, leg)
# -> (runner kind, CARGO_PROFILE_DEV_DEBUG, CARGO_PROFILE_TEST_DEBUG) as the leg builds. `leg` is
# the value of the first key of the matrix entry, "" without a matrix. "" as a value = undeclared.
# Hosted rows outside ci.yml keep what they have (release-shaped, coverage and bench builds are
# not changed); every ci.yml row is declared by the workflow-level env, and every self-hosted
# row is 0 and 0.
_H, _S = "hosted", "self-hosted"
_LTO = DEBUG_WORKFLOW_VALUE
EXPECTED_CARGO_DEBUG: dict = {
    ("batman-mode-acceptance.yml", "rust-integration", ""): (_H, "", ""),
    ("batman-mode-acceptance.yml", "bash-integration", ""): (_H, "", ""),
    ("bench.yml", "bench", ""): (_H, "", ""),
    ("bench.yml", "regenerate-baseline", ""): (_H, "", ""),
    ("cert-postgres-age.yml", "cert-postgres-age", ""): (_S, "0", "0"),
    ("ci.yml", "lint", ""): (_H, _LTO, _LTO),
    ("ci.yml", "build-script-vetting", ""): (_H, _LTO, _LTO),
    ("ci.yml", "msrv", ""): (_H, _LTO, _LTO),
    ("ci.yml", "check", "ubuntu-latest,sqlite"): (_H, "0", "0"),
    ("ci.yml", "check", "linux-fed,enterprise-fed"): (_S, "0", "0"),
    ("ci.yml", "check", "macos-fed,sqlite"): (_S, "0", "0"),
    ("ci.yml", "check", "macos-fed,enterprise-fed"): (_S, "0", "0"),
    ("ci.yml", "postgres-feature", ""): (_H, _LTO, _LTO),
    ("ci.yml", "mobile-cross-compile", "aarch64-apple-ios"): (_H, _LTO, _LTO),
    ("ci.yml", "mobile-cross-compile", "aarch64-linux-android"): (_H, _LTO, _LTO),
    ("ci.yml", "sal-feature", ""): (_H, _LTO, _LTO),
    ("ci.yml", "vectorlite-feature", ""): (_H, _LTO, _LTO),
    ("coverage.yml", "per-module-thresholds", ""): (_H, "0", ""),
    ("fuzz.yml", "fuzz", ""): (_H, "", ""),
    ("mobile-runtime.yml", "ios-simulator", ""): (_H, "", ""),
    ("mobile-runtime.yml", "android-emulator", ""): (_H, "", ""),
    ("postgres-ignored.yml", "postgres-ignored", ""): (_S, "0", "0"),
    ("release-shape.yml", "release-shape", ""): (_H, "", ""),
    ("release.yml", "supply-chain", ""): (_H, "", ""),
    ("release.yml", "release", "x86_64-unknown-linux-gnu"): (_H, "", ""),
    ("release.yml", "release", "aarch64-unknown-linux-gnu"): (_H, "", ""),
    ("release.yml", "release", "x86_64-apple-darwin"): (_H, "", ""),
    ("release.yml", "release", "aarch64-apple-darwin"): (_H, "", ""),
    ("release.yml", "sbom", ""): (_H, "", ""),
    ("release.yml", "mobile-ios", ""): (_H, "", ""),
    ("release.yml", "mobile-android", ""): (_H, "", ""),
    ("release.yml", "crates-io", ""): (_H, "", ""),
    ("rust-cache-warm.yml", "check-hosted-sqlite", ""): (_H, "0", "0"),
    ("rust-cache-warm.yml", "coverage", ""): (_H, "0", ""),
    ("rust-cache-warm.yml", "mobile-android-audit-release", ""): (_H, _LTO, _LTO),
    ("session-boot-lifetime.yml", "lifetime-tests", "ubuntu-latest"): (_H, "", ""),
    ("session-boot-lifetime.yml", "lifetime-tests", "macos-fed"): (_H, "", ""),
    ("token-budget.yml", "budget", ""): (_H, "", ""),
    ("yank.yml", "yank", ""): (_H, "", ""),
}
# Allowlist (written from the workflow files at 90a4df1b2, never derived): every live line of a
# workflow file that mentions a debuginfo setting, as (workflow, job, indent, text); job "" = before
# `jobs:` (workflow level). A line of this shape anywhere else is a finding, so a step-level env,
# an unquoted echo, a printf, a here-document, a cargo --config or a RUSTFLAGS edit all go red.
_DD, _DT = "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"
_MATRIX_EXPR = "${{ matrix.cargo_debug || 'line-tables-only' }}"
_LOWMEM = "- name: Low-mem hosted sqlite link (debuginfo=0, system ld — mold isolation)"
ALLOWED_SETTING_SITES = (
    ("cert-postgres-age.yml", "", 2, _DD + ': "0"'),
    ("cert-postgres-age.yml", "", 2, _DT + ': "0"'),
    ("ci.yml", "", 2, _DD + ": line-tables-only"),
    ("ci.yml", "", 2, _DT + ": line-tables-only"),
    ("ci.yml", "check", 6, _DD + ": " + _MATRIX_EXPR),
    ("ci.yml", "check", 6, _DT + ": " + _MATRIX_EXPR),
    ("ci.yml", "check", 6, _LOWMEM),
    ("ci.yml", "check", 12, 'echo "%s=0"' % _DD),
    ("ci.yml", "check", 12, 'echo "%s=0"' % _DT),
    ("ci.yml", "check", 12, 'echo "RUSTFLAGS=-C debuginfo=0"'),
    ("coverage.yml", "per-module-thresholds", 6, 'RUSTFLAGS: "-C link-arg=-fuse-ld=mold"'),
    ("coverage.yml", "per-module-thresholds", 6, _DD + ': "0"'),
    ("postgres-ignored.yml", "", 2, _DD + ': "0"'),
    ("postgres-ignored.yml", "", 2, _DT + ': "0"'),
    ("rust-cache-warm.yml", "check-hosted-sqlite", 6, _DD + ": line-tables-only"),
    ("rust-cache-warm.yml", "check-hosted-sqlite", 6, _DT + ": line-tables-only"),
    ("rust-cache-warm.yml", "check-hosted-sqlite", 6, _LOWMEM),
    ("rust-cache-warm.yml", "check-hosted-sqlite", 12, 'echo "%s=0"' % _DD),
    ("rust-cache-warm.yml", "check-hosted-sqlite", 12, 'echo "%s=0"' % _DT),
    ("rust-cache-warm.yml", "check-hosted-sqlite", 12, 'echo "RUSTFLAGS=-C debuginfo=0"'),
    ("rust-cache-warm.yml", "mobile-android-audit-release", 6, _DD + ": line-tables-only"),
    ("rust-cache-warm.yml", "mobile-android-audit-release", 6, _DT + ": line-tables-only"),
    ("rust-cache-warm.yml", "coverage", 6, 'RUSTFLAGS: "-C link-arg=-fuse-ld=mold"'),
    ("rust-cache-warm.yml", "coverage", 6, _DD + ': "0"'),
)
# The writes to GITHUB_ENV that are not a literal `echo "NAME=value"`: (workflow, job, text). Each
# one writes names the test cannot read from the line (a loop variable, a helper script's output);
# none can name a debuginfo variable: the loop is over the two passphrase names, and the helpers
# are scripts/ci/shared_cargo_target.py, scripts/ci/sccache_env.py and
# scripts/test/pg_isolated_binary.py, none of which mentions debuginfo.
ALLOWED_DYNAMIC_ENV_WRITERS = frozenset({
    ("ci.yml", "check", "printf '%s=\\n' \"$name\" >> \"$GITHUB_ENV\""),
    ("ci.yml", "check", ('run: python3 scripts/ci/shared_cargo_target.py --github-env "$GITHUB_ENV" '
                         '--runner-name "$RUNNER_NAME_ARG"')),
    ("ci.yml", "check", 'run: python3 scripts/ci/sccache_env.py --github-env "$GITHUB_ENV"'),
    ("ci.yml", "check", ('AI_MEMORY_TEST_POSTGRES_URL="$new_url" python3 scripts/test/pg_isolated_binary.py '
                         'setup --db "$CI_FED_DB" --jobs 8 --emit-env >> "$GITHUB_ENV"')),
})
# What can set a debuginfo level: the cargo profile variables, rustc's -C debuginfo, RUSTFLAGS in any
# spelling, a cargo --config profile key.
SETTING_RE = re.compile(
    r"CARGO_PROFILE_\w*DEBUG\w*|debuginfo|RUSTFLAGS|CARGO_ENCODED_\w+|profile\.\w+\.debug|-C\s*debug", re.I)
ENV_ECHO_RE = re.compile(r'^(?:run: )?echo "[A-Za-z_][A-Za-z0-9_]*=[^"]*" >> "\$GITHUB_ENV"$')
GROUP_ECHO_RE = re.compile(r'^echo "[A-Za-z_][A-Za-z0-9_]*=[^"]*"$')
GROUP_CLOSE = '} >> "$GITHUB_ENV"'
UNIT_COMMAND = "python3 -m unittest discover -s scripts/ci/tests"
UNIT_JOB = "build-script-vetting"
UNIT_STEP = "Shard partition and wiring unit tests (#6344)"
# (e) The checkout line a push needs: the Resolve step anchors the ratchet on HEAD^.
UNIT_CHECKOUT_ACTION = "actions/checkout@"
UNIT_CHECKOUT_DEPTH = "          fetch-depth: 2"
# (e) The steps the unit-test step needs, in this order, right before it, each with the line
# that does its work (moved byte for byte from `classify` at the base 6c67b17b7).
UNIT_PREP_STEPS = (
    ("Resolve the corpus ratchet base (#7987)", 'echo "CERT_MANIFEST_BASE_REF=HEAD^" >> "$GITHUB_ENV"'),
    ("Fetch the corpus replay objects (#7988)",
     "run: python3 -I scripts/ci/tests/test_check_cert_expiry_corpus.py --print-replay-shas"
     " | xargs git fetch --no-tags --depth=1 origin"),
    ("Fetch the amendment ledger replay objects (#9303)",
     "run: python3 -I scripts/ci/tests/test_cert_amendment_ledger_6124.py --print-replay-shas"
     " | xargs git fetch --no-tags --depth=1 origin"),
)
# (e) Timeout floor: the step took 674.9 s in build-script-vetting (run 44738653471) and
# 11.7 min in classify; the job's own gate work is about 0.5 min. Rounded up, then doubled.
UNIT_STEP_MEASURED_MIN = 12
UNIT_JOB_OWN_MIN = 1
TIMEOUT_HEADROOM_FACTOR = 2
UNIT_JOB_TIMEOUT_FLOOR_MIN = TIMEOUT_HEADROOM_FACTOR * (UNIT_STEP_MEASURED_MIN + UNIT_JOB_OWN_MIN)
# Job id -> `name:` of ci.yml at the base 6c67b17b7, in file order.
PINNED_JOBS = (
    ("select", "Impact selection"),
    ("classify", "Classify changes"),
    ("lint", "Lint (fmt + clippy)"),
    ("build-script-vetting", "Build-script custom-build ledger gate (#2635)"),
    ("actionlint", "actionlint (workflow-injection guard)"),
    ("msrv", "MSRV (Rust 1.98)"),
    ("check", "Check (${{ matrix.leg }})"),
    ("postgres-feature", "Postgres feature gate"),
    ("mobile-cross-compile", "Cross-compile (${{ matrix.target }})"),
    ("sal-feature", "SAL-only feature gate"),
    ("vectorlite-feature", "vectorlite feature gate"),
    ("dockerfile-validate", "Dockerfile build (no push)"),
    ("ci-gate", "ci-gate"),
)

JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*$")
KEY_RE = re.compile(r"^    ([A-Za-z0-9_-]+):(.*)$")
STEP_RE = re.compile(r"^      - name: (.*)$")


def read(name: str) -> str:
    return (WORKFLOWS / name).read_text()


def jobs_of(text: str) -> dict:
    """Job id -> its block of lines, in file order (a dict keeps the order)."""
    out: dict = {}
    lines = text.split("\n")
    try:
        start = lines.index("jobs:") + 1
    except ValueError:
        return out
    current = None
    for line in lines[start:]:
        match = JOB_RE.match(line)
        if match:
            current = match.group(1)
            out[current] = []
        elif current is not None:
            out[current].append(line)
    return out


def job_name(block: list) -> str:
    for line in block:
        match = KEY_RE.match(line)
        if match and match.group(1) == "name":
            return match.group(2).strip().strip('"')
    return ""


def job_needs(block: list) -> list:
    """The job-level `needs:` ids: `needs: a`, `needs: [a, b]` or a block list."""
    ids: list = []
    for index, line in enumerate(block):
        match = KEY_RE.match(line)
        if not match or match.group(1) != "needs":
            continue
        rest = match.group(2).strip()
        if rest:
            ids += [w for w in re.split(r"[\s,\[\]]+", rest) if w]
        else:
            for item in block[index + 1:]:
                m2 = re.match(r"^      - ([A-Za-z0-9_-]+)\s*$", item)
                if not m2:
                    break
                ids.append(m2.group(1))
        break
    return ids


def job_has_key(block: list, key: str) -> bool:
    return any(m.group(1) == key for m in map(KEY_RE.match, block) if m)


def ancestors(jobs: dict, job: str) -> set:
    seen: set = set()
    todo = list(job_needs(jobs.get(job, [])))
    while todo:
        nxt = todo.pop()
        if nxt in seen:
            continue
        seen.add(nxt)
        todo += job_needs(jobs.get(nxt, []))
    return seen


def matrix_entry(block: list, leg: str) -> list:
    """The lines of the `include:` entry whose `leg:` is LEG, up to the next entry."""
    text = "\n".join(block)
    entries = re.split(r"\n          - (?=leg: )", text)
    for entry in entries[1:]:
        if entry.startswith("leg: %s\n" % leg):
            return entry.split("\n")
    return []


def step_run(text: str, name: str) -> str:
    start = text.find("      - name: %s\n" % name)
    if start < 0:
        return ""
    nxt = text.find("\n      - name: ", start + 1)
    return text[start:] if nxt < 0 else text[start:nxt]


# ---------------------------------------------------------------------------------------
# (a) debuginfo: every self-hosted cargo job declares both variables, equal, and 0
# ---------------------------------------------------------------------------------------

def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _live(line: str) -> bool:
    return bool(line.strip()) and not line.strip().startswith("#")


def _value(raw: str) -> str:
    """A scalar as written, one trailing ` # comment` and the quotes removed."""
    raw = re.sub(r"\s+#.*$", "", raw.strip())
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1]
    return raw


def _mapping_under(lines: list, header_indent: int, header: str) -> dict:
    """`NAME: value` pairs of the block `<header>:` at HEADER_INDENT; keys at HEADER_INDENT + 2."""
    out: dict = {}
    inside = False
    for line in lines:
        if not _live(line):
            continue
        if _indent(line) <= header_indent:
            inside = _indent(line) == header_indent and line.strip() == header + ":"
            continue
        if inside and _indent(line) == header_indent + 2 and ":" in line:
            name, _, raw = line.strip().partition(":")
            out[name] = _value(raw)
    return out


def workflow_env(text: str) -> dict:
    return _mapping_under(text.split("\n"), 0, "env")


def job_env(block: list) -> dict:
    return _mapping_under(block, 4, "env")


def matrix_legs(block: list) -> list:
    """The `strategy.matrix.include` entries as raw-scalar dicts (quotes kept), in file order."""
    legs: list = []
    include_indent = -1
    for line in block:
        if not _live(line):
            continue
        if include_indent < 0:
            if line.strip() == "include:" and _indent(line) == 8:
                include_indent = _indent(line)
            continue
        if _indent(line) <= include_indent:
            break
        stripped = line.strip()
        if stripped.startswith("- ") and _indent(line) == include_indent + 2:
            legs.append({})
            stripped = stripped[2:]
        elif _indent(line) != include_indent + 4:
            continue
        name, _, raw = stripped.partition(":")
        legs[-1][name.strip()] = re.sub(r"\s+#.*$", "", raw.strip())
    return legs


def leg_id(leg: dict) -> str:
    return _value(next(iter(leg.values()))) if leg else ""


def runner_of(block: list, leg: dict) -> str:
    """The runner labels of one leg; a runs-on form that is not read here is returned as written."""
    for line in block:
        if _indent(line) == 4 and line.strip().startswith("runs-on:"):
            raw = line.strip()[len("runs-on:"):].strip()
            if "matrix.os" in raw:
                return _value(leg.get("os", ""))
            if "matrix.runner" in raw:
                return _value(leg.get("runner", ""))
            return raw
    return ""


def effective_value(raw: str, leg: dict) -> tuple:
    """(value, problem): the value one env entry takes on a leg. `${{ matrix.K || 'L' }}` is the
    leg's K when K is a QUOTED non-empty scalar, L when K is unset; any other expression form, and
    an unquoted 0 (falsy in the expression, so it would silently take L), is a problem."""
    if "${{" not in raw:
        return raw, ""
    match = re.match(r"^\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_-]*)\s*\|\|\s*'([^']*)'\s*\}\}$", raw)
    if not match:
        return "", "unrecognised expression form %r" % raw
    key, literal = match.groups()
    if key not in leg:
        return literal, ""
    written = leg[key]
    if not (len(written) >= 2 and written[0] == written[-1] and written[0] in "'\""):
        return "", "matrix.%s = %s is not a quoted string, so `||` may take the literal" % (key, written)
    return written[1:-1] or literal, ""


def step_exports(block: list, leg: str) -> dict:
    """`echo "VAR=value"` exports of a debug variable in steps that apply to LEG: a step whose `if:`
    names `matrix.leg == '<other>'` is skipped."""
    out: dict = {}
    starts = [i for i, line in enumerate(block) if _indent(line) == 6 and line.startswith("      - ")]
    for n, start in enumerate(starts):
        step = block[start:starts[n + 1] if n + 1 < len(starts) else len(block)]
        text = "\n".join(line for line in step if _live(line))
        named = re.findall(r"matrix\.leg == '([^']*)'", text)
        if named and leg not in named:
            continue
        for var in DEBUG_VARS:
            found = re.findall(r'echo "%s=([^"]*)"' % var, text)
            if found:
                out[var] = found[-1]
    return out


def cargo_jobs(text: str) -> dict:
    return {job: block for job, block in jobs_of(text).items()
            if any(_live(line) and "name:" not in line and CARGO_CMD_RE.search(line) for line in block)}


def cargo_debug_rows(workflows: dict) -> tuple:
    """({(workflow, job, leg): (kind, dev, test)}, [problems]) read from the workflow files."""
    rows: dict = {}
    problems: list = []
    for name in sorted(workflows):
        text = workflows[name]
        wf_env = workflow_env(text)
        for job, block in cargo_jobs(text).items():
            legs = matrix_legs(block) or [{}]
            env = {**wf_env, **job_env(block)}
            for leg in legs:
                lid = leg_id(leg)
                kind = "self-hosted" if SELF_HOSTED in runner_of(block, leg) else "hosted"
                values = []
                for var in DEBUG_VARS:
                    raw = env.get(var)
                    value, problem = ("", "") if raw is None else effective_value(raw, leg)
                    if problem:
                        problems.append("%s %s leg %r: %s: %s" % (name, job, lid, var, problem))
                    values.append(value)
                exported = step_exports(block, lid)
                values = [exported.get(var, value) for var, value in zip(DEBUG_VARS, values)]
                rows[(name, job, lid)] = (kind, values[0], values[1])
    return rows, problems


def problems_setting_sites(workflows: dict) -> list:
    """Fail-closed allowlist over every workflow: (1) a write to GITHUB_ENV is a literal
    `echo "NAME=value"`, a `{ echo "NAME=value"; ... } >> "$GITHUB_ENV"` group of literal echoes, or an
    ALLOWED_DYNAMIC_ENV_WRITERS line; (2) every line that mentions a debuginfo setting is one of
    ALLOWED_SETTING_SITES, the same number of times."""
    out: list = []
    want = Counter(ALLOWED_SETTING_SITES)
    found: Counter = Counter()
    for name in sorted(workflows):
        lines = workflows[name].split("\n")
        job = ""
        in_jobs = False
        for index, line in enumerate(lines):
            if line == "jobs:":
                in_jobs = True
            match = JOB_RE.match(line) if in_jobs else None
            if match:
                job = match.group(1)
            if not _live(line):
                continue
            text = line.strip()
            if SETTING_RE.search(line):
                found[(name, job, _indent(line), text)] += 1
            if "GITHUB_ENV" not in line and "--github-env" not in line:
                continue
            if text == GROUP_CLOSE:
                start = index - 1
                while start >= 0 and lines[start].strip() != "{":
                    start -= 1
                if start < 0:
                    out.append("%s %s: a write to GITHUB_ENV in a form the test cannot classify: %s" % (name, job, text))
                for body in lines[max(start, 0) + 1:index]:
                    if _live(body) and not GROUP_ECHO_RE.match(body.strip()):
                        out.append("%s %s: a line of a GITHUB_ENV group the test cannot classify: %s"
                                   % (name, job, body.strip()))
            elif not ENV_ECHO_RE.match(text) and (name, job, text) not in ALLOWED_DYNAMIC_ENV_WRITERS:
                out.append("%s %s: a write to GITHUB_ENV in a form the test cannot classify: %s" % (name, job, text))
    for key in sorted(set(want) | set(found)):
        if found[key] != want[key]:
            out.append("%s %s: debuginfo setting site (indent %d) %r occurs %d times, the allowlist has %d"
                       % (key + (found[key], want[key])))
    return out


def problems_debuginfo(workflows: dict) -> list:
    rows, out = cargo_debug_rows(workflows)
    for var in DEBUG_VARS:
        if workflow_env(workflows[CI]).get(var) != DEBUG_WORKFLOW_VALUE:
            out.append("ci.yml: the workflow env must declare %s: %s" % (var, DEBUG_WORKFLOW_VALUE))
    jobs = jobs_of(workflows[CI])
    check = jobs.get("check", [])
    for var in DEBUG_VARS:
        want = "      %s: %s" % (var, DEBUG_EXPR)
        if want not in check:
            out.append("ci.yml check: the job env must read %r" % want)
    for leg in matrix_legs(check):
        hosted = SELF_HOSTED not in runner_of(check, leg)
        if hosted and DEBUG_KEY in leg:
            out.append("ci.yml check: leg %s is hosted and must not set %s" % (leg_id(leg), DEBUG_KEY))
    for job, block in jobs.items():
        if job != "check" and any("CARGO_PROFILE_" in line and "_DEBUG" in line for line in block):
            out.append("ci.yml %s: only the check job may set a CARGO_PROFILE_*_DEBUG variable" % job)
    for name, text in workflows.items():
        if name != CI and DEBUG_KEY in text:
            out.append("%s: release-shaped and coverage builds must not use %s" % (name, DEBUG_KEY))
    for key in sorted(set(rows) - set(EXPECTED_CARGO_DEBUG)):
        out.append("%s %s leg %r: a cargo job with no row in EXPECTED_CARGO_DEBUG" % key)
    for key in sorted(set(EXPECTED_CARGO_DEBUG) - set(rows)):
        out.append("%s %s leg %r: a row of EXPECTED_CARGO_DEBUG names no cargo job" % key)
    for key in sorted(set(rows) & set(EXPECTED_CARGO_DEBUG)):
        kind, dev, test = rows[key]
        label = "%s %s leg %r" % key
        found = False
        if kind == "self-hosted":
            for var, value in zip(DEBUG_VARS, (dev, test)):
                if value == "":
                    out.append("%s: self-hosted job leaves %s undeclared" % (label, var))
                    found = True
                elif value != SELF_HOSTED_VALUE:
                    out.append("%s: self-hosted job sets %s to %r, must be 0" % (label, var, value))
                    found = True
        if dev and test and dev != test:
            out.append("%s: CARGO_PROFILE_DEV_DEBUG %r differs from CARGO_PROFILE_TEST_DEBUG %r" % (label, dev, test))
            found = True
        if not found and (kind, dev, test) != EXPECTED_CARGO_DEBUG[key]:
            out.append("%s: reads %r, the hand table says %r" % (label, (kind, dev, test), EXPECTED_CARGO_DEBUG[key]))
    return out + problems_setting_sites(workflows)


# ---------------------------------------------------------------------------------------
# (c) the unit-test step: one job, no path to a Check leg, every push
# ---------------------------------------------------------------------------------------

def problems_unit_placement(workflows: dict) -> list:
    out: list = []
    text = workflows[CI]
    jobs = jobs_of(text)
    holders = [job for job, block in jobs.items() if any(line.strip() == "run: " + UNIT_COMMAND for line in block)]
    if holders != [UNIT_JOB]:
        out.append("ci.yml: the unit-test step must be in exactly the job %s, found %r" % (UNIT_JOB, holders))
    block = jobs.get(UNIT_JOB, [])
    if not any(line == "      - name: " + UNIT_STEP for line in block):
        out.append("ci.yml %s: the step %r is missing" % (UNIT_JOB, UNIT_STEP))
    for job in holders:
        blk = jobs[job]
        if job_needs(blk):
            out.append("ci.yml %s: the unit-test job must have no needs" % job)
        if job_has_key(blk, "if"):
            out.append("ci.yml %s: the unit-test job must have no job-level if" % job)
        for leg_job in jobs:
            if job in ancestors(jobs, leg_job) and leg_job == "check":
                out.append("ci.yml: %s is a needs ancestor of check" % job)
    if "ci-gate" in jobs and UNIT_JOB not in job_needs(jobs["ci-gate"]):
        out.append("ci.yml ci-gate: must keep %s in needs" % UNIT_JOB)
    head = text.split("\njobs:", 1)[0]
    if re.search(r"^\s+paths(-ignore)?:", head, re.M):
        out.append("ci.yml: a path filter on the triggers would skip the unit-test job")
    if not any(event in head for event in ("  push:", "  pull_request:")):
        out.append("ci.yml: push and pull_request triggers are missing")
    return out


# ---------------------------------------------------------------------------------------
# (e) what the moved unit-test step needs, in its new job
# ---------------------------------------------------------------------------------------

STEP_START_RE = re.compile(r"^      - ")
STEP_NAME_RE = re.compile(r"^      (?:- |  )name: (.*)$")


def job_steps(block: list) -> list:
    """(step name, its lines) per step of a job block; a `uses:` step without a name gets ''."""
    steps: list = []
    for line in block:
        if STEP_START_RE.match(line):
            steps.append(["", []])
        if steps:
            steps[-1][1].append(line)
            match = STEP_NAME_RE.match(line)
            if match and not steps[-1][0]:
                steps[-1][0] = match.group(1).strip()
    return [(name, lines) for name, lines in steps]


def job_timeout(block: list):
    for line in block:
        match = KEY_RE.match(line)
        if match and match.group(1) == "timeout-minutes":
            value = match.group(2).strip()
            return int(value) if value.isdigit() else None
    return None


def problems_unit_needs(workflows: dict) -> list:
    out: list = []
    block = jobs_of(workflows[CI]).get(UNIT_JOB, [])
    where = "ci.yml %s" % UNIT_JOB
    steps = job_steps(block)
    checkouts = [lines for _name, lines in steps if any(UNIT_CHECKOUT_ACTION in line for line in lines[:1])]
    if len(checkouts) != 1 or UNIT_CHECKOUT_DEPTH not in checkouts[0]:
        out.append("%s: the checkout must set fetch-depth: 2 (a push anchors the corpus ratchet on HEAD^)" % where)
    names = [name for name, _lines in steps]
    if UNIT_STEP not in names:
        out.append("%s: the step %r is missing" % (where, UNIT_STEP))
        return out
    unit_at = names.index(UNIT_STEP)
    present = []
    for name, line_needed in UNIT_PREP_STEPS:
        if name not in names:
            out.append("%s: the step %r the unit-test step needs is missing" % (where, name))
            continue
        present.append(name)
        if not any(line.strip() == line_needed for line in steps[names.index(name)][1]):
            out.append("%s: the step %r must carry %r" % (where, name, line_needed))
    if names[max(unit_at - len(present), 0):unit_at] != present:
        out.append("%s: the preparation steps must run right before the unit-test step, in the order "
                   "7987, 7988, 9303" % where)
    timeout = job_timeout(block)
    if timeout is None or timeout < UNIT_JOB_TIMEOUT_FLOOR_MIN:
        out.append("%s: timeout-minutes %s is under the floor %d (%d x (%d min measured unit step + %d min own work))"
                   % (where, timeout, UNIT_JOB_TIMEOUT_FLOOR_MIN, TIMEOUT_HEADROOM_FACTOR,
                      UNIT_STEP_MEASURED_MIN, UNIT_JOB_OWN_MIN))
    return out


# ---------------------------------------------------------------------------------------
# (d) job ids and names pinned from the base
# ---------------------------------------------------------------------------------------

def problems_job_names(workflows: dict) -> list:
    jobs = jobs_of(workflows[CI])
    got = tuple((job, job_name(block)) for job, block in jobs.items())
    if got != PINNED_JOBS:
        return ["ci.yml: job ids and names differ from the pinned base list: added %r, removed %r" % (
            sorted(set(got) - set(PINNED_JOBS)), sorted(set(PINNED_JOBS) - set(got)))]
    return []


def real_workflows() -> dict:
    return {path.name: path.read_text() for path in sorted(WORKFLOWS.glob("*.yml"))}


class RealFiles(unittest.TestCase):
    def test_8216_debuginfo_pair_declared_and_0_on_every_self_hosted_leg(self):
        self.assertEqual(problems_debuginfo(real_workflows()), [])

    def test_9593_unit_test_step_is_in_one_job_with_no_path_to_a_check_leg(self):
        self.assertEqual(problems_unit_placement(real_workflows()), [])

    def test_9593_job_ids_and_names_equal_the_pinned_base_list(self):
        self.assertEqual(problems_job_names(real_workflows()), [])

    def test_9593_unit_step_keeps_what_it_needs_in_its_new_job(self):
        self.assertEqual(problems_unit_needs(real_workflows()), [])


# (e) Broken copies of the unit-test job: (cell id, text in the job, replacement, exact problems).
WHERE = "ci.yml " + UNIT_JOB
NEEDS_MUTANTS = (
    ("fetch_depth_removed", UNIT_CHECKOUT_DEPTH + "\n", "",
     [WHERE + ": the checkout must set fetch-depth: 2 (a push anchors the corpus ratchet on HEAD^)"]),
    ("replay_fetch_7988_dropped",
     "      - name: Fetch the corpus replay objects (#7988)\n        " + UNIT_PREP_STEPS[1][1] + "\n", "",
     [WHERE + ": the step 'Fetch the corpus replay objects (#7988)' the unit-test step needs is missing"]),
    ("timeout_lowered_40_to_15", "    timeout-minutes: 40\n", "    timeout-minutes: 15\n",
     [WHERE + ": timeout-minutes 15 is under the floor 26 (2 x (12 min measured unit step + 1 min own work))"]),
    ("ratchet_anchor_line_changed", 'echo "CERT_MANIFEST_BASE_REF=HEAD^"', 'echo "CERT_MANIFEST_BASE_REF=HEAD"',
     [WHERE + ": the step 'Resolve the corpus ratchet base (#7987)' must carry "
      + repr(UNIT_PREP_STEPS[0][1])]),
    ("step_between_prep_and_unit",
     "      - name: " + UNIT_STEP + "\n", "      - name: Interloper\n        run: true\n      - name: " + UNIT_STEP + "\n",
     [WHERE + ": the preparation steps must run right before the unit-test step, in the order 7987, 7988, 9303"]),
    ("replay_fetch_9303_dropped",
     "      - name: Fetch the amendment ledger replay objects (#9303)\n        " + UNIT_PREP_STEPS[2][1] + "\n", "",
     [WHERE + ": the step 'Fetch the amendment ledger replay objects (#9303)' the unit-test step needs is missing"]),
)


class NeedsBrokenCopies(unittest.TestCase):
    """(e) Each need of the moved step is red, with its exact message, when a copy breaks it."""

    @staticmethod
    def _broken_job(old: str, new: str) -> dict:
        workflows = real_workflows()
        text = workflows[CI]
        start = text.index("\n  %s:\n" % UNIT_JOB) + 1
        rest = text[start:].split("\n")
        end = start + len(rest[0]) + 1
        for line in rest[1:]:
            if JOB_RE.match(line):
                break
            end += len(line) + 1
        job = text[start:end]
        if job.count(old) != 1:
            raise AssertionError("mutant anchor %r occurs %d times in the %s job" % (old, job.count(old), UNIT_JOB))
        workflows[CI] = text[:start] + job.replace(old, new) + text[end:]
        return workflows

    def test_each_need_is_red_on_its_broken_copy(self):
        for cell, old, new, want in NEEDS_MUTANTS:
            with self.subTest(cell=cell):
                self.assertEqual(problems_unit_needs(self._broken_job(old, new)), want)


# (a) Broken copies of the debuginfo setting sites, one per form a workflow can set the pair (or
# RUSTFLAGS debuginfo): (cell, workflow, old text or None = append to the file, new text, exact
# problems written by hand). `old` occurs once in the real file. Forms: step env (M12, M14), unquoted
# echo (M13), printf (M15), here-document, tee, a composed variable name, a group line with a dynamic
# name, RUSTFLAGS in a workflow env, a cargo --config, a flow-style job env, a changed value at an
# allowed site, a duplicated allowed line, a literal echo in another workflow.
CERT = "cert-postgres-age.yml"
CERT_STEP = ("      - name: Run #[ignore]-gated pg + AGE cells against the certified stack\n"
             "        if: steps.docs.outputs.docs_only != 'true'\n        run: |\n")
CERT_STEP_SET = CERT_STEP + "          set -euo pipefail\n"
RCW_DEV_ECHO = '            echo "CARGO_PROFILE_DEV_DEBUG=0"\n'
RCW_TEST_ECHO = '            echo "CARGO_PROFILE_TEST_DEBUG=0"\n'
_BAD_WRITE = "%s %s: a write to GITHUB_ENV in a form the test cannot classify: %s"
_BAD_SITE = "%s %s: debuginfo setting site (indent %d) %r occurs %d times, the allowlist has %d"
CERT_JOB = "cert-postgres-age"
UNQUOTED_ECHO = 'echo CARGO_PROFILE_DEV_DEBUG=2 >> "$GITHUB_ENV"'
PRINTF = "printf 'CARGO_PROFILE_TEST_DEBUG=line-tables-only\\n' >> \"$GITHUB_ENV\""
HEREDOC_OPEN = 'cat >> "$GITHUB_ENV" <<EOF'
TEE = 'echo "CARGO_PROFILE_DEV_DEBUG=2" | tee -a "$GITHUB_ENV"'
COMPOSED = 'k=CARGO_PROFILE_DEV; echo "${k}_DEBUG=2" >> "$GITHUB_ENV"'
CARGO_CONFIG = "cargo build --config profile.dev.debug=2 --features sal-postgres --bin ai-memory"
FLOW_ENV = 'env: {CARGO_PROFILE_DEV_DEBUG: "2"}'
RUSTFLAGS_STEP = 'run: echo "RUSTFLAGS=-C debuginfo=2" >> "$GITHUB_ENV"'
SITE_MUTANTS = (
    ("M12_step_env_on_the_check_job",
     CI,
     "      - name: Run tests (impact-aware)\n        if: needs.classify.outputs.cargo_skip != 'true'\n        env:\n",
     ("      - name: Run tests (impact-aware)\n        if: needs.classify.outputs.cargo_skip != 'true'\n        env:\n"
      "          CARGO_PROFILE_DEV_DEBUG: line-tables-only\n          CARGO_PROFILE_TEST_DEBUG: line-tables-only\n"),
     [_BAD_SITE % (CI, "check", 10, "CARGO_PROFILE_DEV_DEBUG: line-tables-only", 1, 0),
      _BAD_SITE % (CI, "check", 10, "CARGO_PROFILE_TEST_DEBUG: line-tables-only", 1, 0)]),
    ("M13_unquoted_echo_to_github_env",
     CERT, CERT_STEP_SET, CERT_STEP_SET + "          " + UNQUOTED_ECHO + "\n",
     [_BAD_WRITE % (CERT, CERT_JOB, UNQUOTED_ECHO),
      _BAD_SITE % (CERT, CERT_JOB, 10, UNQUOTED_ECHO, 1, 0)]),
    ("M14_step_env_on_another_self_hosted_job",
     CERT, CERT_STEP,
     CERT_STEP.replace("        run: |\n", '        env:\n          CARGO_PROFILE_TEST_DEBUG: "2"\n        run: |\n'),
     [_BAD_SITE % (CERT, CERT_JOB, 10, 'CARGO_PROFILE_TEST_DEBUG: "2"', 1, 0)]),
    ("M15_printf_to_github_env",
     CERT, CERT_STEP_SET, CERT_STEP_SET + "          " + PRINTF + "\n",
     [_BAD_WRITE % (CERT, CERT_JOB, PRINTF),
      _BAD_SITE % (CERT, CERT_JOB, 10, PRINTF, 1, 0)]),
    ("M16_here_document_to_github_env",
     CERT, CERT_STEP_SET,
     CERT_STEP_SET + "          " + HEREDOC_OPEN + "\n          CARGO_PROFILE_TEST_DEBUG=2\n          EOF\n",
     [_BAD_WRITE % (CERT, CERT_JOB, HEREDOC_OPEN),
      _BAD_SITE % (CERT, CERT_JOB, 10, "CARGO_PROFILE_TEST_DEBUG=2", 1, 0)]),
    ("M17_tee_to_github_env",
     CERT, CERT_STEP_SET, CERT_STEP_SET + "          " + TEE + "\n",
     [("cert-postgres-age.yml cert-postgres-age leg '': self-hosted job sets CARGO_PROFILE_DEV_DEBUG to '2', "
       "must be 0"),
      ("cert-postgres-age.yml cert-postgres-age leg '': CARGO_PROFILE_DEV_DEBUG '2' differs from "
       "CARGO_PROFILE_TEST_DEBUG '0'"),
      _BAD_WRITE % (CERT, CERT_JOB, TEE),
      _BAD_SITE % (CERT, CERT_JOB, 10, TEE, 1, 0)]),
    ("M18_composed_variable_name",
     CERT, CERT_STEP_SET, CERT_STEP_SET + "          " + COMPOSED + "\n",
     [_BAD_WRITE % (CERT, CERT_JOB, COMPOSED)]),
    ("M19_dynamic_name_in_an_env_group",
     "rust-cache-warm.yml", '            echo "CARGO_BUILD_JOBS=1"\n', '            echo "${k}=2"\n',
     [('rust-cache-warm.yml check-hosted-sqlite: a line of a GITHUB_ENV group the test cannot classify: '
       'echo "${k}=2"')]),
    ("M20_rustflags_debuginfo_in_the_workflow_env",
     "postgres-ignored.yml", '  CARGO_PROFILE_TEST_DEBUG: "0"\n',
     '  CARGO_PROFILE_TEST_DEBUG: "0"\n  RUSTFLAGS: "-C debuginfo=2"\n',
     [_BAD_SITE % ("postgres-ignored.yml", "", 2, 'RUSTFLAGS: "-C debuginfo=2"', 1, 0)]),
    ("M21_cargo_config_profile_key",
     CERT, "          cargo build --features sal-postgres --bin ai-memory\n", "          " + CARGO_CONFIG + "\n",
     [_BAD_SITE % (CERT, CERT_JOB, 10, CARGO_CONFIG, 1, 0)]),
    ("M22_flow_style_job_env",
     CERT, "    steps:\n", "    " + FLOW_ENV + "\n    steps:\n",
     [_BAD_SITE % (CERT, CERT_JOB, 4, FLOW_ENV, 1, 0)]),
    ("M23_value_changed_at_an_allowed_echo",
     "rust-cache-warm.yml", RCW_TEST_ECHO, RCW_TEST_ECHO.replace("=0", "=2"),
     [("rust-cache-warm.yml check-hosted-sqlite leg '': CARGO_PROFILE_DEV_DEBUG '0' differs from "
       "CARGO_PROFILE_TEST_DEBUG '2'"),
      _BAD_SITE % ("rust-cache-warm.yml", "check-hosted-sqlite", 12, 'echo "CARGO_PROFILE_TEST_DEBUG=0"', 0, 1),
      _BAD_SITE % ("rust-cache-warm.yml", "check-hosted-sqlite", 12, 'echo "CARGO_PROFILE_TEST_DEBUG=2"', 1, 0)]),
    ("M24_allowed_echo_duplicated",
     "rust-cache-warm.yml", RCW_DEV_ECHO, RCW_DEV_ECHO + RCW_DEV_ECHO,
     [_BAD_SITE % ("rust-cache-warm.yml", "check-hosted-sqlite", 12, 'echo "CARGO_PROFILE_DEV_DEBUG=0"', 2, 1)]),
    ("M25_literal_rustflags_echo_in_another_workflow",
     "yank.yml", None, "        " + RUSTFLAGS_STEP + "\n",
     [_BAD_SITE % ("yank.yml", "yank", 8, RUSTFLAGS_STEP, 1, 0)]),
)


class BrokenCopies(unittest.TestCase):
    """Each check is red, with its exact message, on a deliberately broken copy."""

    def _broken(self, name: str, old: str, new: str) -> dict:
        workflows = real_workflows()
        self.assertEqual(workflows[name].count(old), 1, old)
        workflows[name] = workflows[name].replace(old, new)
        return workflows

    def test_each_debuginfo_setting_form_is_red_on_its_broken_copy(self):
        for cell, name, old, new, want in SITE_MUTANTS:
            with self.subTest(cell=cell):
                if old is None:
                    workflows = real_workflows()
                    workflows[name] = workflows[name].rstrip("\n") + "\n" + new
                else:
                    workflows = self._broken(name, old, new)
                self.assertEqual(problems_debuginfo(workflows), want)

    def test_debuginfo_key_on_a_hosted_leg(self):
        leg = "ubuntu-latest,sqlite"
        workflows = real_workflows()
        text = workflows[CI]
        start = text.index("          - leg: %s\n" % leg)
        at = text.index("            tier: sqlite\n", start) + len("            tier: sqlite\n")
        workflows[CI] = text[:at] + "            cargo_debug: '0'\n" + text[at:]
        self.assertEqual(problems_debuginfo(workflows),
                         ["ci.yml check: leg %s is hosted and must not set cargo_debug" % leg])

    def _without_debug_key(self, leg: str) -> dict:
        """A copy of ci.yml whose matrix entry for LEG has no `cargo_debug: '0'` line."""
        workflows = real_workflows()
        text = workflows[CI]
        start = text.index("          - leg: %s\n" % leg)
        line = "            %s: '0'\n" % DEBUG_KEY
        end = text.find("          - leg: ", start + 1)
        at = text.find(line, start, end if end >= 0 else len(text))
        self.assertGreaterEqual(at, 0, "leg %s has no %s line to remove" % (leg, DEBUG_KEY))
        workflows[CI] = text[:at] + text[at + len(line):]
        return workflows

    def test_debuginfo_key_missing_on_each_self_hosted_leg(self):
        for leg in ("linux-fed,enterprise-fed", "macos-fed,sqlite", "macos-fed,enterprise-fed"):
            with self.subTest(leg=leg):
                self.assertEqual(problems_debuginfo(self._without_debug_key(leg)), [
                    "ci.yml check leg %r: self-hosted job sets CARGO_PROFILE_DEV_DEBUG to 'line-tables-only', must be 0" % leg,
                    "ci.yml check leg %r: self-hosted job sets CARGO_PROFILE_TEST_DEBUG to 'line-tables-only', must be 0" % leg])

    def test_debuginfo_key_in_a_coverage_style_workflow(self):
        workflows = real_workflows()
        workflows["coverage.yml"] += "\n# cargo_debug\n"
        self.assertEqual(problems_debuginfo(workflows),
                         ["coverage.yml: release-shaped and coverage builds must not use cargo_debug"])

    def test_self_hosted_cargo_job_with_no_declaration(self):
        workflows = self._broken("cert-postgres-age.yml", '  CARGO_PROFILE_TEST_DEBUG: "0"\n', "")
        self.assertEqual(problems_debuginfo(workflows), [
            "cert-postgres-age.yml cert-postgres-age leg '': self-hosted job leaves CARGO_PROFILE_TEST_DEBUG undeclared",
            ("cert-postgres-age.yml : debuginfo setting site (indent 2) 'CARGO_PROFILE_TEST_DEBUG: \"0\"' occurs 0 "
             "times, the allowlist has 1")])

    def test_self_hosted_dev_and_test_differ(self):
        workflows = self._broken("postgres-ignored.yml", '  CARGO_PROFILE_TEST_DEBUG: "0"\n',
                                 '  CARGO_PROFILE_TEST_DEBUG: "1"\n')
        self.assertEqual(problems_debuginfo(workflows), [
            "postgres-ignored.yml postgres-ignored leg '': self-hosted job sets CARGO_PROFILE_TEST_DEBUG to '1', must be 0",
            ("postgres-ignored.yml postgres-ignored leg '': CARGO_PROFILE_DEV_DEBUG '0' differs from "
             "CARGO_PROFILE_TEST_DEBUG '1'"),
            ("postgres-ignored.yml : debuginfo setting site (indent 2) 'CARGO_PROFILE_TEST_DEBUG: \"0\"' occurs 0 "
             "times, the allowlist has 1"),
            ("postgres-ignored.yml : debuginfo setting site (indent 2) 'CARGO_PROFILE_TEST_DEBUG: \"1\"' occurs 1 "
             "times, the allowlist has 0")])

    def test_hosted_ci_job_dev_and_test_differ(self):
        workflows = self._broken(CI, "\n  CARGO_PROFILE_TEST_DEBUG: line-tables-only\n",
                                 "\n  CARGO_PROFILE_TEST_DEBUG: full\n")
        got = problems_debuginfo(workflows)
        self.assertIn("ci.yml: the workflow env must declare CARGO_PROFILE_TEST_DEBUG: line-tables-only", got)
        self.assertIn("ci.yml lint leg '': CARGO_PROFILE_DEV_DEBUG 'line-tables-only' differs from "
                      "CARGO_PROFILE_TEST_DEBUG 'full'", got)

    def test_workflow_env_missing_in_ci(self):
        workflows = self._broken(CI, "\n  CARGO_PROFILE_DEV_DEBUG: line-tables-only\n", "\n")
        got = problems_debuginfo(workflows)
        self.assertEqual(got[0], "ci.yml: the workflow env must declare CARGO_PROFILE_DEV_DEBUG: line-tables-only")
        self.assertIn("ci.yml lint leg '': reads ('hosted', '', 'line-tables-only'), the hand table says "
                      "('hosted', 'line-tables-only', 'line-tables-only')", got)

    def test_new_self_hosted_cargo_job_has_no_row(self):
        workflows = real_workflows()
        workflows["yank.yml"] += ("\n  extra-8216:\n    name: Extra\n    runs-on: [self-hosted, linux-fed]\n"
                                  "    steps:\n      - run: cargo test --no-run\n")
        self.assertEqual(problems_debuginfo(workflows),
                         ["yank.yml extra-8216 leg '': a cargo job with no row in EXPECTED_CARGO_DEBUG"])

    def test_a_row_that_names_no_cargo_job(self):
        workflows = real_workflows()
        workflows["yank.yml"] = workflows["yank.yml"].replace("cargo yank", "echo yank")
        self.assertEqual(problems_debuginfo(workflows),
                         ["yank.yml yank leg '': a row of EXPECTED_CARGO_DEBUG names no cargo job"])

    def test_unquoted_zero_in_a_matrix_is_refused(self):
        workflows = real_workflows()
        text = workflows[CI]
        start = text.index("          - leg: linux-fed,enterprise-fed\n")
        at = text.index("            cargo_debug: '0'\n", start)
        workflows[CI] = text[:at] + "            cargo_debug: 0\n" + text[at + len("            cargo_debug: '0'\n"):]
        got = problems_debuginfo(workflows)
        self.assertIn("ci.yml check leg 'linux-fed,enterprise-fed': CARGO_PROFILE_DEV_DEBUG: matrix.cargo_debug = 0 "
                      "is not a quoted string, so `||` may take the literal", got)

    def test_unit_step_back_in_classify(self):
        workflows = real_workflows()
        text = workflows[CI]
        i = text.index("  classify:\n")
        j = text.index("      - name: AGE self-heal helper unit test (#6161)")
        workflows[CI] = text[:j] + "      - name: Dup\n        run: " + UNIT_COMMAND + "\n" + text[j:]
        self.assertTrue(i < j)
        self.assertEqual(problems_unit_placement(workflows), [
            "ci.yml: the unit-test step must be in exactly the job build-script-vetting, found "
            "['classify', 'build-script-vetting']",
            "ci.yml: classify is a needs ancestor of check"])

    def test_unit_job_gets_a_needs_edge_to_classify(self):
        workflows = self._broken(CI, '    name: "Build-script custom-build ledger gate (#2635)"\n',
                                 '    name: "Build-script custom-build ledger gate (#2635)"\n    needs: classify\n')
        self.assertEqual(problems_unit_placement(workflows),
                         ["ci.yml build-script-vetting: the unit-test job must have no needs"])

    def test_job_renamed(self):
        workflows = self._broken(CI, '    name: "Build-script custom-build ledger gate (#2635)"\n',
                                 '    name: "Build-script vetting"\n')
        self.assertEqual(problems_job_names(workflows), [
            "ci.yml: job ids and names differ from the pinned base list: added "
            "[('build-script-vetting', 'Build-script vetting')], removed "
            "[('build-script-vetting', 'Build-script custom-build ledger gate (#2635)')]"])

    def test_job_added(self):
        workflows = real_workflows()
        workflows[CI] = workflows[CI].rstrip("\n") + "\n  extra:\n    name: Extra\n"
        self.assertEqual(problems_job_names(workflows), [
            "ci.yml: job ids and names differ from the pinned base list: added [('extra', 'Extra')], removed []"])


if __name__ == "__main__":
    unittest.main()
