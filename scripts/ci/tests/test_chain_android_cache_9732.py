# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Issue #9732: chain PRs never find a warm cache for the android leg of `mobile-cross-compile`.

Class: a chain job rebuilds from cold because its cache is neither restored nor saved on the chain.
Since #9680 the android entry of `mobile-cross-compile` builds the cargo-audit binary and the
release-profile smoke, two of the longest compiles of the workflow, under a cache that only a
trunk push writes; a pull request into a `chain/**` branch reads `chain/<name>` and then the
default branch and finds nothing there, so both build cold on every chain PR.

Invariant: for every run of that leg on the chain branch and on a pull request against it, the leg
restores the cache the chain run saved, under a key computed from the same inputs on both sides; a
pull_request run never writes a cache the chain reads. Same scheme as #9681 (copied, not invented):

* `rust-cache-warm.yml` (push on `chain/**`, hosted, sole writer) gains the job
  `mobile-android-audit-release`, which runs the exact cargo lines of the android leg.
* Both sides key by `shared-key` (the PR step resolves `matrix.target` to the literal the warm job
  spells) and carry the one `prefix-key` generation constant. A `key:` input would be suffixed with
  the job id by rust-cache, so a pair of differently named jobs could never match.
* The PR step still saves on a `push` only.

Second class (review r1, F1): an input of the cache key or of the cached output that no test reads.
The module reads the whole of every mirrored step and of every job-level input against a hand table
(`MIRRORS`, `JOB_KEYS_MAY_DIFFER`, `ENV_ONE_SIDED`): any added, removed or changed key or value on
either side is a failure unless the table names that key for that step as allowed to differ, and a
step key, a job key or a step the table does not know is a failure naming workflow, job, step and
key. No key is skipped by default. Fixture tests feed `mirror_problems` mutated copies of the two
workflow texts (the reviewer's R1 and R2 and one per key and side) and assert the exact text.

Run: python3 -I -m unittest discover -s scripts/ci/tests -p 'test_chain_android_cache_9732.py'
"""

from __future__ import annotations

import re
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_rust_cache_save_scope_9681 as base  # noqa: E402

PR_NAME, PR_JOB_ID, LEG_ID = next(iter(base.LEG_PAIRS))
WARM_JOB_ID, SHARED_KEY = base.LEG_PAIRS[(PR_NAME, PR_JOB_ID, LEG_ID)]
TEMPLATE = base.LEG_SHARED_KEY_TEMPLATES[(PR_NAME, PR_JOB_ID)]
TOOLCHAIN_ACTION = "dtolnay/rust-toolchain"
NDK_STEPS = ("Install Android NDK r26d", "Configure NDK toolchain for cargo")
# Written by hand from the android leg (independent of the reader): the cargo lines rust-cache keeps.
EXPECTED_COMMANDS = (
    "cargo build --release",
    "cargo check --target aarch64-linux-android --no-default-features --features "
    "sqlite-bundled --lib",
    "cargo install cargo-audit --locked --force --version 0.22.2",
)
CACHE_KEY_INPUTS_FORBIDDEN = ("key", "add-job-id-key", "add-rust-environment-hash-key", "env-vars",
                              "workspaces")


def _android_leg() -> tuple[base.Workflow, base.Job, dict[str, object]]:
    wf = base.Workflow.load(PR_NAME)
    job = wf.jobs()[PR_JOB_ID]
    legs = [leg for leg in base._hosted_legs(job) if base._leg_id(leg) == LEG_ID]
    if len(legs) != 1:
        raise AssertionError(f"{PR_NAME}:{PR_JOB_ID}: expected one hosted leg {LEG_ID}, found "
                             f"{len(legs)}")
    return wf, job, legs[0]


def _warm_job() -> tuple[base.Workflow, base.Job]:
    wf = base.Workflow.load(base.WARM)
    jobs = wf.jobs()
    if WARM_JOB_ID not in jobs:
        raise AssertionError(f"{base.WARM}: no job {WARM_JOB_ID!r}; the android leg has no chain "
                             f"cache writer (#9732)")
    return wf, jobs[WARM_JOB_ID]


def _by_label(job: base.Job, label: str) -> base.Step:
    found = [s for s in job.steps() if s.label() == label]
    if len(found) != 1:
        raise AssertionError(f"{job.job_id}: expected one step {label!r}, found {len(found)}")
    return found[0]


def _expanded(step: base.Step, key: str, leg: dict[str, object]) -> dict[str, str]:
    return {k: base._expand_matrix(v, leg) for k, v in step.mapping(key).items()}


# --- fix-begin ---
# The whole-step and whole-job comparison (review r1 F1). Written by hand from the two workflows,
# never derived from the text under test.
KNOWN_STEP_KEYS = ("uses", "with", "env", "run", "if", "shell", "working-directory", "id", "name",
                   "continue-on-error", "timeout-minutes")
# Job-level keys that must be equal on both sides (`runs-on` and `env` are read by their own rule).
JOB_KEYS_COMPARED = ("defaults", "container", "services", "permissions", "if", "concurrency",
                     "outputs", "environment", "continue-on-error")
# Job-level keys that may differ: the warm job is a different job with its own name, no `needs`,
# its own cap, no matrix and its own step list (the steps are read step by step below).
JOB_KEYS_MAY_DIFFER = ("name", "needs", "timeout-minutes", "strategy", "steps")
JOB_KEYS_KNOWN = ("runs-on", "env", *JOB_KEYS_COMPARED, *JOB_KEYS_MAY_DIFFER)
# Workflow-level keys compared the same way (`env` is read with the job-level env).
WORKFLOW_KEYS_COMPARED = ("defaults",)
# An env name one workflow carries and the other does not, by workflow. The cap only sizes the
# self-hosted runner target directory; the hosted android leg and the warm job never read it.
ENV_ONE_SIDED = {PR_NAME: ("SELF_HOSTED_TARGET_CAP_BYTES",), base.WARM: ()}

SKIP_GATE = "needs.classify.outputs.cargo_skip != 'true'"
CACHE_GATE = "steps.rust-cache.outputs.cache-hit != 'true'"
ONCE_GATE = f"{SKIP_GATE} && matrix.once"
NDK_GATE = f"{SKIP_GATE} && matrix.target == 'aarch64-linux-android'"
CARGO_CHECK_STEP = "cargo check (--lib --features sqlite-bundled)"
AUDIT_PR_STEP = "Security audit"
AUDIT_WARM_STEP = "Install the pinned cargo-audit (no audit run)"
AUDIT_WARM_RUN = 'cargo install cargo-audit --locked --force --version "${CARGO_AUDIT_VERSION}"'
BUILD_PR_STEP = "Build release (once leg — release-profile smoke)"
BUILD_WARM_STEP = "Build release (release-profile smoke)"
CACHE_WARM_NAME = "Rust cache (write the key the PR job restores)"
ANY = object()  # in a row: the value on that side is read by another test, not pinned here


@dataclass(frozen=True)
class Row:
    """One mirrored step: its identity on each side and the keys allowed to differ, each with the
    value the hand table expects on the PR side and on the warm side (None = key absent)."""

    pr_id: str
    warm_id: str
    allowed: dict[str, tuple[object, object]]


MIRRORS = (
    Row("actions/checkout", "actions/checkout", {}),
    Row(TOOLCHAIN_ACTION, TOOLCHAIN_ACTION, {"if": (SKIP_GATE, None)}),
    Row(base.RUST_CACHE, base.RUST_CACHE,
        {"if": (SKIP_GATE, None), "name": (None, CACHE_WARM_NAME), "id": (None, "rust-cache")}),
    Row("nttld/setup-ndk", "nttld/setup-ndk", {"if": (NDK_GATE, CACHE_GATE)}),
    Row(NDK_STEPS[1], NDK_STEPS[1], {"if": (NDK_GATE, CACHE_GATE)}),
    Row(CARGO_CHECK_STEP, CARGO_CHECK_STEP, {"if": (SKIP_GATE, CACHE_GATE)}),
    Row("actions/setup-python", "actions/setup-python", {"if": (ONCE_GATE, CACHE_GATE)}),
    Row(AUDIT_PR_STEP, AUDIT_WARM_STEP,
        {"name": (AUDIT_PR_STEP, AUDIT_WARM_STEP), "if": (ONCE_GATE, CACHE_GATE),
         "run": (ANY, AUDIT_WARM_RUN)}),
    Row(BUILD_PR_STEP, BUILD_WARM_STEP,
        {"name": (BUILD_PR_STEP, BUILD_WARM_STEP), "if": (ONCE_GATE, CACHE_GATE)}),
)
# Steps of the PR job that have no warm counterpart (they run no cargo and write no cache input).
PR_ONLY_STEPS = ("cargo_skip short-circuit",)

# Literal 40-hex pins of every mirrored action (review r2 F7). Written by hand: a swap of the sha on
# both sides at once, or a tag form, passes a side-to-side compare and fails this table.
PINNED_USES = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    TOOLCHAIN_ACTION: "4360b52568e2003a75bf9bc1d59f33a8e3fc893c",
    base.RUST_CACHE: "6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
    "nttld/setup-ndk": "ed92fe6cadad69be94a966a7ee3271275e62f779",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
}
# `with` inputs of a mirrored action pinned to one value on both sides (review r2 F2).
PINNED_WITH = {("actions/setup-python", "python-version"): "3.12"}
# Job-level env names pinned to one value on both sides: a job env enters the rust-cache key hash
# and a step env does not, so the build-input version lives here (review r2 F4).
JOB_ENV_PINNED = {"CARGO_AUDIT_VERSION": "0.22.2"}
# The NDK version the cache holds and the prefix-key generation that goes with it: bump both
# together, or the warm cache of the old NDK is restored for the new one (review r2 F4).
NDK_GENERATION = (("r26d", "chain-cache-g1"),)
# The contexts a `${{ }}` of a mirrored step may read (comment lines included); anything else, and
# any expression the scan cannot read to its end, is a failure (review r2 F6).
EXPRESSION_ALLOWED = tuple(re.compile(pattern) for pattern in (
    r"matrix\.[A-Za-z0-9_-]+",
    r"steps\.setup-ndk\.outputs\.[A-Za-z0-9_-]+",
    r"needs\.classify\.outputs\.[A-Za-z0-9_-]+",
    r"github\.event_name == 'push'",
))
EXPRESSION_OPEN = "${{"
EXPRESSION_CLOSE = "}}"


def _relative(lines: list[str], indent: int) -> str:
    """The non-comment lines of a block with `indent` columns removed (relative indent kept)."""
    out = []
    for line in lines:
        if base._is_comment_or_blank(line):
            continue
        out.append(line.rstrip()[indent:] if base._indent(line) >= indent else line.strip())
    return "\n".join(out)


def _step_id(step: base.Step) -> str:
    return step.uses_name() or step.label()


def _run_text(step: base.Step) -> str | None:
    """The `run:` text with every comment kept: a block's comment lines, and the text of a
    single-line `run:` up to the end of the line (the parser drops a trailing ` #` comment)."""
    if "run" not in step.blocks:
        return None
    if "run" not in step.keys:
        return step.run()
    for index, line in enumerate(step.lines):
        text = (" " * base.KEY_INDENT + line.strip()[2:]) if index == 0 else line
        if base._indent(text) == base.KEY_INDENT and text.strip().startswith("run:"):
            return text.strip()[len("run:"):].strip()
    raise AssertionError(f"step {step.label()!r}: its single-line run is not on a step line")


def _step_value(step: base.Step, key: str, leg: dict[str, object]) -> str | None:
    """The whole value of one step key (None when absent); the PR side expands `matrix.<name>`."""
    if key == "run":
        value = _run_text(step)
    elif key in step.keys:
        value = step.keys[key]
    elif key in step.blocks:
        value = _relative(step.blocks[key], base.KEY_INDENT + 2)
    else:
        return None
    return None if value is None else base._expand_matrix(value, leg)


def _identities(wf: base.Workflow, job: base.Job,
                problems: list[str]) -> tuple[dict[str, base.Step], set[str]]:
    groups: dict[str, list[base.Step]] = {}
    for step in job.steps():
        groups.setdefault(_step_id(step), []).append(step)
    found: dict[str, base.Step] = {}
    duplicated: set[str] = set()
    for ident, group in groups.items():
        if len(group) > 1:
            duplicated.add(ident)
            problems.append(f"{wf.name}:{job.job_id}: step {ident!r} appears {len(group)} times")
        else:
            found[ident] = group[0]
    return found, duplicated


def _order_problems(wf: base.Workflow, job: base.Job, steps: dict[str, base.Step],
                    duplicated: set[str], ids: list[str]) -> list[str]:
    """The mirrored steps run in the order of the hand table (every row present once)."""
    want = [ident for ident in ids if ident in steps]
    got = [_step_id(step) for step in job.steps()
           if _step_id(step) in want and _step_id(step) not in duplicated]
    if got == want:
        return []
    return [f"{wf.name}:{job.job_id}: mirrored steps run in the order {got!r}, the hand table "
            f"says {want!r}"]


def _expression_problems(wf: base.Workflow, job: base.Job, ident: str,
                         step: base.Step) -> list[str]:
    """Every `${{ }}` on every line of a mirrored step, comment lines included, reads an allowed
    context; an expression the scan cannot read to its end is a failure, never a pass."""
    problems: list[str] = []
    for raw in step.lines:
        if EXPRESSION_OPEN not in raw:
            continue
        line, at = raw.strip(), 0
        while (start := raw.find(EXPRESSION_OPEN, at)) != -1:
            end = raw.find(EXPRESSION_CLOSE, start + len(EXPRESSION_OPEN))
            if end == -1:
                problems.append(f"{wf.name}:{job.job_id} step {ident!r}: line {line!r} holds an "
                                f"expression the scan cannot classify")
                break
            body = raw[start + len(EXPRESSION_OPEN):end].strip()
            if not any(allowed.fullmatch(body) for allowed in EXPRESSION_ALLOWED):
                problems.append(f"{wf.name}:{job.job_id} step {ident!r}: line {line!r} holds the "
                                f"expression {body!r}, outside the allowlist")
            at = end + len(EXPRESSION_CLOSE)
    return problems


def _row_pin_problems(row: Row, pr_wf: base.Workflow, pr_job: base.Job, pr_step: base.Step,
                      warm_wf: base.Workflow, warm_job: base.Job, warm_step: base.Step,
                      leg: dict[str, object]) -> list[str]:
    """The literal pins of one mirrored step on each side: its action sha, its pinned `with`
    inputs, a step env on both sides, and every expression of every line."""
    problems: list[str] = []
    for wf, job, ident, step, scope in ((pr_wf, pr_job, row.pr_id, pr_step, leg),
                                        (warm_wf, warm_job, row.warm_id, warm_step, {})):
        action = step.uses_name()
        if action in PINNED_USES:
            expected = f"{action}@{PINNED_USES[action]}"
            actual = step.keys.get("uses")
            if actual != expected:
                problems.append(f"{wf.name}:{job.job_id} step {ident!r}: uses is {actual!r}, the "
                                f"pinned form is {expected!r}")
        for (pinned_action, key), expected_value in PINNED_WITH.items():
            if action == pinned_action:
                actual_value = _expanded(step, "with", scope).get(key)
                if actual_value != expected_value:
                    problems.append(f"{wf.name}:{job.job_id} step {ident!r}: with {key!r} is "
                                    f"{actual_value!r}, the pinned value is {expected_value!r}")
    pr_env = _step_value(pr_step, "env", leg)
    if (pr_env is not None and pr_env == _step_value(warm_step, "env", {})
            and "env" not in row.allowed):
        for wf, job, ident in ((pr_wf, pr_job, row.pr_id), (warm_wf, warm_job, row.warm_id)):
            problems.append(f"{wf.name}:{job.job_id} step {ident!r}: step env {pr_env!r} is on "
                            f"both sides but the hand table names none (a step env is outside the "
                            f"rust-cache key)")
    for wf, job, ident, step in ((pr_wf, pr_job, row.pr_id, pr_step),
                                 (warm_wf, warm_job, row.warm_id, warm_step)):
        problems.extend(_expression_problems(wf, job, ident, step))
    return problems


def _generation_problems(wf: base.Workflow, job: base.Job) -> list[str]:
    """The setup-ndk `ndk-version` and the rust-cache `prefix-key` of one side form a table pair."""
    ndk = next((s.mapping("with").get("ndk-version") for s in job.steps()
                if s.uses_name() == "nttld/setup-ndk"), None)
    generation = next((s.mapping("with").get("prefix-key") for s in job.steps()
                       if s.uses_name() == base.RUST_CACHE), None)
    if (ndk, generation) in NDK_GENERATION:
        return []
    want_ndk, want_generation = NDK_GENERATION[0]
    return [f"{wf.name}:{job.job_id}: NDK {ndk!r} is cached under generation {generation!r}; the "
            f"hand table pairs {want_ndk!r} with {want_generation!r}"]


def _step_problems(pr_wf: base.Workflow, pr_job: base.Job, warm_wf: base.Workflow,
                   warm_job: base.Job, leg: dict[str, object]) -> list[str]:
    problems: list[str] = []
    pr_steps, pr_dup = _identities(pr_wf, pr_job, problems)
    warm_steps, warm_dup = _identities(warm_wf, warm_job, problems)
    for row in MIRRORS:
        missing = False
        for wf, job, ident, steps, dup in ((pr_wf, pr_job, row.pr_id, pr_steps, pr_dup),
                                           (warm_wf, warm_job, row.warm_id, warm_steps, warm_dup)):
            if ident not in steps and ident not in dup:
                problems.append(f"{wf.name}:{job.job_id}: no step {ident!r} (the mirror table "
                                f"needs it)")
                missing = True
        if missing or row.pr_id not in pr_steps or row.warm_id not in warm_steps:
            continue
        pr_step, warm_step = pr_steps[row.pr_id], warm_steps[row.warm_id]
        for wf, job, ident, step in ((pr_wf, pr_job, row.pr_id, pr_step),
                                     (warm_wf, warm_job, row.warm_id, warm_step)):
            for key in dict.fromkeys([*step.blocks, *step.keys]):
                if key not in KNOWN_STEP_KEYS:
                    problems.append(f"{wf.name}:{job.job_id} step {ident!r}: step key {key!r} is "
                                    f"not a known step key")
        for key in KNOWN_STEP_KEYS:
            pr_val = _step_value(pr_step, key, leg)
            warm_val = _step_value(warm_step, key, {})
            if key in row.allowed:
                for wf, job, ident, actual, expected in (
                        (pr_wf, pr_job, row.pr_id, pr_val, row.allowed[key][0]),
                        (warm_wf, warm_job, row.warm_id, warm_val, row.allowed[key][1])):
                    if expected is not ANY and actual != expected:
                        problems.append(f"{wf.name}:{job.job_id} step {ident!r}: key {key!r} is "
                                        f"{actual!r}, the hand table says {expected!r}")
            elif pr_val != warm_val:
                problems.append(f"{pr_wf.name}:{pr_job.job_id} step {row.pr_id!r} vs "
                                f"{warm_wf.name}:{warm_job.job_id} step {row.warm_id!r}: key "
                                f"{key!r} differs: {pr_wf.name} has {pr_val!r}, {warm_wf.name} "
                                f"has {warm_val!r}")
        problems.extend(_row_pin_problems(row, pr_wf, pr_job, pr_step, warm_wf, warm_job,
                                          warm_step, leg))
    for wf, job, dup, ids, steps in ((pr_wf, pr_job, pr_dup, [r.pr_id for r in MIRRORS], pr_steps),
                                     (warm_wf, warm_job, warm_dup, [r.warm_id for r in MIRRORS],
                                      warm_steps)):
        problems.extend(_order_problems(wf, job, steps, dup, ids))
    mirrored_pr = {row.pr_id for row in MIRRORS} | set(PR_ONLY_STEPS)
    mirrored_warm = {row.warm_id for row in MIRRORS}
    for wf, job, steps, known in ((pr_wf, pr_job, pr_steps, mirrored_pr),
                                   (warm_wf, warm_job, warm_steps, mirrored_warm)):
        for ident in steps:
            if ident not in known:
                problems.append(f"{wf.name}:{job.job_id} step {ident!r}: no row in the mirror "
                                f"table")
    return problems


def _job_keys(job: base.Job) -> list[str]:
    keys = (line.strip().partition(":")[0] for line in job.lines
            if base._indent(line) == 4 and not base._is_comment_or_blank(line))
    return list(dict.fromkeys(keys))


def _job_value(job: base.Job, key: str, leg: dict[str, object]) -> str | None:
    if key not in _job_keys(job):
        return None
    return base._expand_matrix(_relative(job.block(key), 6), leg)


def _runner(wf: base.Workflow, job: base.Job, leg: dict[str, object],
            problems: list[str]) -> str | None:
    try:
        return base._runs_on(job, leg)
    except AssertionError as exc:
        problems.append(f"{wf.name}:{job.job_id}: runs-on cannot be read: {exc}")
        return None


def _resolved_env(wf: base.Workflow, job: base.Job, leg: dict[str, object],
                  problems: list[str]) -> tuple[dict[str, str], set[str]]:
    env: dict[str, str] = {}
    failed: set[str] = set()
    for name, raw in {**wf.env(), **job.env()}.items():
        try:
            env[name] = base._effective_env_value(name, raw, leg)
        except AssertionError as exc:
            failed.add(name)
            problems.append(f"{wf.name}:{job.job_id}: env {name!r} cannot be evaluated: {exc}")
    return env, failed


def _job_problems(pr_wf: base.Workflow, pr_job: base.Job, warm_wf: base.Workflow,
                  warm_job: base.Job, leg: dict[str, object]) -> list[str]:
    problems: list[str] = []
    where = f"{pr_wf.name}:{pr_job.job_id} vs {warm_wf.name}:{warm_job.job_id}"
    for wf, job in ((pr_wf, pr_job), (warm_wf, warm_job)):
        for key in _job_keys(job):
            if key not in JOB_KEYS_KNOWN:
                problems.append(f"{wf.name}:{job.job_id}: job key {key!r} is not a known job key")
    pr_runner = _runner(pr_wf, pr_job, leg, problems)
    warm_runner = _runner(warm_wf, warm_job, {}, problems)
    pairs = [("runs-on", pr_runner, warm_runner)] if pr_runner and warm_runner else []
    for key in JOB_KEYS_COMPARED:
        pairs.append((key, _job_value(pr_job, key, leg), _job_value(warm_job, key, {})))
    for key, pr_val, warm_val in pairs:
        if pr_val != warm_val:
            problems.append(f"{where}: job key {key!r} differs: {pr_wf.name} has {pr_val!r}, "
                            f"{warm_wf.name} has {warm_val!r}")
    pr_env, pr_failed = _resolved_env(pr_wf, pr_job, leg, problems)
    warm_env, warm_failed = _resolved_env(warm_wf, warm_job, {}, problems)
    pr_free = ENV_ONE_SIDED.get(pr_wf.name, ())
    warm_free = ENV_ONE_SIDED.get(warm_wf.name, ())
    for name in sorted({*pr_env, *warm_env} - pr_failed - warm_failed):
        if name in pr_env and name not in warm_env and name in pr_free:
            continue
        if name in warm_env and name not in pr_env and name in warm_free:
            continue
        if pr_env.get(name) != warm_env.get(name):
            problems.append(f"{where}: env {name!r} differs: {pr_wf.name} has "
                            f"{pr_env.get(name)!r}, {warm_wf.name} has {warm_env.get(name)!r}")
    for wf, job, env, failed in ((pr_wf, pr_job, pr_env, pr_failed),
                                 (warm_wf, warm_job, warm_env, warm_failed)):
        for name, expected in JOB_ENV_PINNED.items():
            if name not in failed and env.get(name) != expected:
                problems.append(f"{wf.name}:{job.job_id}: job env {name!r} is {env.get(name)!r}, "
                                f"the pinned value is {expected!r}")
        problems.extend(_generation_problems(wf, job))
    for key in WORKFLOW_KEYS_COMPARED:
        pr_val = _relative(pr_wf.top(key), 2) or None
        warm_val = _relative(warm_wf.top(key), 2) or None
        if pr_val != warm_val:
            problems.append(f"{pr_wf.name} vs {warm_wf.name}: workflow key {key!r} differs: "
                            f"{pr_wf.name} has {pr_val!r}, {warm_wf.name} has {warm_val!r}")
    return problems


def mirror_problems(pr_wf: base.Workflow, pr_job: base.Job, warm_wf: base.Workflow,
                    warm_job: base.Job, leg: dict[str, object]) -> list[str]:
    """Every difference between the android leg and its warm job that the hand table does not
    allow: step by step (every key), then the job-level keys, `runs-on` and the merged `env`."""
    return (_step_problems(pr_wf, pr_job, warm_wf, warm_job, leg)
            + _job_problems(pr_wf, pr_job, warm_wf, warm_job, leg))
# --- fix-end ---


# --- fixtures: mutated copies of the two workflow texts ---------------------------------------
# An op is ("after", anchor, [lines]) | ("sub", old, new) | ("replace_at", anchor, offset, old,
# new) | ("end", [lines]). An anchor must match exactly one line, or the fixture itself fails.

OLD_CHECKOUT_PIN = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
NEW_CHECKOUT_PIN = "actions/checkout@0000000000000000000000000000000000000000"
CHECKOUT_ID = "actions/checkout"
CACHE_ID = "Swatinem/rust-cache"
GATE_SKIP = "needs.classify.outputs.cargo_skip != 'true'"
BUILD_PR_LABEL = "Build release (once leg — release-profile smoke)"
BUILD_WARM_LABEL = "Build release (release-profile smoke)"
ENV_STEP = ["        env:", "          FOO: bar"]
SIDES = ("pr", "warm")


def _step_span(lines: list[str], anchor: str) -> tuple[int, int]:
    """The line span of the one step whose `- ` line holds `anchor` (it ends at the next step)."""
    starts = [i for i, line in enumerate(lines)
              if anchor in line and base._indent(line) == base.STEP_INDENT
              and line.lstrip().startswith("- ")]
    if len(starts) != 1:
        raise AssertionError(f"fixture step anchor {anchor!r} matched {len(starts)} steps")
    end = next((i for i in range(starts[0] + 1, len(lines))
                if base._indent(lines[i]) == base.STEP_INDENT and lines[i].lstrip().startswith("- ")),
               len(lines))
    return starts[0], end


def _apply(lines: list[str], ops: tuple[tuple, ...]) -> list[str]:
    out = list(lines)
    for op in ops:
        if op[0] == "end":
            out.extend(op[1])
            continue
        if op[0] == "move_before":
            # ("move_before", moved step anchor, step anchor it moves in front of)
            start, end = _step_span(out, op[1])
            moved = out[start:end]
            del out[start:end]
            target, _ = _step_span(out, op[2])
            out[target:target] = moved
            continue
        anchor = op[1]
        hits = [i for i, line in enumerate(out) if anchor in line]
        if len(hits) != 1:
            raise AssertionError(f"fixture anchor {anchor!r} matched {len(hits)} lines")
        at = hits[0]
        if op[0] == "after":
            out[at + 1:at + 1] = op[2]
        elif op[0] == "sub":
            out[at] = out[at].replace(anchor, op[2])
        elif op[0] == "replace_at":
            _, _, offset, old, new = op
            if old not in out[at + offset]:
                raise AssertionError(f"fixture text {old!r} is not on line {at + offset}")
            out[at + offset] = out[at + offset].replace(old, new)
        else:
            raise AssertionError(f"unknown fixture op {op[0]!r}")
    return out


def _problems(pr_wf_ops: tuple = (), warm_wf_ops: tuple = (), pr_job_ops: tuple = (),
              warm_job_ops: tuple = ()) -> list[str]:
    pr_wf, pr_job, leg = _android_leg()
    warm_wf, warm_job = _warm_job()
    if pr_wf_ops:
        pr_wf = base.Workflow(pr_wf.name, _apply(pr_wf.lines, pr_wf_ops))
        pr_job = pr_wf.jobs()[PR_JOB_ID]
    if warm_wf_ops:
        warm_wf = base.Workflow(warm_wf.name, _apply(warm_wf.lines, warm_wf_ops))
        warm_job = warm_wf.jobs()[WARM_JOB_ID]
    if pr_job_ops:
        pr_job = base.Job(pr_job.job_id, _apply(pr_job.lines, pr_job_ops))
    if warm_job_ops:
        warm_job = base.Job(warm_job.job_id, _apply(warm_job.lines, warm_job_ops))
    return mirror_problems(pr_wf, pr_job, warm_wf, warm_job, leg)


def _on_side(side: str, ops: tuple) -> list[str]:
    """The problems when `ops` edit the job of one side (the other side stays as it is)."""
    return _problems(pr_job_ops=ops) if side == "pr" else _problems(warm_job_ops=ops)


def _step_diff(pr_id: str, warm_id: str, key: str, pr_val: object, warm_val: object) -> str:
    return (f"{PR_NAME}:{PR_JOB_ID} step {pr_id!r} vs {base.WARM}:{WARM_JOB_ID} step "
            f"{warm_id!r}: key {key!r} differs: {PR_NAME} has {pr_val!r}, {base.WARM} has "
            f"{warm_val!r}")


def _job_diff(key: str, pr_val: object, warm_val: object) -> str:
    return (f"{PR_NAME}:{PR_JOB_ID} vs {base.WARM}:{WARM_JOB_ID}: job key {key!r} differs: "
            f"{PR_NAME} has {pr_val!r}, {base.WARM} has {warm_val!r}")


def _env_diff(name: str, pr_val: object, warm_val: object) -> str:
    return (f"{PR_NAME}:{PR_JOB_ID} vs {base.WARM}:{WARM_JOB_ID}: env {name!r} differs: "
            f"{PR_NAME} has {pr_val!r}, {base.WARM} has {warm_val!r}")


def _real_problems() -> list[str]:
    pr_wf, pr_job, leg = _android_leg()
    warm_wf, warm_job = _warm_job()
    return mirror_problems(pr_wf, pr_job, warm_wf, warm_job, leg)


class ChainAndroidCache9732(unittest.TestCase):
    """#9732: the android leg restores what a chain push saved, under the same key."""

    def test_the_leg_pair_names_a_real_hosted_leg(self) -> None:
        wf, job, leg = _android_leg()
        self.assertEqual(base._runs_on(job, leg), "ubuntu-latest")
        self.assertIs(leg.get("once"), True)
        self.assertIn(PR_NAME, base.KEY_HOLDERS)

    def test_pr_cache_step_keys_by_shared_key_and_saves_on_push_only(self) -> None:
        wf, job, leg = _android_leg()
        steps = job.steps()
        inputs = steps[base._cache_index(steps)].mapping("with")
        self.assertEqual(inputs.get("shared-key"), TEMPLATE,
                         f"{PR_NAME}:{PR_JOB_ID}: the cache step must key by `shared-key` "
                         f"(rust-cache adds the job id to `key`, so a PR job and a warm job of "
                         f"another name never share it)")
        for absent in CACHE_KEY_INPUTS_FORBIDDEN:
            self.assertNotIn(absent, inputs)
        self.assertEqual(inputs.get("save-if"), base.SAVE_IF_PUSH)
        self.assertRegex(inputs.get("prefix-key", ""), base.PREFIX_KEY_RE)
        self.assertEqual(base._expand_matrix(inputs["shared-key"], leg), SHARED_KEY)

    def test_warm_cache_step_writes_the_key_the_pr_leg_restores(self) -> None:
        _, pr_job, leg = _android_leg()
        _, warm_job = _warm_job()
        pr_steps, warm_steps = pr_job.steps(), warm_job.steps()
        pr_step = pr_steps[base._cache_index(pr_steps)]
        warm_step = warm_steps[base._cache_index(warm_steps)]
        warm_inputs = warm_step.mapping("with")
        self.assertEqual(warm_step.keys.get("id"), "rust-cache")
        self.assertEqual(warm_inputs.get("shared-key"), SHARED_KEY)
        for absent in CACHE_KEY_INPUTS_FORBIDDEN:
            self.assertNotIn(absent, warm_inputs)
        self.assertEqual(warm_inputs.get("save-if"), base.SAVE_IF_PUSH)
        self.assertEqual(warm_inputs.get("prefix-key"), pr_step.mapping("with").get("prefix-key"))
        self.assertEqual(warm_step.keys.get("uses"), pr_step.keys.get("uses"))

    def test_warm_job_runs_on_the_runner_of_the_pr_leg(self) -> None:
        _, job, leg = _android_leg()
        _, warm_job = _warm_job()
        self.assertEqual(warm_job.scalar("runs-on"), base._runs_on(job, leg))
        self.assertIsNone(warm_job.scalar("if"))
        self.assertIsNone(warm_job.scalar("needs"))

    def test_key_env_is_equal_on_both_sides_and_nothing_exports_before_the_cache(self) -> None:
        pr_wf, pr_job, leg = _android_leg()
        warm_wf, warm_job = _warm_job()
        pr_env = base._effective_key_env({**pr_wf.env(), **pr_job.env()}, leg)
        warm_env = base._effective_key_env({**warm_wf.env(), **warm_job.env()}, {})
        self.assertEqual(warm_env, pr_env)
        self.assertEqual(pr_env.get("CARGO_INCREMENTAL"), "0")
        for job in (pr_job, warm_job):
            steps = job.steps()
            before = [s.label() for s in steps[:base._cache_index(steps)]
                      if "GITHUB_ENV" in s.run() or "GITHUB_PATH" in s.run()]
            self.assertEqual(before, [], f"{job.job_id}: a step before the cache exports env")

    def test_toolchain_step_is_mirrored(self) -> None:
        _, pr_job, leg = _android_leg()
        _, warm_job = _warm_job()
        pr_step = next(s for s in pr_job.steps() if s.uses_name() == TOOLCHAIN_ACTION)
        warm_steps = [s for s in warm_job.steps() if s.uses_name() == TOOLCHAIN_ACTION]
        self.assertEqual(len(warm_steps), 1)
        self.assertEqual(warm_steps[0].keys.get("uses"), pr_step.keys.get("uses"))
        self.assertEqual(warm_steps[0].mapping("with"), _expanded(pr_step, "with", leg))
        steps = warm_job.steps()
        self.assertLess(steps.index(warm_steps[0]), base._cache_index(steps))

    def test_ndk_steps_are_mirrored_after_the_cache_and_before_cargo(self) -> None:
        _, pr_job, leg = _android_leg()
        _, warm_job = _warm_job()
        steps = warm_job.steps()
        cache = base._cache_index(steps)
        gate = "steps.rust-cache.outputs.cache-hit != 'true'"
        last = cache
        for label in NDK_STEPS:
            pr_step, warm_step = _by_label(pr_job, label), _by_label(warm_job, label)
            with self.subTest(step=label):
                for key in ("uses", "id", "shell"):
                    self.assertEqual(warm_step.keys.get(key), pr_step.keys.get(key), key)
                self.assertEqual(warm_step.mapping("with"), pr_step.mapping("with"))
                self.assertEqual(warm_step.run(), pr_step.run())
                self.assertEqual(warm_step.keys.get("if"), gate)
                self.assertGreater(steps.index(warm_step), last)
                last = steps.index(warm_step)
        for index, step in enumerate(steps):
            if base._cargo_commands(step.run()):
                self.assertGreater(index, last, f"{step.label()}: cargo before the NDK steps")

    def test_warm_job_runs_exactly_the_cargo_commands_of_the_android_leg(self) -> None:
        pr_wf, pr_job, leg = _android_leg()
        cold, cold_problems = base._cold_commands(pr_wf, pr_job, leg)
        warm, warm_problems = base._warm_commands(WARM_JOB_ID)
        self.assertEqual(cold_problems, [])
        self.assertEqual(warm_problems, [])
        self.assertEqual(cold, EXPECTED_COMMANDS)
        self.assertEqual(len(warm), len(set(warm)), warm)
        self.assertEqual(sorted(set(cold) - set(warm)), [], "only in the PR leg")
        self.assertEqual(sorted(set(warm) - set(cold)), [], "only in the warm job")

    def test_the_other_leg_of_the_job_is_untouched(self) -> None:
        wf, job, _ = _android_leg()
        ios = [leg for leg in base._hosted_legs(job) if base._leg_id(leg) != LEG_ID]
        self.assertEqual([base._leg_id(leg) for leg in ios], ["target=aarch64-apple-ios"])
        self.assertIn((PR_NAME, PR_JOB_ID, "target=aarch64-apple-ios"),
                      base.UNPAIRED_RUST_CACHE_SITES)
        self.assertNotIn((PR_NAME, PR_JOB_ID, LEG_ID), base.UNPAIRED_RUST_CACHE_SITES)


class MirrorInputs9732(unittest.TestCase):
    """Review r1 F1: every input of the cache key and of the cached output is read, both sides."""

    def test_the_real_workflows_have_no_mirror_problem(self) -> None:
        self.assertEqual(_real_problems(), [])

    def test_r1_a_step_env_on_the_pr_cache_step_is_refused(self) -> None:
        ops = (("after", "uses: Swatinem/rust-cache@", ENV_STEP),)
        self.assertEqual(_problems(pr_job_ops=ops),
                         [_step_diff(CACHE_ID, CACHE_ID, "env", "FOO: bar", None)])

    def test_r2_a_step_env_on_the_warm_build_release_step_is_refused(self) -> None:
        ops = (("after", "name: Build release", ENV_STEP),)
        self.assertEqual(_problems(warm_job_ops=ops),
                         [_step_diff(BUILD_PR_LABEL, BUILD_WARM_LABEL, "env", None, "FOO: bar")])

    def test_a_step_env_on_the_other_side_of_each_pair_is_refused(self) -> None:
        for side, anchor, pr_id, warm_id, pr_val, warm_val in (
                ("warm", "uses: Swatinem/rust-cache@", CACHE_ID, CACHE_ID, None, "FOO: bar"),
                ("pr", "name: Build release", BUILD_PR_LABEL, BUILD_WARM_LABEL, "FOO: bar", None)):
            with self.subTest(side=side, anchor=anchor):
                self.assertEqual(_on_side(side, (("after", anchor, ENV_STEP),)),
                                 [_step_diff(pr_id, warm_id, "env", pr_val, warm_val)])

    def test_every_step_key_added_to_either_side_is_refused(self) -> None:
        added = (("if", ["        if: always()"], "always()"),
                 ("shell", ["        shell: bash"], "bash"),
                 ("working-directory", ["        working-directory: sub"], "sub"),
                 ("env", ENV_STEP, "FOO: bar"),
                 ("run", ["        run: echo hi"], "echo hi"),
                 ("id", ["        id: extra"], "extra"),
                 ("name", ["        name: Extra"], "Extra"),
                 ("continue-on-error", ["        continue-on-error: true"], "true"),
                 ("timeout-minutes", ["        timeout-minutes: 5"], "5"))
        for key, lines, value in added:
            for side in SIDES:
                with self.subTest(key=key, side=side):
                    got = _on_side(side, (("after", "uses: actions/checkout@", lines),))
                    pr_val, warm_val = (value, None) if side == "pr" else (None, value)
                    self.assertEqual(got, [_step_diff(CHECKOUT_ID, CHECKOUT_ID, key, pr_val,
                                                      warm_val)])

    def test_a_step_with_block_added_to_either_side_is_refused(self) -> None:
        lines = ["        with:", "          FOO: bar"]
        for side in SIDES:
            with self.subTest(side=side):
                got = _on_side(side, (("after", "name: Build release", lines),))
                pr_val, warm_val = ("FOO: bar", None) if side == "pr" else (None, "FOO: bar")
                self.assertEqual(got, [_step_diff(BUILD_PR_LABEL, BUILD_WARM_LABEL, "with",
                                                  pr_val, warm_val)])

    def test_a_changed_uses_or_with_value_is_refused_on_either_side(self) -> None:
        for side in SIDES:
            with self.subTest(key="uses", side=side):
                got = _on_side(side, (("sub", OLD_CHECKOUT_PIN, NEW_CHECKOUT_PIN),))
                pr_val, warm_val = ((NEW_CHECKOUT_PIN, OLD_CHECKOUT_PIN) if side == "pr"
                                    else (OLD_CHECKOUT_PIN, NEW_CHECKOUT_PIN))
                # The swapped side also misses the literal sha of the pin table (review r2 F7).
                self.assertEqual(got, [_step_diff(CHECKOUT_ID, CHECKOUT_ID, "uses", pr_val,
                                                  warm_val),
                                       _pin_msg(side, CHECKOUT_ID, NEW_CHECKOUT_PIN,
                                                OLD_CHECKOUT_PIN)])
            with self.subTest(key="with", side=side):
                got = _on_side(side, (("sub", "persist-credentials: false",
                                       "persist-credentials: true"),))
                pr_val, warm_val = (("persist-credentials: true", "persist-credentials: false")
                                    if side == "pr"
                                    else ("persist-credentials: false", "persist-credentials: true"))
                self.assertEqual(got, [_step_diff(CHECKOUT_ID, CHECKOUT_ID, "with", pr_val,
                                                  warm_val)])

    def test_a_changed_run_of_the_build_release_step_is_refused_on_either_side(self) -> None:
        for side in SIDES:
            with self.subTest(side=side):
                got = _on_side(side, (("sub", "run: cargo build --release",
                                       "run: cargo build --release --locked"),))
                pr_val, warm_val = (("cargo build --release --locked", "cargo build --release")
                                    if side == "pr"
                                    else ("cargo build --release", "cargo build --release --locked"))
                self.assertEqual(got, [_step_diff(BUILD_PR_LABEL, BUILD_WARM_LABEL, "run", pr_val,
                                                  warm_val)])

    def test_a_step_key_the_table_does_not_know_is_refused_naming_it(self) -> None:
        lines = ["        frobnicate: yes"]
        for side, wf_name, job_id in (("pr", PR_NAME, PR_JOB_ID), ("warm", base.WARM, WARM_JOB_ID)):
            with self.subTest(side=side):
                self.assertEqual(
                    _on_side(side, (("after", "uses: actions/checkout@", lines),)),
                    [f"{wf_name}:{job_id} step {CHECKOUT_ID!r}: step key 'frobnicate' is not a "
                     f"known step key"])

    def test_a_step_the_table_does_not_know_a_missing_step_and_a_duplicate_are_refused(self) -> None:
        extra = ["      - name: Extra", "        run: echo hi"]
        for side, wf_name, job_id in (("pr", PR_NAME, PR_JOB_ID), ("warm", base.WARM, WARM_JOB_ID)):
            with self.subTest(case="unmapped", side=side):
                self.assertEqual(
                    _on_side(side, (("end", extra),)),
                    [f"{wf_name}:{job_id} step 'Extra': no row in the mirror table"])
        with self.subTest(case="missing"):
            got = _problems(warm_job_ops=(("sub", "name: Build release (release-profile smoke)",
                                           "name: Build release (smoke)"),))
            self.assertEqual(got, [
                f"{base.WARM}:{WARM_JOB_ID}: no step {BUILD_WARM_LABEL!r} (the mirror table "
                f"needs it)",
                f"{base.WARM}:{WARM_JOB_ID} step 'Build release (smoke)': no row in the mirror "
                f"table"])
        for side, wf_name, job_id in (("pr", PR_NAME, PR_JOB_ID), ("warm", base.WARM, WARM_JOB_ID)):
            with self.subTest(case="duplicate", side=side):
                dup = ["      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262"]
                self.assertEqual(
                    _on_side(side, (("after", "uses: actions/checkout@", dup),)),
                    [f"{wf_name}:{job_id}: step {CHECKOUT_ID!r} appears 2 times"])

    def test_the_hand_table_names_the_exact_value_of_every_allowed_difference(self) -> None:
        with self.subTest(case="warm cache id"):
            self.assertEqual(
                _problems(warm_job_ops=(("sub", "id: rust-cache", "id: rust-cache2"),)),
                [f"{base.WARM}:{WARM_JOB_ID} step {CACHE_ID!r}: key 'id' is 'rust-cache2', the "
                 f"hand table says 'rust-cache'"])
        with self.subTest(case="warm cache name"):
            self.assertEqual(
                _problems(warm_job_ops=(("sub", f"name: {CACHE_WARM_NAME}", "name: Rust cache"),)),
                [f"{base.WARM}:{WARM_JOB_ID} step {CACHE_ID!r}: key 'name' is 'Rust cache', the "
                 f"hand table says {CACHE_WARM_NAME!r}"])
        with self.subTest(case="warm toolchain gets an if"):
            self.assertEqual(
                _problems(warm_job_ops=(("after", "name: Install Rust 1.99.1",
                                         ["        if: always()"]),)),
                [f"{base.WARM}:{WARM_JOB_ID} step {TOOLCHAIN_ACTION!r}: key 'if' is "
                 f"'always()', the hand table says None"])
        with self.subTest(case="pr toolchain gate changed"):
            self.assertEqual(
                _problems(pr_job_ops=(("replace_at", "name: Install Rust 1.99.1", 1,
                                       "!= 'true'", "== 'true'"),)),
                [f"{PR_NAME}:{PR_JOB_ID} step {TOOLCHAIN_ACTION!r}: key 'if' is "
                 f"\"needs.classify.outputs.cargo_skip == 'true'\", the hand table says "
                 f"\"{GATE_SKIP}\""])
        with self.subTest(case="warm audit run changed"):
            got = _problems(warm_job_ops=(("sub", "run: cargo install cargo-audit --locked",
                                           "run: cargo install cargo-audit"),))
            self.assertEqual(len(got), 1)
            self.assertTrue(got[0].startswith(
                f"{base.WARM}:{WARM_JOB_ID} step 'Install the pinned cargo-audit (no audit run)': "
                f"key 'run' is 'cargo install cargo-audit --force"), got)

    def test_a_difference_the_table_allows_is_not_a_problem(self) -> None:
        for side, ops in (("warm timeout", ("warm", ("sub", "timeout-minutes: 45",
                                                      "timeout-minutes: 30"))),
                          ("pr timeout", ("pr", ("sub", "timeout-minutes: 45",
                                                  "timeout-minutes: 50"))),
                          ("warm name", ("warm", ("sub", "name: Rust cache warm (Cross-compile "
                                                  "android audit+release deps)",
                                                  "name: Renamed"))),
                          ("pr name", ("pr", ("sub", "name: Cross-compile (${{ matrix.target }})",
                                              "name: Renamed")))):
            with self.subTest(case=side):
                self.assertEqual(_on_side(ops[0], (ops[1],)), [])

    def test_every_job_level_input_added_to_either_side_is_refused(self) -> None:
        for key in ("defaults", "container", "services", "permissions", "if", "concurrency",
                    "outputs", "environment", "continue-on-error"):
            for side in SIDES:
                with self.subTest(key=key, side=side):
                    got = _on_side(side, (("after", "timeout-minutes: 45", [f"    {key}: v1"]),))
                    pr_val, warm_val = ("v1", None) if side == "pr" else (None, "v1")
                    self.assertEqual(got, [_job_diff(key, pr_val, warm_val)])

    def test_a_changed_runs_on_is_refused_on_either_side(self) -> None:
        self.assertEqual(
            _problems(pr_job_ops=(("sub", "runs-on: ${{ matrix.os }}", "runs-on: ubuntu-24.04"),)),
            [_job_diff("runs-on", "ubuntu-24.04", "ubuntu-latest")])
        self.assertEqual(
            _problems(warm_job_ops=(("sub", "runs-on: ubuntu-latest", "runs-on: ubuntu-24.04"),)),
            [_job_diff("runs-on", "ubuntu-latest", "ubuntu-24.04")])

    def test_an_unreadable_runs_on_is_refused_with_the_reason(self) -> None:
        got = _problems(warm_job_ops=(("sub", "runs-on: ubuntu-latest",
                                       "runs-on: ${{ github.x }}"),))
        self.assertEqual(got, [f"{base.WARM}:{WARM_JOB_ID}: runs-on cannot be read: "
                               f"{WARM_JOB_ID}: unrecognised runs-on form: '${{{{ github.x }}}}'"])

    def test_a_job_key_the_table_does_not_know_is_refused_naming_it(self) -> None:
        for side, wf_name, job_id in (("pr", PR_NAME, PR_JOB_ID), ("warm", base.WARM, WARM_JOB_ID)):
            with self.subTest(side=side):
                self.assertEqual(
                    _on_side(side, (("after", "timeout-minutes: 45", ["    frobnicate: x"]),)),
                    [f"{wf_name}:{job_id}: job key 'frobnicate' is not a known job key"])

    def test_env_is_compared_at_workflow_and_job_level_on_both_sides(self) -> None:
        with self.subTest(case="pr workflow env value changed"):
            self.assertEqual(
                _problems(pr_wf_ops=(("sub", "CARGO_TERM_COLOR: always",
                                      "CARGO_TERM_COLOR: never"),)),
                [_env_diff("CARGO_TERM_COLOR", "never", "always")])
        with self.subTest(case="warm workflow env value changed"):
            self.assertEqual(
                _problems(warm_wf_ops=(("sub", "CARGO_TERM_COLOR: always",
                                        "CARGO_TERM_COLOR: never"),)),
                [_env_diff("CARGO_TERM_COLOR", "always", "never")])
        with self.subTest(case="pr workflow CARGO_INCREMENTAL changed"):
            self.assertEqual(
                _problems(pr_wf_ops=(("sub", 'CARGO_INCREMENTAL: "0"', 'CARGO_INCREMENTAL: "1"'),)),
                [_env_diff("CARGO_INCREMENTAL", "1", "0")])
        with self.subTest(case="warm job env name removed"):
            self.assertEqual(
                _problems(warm_job_ops=(("sub", 'CARGO_INCREMENTAL: "0"', ""),)),
                [_env_diff("CARGO_INCREMENTAL", "0", None)])
        for name, value in (("CARGO_NET_RETRY", "9"), ("FOO", "bar")):
            with self.subTest(case="warm job env name added", name=name):
                self.assertEqual(
                    _problems(warm_job_ops=(("after", 'CARGO_INCREMENTAL: "0"',
                                             [f'      {name}: "{value}"']),)),
                    [_env_diff(name, None, value)])
            with self.subTest(case="pr job env name added", name=name):
                self.assertEqual(
                    _problems(pr_job_ops=(("after", "timeout-minutes: 45",
                                           ["    env:", f"      {name}: {value}"]),)),
                    [_env_diff(name, value, None)])

    def test_the_self_hosted_cap_is_allowed_on_the_pr_side_only(self) -> None:
        self.assertEqual(_problems(), [])
        got = _problems(warm_job_ops=(("after", 'CARGO_INCREMENTAL: "0"',
                                       ["      SELF_HOSTED_TARGET_CAP_BYTES: 1"]),))
        self.assertEqual(got, [_env_diff("SELF_HOSTED_TARGET_CAP_BYTES", "42949672960", "1")])

    def test_an_env_value_that_cannot_be_evaluated_is_refused_with_the_reason(self) -> None:
        got = _problems(warm_job_ops=(("after", 'CARGO_INCREMENTAL: "0"',
                                       ["      FOO: ${{ github.sha }}"]),))
        self.assertEqual(got, [f"{base.WARM}:{WARM_JOB_ID}: env 'FOO' cannot be evaluated: FOO: "
                               f"unrecognised expression form in an env value: "
                               f"'${{{{ github.sha }}}}'"])

    def test_a_workflow_level_defaults_block_on_either_side_is_refused(self) -> None:
        lines = ["defaults:", "  run:", "    shell: bash"]
        self.assertEqual(
            _problems(pr_wf_ops=(("end", lines),)),
            [f"{PR_NAME} vs {base.WARM}: workflow key 'defaults' differs: {PR_NAME} has "
             f"'run:\\n  shell: bash', {base.WARM} has None"])
        self.assertEqual(
            _problems(warm_wf_ops=(("end", lines),)),
            [f"{PR_NAME} vs {base.WARM}: workflow key 'defaults' differs: {PR_NAME} has None, "
             f"{base.WARM} has 'run:\\n  shell: bash'"])

    def test_the_hand_tables_are_pinned(self) -> None:
        self.assertEqual(KNOWN_STEP_KEYS, ("uses", "with", "env", "run", "if", "shell",
                                           "working-directory", "id", "name", "continue-on-error",
                                           "timeout-minutes"))
        self.assertEqual([(r.pr_id, r.warm_id) for r in MIRRORS], [
            ("actions/checkout", "actions/checkout"),
            ("dtolnay/rust-toolchain", "dtolnay/rust-toolchain"),
            ("Swatinem/rust-cache", "Swatinem/rust-cache"),
            ("nttld/setup-ndk", "nttld/setup-ndk"),
            ("Configure NDK toolchain for cargo", "Configure NDK toolchain for cargo"),
            ("cargo check (--lib --features sqlite-bundled)",
             "cargo check (--lib --features sqlite-bundled)"),
            ("actions/setup-python", "actions/setup-python"),
            ("Security audit", "Install the pinned cargo-audit (no audit run)"),
            (BUILD_PR_LABEL, BUILD_WARM_LABEL)])
        for row in MIRRORS:
            self.assertLessEqual(set(row.allowed), set(KNOWN_STEP_KEYS), row.pr_id)
            self.assertNotIn("uses", row.allowed, row.pr_id)
            self.assertNotIn("with", row.allowed, row.pr_id)
            self.assertNotIn("env", row.allowed, row.pr_id)
        self.assertEqual(PR_ONLY_STEPS, ("cargo_skip short-circuit",))
        self.assertEqual(PINNED_USES, LITERAL_SHAS)
        self.assertEqual(PINNED_WITH, {("actions/setup-python", "python-version"): "3.12"})
        self.assertEqual(JOB_ENV_PINNED, {"CARGO_AUDIT_VERSION": AUDIT_PIN})
        self.assertEqual(NDK_GENERATION, ((NDK_VERSION_PIN, CACHE_GENERATION_PIN),))
        self.assertEqual(JOB_KEYS_MAY_DIFFER, ("name", "needs", "timeout-minutes", "strategy",
                                               "steps"))
        self.assertEqual(set(JOB_KEYS_COMPARED), {"defaults", "container", "services",
                                                  "permissions", "if", "concurrency", "outputs",
                                                  "environment", "continue-on-error"})
        self.assertEqual(ENV_ONE_SIDED, {"ci.yml": ("SELF_HOSTED_TARGET_CAP_BYTES",),
                                         "rust-cache-warm.yml": ()})
        self.assertEqual(WORKFLOW_KEYS_COMPARED, ("defaults",))


# --- review r2: the class is "a change the pin module does not refuse" -------------------------
# Written by hand, independent of the reader. Each builder spells the exact refusal text.
LITERAL_SHAS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "dtolnay/rust-toolchain": "4360b52568e2003a75bf9bc1d59f33a8e3fc893c",
    "Swatinem/rust-cache": "6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
    "nttld/setup-ndk": "ed92fe6cadad69be94a966a7ee3271275e62f779",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
}
FOREIGN_SHA = "a" * 40
NDK_VERSION_PIN = "r26d"
CACHE_GENERATION_PIN = "chain-cache-g1"
AUDIT_PIN = "0.22.2"
EVENT_EXPR = "${{ github.event.head_commit.message }}"
EVENT_BODY = "github.event.head_commit.message"
SIDE_WF = {"pr": (PR_NAME, PR_JOB_ID), "warm": (base.WARM, WARM_JOB_ID)}
NDK_CONFIGURE = NDK_STEPS[1]
LS_ANCHOR = 'ls "$TC" | head -40'
BUILD_RUN_ANCHOR = "run: cargo build --release"
BUILD_WARM_ANCHOR = "- name: Build release (release-profile smoke)"
BUILD_PR_ANCHOR = "- name: Build release (once leg"
CHECK_STEP_ANCHOR = "- name: cargo check (--lib --features sqlite-bundled)"


def _pin_msg(side: str, ident: str, actual: object, expected: object) -> str:
    wf_name, job_id = SIDE_WF[side]
    return f"{wf_name}:{job_id} step {ident!r}: uses is {actual!r}, the pinned form is {expected!r}"


def _expr_msg(side: str, ident: str, line: str, expr: str) -> str:
    wf_name, job_id = SIDE_WF[side]
    return (f"{wf_name}:{job_id} step {ident!r}: line {line!r} holds the expression {expr!r}, "
            f"outside the allowlist")


def _unterminated_msg(side: str, ident: str, line: str) -> str:
    wf_name, job_id = SIDE_WF[side]
    return (f"{wf_name}:{job_id} step {ident!r}: line {line!r} holds an expression the scan "
            f"cannot classify")


def _order_msg(side: str, got: list[str], want: list[str]) -> str:
    wf_name, job_id = SIDE_WF[side]
    return f"{wf_name}:{job_id}: mirrored steps run in the order {got!r}, the hand table says {want!r}"


def _jobenv_msg(side: str, name: str, actual: object, expected: object) -> str:
    wf_name, job_id = SIDE_WF[side]
    return f"{wf_name}:{job_id}: job env {name!r} is {actual!r}, the pinned value is {expected!r}"


def _gen_msg(side: str, ndk: object, generation: object) -> str:
    wf_name, job_id = SIDE_WF[side]
    return (f"{wf_name}:{job_id}: NDK {ndk!r} is cached under generation {generation!r}; the hand "
            f"table pairs {NDK_VERSION_PIN!r} with {CACHE_GENERATION_PIN!r}")


def _step_env_msg(side: str, ident: str, value: str) -> str:
    wf_name, job_id = SIDE_WF[side]
    return (f"{wf_name}:{job_id} step {ident!r}: step env {value!r} is on both sides but the hand "
            f"table names none (a step env is outside the rust-cache key)")


class ClassInvariants9732(unittest.TestCase):
    """Review r2 (F2, F3, F4, F6, F7): a change to `uses`, `with`, `env`, `run` text (comment lines
    included), step order or a build-input version is refused unless a hand table names it."""

    # F2: setup-python exports PKG_CONFIG_PATH and LD_LIBRARY_PATH into the cargo steps of the PR
    # leg; the warm job mirrors it.
    def test_setup_python_is_a_mirrored_step_of_the_warm_job(self) -> None:
        _, pr_job, _ = _android_leg()
        _, warm_job = _warm_job()
        pr_steps = [s for s in pr_job.steps() if s.uses_name() == "actions/setup-python"]
        warm_steps = [s for s in warm_job.steps() if s.uses_name() == "actions/setup-python"]
        self.assertEqual(len(pr_steps), 1)
        self.assertEqual(len(warm_steps), 1, f"{WARM_JOB_ID}: no actions/setup-python step")
        self.assertEqual(warm_steps[0].keys.get("uses"), pr_steps[0].keys.get("uses"))
        self.assertEqual(warm_steps[0].mapping("with"), pr_steps[0].mapping("with"))
        self.assertNotIn("actions/setup-python", PR_ONLY_STEPS)
        self.assertIn("actions/setup-python", [row.pr_id for row in MIRRORS])

    # F4: a step-level env is outside the rust-cache key hash; a job-level env is inside it.
    def test_the_audit_pin_is_a_job_level_env_on_both_sides(self) -> None:
        _, pr_job, _ = _android_leg()
        _, warm_job = _warm_job()
        for job in (pr_job, warm_job):
            with self.subTest(job=job.job_id):
                self.assertEqual(job.env().get("CARGO_AUDIT_VERSION"), AUDIT_PIN)
                self.assertEqual([s.label() for s in job.steps()
                                  if "CARGO_AUDIT_VERSION" in s.mapping("env")], [])

    # F3: the order of the mirrored warm steps is the PR order (07e).
    def test_a_mirrored_warm_step_moved_out_of_order_is_refused(self) -> None:
        got = _problems(warm_job_ops=(("move_before", BUILD_WARM_ANCHOR, CHECK_STEP_ANCHOR),))
        want = [row.warm_id for row in MIRRORS]
        moved = [i for i in want if i != BUILD_WARM_LABEL]
        moved.insert(moved.index(CARGO_CHECK_STEP), BUILD_WARM_LABEL)
        self.assertEqual(got, [_order_msg("warm", moved, want)])

    def test_the_same_reorder_on_the_pr_side_is_refused(self) -> None:
        got = _problems(pr_job_ops=(("move_before", BUILD_PR_ANCHOR, CHECK_STEP_ANCHOR),))
        want = [row.pr_id for row in MIRRORS]
        moved = [i for i in want if i != BUILD_PR_LABEL]
        moved.insert(moved.index(CARGO_CHECK_STEP), BUILD_PR_LABEL)
        self.assertEqual(got, [_order_msg("pr", moved, want)])

    # F4: P1 (audit pin changed on both sides) is refused for the right reason.
    def test_p1_the_audit_pin_changed_on_both_sides_is_refused(self) -> None:
        ops = (("sub", f'CARGO_AUDIT_VERSION: "{AUDIT_PIN}"', 'CARGO_AUDIT_VERSION: "0.22.3"'),)
        self.assertEqual(_problems(pr_job_ops=ops, warm_job_ops=ops),
                         [_jobenv_msg("pr", "CARGO_AUDIT_VERSION", "0.22.3", AUDIT_PIN),
                          _jobenv_msg("warm", "CARGO_AUDIT_VERSION", "0.22.3", AUDIT_PIN)])

    # F4: P2 (NDK r27 on both sides) and a generation bump without the NDK are refused.
    def test_p2_the_ndk_version_changed_without_the_cache_generation_is_refused(self) -> None:
        ops = (("sub", f"ndk-version: {NDK_VERSION_PIN}", "ndk-version: r27"),)
        self.assertEqual(_problems(pr_job_ops=ops, warm_job_ops=ops),
                         [_gen_msg("pr", "r27", CACHE_GENERATION_PIN),
                          _gen_msg("warm", "r27", CACHE_GENERATION_PIN)])

    def test_a_cache_generation_bump_without_the_ndk_version_is_refused(self) -> None:
        ops = (("sub", f"prefix-key: {CACHE_GENERATION_PIN}", "prefix-key: chain-cache-g2"),)
        self.assertEqual(_problems(pr_job_ops=ops, warm_job_ops=ops),
                         [_gen_msg("pr", NDK_VERSION_PIN, "chain-cache-g2"),
                          _gen_msg("warm", NDK_VERSION_PIN, "chain-cache-g2")])

    # F6: comment text of a `run:` is compared (G04) and an expression anywhere is classified (H08).
    def test_g04_a_comment_after_a_single_line_run_is_refused_on_either_side(self) -> None:
        for side in SIDES:
            with self.subTest(side=side):
                got = _on_side(side, (("sub", BUILD_RUN_ANCHOR, f"{BUILD_RUN_ANCHOR} # keep"),))
                bare, kept = "cargo build --release", "cargo build --release # keep"
                pr_val, warm_val = (kept, bare) if side == "pr" else (bare, kept)
                self.assertEqual(got, [_step_diff(BUILD_PR_LABEL, BUILD_WARM_LABEL, "run", pr_val,
                                                  warm_val)])

    def test_g04_a_comment_holding_an_event_expression_is_refused_twice(self) -> None:
        line = f"{BUILD_RUN_ANCHOR} # {EVENT_EXPR}"
        got = _on_side("warm", (("sub", BUILD_RUN_ANCHOR, line),))
        self.assertEqual(got, [
            _step_diff(BUILD_PR_LABEL, BUILD_WARM_LABEL, "run", "cargo build --release",
                       f"cargo build --release # {EVENT_EXPR}"),
            _expr_msg("warm", BUILD_WARM_LABEL, line, EVENT_BODY)])

    def test_h08_the_same_expression_comment_in_both_ndk_blocks_is_refused(self) -> None:
        comment = f"# {EVENT_EXPR}"
        ops = (("after", LS_ANCHOR, [f"          {comment}"]),)
        self.assertEqual(_problems(pr_job_ops=ops, warm_job_ops=ops),
                         [_expr_msg("pr", NDK_CONFIGURE, comment, EVENT_BODY),
                          _expr_msg("warm", NDK_CONFIGURE, comment, EVENT_BODY)])

    def test_an_expression_the_scan_cannot_classify_is_refused(self) -> None:
        for side in SIDES:
            with self.subTest(side=side):
                comment = "# ${{ matrix.target"
                got = _on_side(side, (("after", LS_ANCHOR, [f"          {comment}"]),))
                self.assertEqual(got[-1], _unterminated_msg(side, NDK_CONFIGURE, comment))

    # F7: every mirrored action is pinned to its literal 40-hex sha, not only side to side.
    def test_h07_h10_e04_h05_a_sha_swapped_on_both_sides_is_refused(self) -> None:
        for action in ("nttld/setup-ndk", "dtolnay/rust-toolchain", "actions/checkout"):
            with self.subTest(action=action):
                old = f"{action}@{LITERAL_SHAS[action]}"
                new = f"{action}@{FOREIGN_SHA}"
                ops = (("sub", old, new),)
                self.assertEqual(_problems(pr_job_ops=ops, warm_job_ops=ops),
                                 [_pin_msg("pr", action, new, old),
                                  _pin_msg("warm", action, new, old)])

    def test_a_tag_form_of_a_pinned_action_is_refused_on_both_sides(self) -> None:
        for action in ("nttld/setup-ndk", "dtolnay/rust-toolchain", "actions/checkout"):
            with self.subTest(action=action):
                old = f"{action}@{LITERAL_SHAS[action]}"
                new = f"{action}@v4"
                ops = (("sub", old, new),)
                self.assertEqual(_problems(pr_job_ops=ops, warm_job_ops=ops),
                                 [_pin_msg("pr", action, new, old),
                                  _pin_msg("warm", action, new, old)])

    # A step env named on both sides is outside the key hash and outside every pin: refused.
    def test_a_step_env_on_both_sides_of_a_pair_is_refused(self) -> None:
        ops = (("after", "name: Build release", ENV_STEP),)
        self.assertEqual(_problems(pr_job_ops=ops, warm_job_ops=ops),
                         [_step_env_msg("pr", BUILD_PR_LABEL, "FOO: bar"),
                          _step_env_msg("warm", BUILD_WARM_LABEL, "FOO: bar")])


if __name__ == "__main__":
    unittest.main()
