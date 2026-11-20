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


def _apply(lines: list[str], ops: tuple[tuple, ...]) -> list[str]:
    out = list(lines)
    for op in ops:
        if op[0] == "end":
            out.extend(op[1])
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
                self.assertEqual(got, [_step_diff(CHECKOUT_ID, CHECKOUT_ID, "uses", pr_val,
                                                  warm_val)])
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
            ("Security audit", "Install the pinned cargo-audit (no audit run)"),
            (BUILD_PR_LABEL, BUILD_WARM_LABEL)])
        for row in MIRRORS:
            self.assertLessEqual(set(row.allowed), set(KNOWN_STEP_KEYS), row.pr_id)
            self.assertNotIn("uses", row.allowed, row.pr_id)
            self.assertNotIn("with", row.allowed, row.pr_id)
            self.assertNotIn("env", row.allowed, row.pr_id)
        self.assertEqual(PR_ONLY_STEPS, ("cargo_skip short-circuit", "actions/setup-python"))
        self.assertEqual(JOB_KEYS_MAY_DIFFER, ("name", "needs", "timeout-minutes", "strategy",
                                               "steps"))
        self.assertEqual(set(JOB_KEYS_COMPARED), {"defaults", "container", "services",
                                                  "permissions", "if", "concurrency", "outputs",
                                                  "environment", "continue-on-error"})
        self.assertEqual(ENV_ONE_SIDED, {"ci.yml": ("SELF_HOSTED_TARGET_CAP_BYTES",),
                                         "rust-cache-warm.yml": ()})
        self.assertEqual(WORKFLOW_KEYS_COMPARED, ("defaults",))


if __name__ == "__main__":
    unittest.main()
