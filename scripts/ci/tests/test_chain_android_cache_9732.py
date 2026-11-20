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

Run: python3 -I -m unittest discover -s scripts/ci/tests -p 'test_chain_android_cache_9732.py'
"""

from __future__ import annotations

import sys
import unittest
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


if __name__ == "__main__":
    unittest.main()
