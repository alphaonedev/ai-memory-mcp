# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""clients-ci runs the opt-in live sdk/python tests against the real binary (#6746).

Four tests in ``test_client.py`` need a daemon (``AI_MEMORY_TEST_DAEMON=1``)
and one in ``test_wake_client.py`` needs a live ``ai-memory wake-hub``. They
skip without one, and no CI job started either, so the only tests that prove
the SDK against the Rust binary never ran. clients-ci now has a job that builds
``ai-memory``, starts both with ``scripts/sdk-python-live.py`` and fails unless
every live test ran and passed.
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import re
import xml.etree.ElementTree as ET

_SDK = pathlib.Path(__file__).resolve().parents[1]
_REPO = _SDK.parents[1]
_WORKFLOW = _REPO / ".github" / "workflows" / "clients-ci.yml"
_HARNESS = _REPO / "scripts" / "sdk-python-live.py"
_LIVE_ENV = ("AI_MEMORY_TEST_DAEMON", "AI_MEMORY_TEST_WAKE_HUB_SOCKET")


def _harness():
    assert _HARNESS.is_file(), f"{_HARNESS} is missing (#6746)"
    spec = importlib.util.spec_from_file_location("sdk_python_live", _HARNESS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _live_job() -> str:
    text = _WORKFLOW.read_text(encoding="utf-8")
    parts = text.split("\n  sdk-python-live:\n", 1)
    assert len(parts) == 2, "clients-ci.yml has no sdk-python-live job (#6746)"
    return re.split(r"\n  [a-z][\w-]*:\n", parts[1], maxsplit=1)[0]


def _live_tests_in_tree() -> set[str]:
    """Every test function in tests/ gated on a live daemon or hub, by node id."""
    found: set[str] = set()
    for path in sorted((_SDK / "tests").glob("test_*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
                continue
            decorators = " ".join(
                ast.get_source_segment(source, d) or "" for d in node.decorator_list
            )
            if "skip_without_daemon" in decorators or any(v in decorators for v in _LIVE_ENV):
                found.add(f"tests/{path.name}::{node.name}")
    return found


def test_clients_ci_has_a_job_that_runs_the_live_tests_6746() -> None:
    body = _live_job()
    assert "cargo build" in body and "--bin ai-memory" in body, (
        "the live job does not build ai-memory"
    )
    assert re.search(r"python -m pip install -e \"\.\[dev\]\"", body), (
        "the live job does not install sdk/python[dev]"
    )
    run = re.search(r"python (?:-I )?(?:\.\./\.\./)?scripts/sdk-python-live\.py[^\n]*", body)
    assert run is not None, "the live job does not run scripts/sdk-python-live.py (#6746)"
    assert "--binary" in run.group(0) and "--sdk" in run.group(0), run.group(0)


def test_a_daemon_change_triggers_the_live_job_6746() -> None:
    """The live job proves the SDK against the binary, so a change to the binary must run it."""
    text = _WORKFLOW.read_text(encoding="utf-8")
    on = text.split("\njobs:\n", 1)[0]
    for event in ("push", "pull_request"):
        block = re.split(r"\n  [a-z_]+:\n", on.split(f"\n  {event}:\n", 1)[1], maxsplit=1)[0]
        for path in ('"src/**"', '"Cargo.toml"', '"Cargo.lock"', '"scripts/sdk-python-live.py"'):
            assert f"- {path}" in block, f"clients-ci {event} paths miss {path} (#6746)"


def test_harness_lists_every_live_test_in_the_tree_6746() -> None:
    in_tree = _live_tests_in_tree()
    assert len(in_tree) == 5, sorted(in_tree)
    assert set(_harness().LIVE_TESTS) == in_tree


def _report(tmp_path: pathlib.Path, outcomes: dict[str, str]) -> pathlib.Path:
    suite = ET.Element("testsuite")
    for node, outcome in outcomes.items():
        file_part, name = node.split("::")
        case = ET.SubElement(
            suite, "testcase", classname=file_part[: -len(".py")].replace("/", "."), name=name
        )
        if outcome != "passed":
            ET.SubElement(case, outcome)
    path = tmp_path / "junit.xml"
    ET.ElementTree(suite).write(path)
    return path


def test_a_skipped_or_missing_live_test_fails_the_harness_6746(tmp_path: pathlib.Path) -> None:
    harness = _harness()
    tests = list(harness.LIVE_TESTS)
    all_passed = {node: "passed" for node in tests}
    assert harness.verdict(harness.junit_outcomes(_report(tmp_path, all_passed))) == []

    skipped = dict(all_passed, **{tests[0]: "skipped"})
    assert harness.verdict(harness.junit_outcomes(_report(tmp_path, skipped))) == [
        f"{tests[0]}: skipped"
    ]

    failed = dict(all_passed, **{tests[1]: "failure"})
    assert harness.verdict(harness.junit_outcomes(_report(tmp_path, failed))) == [
        f"{tests[1]}: failed"
    ]

    missing = {node: "passed" for node in tests[1:]}
    assert harness.verdict(harness.junit_outcomes(_report(tmp_path, missing))) == [
        f"{tests[0]}: not collected"
    ]
