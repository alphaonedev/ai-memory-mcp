#!/usr/bin/env python3
"""Red cases for the external-PR approval gate's merge_group arm (#6117 class).

Pins #6227, #6229 and #6242 against scripts/check_external_pr_approval.py, plus the
gate-script contract of the batch-B5 spec (undecidable input exits 2, an interrupt
dies of the delivered signal and leaves no orphan, no output path can overwrite a
failing status).

Set GATE_SCRIPT=<path> to replay the cases against another copy of the gate (the
pre-fix replay used to prove each case is red on the real pre-fix code).

Run: python3 -I -m unittest scripts.ci.tests.test_check_external_pr_approval_6117
Standard library only; Python 3.9+. Scratch lives under .local-runs/, never /tmp.
"""
import ast
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GATE = Path(os.environ.get("GATE_SCRIPT") or REPO / "scripts" / "check_external_pr_approval.py")
SCRATCH = REPO / ".local-runs"

SPEC = importlib.util.spec_from_file_location("gate_under_test", GATE)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

REPO_NAME, OP = "o/r", "op"
A, C, E, F = "a" * 40, "c" * 40, "e" * 40, "f" * 40  # A PR head, C queue commit, E base_sha, F other


def pr(number, sha, assoc="NONE", head_repo="fork/r"):
    return {"number": number, "author_association": assoc, "user": {"login": "x"},
            "head": {"sha": sha, "repo": {"full_name": head_repo}}}


APPROVED = {"id": 1, "user": {"login": OP}, "state": "APPROVED", "commit_id": A,
            "submitted_at": "2026-10-01T00:00:00Z"}


def queue_event(pr_number=1, ref_sha=E, base_sha=E, base="release/v1.0.0"):
    group = {"head_sha": C, "base_ref": "refs/heads/" + base,
             "head_ref": f"refs/heads/gh-readonly-queue/{base}/pr-{pr_number}-{ref_sha}"}
    if base_sha is not None:
        group["base_sha"] = base_sha
    return {"merge_group": group}


def queue_rule(max_merge=1, min_merge=1):
    return [{"type": "merge_queue", "parameters": {
        "max_entries_to_merge": max_merge, "min_entries_to_merge": min_merge}}]


def make_api(pulls, reviews=None, rules=None, fail=False):
    """A fake `gh api`: pulls listing, per-PR reviews, branch rules (default: group size 1)."""
    def api(path):
        if fail:
            raise gate.GateError("HTTP 502")
        match = re.search(r"/pulls/(\d+)/reviews", path)
        if match:
            return (reviews or {}).get(int(match.group(1)), [])
        if "/rules/branches/" in path:
            if rules is None:
                return queue_rule()
            if isinstance(rules, Exception):
                raise rules
            return rules
        return pulls
    return api


def run(event_name, event, sha, api):
    return gate.run_gate(event_name, event, REPO_NAME, sha, OP, api)[0]


class Issue6227MergeGroupIsJudged(unittest.TestCase):
    """#6227: "External-PR approval gate: merge_group arm is vacuous (merge-group sha is never a PR head)".

    Acceptance (Proposed fix): "on `merge_group`, read `merge_group.head_ref` from the event
    payload ... Fetch each PR `N` and judge it at its own head sha by the same rule. If the ref
    cannot be parsed, or no PR can be derived, fail closed."
    """

    def test_6227_unapproved_external_pr_in_queue_fails(self):
        # GITHUB_SHA is the queue commit C, never a PR head: the old lookup passed vacuously.
        rc = run("merge_group", queue_event(), C, make_api([pr(1, A)]))
        self.assertNotEqual(rc, 0, "merge_group judged nobody (vacuous pass)")

    def test_6227_approved_external_pr_in_queue_passes(self):
        rc = run("merge_group", queue_event(), C, make_api([pr(1, A)], {1: [APPROVED]}))
        self.assertEqual(rc, 0)

    def test_6227_unparsable_head_ref_fails_closed(self):
        event = queue_event()
        event["merge_group"]["head_ref"] = "refs/heads/not-a-queue-ref"
        rc = run("merge_group", event, C, make_api([pr(1, A)], {1: [APPROVED]}))
        self.assertNotEqual(rc, 0)

    def test_6227_pr_not_open_fails_closed(self):
        rc = run("merge_group", queue_event(7), C, make_api([pr(1, A)], {1: [APPROVED]}))
        self.assertNotEqual(rc, 0)


class Issue6229MultiPrQueueGroup(unittest.TestCase):
    """#6229: "merge_group judges only the PR named by head_ref, not every PR in a multi-PR queue group".

    Acceptance (Proposed fix): "pin the merge-queue group size to 1 in the ruleset and add a ...
    assertion that says so ... fail closed if the mapping is ambiguous." The gate reads the
    base branch's merge_queue rule and passes only when max_entries_to_merge is exactly 1.
    """

    def approved_run(self, rules):
        return run("merge_group", queue_event(), C, make_api([pr(1, A)], {1: [APPROVED]}, rules))

    def test_6229_group_size_above_one_fails_closed(self):
        self.assertNotEqual(self.approved_run(queue_rule(max_merge=5)), 0)

    def test_6229_group_size_one_passes(self):
        self.assertEqual(self.approved_run(queue_rule(max_merge=1)), 0)

    def test_6229_no_merge_queue_rule_is_undecidable(self):
        self.assertEqual(self.approved_run([{"type": "deletion", "parameters": None}]), 2)

    def test_6229_unreadable_rules_is_undecidable(self):
        self.assertEqual(self.approved_run(gate.GateError("HTTP 403")), 2)

    def test_6229_non_integer_group_size_is_undecidable(self):
        for bad in (True, "1", None, 0, -1, 1.0):
            with self.subTest(max_entries_to_merge=bad):
                self.assertEqual(self.approved_run(queue_rule(max_merge=bad)), 2)

    def test_6229_two_merge_queue_rules_is_undecidable(self):
        self.assertEqual(self.approved_run(queue_rule() + queue_rule()), 2)


class Issue6242QueueRefBinding(unittest.TestCase):
    """#6242: "External-PR approval gate: merge_group arm does not bind the queue ref sha to the judged PR head sha".

    Acceptance (Proposed fix): "capture the sha group, require it to equal ... (else GateError,
    fail closed); add the mismatch cell". GitHub names the queue ref after the queue commit's
    parent, merge_group.base_sha (#6325), so the ref sha must equal base_sha.
    """

    def judged(self, event):
        # The PR head A carries the operator's APPROVED review: only the binding can fail it.
        return run("merge_group", event, C, make_api([pr(1, A)], {1: [APPROVED]}))

    def test_6242_ref_sha_that_is_not_base_sha_fails(self):
        self.assertNotEqual(self.judged(queue_event(ref_sha=F, base_sha=E)), 0)

    def test_6242_ref_sha_equal_to_pr_head_but_not_base_sha_fails(self):
        self.assertNotEqual(self.judged(queue_event(ref_sha=A, base_sha=E)), 0)

    def test_6242_missing_base_sha_fails(self):
        self.assertNotEqual(self.judged(queue_event(base_sha=None)), 0)

    def test_6242_short_ref_sha_fails(self):
        self.assertNotEqual(self.judged(queue_event(ref_sha="e" * 7, base_sha="e" * 7)), 0)

    def test_6242_bound_ref_passes(self):
        self.assertEqual(self.judged(queue_event()), 0)


class GateScriptContract(unittest.TestCase):
    """Batch-B5 gate-script contract (spec section 3): exit 0 pass, 1 finding, 2 undecidable."""

    def test_6117_missing_approval_is_exit_1(self):
        self.assertEqual(run("push", {}, A, make_api([pr(1, A)])), 1)

    def test_6117_api_error_is_exit_2(self):
        self.assertEqual(run("push", {}, A, make_api([], fail=True)), 2)

    def test_6117_unparsable_ref_is_exit_2(self):
        event = queue_event()
        event["merge_group"]["head_ref"] = "refs/heads/nope"
        self.assertEqual(run("merge_group", event, C, make_api([pr(1, A)])), 2)

    def test_6117_bad_run_sha_is_exit_2(self):
        self.assertEqual(run("push", {}, "short", make_api([])), 2)

    def test_6117_no_operator_is_exit_2(self):
        self.assertEqual(gate.run_gate("push", {}, REPO_NAME, A, "", make_api([]))[0], 2)

    def test_6117_unreadable_event_payload_is_exit_2(self):
        env = dict(os.environ, GITHUB_EVENT_NAME="merge_group", GITHUB_REPOSITORY=REPO_NAME,
                   GITHUB_EVENT_PATH=str(SCRATCH / "no-such-event.json"), OPERATOR_LOGIN=OP)
        proc = subprocess.run([sys.executable, "-I", str(GATE)], env=env, capture_output=True,
                              text=True, timeout=60, check=False)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_6117_output_failure_cannot_become_pass(self):
        """A failing verdict whose output path breaks stays non-zero (never 0)."""
        real_print = print

        def broken(*_a, **_k):
            raise BrokenPipeError("stdout closed")

        env = {"GITHUB_EVENT_NAME": "push", "GITHUB_SHA": A, "GITHUB_REPOSITORY": REPO_NAME,
               "OPERATOR_LOGIN": OP}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        real_gh_api = gate.gh_api
        real_argv = sys.argv
        real_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        sys.argv = [str(GATE)]
        gate.gh_api = make_api([pr(1, A)])
        try:
            import builtins
            builtins.print = broken
            try:
                rc = gate.entry()
            finally:
                builtins.print = real_print
        finally:
            gate.gh_api = real_gh_api
            sys.argv = real_argv
            for sig, handler in real_handlers.items():
                signal.signal(sig, handler)
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertNotEqual(rc, 0)


class InterruptDiesOfSignal(unittest.TestCase):
    """An interrupt kills the in-flight `gh` child and the gate dies of the delivered signal."""

    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.dir = SCRATCH / f"b5-signal-{os.getpid()}"
        shutil.rmtree(self.dir, ignore_errors=True)
        self.dir.mkdir()
        self.pidfile = self.dir / "gh.pid"
        fake = self.dir / "gh"
        fake.write_text("#!%s\nimport os, time\nopen(%r, 'w').write(str(os.getpid()))\ntime.sleep(60)\n"
                        % (sys.executable, str(self.pidfile)))
        fake.chmod(0o755)

    def tearDown(self):
        if self.pidfile.exists():
            try:
                os.kill(int(self.pidfile.read_text()), signal.SIGKILL)
            except (OSError, ValueError):
                pass
        shutil.rmtree(self.dir, ignore_errors=True)

    def alive(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        # A zombie child of a dead parent is reaped by init; treat state Z as gone.
        try:
            return Path(f"/proc/{pid}/stat").read_text().split(")")[-1].split()[0] != "Z"
        except OSError:
            return False

    def test_6117_sigterm_kills_child_and_dies_of_sigterm(self):
        env = dict(os.environ, PATH=f"{self.dir}{os.pathsep}{os.environ['PATH']}",
                   GITHUB_EVENT_NAME="push", GITHUB_SHA=A, GITHUB_REPOSITORY=REPO_NAME,
                   OPERATOR_LOGIN=OP)
        proc = subprocess.Popen([sys.executable, "-I", str(GATE)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 20
            while not self.pidfile.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(self.pidfile.exists(), "the fake gh never started")
            time.sleep(0.2)
            child = int(self.pidfile.read_text())
            proc.send_signal(signal.SIGTERM)
            proc.communicate(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, -signal.SIGTERM)
        deadline = time.monotonic() + 5
        while self.alive(child) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(self.alive(child), "the gh child outlived the gate (orphan)")


class Round2StaticPins(unittest.TestCase):
    """Source-level pins for the round-2 review findings (#8007 #8008 #8009 #8012 #8014 #8015 #8016 #8017)."""

    @staticmethod
    def tree(path):
        return ast.parse(Path(path).read_text(encoding="utf-8"))

    def test_8008_8016_no_empty_except_in_gate_or_tests(self):
        """#8008 / #8016 (py/empty-except): every except body does something besides ``pass``."""
        for path in (GATE, Path(__file__)):
            for node in ast.walk(self.tree(path)):
                if isinstance(node, ast.ExceptHandler):
                    self.assertFalse(all(isinstance(stmt, ast.Pass) for stmt in node.body),
                                     f"{path.name}:{node.lineno} is an empty except")

    def test_8009_8017_no_unused_import_in_test_module(self):
        """#8009 / #8017 (py/unused-import): every imported name in this module is used."""
        tree = self.tree(Path(__file__))
        imported = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported[(alias.asname or alias.name).split(".")[0]] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported[alias.asname or alias.name] = node.lineno
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        unused = sorted(name for name in imported if name not in used)
        self.assertEqual(unused, [], f"unused imports: {unused}")

    def test_8007_8015_control_char_class_is_a_raw_regex(self):
        """#8007 / #8015 (py/overly-large-range): the control-character class is a raw regex constant."""
        pattern = getattr(gate, "CONTROL_RE", None)
        self.assertIsNotNone(pattern, "scripts/check_external_pr_approval.py has no CONTROL_RE")
        self.assertIn("\\x0e-\\x1f", pattern.pattern, "the class must be spelled as raw escapes")
        for char in ("\x00", "\x08", "\x0b", "\x0c", "\x0e", "\x1f", "\x7f", "\x85", "\u2028", "\u2029"):
            self.assertEqual(gate.workflow_error("a" + char + "b"), "::error::a?b", repr(char))
        for char in ("\t", " ", "~", "\xa0", "\u2027", "\u202a"):
            self.assertEqual(gate.workflow_error("a" + char + "b"), "::error::a" + char + "b", repr(char))

    def test_8014_entry_docstring_states_that_a_print_failure_becomes_exit_2(self):
        """#8014: entry() must not claim a failing verdict survives a print failure as-is."""
        doc = " ".join((gate.entry.__doc__ or "").split()) if hasattr(gate, "entry") else ""
        self.assertNotIn("returned as-is", doc)
        self.assertIn("print failure turns", doc)
        self.assertIn("exit 2", doc)

    def test_8012_6229_docstring_does_not_splice_the_two_options(self):
        """#8012: the #6229 acceptance quote is option 1 only; option 2's sentence is not spliced in."""
        doc = " ".join((Issue6229MultiPrQueueGroup.__doc__ or "").split())
        self.assertNotIn("fail closed if the mapping is ambiguous", doc)
        self.assertNotIn("assertion that says so ... fail closed", doc)
        self.assertIn("option 1", doc)

    def test_8011_6242_docstring_is_refs_not_closes(self):
        """#8011: the #6242 class says the residual stays open and the PR only references the issue."""
        doc = " ".join((Issue6242QueueRefBinding.__doc__ or "").split())
        self.assertIn("Refs #6242", doc)
        self.assertIn("stays open", doc)


class Round2RulesRead(unittest.TestCase):
    """#8013: the rules read is merge_group only, and every gh failure on it is exit 2."""

    def paths_read(self, event_name, event, sha):
        seen = []
        base = make_api([pr(1, A)], {1: [APPROVED]})

        def api(path):
            seen.append(path)
            return base(path)

        rc = run(event_name, event, sha, api)
        return rc, seen

    def test_8013_push_never_reads_the_rules_endpoint(self):
        rc, seen = self.paths_read("push", {}, A)
        self.assertEqual(rc, 0)
        self.assertTrue(seen)
        self.assertFalse([p for p in seen if "/rules/" in p], seen)

    def test_8013_pull_request_never_reads_the_rules_endpoint(self):
        event = {"pull_request": pr(1, A)}
        rc, seen = self.paths_read("pull_request", event, A)
        self.assertEqual(rc, 0)
        self.assertTrue(seen)
        self.assertFalse([p for p in seen if "/rules/" in p], seen)

    def test_8013_merge_group_reads_the_rules_of_the_base_branch(self):
        rc, seen = self.paths_read("merge_group", queue_event(), C)
        self.assertEqual(rc, 0)
        self.assertEqual(seen[0], f"repos/{REPO_NAME}/rules/branches/release/v1.0.0")

    def run_with_failing_gh(self, stderr_text):
        """Drive the REAL gh_api through a fake `gh` that exits 1 on the rules read."""
        scratch = SCRATCH / f"b5-rules-{os.getpid()}"
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, scratch, True)
        fake = scratch / "gh"
        fake.write_text("#!%s\nimport sys\nsys.stderr.write(%r)\nsys.exit(1)\n" % (sys.executable, stderr_text))
        fake.chmod(0o755)
        event_file = scratch / "event.json"
        event_file.write_text(gate.json.dumps(queue_event()), encoding="utf-8")
        env = dict(os.environ, PATH=f"{scratch}{os.pathsep}{os.environ['PATH']}",
                   GITHUB_EVENT_NAME="merge_group", GITHUB_EVENT_PATH=str(event_file),
                   GITHUB_REPOSITORY=REPO_NAME, GITHUB_SHA=C, OPERATOR_LOGIN=OP)
        return subprocess.run([sys.executable, "-I", str(GATE)], env=env, capture_output=True,
                              text=True, timeout=60, check=False)

    def test_8013_rules_read_http_403_is_exit_2(self):
        proc = self.run_with_failing_gh("gh: Resource not accessible (HTTP 403)\n")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("Failing closed", proc.stdout)

    def test_8013_rules_read_http_404_is_exit_2(self):
        proc = self.run_with_failing_gh("gh: Not Found (HTTP 404)\n")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_8013_rules_read_network_failure_is_exit_2(self):
        proc = self.run_with_failing_gh("error connecting to api.github.com\n")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_8014_print_failure_on_a_failing_verdict_is_exit_2_not_0(self):
        """A finding (exit 1) whose output path breaks becomes exit 2: still non-zero, never a pass."""
        real_print, real_argv = print, sys.argv
        real_gh_api, real_env = gate.gh_api, dict(os.environ)
        real_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}

        def broken(*_a, **_k):
            raise BrokenPipeError("stdout closed")

        import builtins
        os.environ.update(GITHUB_EVENT_NAME="push", GITHUB_SHA=A, GITHUB_REPOSITORY=REPO_NAME,
                          OPERATOR_LOGIN=OP)
        sys.argv = [str(GATE)]
        gate.gh_api = make_api([pr(1, A)])
        builtins.print = broken
        try:
            rc = gate.entry()
        finally:
            builtins.print = real_print
            gate.gh_api, sys.argv = real_gh_api, real_argv
            os.environ.clear()
            os.environ.update(real_env)
            for sig, handler in real_handlers.items():
                signal.signal(sig, handler)
        self.assertEqual(rc, 2)


# One row per issue the PR closes by a pinned behaviour case: (issue, test class).
# The CodeQL and review issues (#8007-#8009, #8011-#8017) are pinned by the Round2 classes below.
CLOSES = [
    (6227, Issue6227MergeGroupIsJudged),
    (6229, Issue6229MultiPrQueueGroup),
]
# Pinned but NOT closed (the residual stays open), and the parent: #6117 is Refs only.
REFS = [
    (6242, Issue6242QueueRefBinding),
]


class PinnedCaseCount(unittest.TestCase):
    """Self-check: every Closes issue is pinned by at least one case named test_<issue>_*."""

    def test_every_closes_issue_has_pinned_cases(self):
        issues = [issue for issue, _cls in CLOSES]
        self.assertEqual(len(issues), len(set(issues)), "duplicate row in CLOSES")
        self.assertFalse({6117, 6242} & set(issues), "#6117 and #6242 are Refs, never Closes")
        for issue, cls in CLOSES + REFS:
            names = [n for n in dir(cls) if n.startswith(f"test_{issue}_")]
            self.assertTrue(names, f"issue {issue} has no pinned test_{issue}_* case")
            self.assertEqual(sorted(re.findall(r"#(\d+)", (cls.__doc__ or "").split(":")[0])),
                             [str(issue)], f"{cls.__name__} docstring must open with #{issue}")

    def test_no_unlisted_issue_class(self):
        listed = {cls for _issue, cls in CLOSES + REFS}
        for name, obj in globals().items():
            if isinstance(obj, type) and name.startswith("Issue") and issubclass(obj, unittest.TestCase):
                self.assertIn(obj, listed, f"{name} pins an issue that is not in CLOSES")


if __name__ == "__main__":
    unittest.main()
