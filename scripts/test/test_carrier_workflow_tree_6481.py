#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the tree reader and the token/trigger pins built on it (#6481, #6482, #6542, #6543, #6545).

Each case names the construct it protects; the mutant campaign (.local-runs/mutants.py, round 7)
uses this file with the gate self-test to kill mutations of `parse_workflow` and the pins.
Stdlib only; run with `python3 scripts/test/test_carrier_workflow_tree_6481.py`.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent
REPO = SCRIPTS.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GATE = _load("check_carrier_ruleset_live")
SUBSET = GATE.SUBSET
Unparsed = SUBSET.Unparsed
WF = (REPO / ".github" / "workflows" / "c8-precheck.yml").read_text(encoding="utf-8")


def refused(text, needle):
    try:
        SUBSET.parse_workflow(text)
    except Unparsed as exc:
        return needle in str(exc)
    return False


def with_verifier(extra, anchor="    permissions:\n      contents: read\n      issues: read\n    steps:\n"):
    """The committed workflow with `extra` spliced into the verifier job just before `steps:`."""
    head, _, tail = WF.partition("  carrier-ruleset-live-gate:\n")
    pre, mid, post = tail.partition(anchor)
    assert mid, "anchor missing"
    return head + "  carrier-ruleset-live-gate:\n" + pre + extra + mid + post


class TreeShape(unittest.TestCase):
    DOC = "a:\n  b: 1\n  c:\n    - x\n    - y: 2\n      z: 3\nd: |\n  text # not a comment\n  more\n\ne: 5\n"

    def test_lines_ends_cols(self):
        root = SUBSET.parse_workflow(self.DOC)
        a, d, e = root.get("a"), root.get("d"), root.get("e")
        self.assertEqual((a.line, a.end, a.col), (1, 6, 0))
        self.assertEqual((root.get("a").get("b").line, root.get("a").get("b").end), (2, 2))
        c = a.get("c")
        self.assertEqual((c.line, c.end, c.col), (3, 6, 2))
        self.assertEqual([i.line for i in c.items()], [4, 5])
        self.assertEqual(c.items()[0].value, "x")
        self.assertEqual(c.items()[1].keys()[0].name if c.items()[1].keys() else "y", "y")
        self.assertEqual((d.line, d.end), (7, 10))
        self.assertEqual(e.line, 11)
        self.assertEqual(root.end, 12)

    def test_block_range(self):
        root = SUBSET.parse_workflow(self.DOC)
        self.assertEqual(root.get("d").block, (8, 9))
        self.assertIsNone(root.get("e").block)
        self.assertIsNone(root.get("a").block)

    def test_block_stops_at_next_structure_row_6611(self):
        # the block ends at the next structure row even when a nested mapping follows it, so the
        # nested rows are never read as block text (pins the row_lines / bisection of #6611)
        doc = "".join("k%d: 1\n" % i for i in range(9)) + "b: |\n  x\nc:\n  y: 1\n  z: 2\n"
        b = SUBSET.parse_workflow(doc).get("b")
        self.assertEqual(b.block, (11, 11))
        self.assertEqual(b.block_lines, [(11, "  x")])

    def test_quote_in_plain_key_refused_6617(self):
        for doc, n in (("a:\n  b'c: 1\n", 2), ('a:\n  x: 1\n  b"c: 1\n', 3)):
            with self.assertRaises(Unparsed) as ctx:
                SUBSET.parse_workflow(doc)
            self.assertIn("line %d: quote character inside a plain mapping key" % n, str(ctx.exception))
        self.assertIsNotNone(SUBSET.parse_workflow("\"on\": push\n"))  # top level quoted on stays readable

    def test_depth_cap_named_refusal_6612(self):
        self.assertIsNotNone(SUBSET.parse_workflow("".join(" " * i + "k%d:\n" % i for i in range(64))))
        with self.assertRaises(Unparsed) as ctx:
            SUBSET.parse_workflow("".join(" " * i + "k%d:\n" % i for i in range(200)))
        self.assertIn("line 65: nesting deeper than 64 levels", str(ctx.exception))
        with self.assertRaises(Unparsed) as ctx:
            SUBSET.parse_workflow("a:\n  " + "- " * 200 + "x\n")
        self.assertIn("nesting deeper than 64 levels", str(ctx.exception))
        self.assertIsNotNone(SUBSET.parse_workflow("a: " + "[" * 64 + "]" * 64 + "\n"))
        with self.assertRaises(Unparsed) as ctx:
            SUBSET.parse_workflow("a: " + "[" * 2000 + "]" * 2000 + "\n")
        self.assertIn("line 1: flow collection nested deeper than 64 levels", str(ctx.exception))

    def test_walk_is_iterative_document_order_6612(self):
        root = SUBSET.parse_workflow("".join(" " * i + "k%d:\n" % i for i in range(64)) + "z: 1\n")
        names = [n.name for n in root.walk() if n.kind == "key"]
        self.assertEqual(names, ["k%d" % i for i in range(64)] + ["z"])

    def test_8000_block_scalars_parse_in_linear_time_6611(self):
        import time
        for doc in ("a:\n" + "".join("  k%d: |\n    x\n" % i for i in range(8000)),
                    "a:\n" + "".join("  - |\n    x\n" for _ in range(8000)),
                    "".join("k%d: |\n  x\n" % i for i in range(8000))):
            start = time.monotonic()
            SUBSET.parse_workflow(doc)
            self.assertLess(time.monotonic() - start, 5.0)

    def test_block_excludes_trailing_blank_and_outdented_comment(self):
        root = SUBSET.parse_workflow("k: |\n  one\n\n# tail\nz: 1\n")
        self.assertEqual(root.get("k").block, (2, 2))

    def test_block_keeps_equal_indent_text(self):
        root = SUBSET.parse_workflow("k:\n  s: |\n    one\n    two\n")
        self.assertEqual(root.get("k").get("s").block, (3, 4))

    def test_empty_block_scalar(self):
        self.assertIsNone(SUBSET.parse_workflow("k: |\nz: 1\n").get("k").block)

    def test_block_scalar_last_line_without_newline(self):
        self.assertEqual(SUBSET.parse_workflow("k: |\n  one").get("k").block, (2, 2))

    def test_walk_order_and_get(self):
        root = SUBSET.parse_workflow("a:\n  b: 1\nc: 2\n")
        self.assertEqual([n.name for n in root.walk()], ["", "a", "b", "c"])
        self.assertIsNone(root.get("zz"))
        self.assertEqual(len(root.keys()), 2)
        self.assertEqual(root.items(), [])

    def test_sequence_item_value_and_nested_dash(self):
        root = SUBSET.parse_workflow("l:\n  - a\n  - b: 1\n    c: 2\n")
        items = root.get("l").items()
        self.assertEqual([i.value for i in items], ["a", ""])
        self.assertEqual([k.name for k in items[1].keys()], ["b", "c"])

    def test_nested_dashes_value_on_last_only(self):
        root = SUBSET.parse_workflow("l:\n  - - x\n")
        outer = root.get("l").items()[0]
        self.assertEqual(outer.value, "")
        self.assertEqual(outer.items()[0].value, "x")

    def test_casefold_duplicate_refused_with_lines(self):
        self.assertTrue(refused("A: 1\na: 2\n", "line 2"))
        self.assertTrue(refused("x:\n  A: 1\n  a: 2\n", "line 3"))
        self.assertTrue(refused("x:\n  a: 1\n  A: 2\n", "line 3"))
        self.assertTrue(refused("x:\n  A: 1\n  a: 2\n", "first on line 2"))

    def test_same_key_in_different_parents_allowed(self):
        SUBSET.parse_workflow("x:\n  a: 1\nq:\n  a: 2\n")

    def test_key_after_item_same_name_allowed(self):
        SUBSET.parse_workflow("l:\n  - a: 1\n  - a: 2\n")

    def test_document_marker_refused_with_line(self):
        self.assertTrue(refused("a: 1\n---\nb: 2\n", "line 2"))

    def test_leading_document_marker_parses(self):
        root = SUBSET.parse_workflow("---\na: 1\n")
        self.assertEqual(root.get("a").line, 2)

    def test_failing_line_for_reader_refusals(self):
        self.assertTrue(refused("a: 1\nb: &x 2\n", "line 2"))
        self.assertTrue(refused("a: 1\nb: *x\n", "line 2"))
        self.assertTrue(refused("a: 1\n<<: *x\n", "line 2"))
        self.assertTrue(refused("a: 1\nb: 2\n\tc: 3\n", "line 3"))
        self.assertTrue(refused("a: 1\nb: 2\nc: 3\nd: 4\ne: 5\nb: 6\n", "line 6"))
        self.assertTrue(refused("a: 1\nb: 2\nc: 3\nd: 4\ne: &z 5\nf: 6\n", "line 5"))

    def test_failing_line_for_stream_checks(self):
        for bad in ("\ufeffa: 1\n", "a: 1\u2028b: 2\n", "a: 1\n\u0085b: 2\n", "a: 1\rb: 2\n"):
            with self.assertRaises(Unparsed):
                SUBSET.parse_workflow(bad)
        self.assertTrue(refused("a: 1\nb: 2\n\u2028c: 3\n", "line 3"))
        self.assertTrue(refused("a: 1\nb: 2\nc: \x01\n", "line 3"))
        self.assertTrue(refused("a: 1\r\nb: 2\rc: 3\r\n", "line 2"))
        self.assertTrue(refused("a: 1\nb: 2\n\ufeffc: 3\n", "line 3"))

    def test_failing_line_for_top_level_checks(self):
        self.assertTrue(refused("a: 1\nb: 2\na: 3\n", "line 3"))

    def test_helpers(self):
        self.assertEqual(SUBSET.scalar_of('"x y"'), "x y")
        self.assertEqual(SUBSET.scalar_of("plain"), "plain")
        self.assertEqual(SUBSET.flow_of("[a, b]"), ["a", "b"])
        self.assertEqual(SUBSET.flow_of("{a: 1}"), {"a": "1"})
        self.assertEqual(SUBSET.key_name('"on"'), "on")
        self.assertEqual(SUBSET.key_name("on"), "on")


class OnEvents(unittest.TestCase):
    def ev(self, text):
        return GATE.on_events(text)

    def test_forms(self):
        self.assertEqual(self.ev("on: push\n"), {"push", "push"} | {"push"})
        self.assertEqual(self.ev("on: [push, pull_request]\n"), {"push", "pull_request"})
        self.assertEqual(self.ev("on: {push: {}, pull_request: {}}\n"), {"push", "pull_request"})
        self.assertEqual(self.ev("on:\n  - push\n  - pull_request\n"), {"push", "pull_request"})
        self.assertEqual(self.ev("on:\n  push:\n    branches: [a]\n  schedule:\n    - cron: x\n"), {"push", "schedule"})
        self.assertEqual(self.ev("name: x\n"), set())

    def test_refusals(self):
        for text, needle in (
                ("on: |\n  push\n", "block scalar"), ("on:\n", "empty"), ("on: [[a]]\n", "not a scalar"),
                ("on:\n  - [a]\n", "not a scalar"), ("on:\n  - a: b\n", "not a scalar"),
                ("on:\n  - {a: b}\n", "not a scalar"), ("on:\n  -\n", "not a scalar"),
                ("on:\n  - |\n    x\n", "not a scalar"),
                ("on:\n  yes:\n", "boolean"), ("on:\n  NULL:\n", "boolean"), ("on:\n  On:\n", "boolean"),
                ("on:\n  push-é:\n", "ASCII"), ("on:\n  1push:\n", "ASCII")):
            with self.assertRaises(Unparsed, msg=text) as ctx:
                self.ev(text)
            self.assertIn(needle, str(ctx.exception), text)

    def test_refusal_line_numbers(self):
        with self.assertRaises(Unparsed) as ctx:
            self.ev("name: x\non:\n  push:\n  yes:\n")
        self.assertIn("line 4", str(ctx.exception))

    def test_forbidden_case_and_sorted(self):
        self.assertEqual(GATE.forbidden_triggers("on:\n  Workflow_Call:\n  PULL_REQUEST_TARGET:\n  push:\n"),
                         ["pull_request_target", "workflow_call"])
        self.assertEqual(GATE.forbidden_triggers("on: [workflow_run]\n"), ["workflow_run"])
        self.assertEqual(GATE.forbidden_triggers("on: push\n"), [])


class TokenPins(unittest.TestCase):
    def problems(self, text):
        return GATE.job_token_problems(text)

    def has(self, text, needle):
        found = [p for p in self.problems(text) if needle in p]
        return found

    def test_empty_workflow_names_the_document(self):
        got = GATE.workflow_pin_problems("")
        self.assertTrue([p for p in got if "line 0: document has the shape empty" in p], got)

    def test_committed_is_clean(self):
        self.assertEqual(self.problems(WF), [])
        self.assertEqual(GATE.workflow_pin_problems(WF), [])

    def test_secret_line_numbers(self):
        text = with_verifier("    env:\n      EXTRA: ${{ secrets.PAT }}\n")
        n = text.split("\n").index("      EXTRA: ${{ secrets.PAT }}") + 1
        self.assertTrue(self.has(text, f"references a repository secret (line {n})"))

    def test_secret_first_and_last_line_of_job(self):
        first = with_verifier("")
        lines = first.split("\n")
        start = lines.index("  carrier-ruleset-live-gate:")
        lines.insert(start + 1, "    # ${{ secrets.NOPE }}")  # a real comment: not a reference
        self.assertEqual(self.problems("\n".join(lines)), [])

    def test_secret_last_line_of_final_section(self):
        text = WF.rstrip("\n") + "\nenv:\n  K: ${{ secrets.X }}"
        self.assertTrue(self.has(text, "workflow references a repository secret"))
        text2 = WF.rstrip("\n") + "\nenv:\n  K: v # ${{ secrets.X }}"
        self.assertEqual(self.problems(text2), [])
        # #6610: a top-level key outside the closed workflow shape is refused with its line
        text3 = WF.rstrip("\n") + "\nzz:\n  k: v\n"
        n = len(WF.rstrip("\n").split("\n")) + 1
        self.assertTrue(self.has(text3, f"line {n}: zz is not an allowed key here"))

    def test_hash_secret_hidden_in_block_scalar_first_and_last(self):
        for body in ("        run: |\n          echo a #${{ secrets.P }}\n          echo b\n          echo c\n",
                     "        run: |\n          echo a\n          echo b\n          echo c #${{ secrets.P }}\n"):
            text = WF.replace("        run: python3 -I scripts/check_carrier_ruleset_live.py\n", body, 1)
            self.assertTrue(self.has(text, "references a repository secret"), body)

    def test_comment_hash_is_not_a_reference(self):
        text = with_verifier("    env:\n      EXTRA: ok # ${{ secrets.P }}\n")
        self.assertEqual(self.problems(text), [])
        self.assertTrue(self.has(with_verifier("    env:\n      EXTRA: ok\u00a0# ${{ secrets.P }}\n"), "secret"))
        self.assertTrue(self.has(with_verifier("    env:\n      EXTRA: ok\u3000# ${{ secrets.P }}\n"), "secret"))
        with self.assertRaises(Unparsed):  # a tab on a structure row is refused outright
            self.problems(with_verifier("    env:\n      EXTRA: ok\t# ${{ secrets.P }}\n"))

    def test_needs_reads(self):
        text = with_verifier("    env:\n      EXTRA: ${{ needs.a.outputs.b }}\n")
        self.assertTrue(self.has(text, "reads a needs output or declares needs"))
        text = with_verifier("    needs: other\n")
        self.assertTrue(self.has(text, "job carrier-ruleset-live-gate declares needs (line"))
        # workflow-level text is not a job: a needs expression there is not this pin's concern
        clean = WF.replace("permissions:\n  contents: read\n", "permissions:\n  contents: read\nenv:\n  K: ${{ needs.a.b }}\n", 1)
        self.assertNotEqual(clean, WF)
        self.assertEqual([p for p in self.problems(clean) if "needs" in p], [])

    def test_token_values(self):
        for body, bad in (("    env:\n      GH_TOKEN: ${{ github.token }}x\n", True),
                          ("    env:\n      gh_token: ${{ github.token }}\n", False),
                          ("    env:\n      Github_Token: abc\n", True),
                          ("    env: {GH_TOKEN: abc}\n", True),
                          ("    env: {gh_token: abc}\n", True),
                          ("    env: {OTHER: abc}\n", True),
                          ("    env: {GH_TOKEN: \"${{ github.token }}\"}\n", True),
                          ("    env: plain\n", True),
                          ("    env:\n      OTHER: |\n        abc\n", True)):
            text = with_verifier(body)
            got = [p for p in self.problems(text) if "TOKEN" in p.upper() or "allowed-shape accessor" in p]
            self.assertEqual(bool(got), bad, body)
        # 3-agent vote (6def5ab6): an env value is read as a scalar through the accessor, so the refusal
        # names the shape and the line instead of comparing raw text
        flow = with_verifier("    env: {OTHER: abc}\n")
        n = flow.split("\n").index("    env: {OTHER: abc}") + 1
        self.assertTrue(self.has(flow, f"line {n}: env has the shape flow mapping"))

    def test_permissions(self):
        for grant, bad in (("write", True), ("Write-All", True), ("WRITE", True), (" write ", True),
                           ("read", False), ("read-all", True), ("none", False), ("Read", True)):
            # #6620: the contents: and the issues: grant are separate variants, each asserted
            contents = with_verifier("").replace("      contents: read\n      issues: read\n    steps:",
                                                 f"      contents: {grant}\n      issues: read\n    steps:", 1)
            issues = with_verifier("").replace("      issues: read\n    steps:", f"      issues: {grant}\n    steps:", 1)
            for text in (contents, issues):
                self.assertTrue(grant == "read" or text != with_verifier(""), grant)
                got = [p for p in self.problems(text) if "job carrier-ruleset-live-gate permissions grant write" in p]
                self.assertEqual(bool(got), bad, grant)
        scalar = WF.replace("permissions:\n  contents: read\n", "permissions: write-all\n", 1)
        self.assertTrue([p for p in self.problems(scalar) if "grant write" in p])

    def test_missing_and_imitating_jobs(self):
        lowered = WF.replace("  carrier-ruleset-live-gate:\n", "  Carrier-Ruleset-Live-Gate:\n", 1)
        got = self.problems(lowered)
        self.assertTrue([p for p in got if "imitates" in p])
        self.assertTrue([p for p in got if "not found" in p])
        decoy_id = WF.replace("  carrier-ruleset-live-gate:\n", "  Carrier-Ruleset-Live-Gate:\n", 1).replace(
            "    name: Carrier-ruleset live verifier (#6143)\n", "    name: unrelated\n", 1)
        self.assertTrue([p for p in self.problems(decoy_id) if "Carrier-Ruleset-Live-Gate" in p and "imitates" in p])
        gone = WF.replace("  carrier-ruleset-live-gate:\n", "  other-job:\n", 1)
        got = self.problems(gone)
        self.assertTrue([p for p in got if "job carrier-ruleset-live-gate not found" in p])
        self.assertTrue([p for p in got if "other-job" in p and "imitates" in p])  # still claims the name
        renamed = WF.replace("    name: Carrier-ruleset live verifier (#6143)\n", "    name: Something else\n", 1)
        self.assertTrue([p for p in self.problems(renamed) if "does not carry name" in p])
        noname = WF.replace("    name: Carrier-ruleset live verifier (#6143)\n", "", 1)
        self.assertTrue([p for p in self.problems(noname) if "does not carry name" in p])
        upper = WF.replace("    name: Carrier-ruleset live verifier (#6143)\n", "    name: CARRIER-RULESET LIVE VERIFIER (#6143)\n", 1)
        self.assertTrue([p for p in self.problems(upper) if "does not carry name" in p])

    def test_verifier_must_set_gh_token(self):
        lower = WF.replace("          GH_TOKEN: ${{ github.token }}\n        run: python3 -I scripts/check_carrier_ruleset_live.py\n",
                           "          gh_token: ${{ github.token }}\n        run: python3 -I scripts/check_carrier_ruleset_live.py\n", 1)
        self.assertNotEqual(lower, WF)
        self.assertTrue([p for p in self.problems(lower) if "does not set GH_TOKEN" in p])  # #6620, mutant R16
        for spelling in ("SECRETS", "Secrets", "sEcReTs"):  # #6620, mutant R23
            text = with_verifier(f"    env:\n      EXTRA: ${{{{ {spelling}.PAT }}}}\n")
            self.assertTrue(self.has(text, "references a repository secret"), spelling)
        for old, new in (("          GH_TOKEN: ${{ github.token }}\n        run: python3 -I scripts/check_carrier_ruleset_live.py\n",
                          "          GITHUB_TOKEN: ${{ github.token }}\n        run: python3 -I scripts/check_carrier_ruleset_live.py\n"),
                         ("          GH_TOKEN: ${{ github.token }}\n        run: python3 -I scripts/check_carrier_ruleset_live.py\n",
                          "        run: python3 -I scripts/check_carrier_ruleset_live.py\n")):
            text = WF.replace(old, new, 1)
            self.assertNotEqual(text, WF)
            self.assertTrue([p for p in self.problems(text) if "does not set GH_TOKEN" in p])

    def test_workflow_pin_reports_unreadable(self):
        got = GATE.workflow_pin_problems("\ufeff" + WF)
        self.assertEqual(len(got), 1)
        self.assertIn("not readable", got[0])
        forbidden = WF.replace("on:\n", "on:\n  workflow_call:\n", 1) if "\non:\n" in WF else None
        if forbidden:
            self.assertTrue([p for p in GATE.workflow_pin_problems(forbidden) if "forbidden trigger" in p])


def pr_on(block):
    """A workflow whose `on:` is `block` (indented two spaces under `on:`)."""
    return "on:\n" + block + "jobs: {}\n"


class CheckTipWiring(unittest.TestCase):
    """#6619: check_tip (pre-apply and the release-tip check) reports every workflow pin problem."""

    def tip(self, text):
        return GATE.check_tip("t", text, "rehearsal/audit-wip", GATE.CARRIER_JOBS)

    def test_clean_tip(self):
        self.assertEqual(self.tip(WF), [])

    def test_pin_problems_reach_check_tip(self):
        forbidden = WF.replace("\non:\n", "\non:\n  workflow_run:\n    workflows: [x]\n", 1)
        self.assertNotEqual(forbidden, WF)
        self.assertIn("t: workflow names the forbidden trigger workflow_run", self.tip(forbidden))
        no_perm = WF.replace("\npermissions:\n  contents: read\n", "\n", 1)
        self.assertNotEqual(no_perm, WF)
        self.assertTrue([r for r in self.tip(no_perm) if r.startswith("t: workflow permissions grant write")])
        secret = with_verifier("    env:\n      EXTRA: ${{ secrets.PAT }}\n")
        self.assertTrue([r for r in self.tip(secret) if "references a repository secret" in r])

    def test_refused_tip_names_line(self):
        got = self.tip("\ufeff" + WF)
        self.assertTrue([r for r in got if r.startswith("t: workflow is not readable by the fail-closed reader: line 1")])


class TriggerFilters(unittest.TestCase):
    """trigger_covers reads `on.pull_request` filters through the allowed-shape accessor (#6610)."""

    def test_flow_list_filter(self):
        self.assertTrue(GATE.trigger_covers(pr_on("  pull_request:\n    branches: [a, rel/*]\n"), "rel/x"))
        self.assertFalse(GATE.trigger_covers(pr_on("  pull_request:\n    branches: [a, b]\n"), "rel/x"))

    def test_block_list_filter(self):
        self.assertTrue(GATE.trigger_covers(pr_on("  pull_request:\n    branches:\n      - a\n      - b\n"), "b"))
        self.assertFalse(GATE.trigger_covers(pr_on("  pull_request:\n    branches:\n      - a\n"), "b"))

    def test_scalar_filter(self):
        self.assertTrue(GATE.trigger_covers(pr_on("  pull_request:\n    branches: main\n"), "main"))

    def test_negation_and_ignore(self):
        self.assertFalse(GATE.trigger_covers(pr_on("  pull_request:\n    branches: ['**', '!rel/x']\n"), "rel/x"))
        self.assertFalse(GATE.trigger_covers(pr_on("  pull_request:\n    branches-ignore: [rel/*]\n"), "rel/x"))
        self.assertTrue(GATE.trigger_covers(pr_on("  pull_request:\n    branches-ignore: [other]\n"), "rel/x"))

    def test_shapes_not_read_fail_closed(self):
        for block in ("  pull_request: {branches: [x]}\n",           # flow mapping event
                      "  pull_request:\n    branches: |\n      x\n",  # block scalar filter
                      "  pull_request:\n    branches:\n      - [x]\n",  # nested flow entry
                      "  pull_request:\n    labels: [x]\n",          # key outside the five filters
                      "  pull_request:\n    paths: [src/**]\n",
                      "  pull_request:\n    types: [opened]\n",
                      "  pull_request:\n    branches: [x]\n    branches-ignore: [y]\n",
                      "  pull_request:\n    branches: ['x?']\n"):
            self.assertFalse(GATE.trigger_covers(pr_on(block), "x"), block)

    def test_empty_and_null_event(self):
        for block in ("  pull_request:\n", "  pull_request: null\n", "  pull_request: ~\n"):
            self.assertTrue(GATE.trigger_covers(pr_on(block), "x"), block)

    def test_list_forms(self):
        self.assertTrue(GATE.trigger_covers("on: [push, pull_request]\n", "x"))
        self.assertTrue(GATE.trigger_covers("on:\n  - push\n  - pull_request\n", "x"))
        self.assertTrue(GATE.trigger_covers("on: pull_request\n", "x"))
        self.assertFalse(GATE.trigger_covers("on:\n  - push\n", "x"))
        self.assertFalse(GATE.trigger_covers("on: {pull_request: null}\n", "x"))


class HostileText(unittest.TestCase):
    def test_hostile_text_never_covers_or_defines(self):
        job, ctx = GATE.VERIFIER_JOB_ID, GATE.VERIFIER_CONTEXT
        self.assertTrue(GATE.job_defined(WF, job, ctx))
        self.assertTrue(GATE.trigger_covers(WF, "rehearsal/audit-wip"))
        for bad in ("\ufeff" + WF, WF + "\n# \u2028x\n", WF.replace("\n", "\n\u0085", 1)):
            with self.assertRaises(Unparsed):
                SUBSET.parse_workflow(bad)
            self.assertFalse(GATE.job_defined(bad, job, ctx))
            self.assertFalse(GATE.trigger_covers(bad, "rehearsal/audit-wip"))


class Round9AccessorShape(unittest.TestCase):
    """#6679: child() refuses a node that is not a block mapping; #6680: a repeated flow key is refused;
    #6681: echoed row text is cut and token-shaped strings are masked."""

    def test_child_refuses_flow_mapping_6679(self):
        root = SUBSET.parse_workflow("jobs:\n  decoy: {name: x, permissions: write-all}\n")
        decoy = root.get("jobs").get("decoy")
        with self.assertRaisesRegex(Unparsed, r"line 2: decoy has the shape flow mapping; allowed: block mapping"):
            SUBSET.child(decoy, "name")
        with self.assertRaisesRegex(Unparsed, r"line 2: decoy has the shape flow mapping"):
            SUBSET.child(decoy, "permissions")

    def test_child_refuses_scalar_empty_and_sequence_6679(self):
        root = SUBSET.parse_workflow("a: x\nb:\nc: [x]\nd:\n  - x\n")
        for key, form in (("a", "plain scalar"), ("b", "empty"), ("c", "flow sequence"), ("d", "block sequence")):
            with self.assertRaisesRegex(Unparsed, "has the shape " + form):
                SUBSET.child(root.get(key), "name")

    def test_child_refuses_empty_document_6679(self):
        with self.assertRaisesRegex(Unparsed, "line 0: document has the shape empty"):
            SUBSET.child(SUBSET.parse_workflow(""), "jobs")

    def test_child_reads_block_mapping_6679(self):
        root = SUBSET.parse_workflow("jobs:\n  a:\n    name: x\n")
        job = root.get("jobs").get("a")
        self.assertIs(SUBSET.child(job, "name"), job.get("name"))
        self.assertIsNone(SUBSET.child(job, "permissions"))

    def test_flow_job_reported_with_line_6679(self):
        text = WF.replace("  carrier-base-fresh-gate:\n",
                          '  decoy: {name: "Carrier-ruleset live verifier (#6143)"}\n  carrier-base-fresh-gate:\n', 1)
        at = text.split("\n").index('  decoy: {name: "Carrier-ruleset live verifier (#6143)"}') + 1
        got = GATE.workflow_pin_problems(text)
        self.assertTrue([p for p in got if f"job decoy (line {at}) is not a block mapping" in p], got)

    def test_flow_duplicate_key_refused_6680(self):
        self.assertTrue(refused("on: {push: x, push: y}\n", "repeated flow mapping key"))
        self.assertTrue(refused("on: {push: x, Push: y}\n", "repeated flow mapping key"))
        self.assertTrue(refused("on: {push: {branches: [a], branches: [b]}}\n", "repeated flow mapping key"))
        self.assertTrue(refused("a:\n  b: {k: 1, k: 2}\n", "line 2: repeated flow mapping key"))
        self.assertEqual(SUBSET.flow_of("{push: x, pull_request: y}"), {"push": "x", "pull_request": "y"})

    def test_mask_withholds_the_whole_value_6735(self):
        tail = "LEAK" + "TAIL123"
        for row in ("API_KEY: abc,%s", "PASSWORD: abc]%s", "TOKEN: abc}%s", "TOKEN: abc #%s",
                    "export TOKEN=abc,%s", "PASSWORD: ${{ secrets.P }} %s", "TOKEN: ${{ 'x' }}%s",
                    "TOKEN: ${{ a }}${{ b }}%s", "PASSWORD: ${{ secrets.P }},%s",
                    "PASSWORD: ${{ secrets.A }} %s ${{ secrets.B }}"):
            self.assertNotIn(tail, SUBSET.mask(row % tail), row)
            self.assertNotIn(tail, SUBSET.clip(row % tail), row)
        self.assertEqual(SUBSET.mask("GH_TOKEN: ${{ github.token }}"), "GH_TOKEN: ${{ github.token }}")
        self.assertEqual(SUBSET.mask("GH_TOKEN: ${{ github.token }}'"), "GH_TOKEN: ${{ github.token }}'")
        self.assertEqual(SUBSET.mask(SUBSET.mask("A_TOKEN: abc,d")), SUBSET.mask("A_TOKEN: abc,d"))
        self.assertNotIn("github.token", SUBSET.mask("GH_TOKEN: ${{ github.token }} x"))

    def test_mask_token_glued_to_a_word_6736(self):
        for glue in ("MY_", "9", "x", "%3A", "_"):
            tok = "gh" + "p_" + "Q" * 36
            self.assertNotIn("Q" * 8, SUBSET.mask("v=" + glue + tok), glue)
            self.assertNotIn("Q" * 8, SUBSET.mask("v " + glue + "github" + "_pat_" + "Q" * 40), glue)
            self.assertNotIn("Q" * 8, SUBSET.mask("v " + glue + "github" + "_pat_" + "Q" * 20 + "_" + "Q" * 20), glue)

    def test_credential_vocabulary_6739(self):
        for name in ("Authorization", "bearer", "NPM_AUTH", "db_pass", "pwd", "passphrase", "AWS_ACCESS_KEY_ID",
                     "session_id", "cookie", "signing_key"):
            self.assertNotIn("VALUE9", SUBSET.mask(name + ": VALUE9"), name)

    def test_flow_duplicate_key_uppercase_first_6745(self):
        self.assertTrue(refused("on: {Push: x, push: y}\n", "repeated flow mapping key"))
        self.assertTrue(refused("a:\n  b: {REF: a, ref: b}\n", "line 2: repeated flow mapping key"))

    def test_clip_caps_and_masks_6681(self):
        self.assertEqual(SUBSET.clip("a" * 120), "a" * 120)
        self.assertEqual(SUBSET.clip("a" * 121), "a" * SUBSET.ECHO_LIMIT + "...")
        tok = "gh" + "p_" + "Q" * 36
        self.assertNotIn("Q" * 8, SUBSET.clip("x " + tok))
        self.assertNotIn("Q" * 8, str(Unparsed("refused: " + tok)))
        self.assertNotIn("SECRETVALUE", SUBSET.clip("GH_TOKEN: SECRETVALUE"))
        self.assertIn("${{ github.token }}", SUBSET.clip("GH_TOKEN: ${{ github.token }}"))



class Round11EchoMask(unittest.TestCase):
    """#6791 #6792 #6780 #6781 #6782 #6783: the echo mask masks a token cut by its window, keeps only a marker it
    produced, owns nested values by the credential key above them, withholds literal operands, and an echoed row
    keeps only its key."""

    TAIL = "LEAK" + "TAIL123"

    def test_clip_masks_a_token_cut_by_the_window_6791(self):
        for k in range(455, 490):
            body = k - 25
            sizes = [body // 5 + (1 if i < body % 5 else 0) for i in range(5)]
            row = "".join("gh" + "p_" + "A" * n + " " for n in sizes) + "gh" + "p_" + "Zq7" * 40
            self.assertNotIn("ghp_Z", SUBSET.clip(row), k)
        self.assertEqual(SUBSET.mask("v gh" + "p_abc"), "v gh" + "p_<masked>")
        self.assertEqual(SUBSET.mask("v gh" + "p_abc def"), "v gh" + "p_abc def")

    def test_mask_keeps_only_its_own_marker_6792(self):
        self.assertNotIn("X", SUBSET.mask("PASSWORD: <withheld 9 chars> X"))
        self.assertNotIn(self.TAIL, SUBSET.mask("PASSWORD: <withheld ${{ secrets.P }} " + self.TAIL))
        once = SUBSET.mask("A_TOKEN: abc,d")
        self.assertEqual(SUBSET.mask(once), once)
        self.assertEqual(SUBSET.mask("A_TOKEN: <withheld 5 chars>"), "A_TOKEN: <withheld 5 chars>")

    def test_owned_strings_carry_the_credential_owner_down_6780(self):
        root = SUBSET.parse_workflow(
            "PASSWORD:\n  inner: x\n  list:\n    - k: y\nNAME:\n  inner: p\nflow: {PASSWORD: {inner: z}}\n")
        owners = {text: owner for _line, owner, text in SUBSET.owned_strings(root) if text in ("x", "y", "z", "p")}
        self.assertEqual(owners, {"x": "PASSWORD", "y": "PASSWORD", "z": "PASSWORD", "p": "inner"})

    def test_withhold_value_names_the_owner_and_never_the_text_6781(self):
        for owner in ("TOKEN+X", "PASSWORD", "inner", ""):
            got = SUBSET.withhold_value(owner, " " + self.TAIL + " ")
            self.assertNotIn(self.TAIL, got)
            self.assertIn("<withheld %d chars>" % len(self.TAIL), got)
            self.assertTrue(got.startswith(owner), got)

    def test_numeric_and_keyword_operands_are_withheld_6782(self):
        for expr in ("secrets.P || 31337", "0xDEADBEEF", "1.5e7", "secrets.P || true", "a == null", "a && !false",
                     "secrets.P || NaN", "a == 3", "secrets.P || -1", "(1)"):
            got = SUBSET.mask("PIN_TOKEN: ${{ " + expr + " }}")
            self.assertIn("<withheld", got, expr)
        for expr in ("github.token", "secrets.P || secrets.Q", "!(a.b && c-d.e)", "a == b", "trueish.x",
                     "needs.build.outputs.v1"):
            self.assertEqual(SUBSET.mask("PIN_TOKEN: ${{ " + expr + " }}"), "PIN_TOKEN: ${{ " + expr + " }}", expr)

    def test_an_echoed_row_keeps_only_its_key_6783(self):
        self.assertEqual(SUBSET.echo("      PASSWORD: hunter2"), repr("      PASSWORD: <withheld 7 chars>"))
        self.assertEqual(SUBSET.echo("curl --password=hunter2"), repr("curl --password=<withheld 7 chars>"))
        self.assertEqual(SUBSET.echo("T\u041eKEN: " + self.TAIL), repr("T\u041eKEN: <withheld 11 chars>"))
        self.assertEqual(SUBSET.echo("short row"), repr("short row"))
        long_row = "--password " + self.TAIL + " and more text to run past the prefix"
        self.assertEqual(SUBSET.echo(long_row), repr(long_row[:24] + "..."))
        self.assertNotIn(self.TAIL, SUBSET.echo("A: " + "x" * 600 + self.TAIL))


if __name__ == "__main__":
    unittest.main()
