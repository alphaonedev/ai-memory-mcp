#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin #8174: the two Postgres workflows run on EITHER fed node.

``postgres-ignored.yml`` and ``cert-postgres-age.yml`` used to pin their job to
``[self-hosted, linux-fed]`` while the macos-fed tier idled. The custom label
``fed`` is carried by every runner on both nodes, so ``[self-hosted, fed]``
lets whichever node is free take the job. Properties pinned (stdlib only,
Python 3.9+; workflows are read by line because PyYAML is not guaranteed on
every node):

  (a) the single job of each workflow has ``runs-on: [self-hosted, fed]``;
  (b) no ``run:`` block contains a GNU-only token (a macOS runner has BSD tools);
  (c) each workflow self-heals the hand-built macOS AGE install through
      ``scripts/ci/ensure-age-extension.py`` behind a ``$RUNNER_OS`` check, the
      same branch ci.yml takes for its macos-fed enterprise-fed leg. The guard body is pinned
      to exactly the heal call: the stripped lines between the guard line and the guard's
      closing ``fi`` must equal the stripped ``HEAL_CALL`` lines, same order, same count. The
      end is therefore never trusted from line shape alone: a late end or a data ``fi`` (a
      quote of one kind inside a string of the other, ``\\'`` inside single quotes, an
      arithmetic ``(( ))`` command naming ``if`` / ``fi``) changes the body and is refused as a
      named defect. ``guard_end`` keeps its own refusals (unprovable line, not indented deeper,
      uncountable if/fi, guard ``fi`` off the guard indent, no closing ``fi``). Fail-closed
      cost: a valid but different guard body (an elif or case shape) is a named defect too;
      neither live workflow has one.

Run: python3 -m unittest discover -s scripts/ci/tests -p 'test_pg_workflows_fed_label_8174.py'
"""
import re
import unittest
from itertools import zip_longest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORKFLOWS = (
    REPO / ".github" / "workflows" / "postgres-ignored.yml",
    REPO / ".github" / "workflows" / "cert-postgres-age.yml",
)
EXPECTED_RUNS_ON = ["self-hosted", "fed"]
HEAL_SCRIPT = "scripts/ci/ensure-age-extension.py"
HEAL_GUARD = 'if [ "$RUNNER_OS" = "macOS" ]; then'
# GNU-only invocations (name, regex). Each is absent or different on macOS.
GNU_ONLY_TOKENS = (
    ("gtimeout", re.compile(r"\bgtimeout\b")),
    ("timeout", re.compile(r"(?<![-\w])timeout\s")),
    ("du -b", re.compile(r"\bdu\s+-\w*b")),
    ("stat -c", re.compile(r"\bstat\s+-c\b")),
    ("sed -i without suffix", re.compile(r"\bsed\s+(-\w*i\b|--in-place)")),
    ("readlink -f", re.compile(r"\breadlink\s+-f\b")),
    ("date -d", re.compile(r"\bdate\s+-d\b")),
    ("grep -P", re.compile(r"\bgrep\s+-\w*P")),
    ("xargs -r", re.compile(r"\bxargs\s+-\w*r\b")),
    ("sort -V", re.compile(r"\bsort\s+-\w*V")),
)

# Linux-only paths and tools a macOS runner lacks (code r1 F2, #8174).
LINUX_ONLY_TOKENS = (
    ("nproc", re.compile(r"\bnproc\b")),
    ("/proc/", re.compile(r"/proc/")),
    ("free", re.compile(r"(?<![\w./-])free\s+-")),
)
POSTGRES_LINUX_BIN = "/usr/lib/postgresql"
POSTGRES_MACOS_BIN = "/opt/homebrew/opt/postgresql@18/bin"


def lines_of(path):
    return path.read_text(encoding="utf-8").splitlines()


def runs_on_lists(path):
    found = []
    for ln in lines_of(path):
        m = re.match(r"^    runs-on:\s*\[(.*)\]\s*$", ln)
        if m:
            found.append([x.strip() for x in m.group(1).split(",")])
    return found


def run_blocks(path):
    """Each ``run:`` body as a list of non-comment lines."""
    return run_blocks_of(lines_of(path))


def run_blocks_of(lines):
    """``run_blocks`` over already-split text (used for the in-memory mutation rows)."""
    blocks = []
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:- )?run:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1))
        rest = m.group(2).strip()
        body = []
        if rest and rest not in ("|", ">", "|-", ">-"):
            body.append(rest)
        i += 1
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
            if lines[i].strip() and not lines[i].lstrip().startswith("#"):
                body.append(lines[i])
            i += 1
        blocks.append(body)
    return blocks


IF_FI_WORD = re.compile(r"\b(?:if|fi)\b")


def guard_end(body, start):
    """``(end, problem)``: the ``fi`` closing the ``if`` at body[start], by if/fi nesting depth.

    ``end`` is None when unclosed or when a line carries an if/fi the per-line rule cannot count
    (sec r4 F1 = code r4 O1): then ``problem`` names the line. decision: fail closed on uncountable
    if/fi lines over a real shell parser because the pin's job is to refuse what it cannot prove and
    a parser would be a second implementation of bash in a test.
    """
    depth = 0
    indent = len(body[start]) - len(body[start].lstrip())
    for i in range(start, len(body)):
        word = body[i].strip()
        if i > start:
            # code r5 F1 + sec r5 F1: bash reads if/fi as DATA after a continuation, in a heredoc
            # or in a multi-line string; refuse lines that can hide that, then demand indentation.
            bare = word.replace("\\\\", "").replace('\\"', "").replace("\\'", "")
            if word.endswith("\\") or "<<" in word or bare.count('"') % 2 or bare.count("'") % 2:
                return None, "unprovable line in the RUNNER_OS guard: " + word
            if len(body[i]) - len(body[i].lstrip()) <= indent and not (word == "fi" and depth == 1):
                return None, "line inside the guard not indented deeper: " + word
        if word.startswith("if ") and len(IF_FI_WORD.findall(word)) == 1:
            depth += 1
        elif word == "fi":
            depth -= 1
            if depth == 0:
                if len(body[i]) - len(body[i].lstrip()) != indent:
                    return None, "guard fi not at the guard indent: " + word
                return i, None
        elif IF_FI_WORD.search(word):
            return None, "uncountable if/fi line in the RUNNER_OS guard: " + word
    return None, "RUNNER_OS guard has no closing fi"


def heal_defects(lines):
    """The heal call must appear exactly once, inside the RUNNER_OS guard block of its step."""
    inside = 0
    total = 0
    for body in run_blocks_of(lines):
        total += sum(HEAL_SCRIPT in x for x in body)
        for n, ln in enumerate(body):
            if ln.strip() != HEAL_GUARD:
                continue
            end, problem = guard_end(body, n)
            if end is None:
                return [problem]
            # decision: pin the guard body to exactly the heal call over a per-line quote-state
            # scanner because the exact-body pin stops inferring the guard end from line shape at
            # all (no shell lexing left to fool), ends the defect class in one function, and keeps
            # the settled fail-closed no-parser design; a quote scanner would still leave
            # arithmetic and future contexts (y3) open.
            got = [x.strip() for x in body[n + 1:end]]
            want = [x.strip() for x in HEAL_CALL.splitlines()]
            if got != want:
                differing = next(
                    (g if g is not None else "(guard ends before: " + w + ")")
                    for g, w in zip_longest(got, want)
                    if g != w
                )
                return ["RUNNER_OS guard body is not exactly the heal call: " + differing]
            inside += sum(HEAL_SCRIPT in x for x in body[n + 1:end])
    if inside != 1 or total != 1:
        return ["heal call not exactly once inside the guard"]
    return []


def linux_only_defects(lines):
    """Linux-only tools or paths (nproc, /proc/, free) in any run block."""
    return [
        "linux-only " + name
        for body in run_blocks_of(lines)
        for ln in body
        for name, rx in LINUX_ONLY_TOKENS
        if rx.search(ln)
    ]


def twin_defects(lines):
    """A /usr/lib/postgresql search path without the homebrew bin dir beside it."""
    return [
        "no homebrew twin"
        for body in run_blocks_of(lines)
        for ln in body
        if POSTGRES_LINUX_BIN in ln and POSTGRES_MACOS_BIN not in ln
    ]


# One named table of checks: the property tests and the mutation rows both read it.
MACOS_CHECKS = (heal_defects, linux_only_defects, twin_defects)


def macos_defects(lines):
    """All defects of one workflow text, from every check in MACOS_CHECKS."""
    return [d for check in MACOS_CHECKS for d in check(lines)]


HEAL_CALL = (
    '            if ! python3 -I scripts/ci/ensure-age-extension.py --url-file "$url_file"; then\n'
    '              echo "::error::$RUNNER_NAME: AGE self-heal failed (#6161), see the ensure-age-extension line above"\n'
    "              exit 1\n"
    "            fi\n"
)
GUARD_END = HEAL_CALL + "          fi\n"
# Mutation table (code r1 F1/F2): name -> (old text, new text) applied to an in-memory copy of
# postgres-ignored.yml. Every row must make macos_defects report a defect.
MUTATIONS = {
    "M11 heal call moved after the guard fi": (
        GUARD_END,
        "          if true; then\n            :\n          fi\n" + HEAL_CALL.replace("            ", "          "),
    ),
    "M19 guard fi indented deeper, heal block after it at the guard indent": (
        GUARD_END,
        "            :\n            fi\n" + "".join(x[2:] for x in HEAL_CALL.splitlines(keepends=True)),
    ),
    "M20 one-line if/fi in the guard, heal after the real fi, later mid-line if (sec r4 F1 = code r4 O1)": (
        GUARD_END,
        "            if true; then :; fi\n          fi\n"
        + "".join(x[2:] for x in HEAL_CALL.splitlines(keepends=True))
        + "          x=1; if true; then\n            :\n          fi\n",
    ),
    "M21 heredoc body carries if x / fi, heal after the real fi (code r5 F1 = sec r5 F1, x1)": (
        GUARD_END,
        "            cat <<'EOF'\n            if x\n          EOF\n          fi\n"
        + "".join(x[2:] for x in HEAL_CALL.splitlines(keepends=True))
        + "          cat <<'EOF'\n          fi\n          EOF\n",
    ),
    "M22 backslash-continued command whose next line is if x / fi (x2)": (
        GUARD_END,
        "            echo a \\\n            if x\n          fi\n"
        + "".join(x[2:] for x in HEAL_CALL.splitlines(keepends=True))
        + "          echo b \\\n          fi\n",
    ),
    "M23 multi-line double-quoted string carries if x / fi (x3)": (
        GUARD_END,
        '            echo "a\n            if x\n            b"\n          fi\n'
        + "".join(x[2:] for x in HEAL_CALL.splitlines(keepends=True))
        + '          echo "a\n          fi\n          b"\n',
    ),
    "M24 mixed-quote multi-line string hides if x / fi, heal after the real fi (code r6 x9 = sec r6 y1)": (
        GUARD_END,
        "            echo \"'\" '\n            if x\n            x' \"'\"\n            fi\n"
        + HEAL_CALL
        + "            echo \"'\" '\n          fi\n          x' \"'\"\n",
    ),
    "M25 backslash inside single quotes hides if x / fi, heal after the real fi (code r6 x10 = sec r6 y2)": (
        GUARD_END,
        "            echo 'a\\'b'\n            if x\n            x\\'\n            fi\n"
        + HEAL_CALL
        + "            echo 'a\\'b'\n          fi\n          x\\'\n",
    ),
    "M26 heal call is data inside a mixed-quote string in the guard (code r6 x11)": (
        GUARD_END,
        "            echo \"'\" '\n" + HEAL_CALL + "            x' \"'\"\n          fi\n",
    ),
    "M27 multi-line (( )) names if / fi as variables, heal after the real fi (sec r6 y3)": (
        GUARD_END,
        "            (( a = 0 +\n            if +\n            1 ))\n            fi\n"
        + HEAL_CALL
        + "            (( a = 0 +\n          fi\n          + 1 ))\n",
    ),
    "M12 nproc added": (GUARD_END, GUARD_END + "          nproc\n"),
    "M13 /proc/meminfo added": (GUARD_END, GUARD_END + "          cat /proc/meminfo\n"),
    "M14 postgresql bin loop without homebrew twin": (
        GUARD_END,
        GUARD_END + "          for d in /usr/lib/postgresql/18/bin; do :; done\n",
    ),
}


class PgWorkflowsRunOnEitherFedNode(unittest.TestCase):
    def test_runs_on_is_the_shared_fed_label(self):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                self.assertEqual(runs_on_lists(path), [EXPECTED_RUNS_ON])

    def test_no_gnu_only_token_in_any_run_block(self):
        for path in WORKFLOWS:
            blocks = run_blocks(path)
            self.assertGreaterEqual(len(blocks), 4, path.name)
            for body in blocks:
                for ln in body:
                    for name, rx in GNU_ONLY_TOKENS:
                        with self.subTest(workflow=path.name, token=name):
                            self.assertIsNone(rx.search(ln), ln.strip())

    def test_macos_age_self_heal_is_behind_a_runner_os_check(self):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                text = "\n".join("\n".join(b) for b in run_blocks(path))
                self.assertIn(HEAL_GUARD, text)
                create_anchor = "CREATE EXTENSION IF NOT EXISTS age"
                for anchor in (HEAL_GUARD, HEAL_SCRIPT, create_anchor):
                    self.assertIn(anchor, text, "anchor absent from the run blocks: " + anchor)
                guard_at = text.index(HEAL_GUARD)
                heal_at = text.index(HEAL_SCRIPT)
                create_at = text.index(create_anchor)
                self.assertLess(guard_at, heal_at)
                self.assertLess(heal_at, create_at)

    def _assert_check_clean(self, check):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name, check=check.__name__):
                self.assertEqual(check(lines_of(path)), [])

    def test_heal_call_is_inside_the_guard_block_of_one_step(self):
        """code r1 F1: the heal call sits between the guard line and its matching fi."""
        self._assert_check_clean(heal_defects)

    def test_no_linux_only_tool_or_path_in_any_run_block(self):
        """code r1 F2: nproc and /proc are absent on macOS."""
        self._assert_check_clean(linux_only_defects)

    def test_every_linux_postgres_bin_path_has_its_homebrew_twin(self):
        """code r1 F2: a /usr/lib/postgresql search path needs the macOS bin dir beside it."""
        self._assert_check_clean(twin_defects)

    def test_unmutated_workflows_have_no_macos_defect(self):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                self.assertEqual(macos_defects(lines_of(path)), [])

    def test_uncountable_if_fi_line_in_guard_is_a_named_defect(self):
        """sec r4 F1: an if/fi the per-line rule cannot count is reported, never a late guard end."""
        base = WORKFLOWS[0].read_text(encoding="utf-8")
        name = next(n for n in MUTATIONS if n.startswith("M20"))
        old, new = MUTATIONS[name]
        got = heal_defects(base.replace(old, new, 1).splitlines())
        self.assertEqual(len(got), 1, got)
        self.assertIn("uncountable if/fi", got[0])
        self.assertIn("if true; then :; fi", got[0])

    def _defects_with_guard_body(self, body_lines):
        """heal_defects of postgres-ignored.yml with the guard body replaced by ``body_lines``."""
        base = WORKFLOWS[0].read_text(encoding="utf-8")
        guard = '          if [ "$RUNNER_OS" = "macOS" ]; then\n'
        self.assertEqual(base.count(guard + HEAL_CALL), 1, "guard anchor drifted")
        return heal_defects(base.replace(guard + HEAL_CALL, guard + body_lines, 1).splitlines())

    def test_data_fi_rows_are_refused_as_a_body_that_is_not_the_heal_call(self):
        """code r6 F1 / sec r6 F1: M24-M27 end late or hide the call; the exact-body pin names it."""
        base = WORKFLOWS[0].read_text(encoding="utf-8")
        for prefix in ("M24", "M25", "M26", "M27"):
            name = next(n for n in MUTATIONS if n.startswith(prefix))
            old, new = MUTATIONS[name]
            with self.subTest(mutation=prefix):
                got = heal_defects(base.replace(old, new, 1).splitlines())
                self.assertEqual(len(got), 1, got)
                self.assertTrue(got[0].startswith("RUNNER_OS guard body is not exactly the heal call: "), got)

    def test_body_defect_names_the_first_differing_line(self):
        got = self._defects_with_guard_body("            echo extra\n" + HEAL_CALL)
        self.assertEqual(got, ["RUNNER_OS guard body is not exactly the heal call: echo extra"])
        got = self._defects_with_guard_body("")
        self.assertEqual(len(got), 1, got)
        self.assertIn("not exactly the heal call", got[0])

    def test_noop_edits_keep_the_guard_body_exact(self):
        """A comment, an empty line, a uniform re-indent or a full-line ``# don't`` change nothing."""
        calls = HEAL_CALL.splitlines(keepends=True)
        shapes = {
            "comment line in guard": "            # note\n" + HEAL_CALL,
            "empty line in guard": "\n" + HEAL_CALL,
            "full-line # don't": "            # don't\n" + HEAL_CALL,
            "body +2 uniformly": "".join("  " + x for x in calls),
        }
        for label, body in shapes.items():
            with self.subTest(shape=label):
                self.assertEqual(self._defects_with_guard_body(body), [])
        base = WORKFLOWS[0].read_text(encoding="utf-8")
        guard = '          if [ "$RUNNER_OS" = "macOS" ]; then\n'
        whole = guard + GUARD_END
        self.assertEqual(base.count(whole), 1, "guard anchor drifted")
        shifted = "".join("  " + x for x in whole.splitlines(keepends=True))
        self.assertEqual(heal_defects(base.replace(whole, shifted, 1).splitlines()), [])

    def test_valid_elif_and_case_bodies_are_named_defects(self):
        """Fail-closed cost: shapes absent from the live guards are refused, not guessed at."""
        elif_body = (
            "            if a; then\n              :\n            elif b; then\n              :\n"
            "            else\n              :\n            fi\n"
        )
        case_body = '            case "$x" in\n              a) : ;;\n            esac\n'
        for label, body in (("elif", elif_body), ("case", case_body)):
            with self.subTest(shape=label):
                got = self._defects_with_guard_body(body + HEAL_CALL)
                self.assertEqual(len(got), 1, got)
                self.assertIn("not exactly the heal call", got[0])

    def test_every_mutation_row_is_detected(self):
        """code r1 F1/F2: each of M11-M14 applied to an in-memory copy must be reported."""
        base = WORKFLOWS[0].read_text(encoding="utf-8")
        for name, (old, new) in MUTATIONS.items():
            with self.subTest(mutation=name):
                self.assertEqual(base.count(old), 1, "mutation anchor drifted")
                self.assertNotEqual(macos_defects(base.replace(old, new, 1).splitlines()), [])


if __name__ == "__main__":
    unittest.main()
