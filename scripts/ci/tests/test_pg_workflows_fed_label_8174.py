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
      same branch ci.yml takes for its macos-fed enterprise-fed leg.

Run: python3 -m unittest discover -s scripts/ci/tests -p 'test_pg_workflows_fed_label_8174.py'
"""
import re
import unittest
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
    for i in range(start, len(body)):
        word = body[i].strip()
        if word.startswith("if ") and len(IF_FI_WORD.findall(word)) == 1:
            depth += 1
        elif word == "fi":
            depth -= 1
            if depth == 0:
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
                guard_at = text.index(HEAL_GUARD)
                heal_at = text.index(HEAL_SCRIPT)
                create_at = text.index("CREATE EXTENSION IF NOT EXISTS age")
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

    def test_every_mutation_row_is_detected(self):
        """code r1 F1/F2: each of M11-M14 applied to an in-memory copy must be reported."""
        base = WORKFLOWS[0].read_text(encoding="utf-8")
        for name, (old, new) in MUTATIONS.items():
            with self.subTest(mutation=name):
                self.assertEqual(base.count(old), 1, "mutation anchor drifted")
                self.assertNotEqual(macos_defects(base.replace(old, new, 1).splitlines()), [])


if __name__ == "__main__":
    unittest.main()
