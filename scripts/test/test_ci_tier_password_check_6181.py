#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin that ci.yml runs the tier password check before it uses the tier URL (#6181).

The "Configure enterprise-fed tier" step must run ``scripts/ci/check-tier-password.py`` as
``python3 -I`` on the URL file, before the first psql call, and a non-zero exit must stop the step
(``exit 1``) with no other branch.  The call must also be reachable (#6671): it sits at the top level of the
step script, with no ``if``/``case``/loop, function body, brace group or subshell open between
``set -euo pipefail`` and the call, and the step's ``if:`` line is exactly ``STEP_IF``.  The check is exercised
against mutants.  Stdlib only.
"""

from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github/workflows/ci.yml"
CHECK = "scripts/ci/check-tier-password.py"
CALL = 'if ! python3 -I ' + CHECK + ' --url-file "$url_file"; then'
READ = 'base_url="$(cat "$url_file")"'
FIRST_PSQL = re.compile(r'\bpsql\s+"\$')
STEP_IF = "if: needs.classify.outputs.docs_only != 'true' && matrix.tier == 'enterprise-fed'"

OPENERS = {"if", "case", "for", "while", "until", "select", "{"}
CLOSERS = {"fi", "esac", "done", "}"}
QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")
INNER = re.compile(r"\$\([^()]*\)|\(\([^()]*\)\)")
COMMANDS = re.compile(r";;|&&|\|\||[;&|]")


def open_blocks(lines):
    """Return the shell block depth after ``lines``.

    Comments, quoted text, ``$(...)`` and ``((...))`` are dropped first.  ``if``/``case``/loops, function
    definitions and brace groups open a block, and so does a command that starts with ``(`` (a subshell, whose
    ``exit 1`` ends only the subshell); ``fi``/``esac``/``done``/``}`` and a command that starts with ``)`` close
    one.  A function body is a brace group.  A ``case`` pattern such as ``never)`` starts with a word, so it does
    not count.  Anything this cannot parse leaves a non-zero depth, so the pin fails closed.
    """
    depth = 0
    for line in lines:
        code = "" if line.lstrip().startswith("#") else line.split(" #", 1)[0]
        code = QUOTED.sub("''", code)
        while INNER.search(code):
            code = INNER.sub("''", code)
        for command in COMMANDS.split(code):
            command = command.strip()
            depth += command.count("(") if command.startswith("(") else 0
            depth -= command.count(")") if command.startswith(")") else 0
            for word in re.findall(r"[{}]|[^\s{}()]+", command):
                if word in OPENERS:
                    depth += 1
                elif word in CLOSERS:
                    depth -= 1
    return depth


def step_lines(text):
    lines = text.splitlines()
    at = next((i for i, ln in enumerate(lines) if CHECK in ln), None)
    if at is None:
        return None, []
    start = at
    while start > 0 and not re.match(r"^\s*- name:", lines[start]):
        start -= 1
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = at + 1
    while end < len(lines) and not (lines[end].strip() and len(lines[end]) - len(lines[end].lstrip()) <= indent
                                    and lines[end].lstrip().startswith("- ")):
        end += 1
    return at - start, lines[start:end]


def wiring_problems(text):
    at, step = step_lines(text)
    found = []
    if at is None:
        return ["ci.yml does not run the tier password check"]
    calls = [i for i, ln in enumerate(step) if CHECK in ln]
    if len(calls) != 1 or step[calls[0]].strip() != CALL:
        return ['the check must run as `' + CALL + '` and nothing else']
    i = calls[0]
    if step[i + 1].strip() != "exit 1" or step[i + 2].strip() != "fi":
        found.append("a failing check must `exit 1` with no other branch")
    body = "\n".join(step)
    if "continue-on-error" in body:
        found.append("the step sets continue-on-error")
    if "Configure enterprise-fed tier" not in step[0]:
        found.append("the check is not in the Configure enterprise-fed tier step")
    if not any(ln.strip() == STEP_IF for ln in step[1:3]):
        found.append("the step `if:` must be exactly `" + STEP_IF + "`")
    set_at = next((j for j, ln in enumerate(step) if ln.strip() == "set -euo pipefail"), None)
    if set_at is None or set_at > i:
        found.append("the step must run `set -euo pipefail` before the check")
    elif open_blocks(step[set_at:i]) != 0 or step[i][:len(step[i]) - len(step[i].lstrip())] != (
            step[set_at][:len(step[set_at]) - len(step[set_at].lstrip())]):
        found.append("the check must sit at the top level of the step script (#6671)")
    psql_at = next((j for j, ln in enumerate(step) if FIRST_PSQL.search(ln)), None)
    read_at = next((j for j, ln in enumerate(step) if READ in ln), None)
    if psql_at is None or read_at is None or not (i < read_at < psql_at):
        found.append("the check must run before the URL is read and before the first psql call")
    return found


class TestTierPasswordWiring6181(unittest.TestCase):
    def test_the_wiring_is_pinned(self):
        self.assertEqual(wiring_problems(CI_YML.read_text(encoding="utf-8")), [])

    def test_the_wiring_check_rejects_each_mutant(self):
        text = CI_YML.read_text(encoding="utf-8")
        mutants = {
            "dropped": (CALL, "true"),
            "no -I": (CALL, CALL.replace("python3 -I", "python3")),
            "|| true": (CALL, CALL[:-6] + " || true; then"),
            "exit 0": (CALL + "\n            exit 1", CALL + "\n            exit 0"),
            "continue-on-error": ("        shell: bash\n        env:\n          # matrix.leg via env",
                                  "        shell: bash\n        continue-on-error: true\n        env:\n          # matrix.leg via env"),
            # #6671: edits that leave every line in place but make the check unreachable.
            "guarded by an if": (CALL + "\n            exit 1\n          fi",
                                 'if [ "${CI_NODE:-}" = "never" ]; then\n          ' + CALL
                                 + "\n            exit 1\n          fi\n          fi"),
            "inside a function": (CALL + "\n            exit 1\n          fi",
                                  "tier_check() {\n          " + CALL + "\n            exit 1\n          fi\n          }"),
            "inside a subshell": (CALL + "\n            exit 1\n          fi",
                                  "(\n          " + CALL + "\n            exit 1\n          fi\n          )"),
            "inside a case": (CALL + "\n            exit 1\n          fi",
                              'case "${CI_NODE:-}" in never)\n          ' + CALL
                              + "\n            exit 1\n          fi\n          ;; esac"),
            "step if && false": (STEP_IF, STEP_IF + " && false"),
            "step if dropped tier": (STEP_IF, STEP_IF.replace(" && matrix.tier == 'enterprise-fed'", " && false")),
        }
        block = CALL + "\n            exit 1\n          fi\n"
        self.assertEqual(text.count(block.replace("            exit 1", "            exit 1")), 1)
        moved = text.replace(block, "", 1).replace(READ + "\n", READ + "\n          " + block, 1)
        self.assertTrue(wiring_problems(moved), "mutant not caught: check moved after the URL read")
        for name, (old, new) in mutants.items():
            with self.subTest(mutant=name):
                self.assertIn(old, text, f"ci.yml no longer holds the text mutated by {name!r}")
                self.assertTrue(wiring_problems(text.replace(old, new, 1)), f"mutant not caught: {name}")


if __name__ == "__main__":
    sys.exit(unittest.main())
