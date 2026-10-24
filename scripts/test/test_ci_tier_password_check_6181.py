#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin how ci.yml handles the enterprise-fed tier credential (#6181, #6671, #6672, #6172, #8187).

Three pins over the "Configure enterprise-fed tier" step and the always() cleanup step that drops the ephemeral db:

* reachability (#6671, the #6508 class): the step runs ``scripts/ci/check-tier-password.py`` as ``python3 -I`` on the
  URL file, at the top level of the step script, before the first use of the credential, and a failure ``exit 1``s
  with no other branch.  The pin is exercised against mutants that keep every line in place but make the call
  unreachable (guard, function, subshell, case, step ``if:``);
* argv and variables (#6172): no ``psql`` line carries a URL, and no step line reads the URL into a shell variable;
  every ``psql`` and every ``pg_isolated_binary.py`` call goes through ``scripts/ci/tier_credential.py run``;
* every line that names the URL file or the tier URL must be one of the exact reviewed lines (#6672), so a new
  ``printf``, ``cat``, ``tee`` or ``$GITHUB_STEP_SUMMARY`` use of it fails here until it is reviewed.

Stdlib only.
"""

from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github/workflows/ci.yml"
CHECK = "scripts/ci/check-tier-password.py"
HELPER = "scripts/ci/tier_credential.py"
CALL = 'if ! python3 -I ' + CHECK + ' --url-file "$url_file"; then'
RUN = 'python3 -I ' + HELPER + ' run --url-file "$url_file"'
STEP_IF = "if: needs.classify.outputs.docs_only != 'true' && matrix.tier == 'enterprise-fed'"
CONFIGURE = "- name: Configure enterprise-fed tier"
CLEANUP_MARK = "no ephemeral db to drop"

OPENERS = {"if", "case", "for", "while", "until", "select", "{"}
CLOSERS = {"fi", "esac", "done", "}"}
QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")
INNER = re.compile(r"\$\([^()]*\)|\(\([^()]*\)\)")
COMMANDS = re.compile(r";;|&&|\|\||[;&|]")
# a line that names the URL file, the tier URL, or a shell variable that could hold it (#6672)
URL_REF = re.compile(r"\$\{?(?:url_file|base_url|new_url|head|q|AI_MEMORY_TEST_POSTGRES_URL)\b|ai-memory-ci-fed-url"
                     r"|\b(?:base_url|new_url)\s*=")
EXPORTS = re.compile(r"^(?:export|declare\s+-\S*x|typeset\s+-\S*x|readonly)\b(.*)$")
URL_NAMES = re.compile(r"\b(?:url_file|base_url|new_url|head|q)\b")
ENV_DUMP = re.compile(r"(?:^|[;&|(]\s*)(?:env|printenv|compgen\s+-[vA]|(?:export|declare|typeset)\s+-p|set)\s*(?:$|[;&|)])")
XTRACE = re.compile(r"\bset\s+-\S*x|\bset\s+-o\s+xtrace\b|\bBASH_XTRACEFD\b|\bPS4\b")
# The reviewed lines (configure step, then cleanup step) that name the URL file or the tier URL.
URL_LINES = frozenset((
    'url_file="$HOME/.ai-memory-ci-fed-url"',
    'if [ ! -f "$url_file" ]; then',
    'echo "::error::enterprise-fed leg on $RUNNER_NAME is missing $url_file — the native pg tier URL is not'
    ' provisioned on this node"',
    CALL,
    'if ! ' + RUN + ' -- psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE \\"$CI_FED_DB\\";"; then',
    'if ! ' + RUN + ' --database "$CI_FED_DB" -- psql -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS age;'
    ' CREATE EXTENSION IF NOT EXISTS vector;"; then',
    'python3 -I ' + HELPER + ' github-env --url-file "$url_file" --database "$CI_FED_DB"',
    'echo "::notice::[enterprise-fed] created ephemeral db $CI_FED_DB on the native tier ($RUNNER_NAME) and'
    ' pointed AI_MEMORY_TEST_POSTGRES_URL at it"',
    RUN + ' --database "$CI_FED_DB" --export-url -- python3 scripts/test/pg_isolated_binary.py setup --db'
    ' "$CI_FED_DB" --jobs 8 --emit-env >> "$GITHUB_ENV"',
    'echo "::warning::cannot drop $CI_FED_DB — $url_file missing on $RUNNER_NAME (leaked ephemeral db)"',
    RUN + ' --export-url -- python3 scripts/test/pg_isolated_binary.py teardown --db "$CI_FED_DB" --run-id'
    ' "$AI_MEMORY_TEST_PG_RUN_ID" \\',
    'if ' + RUN + ' -- psql -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS \\"$CI_FED_DB\\" WITH (FORCE);"; then',
))


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


def step_around(lines, at):
    """The lines of the workflow step that holds line index ``at``."""
    start = at
    while start > 0 and not re.match(r"^\s*- name:", lines[start]):
        start -= 1
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = at + 1
    while end < len(lines) and not (lines[end].strip() and len(lines[end]) - len(lines[end].lstrip()) <= indent
                                    and lines[end].lstrip().startswith("- ")):
        end += 1
    return lines[start:end]


def steps(text):
    """(configure step, cleanup step) as line lists; None for a step that is missing."""
    lines = text.splitlines()
    configure = next((i for i, ln in enumerate(lines) if CONFIGURE in ln), None)
    cleanup = next((i for i, ln in enumerate(lines) if CLEANUP_MARK in ln), None)
    return (step_around(lines, configure) if configure is not None else None,
            step_around(lines, cleanup) if cleanup is not None else None)


def indent_of(line):
    return len(line) - len(line.lstrip())


def wiring_problems(text):
    """#6671: the check must run, unconditionally, before the credential is used."""
    step, _ = steps(text)
    if step is None or not any(CHECK in ln for ln in step):
        return ["ci.yml does not run the tier password check"]
    calls = [i for i, ln in enumerate(step) if CHECK in ln and not ln.lstrip().startswith("#")]
    if len(calls) != 1 or step[calls[0]].strip() != CALL:
        return ['the check must run as `' + CALL + '` and nothing else']
    i = calls[0]
    found = []
    if step[i + 1].strip() != "exit 1" or step[i + 2].strip() != "fi":
        found.append("a failing check must `exit 1` with no other branch")
    if "continue-on-error" in "\n".join(step):
        found.append("the step sets continue-on-error")
    if not any(ln.strip() == STEP_IF for ln in step[1:3]):
        found.append("the step `if:` must be exactly `" + STEP_IF + "`")
    set_at = next((j for j, ln in enumerate(step) if ln.strip() == "set -euo pipefail"), None)
    if set_at is None or set_at > i:
        found.append("the step must run `set -euo pipefail` before the check")
    elif open_blocks(step[set_at:i]) != 0 or indent_of(step[i]) != indent_of(step[set_at]):
        found.append("the check must sit at the top level of the step script (#6671)")
    first_use = next((j for j, ln in enumerate(step) if HELPER in ln and not ln.lstrip().startswith("#")), None)
    if first_use is None or not i < first_use:
        found.append("the check must run before the first use of the tier credential")
    return found


def argv_problems(text):
    """#6172: no URL on argv or in a variable; every psql goes through the helper."""
    found = []
    for name, step in zip(("configure", "cleanup"), steps(text)):
        if step is None:
            found.append(f"the {name} step is missing")
            continue
        for ln in step:
            s = ln.strip()
            if s.startswith("#"):
                continue
            if re.search(r"\bpsql\b", s) and (HELPER not in s or " -- psql " not in s):
                found.append(f"{name}: a psql call bypasses the helper: {s[:60]}")
            if "pg_isolated_binary.py" in s and "python3 scripts/test/pg_isolated_binary.py" in s and HELPER not in s:
                found.append(f"{name}: the isolation wrapper runs without the helper: {s[:60]}")
            if re.search(r"\b(?:base_url|new_url)\b|\$\(cat\b|`cat\b", s):
                found.append(f"{name}: the URL is read into a shell variable: {s[:60]}")
            if re.search(r"\bpsql\s+[\"']?\$", s) or re.search(r"postgres(?:ql)?://", s):
                found.append(f"{name}: a URL is on a command line: {s[:60]}")
    return found


def url_leaks(text):
    """#6672: step lines that use the URL outside the allowlist, export it, trace the shell or dump the env."""
    found = []
    for name, step in zip(("configure", "cleanup"), steps(text)):
        for ln in step or ():
            s = ln.strip()
            if s.startswith("#"):
                continue
            if URL_REF.search(s) and s not in URL_LINES:
                found.append(f"{name}: a line uses the tier URL outside the reviewed lines: {s[:60]}")
            exported = EXPORTS.match(s)
            if exported and URL_NAMES.search(exported.group(1)):
                found.append(f"{name}: a line exports the tier URL: {s[:60]}")
            if ENV_DUMP.search(s):
                found.append(f"{name}: a line dumps the environment: {s[:60]}")
            if XTRACE.search(s):
                found.append(f"{name}: a line traces the shell: {s[:60]}")
    return found


HEADER = "      - name: Configure enterprise-fed tier (per-job ephemeral db, enterprise-fed legs only)\n        "


def sub_once(text, old, new):
    assert text.count(old) == 1, f"ci.yml no longer holds exactly one copy of the mutated text: {old[:50]!r}"
    return text.replace(old, new, 1)


class TestTierPasswordWiring6181(unittest.TestCase):
    def test_the_wiring_is_pinned(self):
        self.assertEqual(wiring_problems(CI_YML.read_text(encoding="utf-8")), [])

    def test_the_wiring_check_rejects_each_mutant(self):
        text = CI_YML.read_text(encoding="utf-8")
        block = CALL + "\n            exit 1\n          fi"
        mutants = {
            "dropped": (CALL, "true"),
            "no -I": (CALL, CALL.replace("python3 -I", "python3")),
            "|| true": (CALL, CALL[:-6] + " || true; then"),
            "exit 0": (CALL + "\n            exit 1", CALL + "\n            exit 0"),
            "continue-on-error": ("        shell: bash\n        env:\n          # matrix.leg via env",
                                  "        shell: bash\n        continue-on-error: true\n        env:\n"
                                  "          # matrix.leg via env"),
            # #6671: edits that leave every line in place but make the check unreachable.
            "guarded by an if": (block, 'if [ "${CI_NODE:-}" = "never" ]; then\n          ' + block + "\n          fi"),
            "inside a function": (block, "tier_check() {\n          " + block + "\n          }"),
            "inside a subshell": (block, "(\n          " + block + "\n          )"),
            "inside a case": (block, 'case "${CI_NODE:-}" in never)\n          ' + block + "\n          ;; esac"),
            "step if && false": (HEADER + STEP_IF, HEADER + STEP_IF + " && false"),
            "step if dropped tier": (HEADER + STEP_IF,
                                     HEADER + STEP_IF.replace(" && matrix.tier == 'enterprise-fed'", " && false")),
        }
        for name, (old, new) in mutants.items():
            with self.subTest(mutant=name):
                self.assertTrue(wiring_problems(sub_once(text, old, new)), f"mutant not caught: {name}")
        # the check moved after the first use of the credential
        moved = sub_once(text, block + "\n", "")
        first = RUN + " --database"
        moved = sub_once(moved, "          if ! " + first, "          " + block + "\n          if ! " + first)
        self.assertTrue(wiring_problems(moved), "mutant not caught: check moved after the first credential use")

    def test_the_check_is_in_the_configure_step_not_only_somewhere_6671(self):
        text = CI_YML.read_text(encoding="utf-8")
        configure, cleanup = steps(text)
        self.assertTrue(configure and cleanup)
        self.assertEqual(sum(CHECK in ln for ln in configure), 1)
        self.assertFalse(any(CHECK in ln for ln in cleanup))

    def test_no_credential_reaches_argv_or_a_shell_variable_6172(self):
        text = CI_YML.read_text(encoding="utf-8")
        self.assertEqual(argv_problems(text), [])
        mutants = {
            "psql with a URL variable": (RUN + " -- psql -v ON_ERROR_STOP=1 -c \"CREATE DATABASE",
                                         'psql "$base_url" -v ON_ERROR_STOP=1 -c "CREATE DATABASE'),
            "psql without the helper": ("if ! " + RUN + " -- psql -v ON_ERROR_STOP=1 -c \"CREATE DATABASE",
                                        "if ! psql -v ON_ERROR_STOP=1 -c \"CREATE DATABASE"),
            "URL read into a variable": ('          set -euo pipefail\n          # psql lives',
                                         '          set -euo pipefail\n          base_url="$(cat "$HOME/.x")"\n'
                                         '          # psql lives'),
            "wrapper without the helper": (RUN + " --export-url -- python3 scripts/test/pg_isolated_binary.py teardown",
                                           'AI_MEMORY_TEST_POSTGRES_URL="$u" python3 scripts/test/'
                                           'pg_isolated_binary.py teardown'),
            "literal URL": ('echo "::notice::[enterprise-fed] created',
                            'echo "postgres://u:p@h/db"\n          echo "::notice::[enterprise-fed] created'),
        }
        for name, (old, new) in mutants.items():
            with self.subTest(mutant=name):
                self.assertTrue(argv_problems(sub_once(text, old, new)), f"mutant not caught: {name}")

    def test_every_line_that_uses_the_url_is_reviewed_6672(self):
        text = CI_YML.read_text(encoding="utf-8")
        self.assertEqual(url_leaks(text), [])
        anchor = 'echo "::notice::[enterprise-fed] created'
        extra = {
            "printf of the file": 'printf "%s\\n" "$(cat "$url_file")"',
            "cat to the summary": 'cat "$url_file" >> "$GITHUB_STEP_SUMMARY"',
            "tee of the file": 'tee -a "$GITHUB_STEP_SUMMARY" < "$url_file"',
            "echo to env": 'echo "AI_MEMORY_TEST_POSTGRES_URL=$AI_MEMORY_TEST_POSTGRES_URL" >> "$GITHUB_ENV"',
            "copy to another name": 'cp "$HOME/.ai-memory-ci-fed-url" "$RUNNER_TEMP/copy"',
            "export of the file name": 'export url_file',
            "dump of the environment": 'env',
            "printenv": 'printenv',
            "export -p": 'export -p',
            "declare -p": 'declare -p',
            "bare set": 'set',
            "xtrace": 'set -x',
            "xtrace by option": 'set -o xtrace',
        }
        for name, line in extra.items():
            with self.subTest(mutant=name):
                self.assertTrue(url_leaks(sub_once(text, anchor, line + "\n          " + anchor)),
                                f"mutant not caught: {name}")
        # an edit of a reviewed line (extra argument, redirect) is a new line and must fail until reviewed
        edited = sub_once(text, 'python3 -I ' + HELPER + ' github-env --url-file "$url_file" --database "$CI_FED_DB"',
                          'python3 -I ' + HELPER + ' github-env --url-file "$url_file" --database "$CI_FED_DB"'
                          ' | tee -a "$GITHUB_STEP_SUMMARY"')
        self.assertTrue(url_leaks(edited), "mutant not caught: tee appended to a reviewed line")

    def test_every_reviewed_url_line_is_in_the_step_6672(self):
        # keeps the allowlist from going stale: each reviewed line still exists in one of the two steps
        configure, cleanup = steps(CI_YML.read_text(encoding="utf-8"))
        present = {ln.strip() for ln in configure + cleanup}
        self.assertEqual(sorted(URL_LINES - present), [])


if __name__ == "__main__":
    sys.exit(unittest.main())
