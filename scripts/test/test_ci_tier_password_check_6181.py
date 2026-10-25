#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin how the tier workflows handle the enterprise-fed tier credential (#6181, #6671, #6672, #6172, #8187).

Pins over the "Configure enterprise-fed tier" step and the always() cleanup step that drops the ephemeral db
(ci.yml), and over the two workflows that share the tier (cert-postgres-age.yml, postgres-ignored.yml):

* reachability (#6671, the #6508 class): the step runs ``scripts/ci/check-tier-password.py`` as ``python3 -I`` on the
  URL file, at the top level of the step script, before the first use of the credential, and a failure ``exit 1``s
  with no other branch.  The pin is exercised against mutants that keep every line in place but make the call
  unreachable (guard, function, subshell, case, step ``if:``);
* argv and variables (#6172): no ``psql`` line carries a URL, and no step line reads the URL into a shell variable;
  every ``psql`` and every ``pg_isolated_binary.py`` call goes through ``scripts/ci/tier_credential.py run``;
* every line that names the URL file or the tier URL must be one of the exact reviewed lines (#6672), so a new
  ``printf``, ``cat``, ``tee`` or ``$GITHUB_STEP_SUMMARY`` use of it fails here until it is reviewed;
* the whole of every tier job and of every workflow-level key (r8, #8187): the workflows are read by
  ``tier_yaml_8187.StrictLoader`` (PyYAML, hash-pinned in ``scripts/test/requirements-ci.txt``), which refuses
  duplicate keys (after the key scalar is normalised), anchors, aliases, merge keys, non-string keys and top-level
  keys outside ``{name, run-name, on, permissions, env, defaults, concurrency, jobs}``.  The SHA-256 of the canonical
  JSON of every tier job (every step and key), of every workflow-level key except ``jobs`` and of the sorted job
  names is the ``primary`` section of ``tier_export_job_pins_8187.json``.  The ``secondary_text`` section keeps the
  whole-job text pin of r7, so a difference between the loader and what GitHub runs cannot pass silently.  Tier
  workflows and tier jobs are found from normalised loader output, ``.github/actions`` is scanned, a local action
  or reusable workflow call in a tier workflow is refused, and a job of the three workflows that is not a tier job
  must run on a GitHub-hosted label.  Every other workflow file gets the same rule: one that PyYAML refuses, one
  whose ``jobs`` is missing or not a mapping, and any job-level ``uses:`` (local or remote reusable call, which is
  not followed) is a problem.  ``runs_on_labels`` resolves NO expression (3-agent vote (6def5ab6), option C): ``${{``
  anywhere in ``runs-on``, a mapping with a key other than ``labels`` or a non-string element yields None, which both
  consumers treat as a problem.  The only green path for a matrix job is an exact row of ``RUNS_ON_EXEMPT``, keyed by
  ``(workflow, job)``: the pinned ``runs-on`` string, a strict matrix parse (lists of plain scalars, an optional flat
  ``include``, no ``exclude``, no expression) and label tuples EQUAL to the row's set.  A row whose job is gone is stale.
  The one row that may name a self-hosted tuple (session-boot-lifetime ``lifetime-tests``) is also pinned in the
  ``exempt_jobs`` section, which pins the exempt job and every workflow-level key except ``jobs`` of its workflow, so a
  step edit or a workflow-level edit of that workflow needs ``--write-pins``.

The job ``tier-credential-pins`` in ci.yml runs this module and the two other tier modules on every PR (before r8
no CI job ran them).  Obligation: any edit of a tier job or of a workflow-level key of the three workflows (and of the exempt job or a
workflow-level key of the exempt workflow), and any
added or removed job, needs ``python3 scripts/test/test_ci_tier_password_check_6181.py --write-pins`` in the same
PR (it regenerates all three sections, primary, secondary_text and exempt_jobs; the diff of the data file is what a reviewer reads).  Failure messages name the
workflow, job, step index, step name or id and the first differing key path, as labels only (r23: no value is printed, nothing is masked after the fact).

Residual (documented, #8187 umbrella item): the URL file is provisioned by the operator in the runner user's home
and stays there between jobs, on both self-hosted runner classes (linux-fed and macos-fed).  Code run there by the
pinned tier jobs or by the pinned exempt job ``lifetime-tests`` can read it, and no check in this repository can stop
that: the checks here pin which jobs, steps and labels this repository's workflows may use on those runners, they do
not isolate the file.  Closing it needs a per-job credential at the operator's runner, the operator item #6181.

Needs PyYAML (``python3 -m pip install --require-hashes --no-deps -r scripts/test/requirements-ci.txt``); a missing
module is an import error of this module, never a skip.
"""

import ast
import concurrent.futures
import contextlib
import copy
import dataclasses
import hashlib
import io
import json
import logging
import multiprocessing
import os
from pathlib import Path
import pickle
import pprint
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import types
import unicodedata
import unittest
import unittest.mock
import urllib.parse
import warnings
import weakref

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tier_yaml_8187 as ty  # noqa: E402  (an ImportError here names scripts/test/requirements-ci.txt)

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
ENV_COMMANDS = frozenset(("env", "printenv", "typeset", "declare", "export", "set", "compgen"))
PREFIX_WORDS = frozenset(("if", "elif", "while", "until", "then", "do", "else", "!", "exec", "command", "time",
                          "nohup", "sudo", "builtin", "{", "[", "[["))
SEPARATORS = re.compile(r"\$\(|`|;;|&&|\|\||[;&|()\n]")
STEP_PREFIX = re.compile(r"^(?:-\s+)?run:\s*")
INTERPRETER = re.compile(r"^(?:python[\d.]*|perl|node|nodejs|ruby|php|lua)$")
INTERPRETER_ENV = re.compile(r"os\.environ|os\.getenv|\bENV\b|process\.env|getenv|\$_ENV")
PROC_ENVIRON = re.compile(r"/proc/.*environ")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def command_words(line):
    """The first real word of every simple command in one shell line (quotes dropped, prefixes skipped)."""
    stripped = STEP_PREFIX.sub("", line.strip()).replace("'", " ").replace('"', " ")
    found = []
    for part in SEPARATORS.split(stripped):
        words = part.split()
        while words and (words[0] in PREFIX_WORDS or ASSIGNMENT.match(words[0])):
            words = words[1:]
        if words:
            found.append(words)
    return found


def dumps_environment(line):
    """True when one shell line can print the process environment: env tools, /proc environ, interpreter dumps."""
    if PROC_ENVIRON.search(line):
        return True
    for words in command_words(line):
        name = words[0].rsplit("/", 1)[-1]
        if name in ("env", "printenv", "compgen"):
            return True
        if name in ENV_COMMANDS and (len(words) == 1 or words[1] == "-p" or "-p" in words[1:2]):
            return True
        if INTERPRETER.match(name) and INTERPRETER_ENV.search(line):
            return True
    return False
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
        for number, ln in enumerate(step, 1):
            s = ln.strip()
            if s.startswith("#"):
                continue
            where = f"{name} step line {number}"
            if re.search(r"\bpsql\b", s) and (HELPER not in s or " -- psql " not in s):
                found.append(f"{where}: a psql call bypasses the helper")
            if "pg_isolated_binary.py" in s and "python3 scripts/test/pg_isolated_binary.py" in s and HELPER not in s:
                found.append(f"{where}: the isolation wrapper runs without the helper")
            if re.search(r"\b(?:base_url|new_url)\b|\$\(cat\b|`cat\b", s):
                found.append(f"{where}: the URL is read into a shell variable")
            if re.search(r"\bpsql\s+[\"']?\$", s) or re.search(r"postgres(?:ql)?://", s):
                found.append(f"{where}: psql argv carries a credential (a URL is on a command line)")
    return found


def url_leaks(text):
    """#6672: step lines that use the URL outside the allowlist, export it, trace the shell or dump the env."""
    found = []
    for name, step in zip(("configure", "cleanup"), steps(text)):
        for number, ln in enumerate(step or (), 1):
            s = ln.strip()
            if s.startswith("#"):
                continue
            where = f"{name} step line {number}"
            if URL_REF.search(s) and s not in URL_LINES:
                found.append(f"{where}: the tier URL is used outside the reviewed lines")
            exported = EXPORTS.match(s)
            if exported and URL_NAMES.search(exported.group(1)):
                found.append(f"{where}: a line exports the tier URL")
            if dumps_environment(s):
                found.append(f"{where}: a line dumps the environment")
            if XTRACE.search(s):
                found.append(f"{where}: a line traces the shell")
        # r6: scan again with backslash continuations joined, so a word split across lines is one word
        numbered = [(number, ln) for number, ln in enumerate(step or (), 1) if not ln.strip().startswith("#")]
        for number, joined in joined_numbered(numbered):
            if dumps_environment(joined) or XTRACE.search(joined):
                found.append(f"{name} step line {number}: a continued line dumps the environment or traces the shell")
    return found


HEADER = "      - name: Configure enterprise-fed tier (per-job ephemeral db, enterprise-fed legs only)\n        "


def sub_once(text, old, new):
    assert text.count(old) == 1, f"ci.yml no longer holds exactly one copy of the {len(old)}-character mutated text"
    return text.replace(old, new, 1)


def assert_same(case, left, right, label):
    """Compare two raw workflow or pin values and report only ``label`` (F40-a): ``assertEqual`` prints both operands when
    it fails, and an operand taken from an author's workflow or from the pin data may hold a credential fragment."""
    case.assertEqual(ty.opaque(left, "key[0]"), ty.opaque(right, "key[0]"), "differs: " + label)


def job_re(name):
    """A regex for the printed form of the job ``name``: the positional label and the length, never the name."""
    return r"(?:job|key)\[(?:\d+|\?)\] len=%d" % len(name)


def step_ref(index, name=""):
    """A regex for ``step N (step[N] len=L)``: the printed form of the step ``index`` named ``name`` (empty: unnamed)."""
    return r"step %d \(step\[%d\] len=%d\)" % (index, index, len(name))


def step_any(index):
    """A regex for ``step N (step[N] len=L)`` with any length (the step's name is not known to the test)."""
    return r"step %d \(step\[%d\] len=\d+\)" % (index, index)


def key_re(name):
    """A regex for the printed form of the key ``name``: ``key[N] len=L``."""
    return r"key\[\d+\] len=%d" % len(name)


def any_match(problems, *patterns):
    """True when one problem line matches every pattern (a bool: a failure prints the problem lines, which hold labels only)."""
    return any(all(re.search(pattern, line) for pattern in patterns) for line in problems)


def assert_has(case, member, container, label):
    """``member in container`` for raw workflow data, reporting only ``label`` (F40-a)."""
    case.assertIs(member in container, True, "missing: " + label)


class TestTierPasswordWiring6181(unittest.TestCase):
    def test_the_wiring_is_pinned(self):
        self.assertEqual(len(wiring_problems(CI_YML.read_text(encoding="utf-8"))), 0)

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
        self.assertEqual(len(argv_problems(text)), 0)
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
        self.assertEqual(len(url_leaks(text)), 0)
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
        self.assertEqual(len(sorted(URL_LINES - present)), 0)


WORKFLOWS = ROOT / ".github/workflows"
BANG = chr(92) + "!"  # a psql shell escape: backslash then bang
# the discovery list: every workflow that names the tier secret or its environment variable (#8187 security F2)
TIER_MARKERS = ty.TIER_MARKERS
# workflows that read the tier URL file: pinned by wiring_problems above (ci.yml) or workflow_problems below
SHARED_TIER = ("cert-postgres-age.yml", "postgres-ignored.yml")
# coverage.yml names the variable only for its own throwaway local database (a literal localhost test credential)
LOCAL_ONLY = {"coverage.yml": "postgres://ai_memory:ai_memory_test@localhost:5432/"}
URL_VARS = re.compile(r"\$\{?(?:base_url|new_url|head|q|AI_MEMORY_TEST_POSTGRES_URL|AI_MEMORY_TEST_AGE_URL)\b")
GITHUB_ENV_LINE = 'python3 -I ' + HELPER + ' github-env --url-file "$url_file" --database "$CI_FED_DB"'


def numbered_code_lines(text):
    """``(line number, stripped line)`` of the non-comment lines of a workflow; the number is 1-based in the file."""
    return [(number, ln.strip()) for number, ln in enumerate(text.splitlines(), 1)
            if ln.strip() and not ln.strip().startswith("#")]


def code_lines(text):
    """The non-comment lines of a workflow, stripped."""
    return [ln for _number, ln in numbered_code_lines(text)]


# a line that names the URL file, its path, or the tier secret (#8187 r3): only the reviewed forms below may do so
URL_FILE_MENTION = re.compile(r"url_file|ai-memory-ci-fed-url|AI_MEMORY_CI_FED_URL|AI_MEMORY_TEST_(?:POSTGRES|AGE)_URL")
URL_FILE_ASSIGN = 'url_file="$HOME/.ai-memory-ci-fed-url"'
URL_FILE_TEST = re.compile(r'^if \[ !? ?-f "\$url_file" \]; then$')
# the expansions a reviewed message or psql argument may carry: plain names only, never a substitution
MESSAGE_NAMES = r"(?:url_file|RUNNER_NAME|CI_FED_DB)"
ARG_NAMES = r"(?:CI_FED_DB)"
MESSAGE_PREFIX = re.compile(r'echo "::(?:error|warning|notice)::')
LOADER_RUN = re.compile(
    r'^(?P<pre>if ! |if |PSQL=\()python3 -I ' + re.escape(HELPER)
    + r' run --url-file "\$url_file"(?: --database "\$CI_FED_DB")? -- psql(?P<tail>.*)$')
LOADER_ENV = re.compile(
    r'^python3 -I ' + re.escape(HELPER) + r' github-env --url-file "\$url_file" --database "\$CI_FED_DB"(?: --age-url)?$')
# the reviewed arguments after `psql`, with every quoted word masked to Q by quote_masked
PSQL_ARGS = r'(?: -v ON_ERROR_STOP=[01])?(?: -tAX| -tAc Q| -c Q)?'
PSQL_ARRAY_MENTION = re.compile(r"PSQL")
ARRAY_TOKEN = '"${PSQL[@]}"'


def quote_masked(text, names):
    """Return ``text`` with each quoted word replaced by ``Q``, or None when it is not a reviewed plain form.

    One left-to-right pass (no regex backtracking).  Refused: an unquoted ``$``, backtick, backslash or ``<``; inside
    double quotes a backtick, a backslash that does not escape ``"`` or ``$``, and a ``$`` not followed by one of
    ``names``; inside single quotes a backslash (a psql shell escape needs one); a quoted word naming ``PROGRAM``.
    """
    expansion = re.compile(r"\$(?:\{" + names + r"\}|" + names + r"(?![A-Za-z0-9_]))")
    out = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == '"':
            j = i + 1
            while True:
                if j >= len(text):
                    return None
                ch = text[j]
                if ch == '"':
                    break
                if ch == "\\":
                    if text[j + 1:j + 2] not in ('"', "$"):
                        return None
                    j += 2
                elif ch == "`":
                    return None
                elif ch == "$":
                    m = expansion.match(text, j)
                    if not m:
                        return None
                    j = m.end()
                else:
                    j += 1
            word = text[i + 1:j]
            i = j + 1
        elif c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                return None
            word = text[i + 1:j]
            if "\\" in word:
                return None
            i = j + 1
        elif c in "`$\\<":
            return None
        else:
            out.append(c)
            i += 1
            continue
        if "program" in word.lower():
            return None
        out.append("Q")
    return "".join(out)


def message_echo(line):
    """True for ``echo "::error|warning|notice::..."`` whose only expansions are plain reviewed names."""
    return bool(MESSAGE_PREFIX.match(line)) and quote_masked(line, MESSAGE_NAMES) == "echo Q"


def loader_line(line):
    """True for a whole `run:` line that is exactly one reviewed loader call and nothing chained after it."""
    if LOADER_ENV.match(line):
        return True
    call = LOADER_RUN.match(line)
    if not call:
        return False
    masked = quote_masked(call.group("tail"), ARG_NAMES)
    if masked is None:
        return False
    if call.group("pre") == "PSQL=(":
        return bool(re.fullmatch(PSQL_ARGS + r"\)", masked))
    return bool(re.fullmatch(PSQL_ARGS + r"(?: >/dev/null 2>&1)?; then", masked))


def array_call(line):
    """True for a reviewed use of the loader array: ``"${PSQL[@]}" -c Q [|| echo Q]`` or a captured `` | tr -d Q``."""
    if ARRAY_TOKEN not in line:
        return False
    sub = re.fullmatch(r"[A-Za-z_]+=\$\((.*)\)", line)
    command = (sub.group(1) if sub else line).replace(ARRAY_TOKEN, "PSQLARR")
    masked = quote_masked(command, ARG_NAMES)
    if masked is None:
        return False
    if sub:
        return bool(re.fullmatch(r"PSQLARR -c Q \| tr -d Q", masked))
    return bool(re.fullmatch(r"PSQLARR -c Q(?: \|\| echo Q)?", masked))


def allowed_url_file_line(line):
    """True when a line that names the URL file, tier secret or loader array is one of the reviewed, non-echoing forms."""
    if line == URL_FILE_ASSIGN or URL_FILE_TEST.match(line):
        return True
    return message_echo(line) or loader_line(line) or array_call(line)


def workflow_problems(text):
    """Problems of a workflow that reads the tier URL file other than ci.yml: argv, shell variables, GITHUB_ENV.

    An allowlist (#8187 r3): wherever a line names the URL file, its path or the tier secret it must be an assignment
    of the path, an existence test, a message that prints the path, or a call of the loader; anything else fails.
    """
    problems = []
    numbered = numbered_code_lines(text)
    lines = [line for _number, line in numbered]
    for number, line in numbered:
        at = f"line {number}: "
        if re.search(r"AI_MEMORY_TEST_(?:POSTGRES|AGE)_URL=", line):
            problems.append(at + "URL written to GITHUB_ENV by hand")
        if dumps_environment(line):
            problems.append(at + "a line dumps the environment")
        if XTRACE.search(line):
            problems.append(at + "a line traces the shell")
        if (URL_FILE_MENTION.search(line) or PSQL_ARRAY_MENTION.search(line)) and not allowed_url_file_line(line):
            problems.append(at + "tier credential line is not an allowed form")
        if re.search(r"\bpsql\b", line) and ("tier_credential.py run" not in line or "--url-file" not in line):
            if not message_echo(line):
                problems.append(at + "psql without the loader")
        if re.search(r"\bpsql\b", line) and URL_VARS.search(line):
            problems.append(at + "psql line carries a URL variable")
        if re.search(r"\b(?:base_url|new_url)\s*=", line) or re.search(r"\bcat\s+\"?\$\{?url_file", line):
            problems.append(at + "URL read into a shell variable")
    for number, joined in joined_numbered(numbered):
        if dumps_environment(joined) or XTRACE.search(joined):
            problems.append(f"line {number}: a continued line dumps the environment or traces the shell")
    if not any(ln.startswith(GITHUB_ENV_LINE) and "--age-url" in ln for ln in lines):
        problems.append("the masked github-env hand-off (with --age-url) is missing")
    return problems


def names_the_tier(text):
    """True when a workflow file names the tier secret in its normalised text or in any normalised loader leaf (r8)."""
    if ty.matches_markers(text):
        return True
    try:
        data = ty.load_lenient(text)
    except ty.StrictYamlError:
        return False
    return data is not None and ty.matches_markers(data)


def tier_workflows(directory=WORKFLOWS):
    """Names of the workflows (``*.yml`` and ``*.yaml``) that name the tier secret, found on normalised loader output
    (an escaped, split or empty-quote padded name is found; r7 searched the raw text)."""
    paths = [*Path(directory).glob("*.yml"), *Path(directory).glob("*.yaml")]
    return sorted(p.name for p in paths if names_the_tier(p.read_text(encoding="utf-8")))


# r7 F11: the complete job that exports the tier URL is pinned line by line, with the set of jobs (the loader-call
# allowlist and dumps_environment stay as the second and third gates).  PyYAML is not a dependency of this
# repository's CI scripts, so the pin reads the text; see job_layout.  The pins are in a data file next to this
# module.
JOB_PINS_FILE = Path(__file__).with_name("tier_export_job_pins_8187.json")
PIN_WORKFLOWS = ("ci.yml", *SHARED_TIER)
JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
STEP_LINE = re.compile(r"^      - ")
EXPORT_CALL = ty.EXPORT_CALL


def workflow_steps(text):
    """Every step of every job as ``(job, name, body, first_line_index, end_line_index)``; body is the exact text."""
    lines = text.splitlines()
    found = []
    job = None
    in_jobs = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
        elif in_jobs and JOB_KEY.match(line):
            job = JOB_KEY.match(line).group(1)
        if in_jobs and job is not None and STEP_LINE.match(line):
            end = i + 1
            while end < len(lines) and not (lines[end].strip() and indent_of(lines[end]) <= 6):
                end += 1
            while end > i + 1 and not lines[end - 1].strip():
                end -= 1
            first = line.strip()[2:].strip()
            name = first[len("name:"):].strip() if first.startswith("name:") else first
            found.append((job, name, "\n".join(lines[i:end]), i, end))
            i = end
            continue
        i += 1
    return found


def post_export_steps(workflow, text):
    """``[(key, body)]`` for the step that writes the tier URL to ``$GITHUB_ENV`` and every later step of its job.

    The key is ``workflow:job:step-name`` (``#2`` and so on for a repeated name).  Empty when no step exports.
    """
    steps_found = workflow_steps(text)
    start = {}
    for index, (job, _name, body, _a, _b) in enumerate(steps_found):
        code = [ln.strip() for ln in body.splitlines() if not ln.strip().startswith("#")]
        if job not in start and any(EXPORT_CALL.search(ln) for ln in code):
            start[job] = index
    result = []
    seen = {}
    for index, (job, name, body, _a, _b) in enumerate(steps_found):
        if job in start and index >= start[job]:
            key = f"{workflow}:{job}:{name}"
            seen[key] = seen.get(key, 0) + 1
            result.append((key if seen[key] == 1 else f"{key}#{seen[key]}", body))
    return result


def pin_entry(body):
    """The pin of one job block: the SHA-256 of its exact text and a 12-hex hash of every line, joined (line numbers).

    Hashes, not the text: the table stays small, and the data file never repeats workflow prose that the repository
    phrase scans read.  Equality of the full SHA-256 is exact-text equality.
    """
    return {"sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "lines": "".join(hashlib.sha256(ln.encode("utf-8")).hexdigest()[:12] for ln in body.split("\n"))}


JOB_HEAD = re.compile(r"^jobs:\s*(?:#.*)?$")
JOB_KEY_LINE = re.compile(r"^( *)([A-Za-z0-9_-]+):\s*(?:#.*)?$")
TIER_JOB_MARK = ty.TIER_JOB_MARK


def comment_or_blank(line):
    return not line.strip() or line.lstrip().startswith("#")


def job_layout(text):
    """``(jobs, problems)``: every job of the single top-level ``jobs:`` section of a workflow.

    A job is ``(name, first, end, block)``: line indexes into ``text.split("\\n")`` and the exact text of the job from
    its key line to its last code line (trailing comment and blank lines belong to no job).  Fails closed, with a
    problem, when ``jobs:`` is missing or repeated, when a line of the section sits left of the job keys or at the job
    indentation without being a plain ``name:`` key, or when a job name repeats.  Comment lines never end a job: the
    keys that follow a column-0 comment belong to the job above it (F11b).  The job key indentation is read from the
    file, not assumed (F11a).
    """
    lines = text.split("\n")
    heads = [i for i, ln in enumerate(lines) if JOB_HEAD.match(ln)]
    if len(heads) != 1:
        return [], [f"expected exactly one top-level jobs: key, found {len(heads)}"]
    start = heads[0] + 1
    stop = len(lines)
    for i in range(start, len(lines)):
        if lines[i].strip() and not lines[i].startswith((" ", "#")):
            stop = i
            break
    code = [i for i in range(start, stop) if not comment_or_blank(lines[i])]
    if not code:
        return [], ["the jobs: section holds no job"]
    unit = indent_of(lines[code[0]])
    problems = []
    keys = []
    for i in code:
        width = indent_of(lines[i])
        if width < unit:
            problems.append(f"line {i + 1}: indentation left of the job keys in the jobs: section")
        elif width == unit:
            match = JOB_KEY_LINE.match(lines[i])
            if match:
                keys.append((match.group(2), i))
            else:
                problems.append(f"line {i + 1}: unrecognised job key at the job indentation")
    jobs = []
    names = set()
    for number, (name, first) in enumerate(keys):
        end = keys[number + 1][1] if number + 1 < len(keys) else stop
        while end > first + 1 and comment_or_blank(lines[end - 1]):
            end -= 1
        if name in names:
            problems.append(f"job {ty.name_label(name, [k[0] for k in keys])} appears twice")
        names.add(name)
        jobs.append((name, first, end, "\n".join(lines[first:end])))
    return jobs, problems


def tier_blocks(jobs):
    """``[(name, block)]`` of the jobs whose code names the tier credential, its loader or its gate."""
    found = []
    for name, _first, _end, block in jobs:
        if TIER_JOB_MARK.search(normalised_code(block)) or TIER_VERBS.search(normalised_code(block)):
            found.append((name, block))
    return found


TIER_VERBS = ty.TIER_VERBS
EMPTY_EXPANSION = ty.EMPTY_EXPANSION


def normalised_code(block):
    """The code lines of a block with continuations joined and the disguises that keep a name intact removed.

    Comment lines go; a backslash before a newline or before any character goes; empty quote pairs and empty
    ``${NAME}`` expansions go.  The tier markers are then searched in this text (F12a), so a name split over a
    continuation, escaped or padded with empty expansions is still found.
    """
    code = "\n".join(ln for ln in block.split("\n") if not comment_or_blank(ln))
    code = re.sub(r"\\\n\s*", "", code)
    code = re.sub(r"\\(.)", r"\1", code)
    for _ in range(3):
        code = EMPTY_EXPANSION.sub("", code)
    return code


def workflow_level_blocks(text):
    """``{key: block text}`` for the workflow-level ``env`` and ``defaults`` keys (F12b); absent keys are left out.

    A block runs from its column-0 key to the next column-0 code line; trailing comment and blank lines are dropped.
    """
    lines = text.split("\n")
    found = {}
    for i, line in enumerate(lines):
        match = re.match(r"^(env|defaults):", line)
        if not match:
            continue
        end = i + 1
        while end < len(lines) and (comment_or_blank(lines[end]) or lines[end].startswith(" ")):
            end += 1
        while end > i + 1 and comment_or_blank(lines[end - 1]):
            end -= 1
        found.setdefault(match.group(1), []).extend(lines[i:end])
    return {key: "\n".join(rows) for key, rows in found.items()}


PRIMARY = "primary"
SECONDARY = "secondary_text"


def load_job_pins():
    """The whole pin data file, three top-level sections: ``primary`` (``{workflow: ty.build_pins(...)}``),
    ``secondary_text`` (``{workflow: {"jobs", "pinned", "workflow"}}``) and ``exempt_jobs``
    (``{workflow: {"jobs", "workflow_keys"}}``, the self-hosted exempt job and its workflow-level keys)."""
    return json.loads(JOB_PINS_FILE.read_text(encoding="utf-8"))


def step_label(block, offset, steps=None):
    """``(step index, step label)`` of the step that holds line ``offset`` of a job block, for the failure message.

    The index is a position counted from the ``- `` heads of the block; the label comes from the LOADED document
    (``ty.step_label(steps[index], index)``, ``steps`` is the loaded step list of the job), else ``step[<index>]`` when
    the document did not load.  No source row is ever read for a label (F30): every source row is author text."""
    rows = block.split("\n")
    steps_at = next((i for i, ln in enumerate(rows) if ln.strip() == "steps:"), None)
    if steps_at is None or offset <= steps_at:
        return None, "job-level keys"
    item = next((indent_of(ln) for ln in rows[steps_at + 1:] if not comment_or_blank(ln)), 0)
    heads = [i for i in range(steps_at + 1, len(rows))
             if indent_of(rows[i]) == item and rows[i].lstrip().startswith("- ")]
    owner = max((n for n, i in enumerate(heads) if i <= offset), default=None)
    if owner is None:
        return None, "job-level keys"
    if isinstance(steps, list) and owner < len(steps):
        return owner, ty.step_label(steps[owner], owner)
    return owner, ty.Opaque("", f"step[{owner}]")


def first_difference(pinned, block):
    """``(line offset, "")`` of the first line of ``block`` that differs from the pinned line hashes; the line itself is
    never returned (F26), so no caller can echo it."""
    new = block.split("\n")
    old = [pinned["lines"][k:k + 12] for k in range(0, len(pinned["lines"]), 12)]
    for number in range(max(len(old), len(new))):
        if number >= len(new):
            return number, "<the job ends here; pinned lines are missing>"
        if number >= len(old) or hashlib.sha256(new[number].encode("utf-8")).hexdigest()[:12] != old[number]:
            return number, ""
    return 0, ""


def job_pin_problems(workflow, text, pins=None):
    """Problems of the complete tier jobs of one workflow against the pins (r7 F11).

    The whole job that names the tier credential is pinned, every line from its key to its last code line, so no step
    before or after the export can change unseen; the set of jobs is pinned too, so a new or renamed job cannot appear
    unpinned.  The export call must sit inside a pinned job.  Messages carry the workflow, job, step index and name,
    and the first differing line number; the changed line itself is never echoed (F24).
    """
    pins = load_job_pins()[SECONDARY] if pins is None else pins
    jobs, problems = job_layout(text)
    problems = [f"{workflow}: {p}" for p in problems]
    entry = pins.get(workflow)
    if entry is None:
        return problems + [f"{workflow}: no job pin exists for this workflow"]
    names = [j[0] for j in jobs]
    if names != entry["jobs"]:
        added = [ty.name_label(n, names) for n in sorted(set(names) - set(entry["jobs"]))]
        gone = [ty.name_label(n, entry["jobs"]) for n in sorted(set(entry["jobs"]) - set(names))]
        problems.append(f"{workflow}: the set of jobs changed (added {added}, missing {gone}"
                        f"{'' if set(names) != set(entry['jobs']) else ', order changed'})")
    tiered = dict(tier_blocks(jobs))
    for name in tiered:
        if name not in entry["pinned"]:
            problems.append(f"{workflow} job {ty.name_label(name, names)}: names the tier credential but is not pinned")
    for name, pinned in entry["pinned"].items():
        if name not in tiered:
            problems.append(f"{workflow} job {ty.name_label(name, entry['pinned'])}: "
                            "pinned job is missing or no longer names the tier credential")
        elif hashlib.sha256(tiered[name].encode("utf-8")).hexdigest() != pinned["sha256"]:
            offset, _changed = first_difference(pinned, tiered[name])
            loaded, _found = ty.parse_workflow(text)
            job = ((loaded or {}).get("jobs") or {}).get(name)
            index, label = step_label(tiered[name], offset, job.get("steps") if isinstance(job, dict) else None)
            where = "job-level keys" if index is None else f"step {index} ({label})"
            first = next(j[1] for j in jobs if j[0] == name)
            problems.append(f"{workflow} job {ty.name_label(name, names)} {where}: "
                            f"differs from the pin at line {first + offset + 1}")
    outside = [i + 1 for i, ln in enumerate(text.split("\n"))
               if EXPORT_CALL.search(normalised_code(ln)) and not any(j[1] <= i < j[2] and j[0] in entry["pinned"]
                                                                      for j in jobs)]
    if outside:
        problems.append(f"{workflow}: the tier export call at line {outside[0]} sits outside a pinned job")
    level = workflow_level_blocks(text)
    pinned_level = entry.get("workflow", {})
    for key in sorted(set(level) | set(pinned_level)):
        if key not in level:
            label = ty.name_label(key, set(level) | set(pinned_level))
            problems.append(f"{workflow}: the pinned workflow-level {label}: block is missing")
        elif key not in pinned_level:
            problems.append(f"{workflow}: a workflow-level {key}: block was added and is not pinned")
        elif hashlib.sha256(level[key].encode("utf-8")).hexdigest() != pinned_level[key]["sha256"]:
            offset, _changed = first_difference(pinned_level[key], level[key])
            problems.append(f"{workflow}: the workflow-level {key}: block differs from the pin at its line {offset + 1}")
    if not any(EXPORT_CALL.search(normalised_code(tiered.get(name, ""))) for name in entry["pinned"]):
        problems.append(f"{workflow}: no pinned job exports the tier URL, so the pin cannot be placed")
    return problems



# The runs-on exemption table lives in tier_yaml_8187.py (the non-tier runner rule of the pinned workflows reads it too):
# (workflow, job) -> (reason, pinned runs-on string, frozenset of label tuples).  No expression is resolved anywhere else.
RUNS_ON_EXEMPT = ty.RUNS_ON_EXEMPT
exemption_problem = ty.exemption_problem
EXEMPT = "exempt_jobs"


def self_hosted_rows():
    """The table rows that may name a label that is not GitHub-hosted: their jobs are pinned step by step (F20)."""
    return sorted(key for key, (_why, _pinned, label_sets) in RUNS_ON_EXEMPT.items()
                  if any(not ty.HOSTED_LABEL.match(label) for labels in label_sets for label in labels))


def exempt_pins(root=None):
    """The ``exempt_jobs`` pin section built from the real workflows (F20, F21):
    ``{workflow: {"jobs": {job: ty.pin_job(job)}, "workflow_keys": {key: digest}}}``.  The workflow-level digest is
    the one ``ty.build_pins`` writes for the tier workflows (decision: reuse the primary workflow_keys digest for
    exempt workflows over a new exempt-only shape because one shared comparison helper, ``workflow_key_problems``,
    keeps one problem-line format and --write-pins stays one generator)."""
    directory = (ROOT if root is None else Path(root)) / ".github" / "workflows"
    table = {}
    for workflow, name in self_hosted_rows():
        data, bad = ty.parse_workflow((directory / workflow).read_text(encoding="utf-8"))
        if bad or name not in data["jobs"]:
            sys.exit(f"{workflow}: cannot pin exempt job {name}")
        entry = table.setdefault(workflow, {"jobs": {}, "workflow_keys": ty.build_pins(data)["workflow_keys"]})
        entry["jobs"][name] = ty.pin_job(data["jobs"][name])
    return table


def exempt_pin_problems(workflow, name, job, pins):
    """Problems of one self-hosted exempt job against its canonical-JSON pin (F20): any step or key edit needs
    ``--write-pins``.  The message names the workflow, job, step index and name and the first differing key path."""
    entry = (((pins.get(EXEMPT) or {}).get(workflow) or {}).get("jobs") or {}).get(name)
    if entry is None:
        return [f"{workflow} job {name}: a self-hosted exempt job has no job pin"]
    if ty.digest(job) == entry["sha256"]:
        return []
    index, path = ty.first_difference(entry, job)
    return [f"{workflow} job {name} {where_differs(job, index)}: differs from the pin at {path}"]


def workflow_key_problems(workflow, data, pinned_keys):
    """The one per-key digest comparison of the workflow-level keys (everything except ``jobs``) against their pin,
    shared by ``primary_pin_problems`` and ``exempt_workflow_key_problems`` (F23b); key names only, never values."""
    level = {key: ty.digest(value) for key, value in data.items() if key != "jobs"}
    problems = []
    for position, key in enumerate(sorted(set(level) | set(pinned_keys))):
        label = ty.key_label(key, position)
        if key not in level:
            problems.append(f"{workflow}: the pinned workflow-level key {label} is missing")
        elif key not in pinned_keys:
            problems.append(f"{workflow}: a workflow-level key {label} was added and is not pinned")
        elif level[key] != pinned_keys[key]:
            problems.append(f"{workflow}: the workflow-level key {label} differs from the pin")
    return problems


def exempt_workflow_key_problems(workflow, raw, pins):
    """Problems of the workflow-level keys (everything except ``jobs``) of a workflow that holds a self-hosted exempt
    row (F21): the per-key digest comparison and wording of ``primary_pin_problems``; never any document text."""
    pinned_keys = ((pins.get(EXEMPT) or {}).get(workflow) or {}).get("workflow_keys")
    if pinned_keys is None:
        return [f"{workflow}: a self-hosted exempt workflow has no workflow-level pin"]
    data, found = ty.parse_workflow(raw)
    if data is None:
        return [f"{workflow}: {p}" for p in found]
    return workflow_key_problems(workflow, data, pinned_keys)


def where_differs(job, index):
    """``job-level keys`` or ``step N (label)`` for a first-difference index of a loaded job."""
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    if index is None:
        return "job-level keys"
    if index < len(steps):
        return f"step {index} ({ty.step_label(steps[index], index)})"
    return f"step {index} (removed)"


def primary_pin_problems(workflow, text, primary):
    """Problems of one tier workflow against the canonical-JSON pins (r8).

    The text is read by ``StrictLoader``; every tier job, every workflow-level key except ``jobs`` and the sorted job
    names are compared with their SHA-256 pin.  A difference names the workflow, the job, the step index and
    name, and the first differing key path (``steps[3].run``), never the changed value (r23: every value is an opaque label, nothing is masked after the fact).
    A non-tier job must run on a GitHub-hosted label, and no local action or reusable workflow may be called.
    """
    data, found = ty.parse_workflow(text)
    problems = [f"{workflow}: {p}" for p in found]
    if data is None or not isinstance(data.get("jobs"), dict):
        return problems
    entry = primary.get(workflow)
    if entry is None:
        return problems + [f"{workflow}: no primary pin exists for this workflow"]
    jobs = data["jobs"]
    names = sorted(jobs)
    if ty.digest(names) != entry["job_names_sha256"]:
        added = [ty.job_label(n, jobs) for n in sorted(set(names) - set(entry["job_names"]))]
        gone = [ty.name_label(n, entry["job_names"]) for n in sorted(set(entry["job_names"]) - set(names))]
        problems.append(f"{workflow}: the set of jobs changed (added {added}, missing {gone})")
    tier = ty.tier_job_names(data)
    for name in tier:
        if name not in entry["tier_jobs"]:
            problems.append(f"{workflow} job {ty.job_label(name, jobs)}: names the tier credential but is not pinned")
    for name, pinned in entry["tier_jobs"].items():
        if name not in tier:
            problems.append(f"{workflow} job {ty.name_label(name, entry['tier_jobs'])}: "
                            "pinned job is missing or no longer names the tier credential")
        elif ty.digest(jobs[name]) != pinned["sha256"]:
            index, path = ty.first_difference(pinned, jobs[name])
            problems.append(f"{workflow} job {ty.job_label(name, jobs)} {where_differs(jobs[name], index)}: differs from the pin at {path}")
    pinned_keys = entry["workflow_keys"]
    problems += workflow_key_problems(workflow, data, pinned_keys)
    for name, job in jobs.items():
        if name not in entry["tier_jobs"] and EXPORT_CALL.search(ty.normalised_leaves(job)):
            problems.append(f"{workflow} job {ty.job_label(name, jobs)}: the tier export call sits outside a pinned job")
    if not any(EXPORT_CALL.search(ty.normalised_leaves(jobs[name])) for name in entry["tier_jobs"] if name in jobs):
        problems.append(f"{workflow}: no pinned job exports the tier URL, so the pin cannot be placed")
    problems += ty.non_tier_runner_problems(workflow, data, set(tier))
    for job, where, value in ty.uses_references(data):
        if where == "job" or value.startswith("./"):
            problems.append(f"{workflow} job {ty.job_label(job, jobs)} {where}: "
                            "a local action or reusable workflow call is not allowed here")
    return problems


def tier_pin_problems(workflow, text, pins=None):
    """Primary (loader, canonical JSON) problems first, then the secondary whole-job text pin of r7."""
    pins = load_job_pins() if pins is None else pins
    return primary_pin_problems(workflow, text, pins[PRIMARY]) + job_pin_problems(workflow, text, pins[SECONDARY])


def repo_problems(root=None, pins=None):
    """Every problem of a repository root: the three pinned workflows, discovery, runners and local actions."""
    root = ROOT if root is None else Path(root)
    pins = load_job_pins() if pins is None else pins
    found = []
    directory = root / ".github" / "workflows"
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        raw = path.read_text(encoding="utf-8")
        name = path.name
        if name in PIN_WORKFLOWS:
            found += tier_pin_problems(name, raw, pins)
            continue
        if names_the_tier(raw) and name not in LOCAL_ONLY:
            found.append(f"{name}: names the tier secret but no pin covers it")
        try:
            data = ty.load_lenient(raw)
        except ty.StrictYamlError as exc:
            found.append(f"{name}: the workflow does not load ({ty.load_failure(exc)}); an unparsable workflow is refused")
            continue
        jobs = data.get("jobs") if isinstance(data, dict) else None
        if not isinstance(jobs, dict):
            found.append(f"{name}: jobs is missing or not a mapping")
            continue
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                found.append(f"{name} job {ty.job_label(job_name, jobs)}: the job is not a mapping")
                continue
            if "uses" in job:
                found.append(f"{name} job {ty.job_label(job_name, jobs)}: a job-level uses (reusable workflow call) is not allowed; "
                             "the called workflow chooses its own runner")
                continue
            why = ty.runner_problem(name, job_name, job)
            if why:
                found.append(f"{name} job {ty.job_label(job_name, jobs)}: {why}")
            if (name, job_name) in self_hosted_rows():
                found += exempt_pin_problems(name, job_name, job, pins)
        if any(wf == name for wf, _job in self_hosted_rows()):
            found += exempt_workflow_key_problems(name, raw, pins)
    for workflow in sorted({wf for wf, _job in RUNS_ON_EXEMPT}):
        target = directory / workflow
        if not target.is_file():
            found.append(f"{workflow}: stale exemption rows (the workflow file is gone)")
            continue
        try:
            found += ty.stale_row_problems(workflow, ty.load_lenient(target.read_text(encoding="utf-8")))
        except ty.StrictYamlError:
            pass  # reported above as an unparsable workflow
    actions = root / ".github" / "actions"
    for path in sorted([*actions.rglob("action.yml"), *actions.rglob("action.yaml")]) if actions.is_dir() else []:
        if names_the_tier(path.read_text(encoding="utf-8")):
            found.append(f"{path.relative_to(root)}: a local action names the tier secret")
    return found


def joined_numbered(rows):
    """``(first line number, joined line)`` of ``(number, line)`` rows with each backslash continuation joined, as the
    shell joins it (``prin\\`` + ``tenv``); the number is that of the first physical line of the joined one."""
    joined = []
    pending = None
    start = 0
    for number, raw in rows:
        if pending is None:
            start = number
        piece = raw.strip() if pending is None else pending + raw.lstrip()
        pending = None
        if piece.endswith("\\"):
            pending = piece[:-1]
        else:
            joined.append((start, piece))
    if pending is not None:
        joined.append((start, pending))
    return joined


def joined_lines(lines):
    """Stripped lines with each backslash continuation joined, as the shell joins it (``prin\\`` + ``tenv``)."""
    return [piece for _number, piece in joined_numbered(list(enumerate(lines, 1)))]


PROC = "/proc/"
DUMP_MUTANTS = {
    "proc self read": "cat " + PROC + "self/environ",
    "proc self piped": "cat " + PROC + "self/environ | base64",
    "base64 of proc": "base64 " + PROC + "self/environ",
    "xxd of proc": "xxd " + PROC + "self/environ",
    "proc pid read": "tr '\\0' '\\n' < " + PROC + "1234/environ",
    "env -0 piped": "env -0 | base64",
    "printenv -0": "printenv -0",
    "absolute env": "/usr/bin/env",
    "absolute printenv": "/usr/bin/printenv",
    "env with flags": "env -i",
    "printenv with a name": "printenv HOME",
    "if env": "if env | base64; then",
    "while printenv": "while printenv; do",
    "test of substitution": '[ -n "$(env)" ]',
    "substitution": 'x=$(env)',
    "backtick": "x=`env`",
    "after then": "then printenv",
    "after bang": "! env",
    "after exec": "exec env",
    "after time": "time printenv",
    "python dump": "python3 -c 'import os; print(os.environ)'",
    "python dict": 'python3 -c "print(dict(os.environ))"',
    "perl dump": "perl -e 'print %ENV'",
    "node dump": "node -e 'console.log(process.env)'",
    "ruby dump": "ruby -e 'p ENV'",
}


class TestEveryTierWorkflowIsCovered8187(unittest.TestCase):
    def test_no_workflow_that_names_the_tier_secret_escapes_the_pins(self):
        covered = {"ci.yml", *SHARED_TIER, *LOCAL_ONLY}
        self.assertEqual(len(sorted(set(tier_workflows()) - covered)), 0, "a workflow names the tier secret but no pin covers it: route it through tier_credential.py")
        self.assertEqual(len(sorted(covered - set(tier_workflows()))), 0, "a covered workflow no longer names the tier")

    def test_the_shared_tier_workflows_never_put_the_url_on_argv_or_in_github_env(self):
        for name in SHARED_TIER:
            with self.subTest(workflow=name):
                self.assertEqual(len(workflow_problems((WORKFLOWS / name).read_text(encoding="utf-8"))), 0)

    def test_the_local_only_workflows_hold_no_tier_url(self):
        for name, literal in LOCAL_ONLY.items():
            text = (WORKFLOWS / name).read_text(encoding="utf-8")
            self.assertIs("ai-memory-ci-fed-url" not in text, True)
            for line in code_lines(text):
                if TIER_MARKERS.search(line):
                    self.assertIs(literal in line, True, "only a literal throwaway local database may name the variable")

    def test_each_mutant_of_a_shared_workflow_is_caught(self):
        text = (WORKFLOWS / "cert-postgres-age.yml").read_text(encoding="utf-8")
        self.assertEqual(len(workflow_problems(text)), 0)
        run = "python3 -I " + HELPER + ' run --url-file "$url_file" --database "$CI_FED_DB" -- psql'
        mutants = {
            "psql on argv": text.replace(run + " -v ON_ERROR_STOP=1 -tAc", 'psql "$AI_MEMORY_TEST_POSTGRES_URL" -tAc', 1),
            "url read by cat": text.replace('          if [ ! -f "$url_file" ]; then',
                                            '          base_url="$(cat "$url_file")"\n          if [ ! -f "$url_file" ]; then', 1),
            "hand-written GITHUB_ENV": text.replace(GITHUB_ENV_LINE, 'echo "AI_MEMORY_TEST_POSTGRES_URL=$x" >> "$GITHUB_ENV"', 1),
            "github-env removed": text.replace(GITHUB_ENV_LINE, "true", 1),
            "age url dropped": text.replace(" --age-url", "", 1),
        }
        for name, edited in mutants.items():
            with self.subTest(mutant=name):
                self.assertIs(edited != text, True, "the mutation did not apply")
                self.assertTrue(workflow_problems(edited), f"mutant not caught: {name}")

    def test_the_allowlist_catches_the_round_2_bypasses_8187(self):
        # F5: a deny-list skipped `echo` lines and a redirection read fed to a client other than psql
        text = (WORKFLOWS / "cert-postgres-age.yml").read_text(encoding="utf-8")
        anchor = '          if [ ! -f "$url_file" ]; then'
        mutants = {
            "echo piped to psql with cat": '          echo "SELECT 1" | psql "$(cat "$url_file")"',
            "redirect read into pg_isready": '          tier="$(< "$url_file")"\n          pg_isready -d "$tier"',
            "read builtin into psql": '          read -r tier < "$url_file"\n          psql "$tier" -c "SELECT 1"',
            "echo of the file": '          echo "$(cat "$url_file")"',
            "redirect read into another client": '          pg_dump "$(< "$url_file")" > dump.sql',
            "file copied": '          cp "$url_file" "$RUNNER_TEMP/x"',
            "file by its path": '          cat "$HOME/.ai-memory-ci-fed-url"',
            "helper output piped on": '          python3 -I ' + HELPER + ' run --url-file "$url_file" -- psql -c x | tee out',
            "helper with substitution": '          python3 -I ' + HELPER + ' run --url-file "$url_file" -- psql -c "$(< "$url_file")"',
        }
        for name, add in mutants.items():
            with self.subTest(mutant=name):
                edited = text.replace(anchor, add + "\n" + anchor, 1)
                self.assertIs(edited != text, True, "the mutation did not apply")
                self.assertTrue(workflow_problems(edited), f"mutant not caught: {name}")

    def test_message_echo_check_is_linear_on_pathological_input_8187(self):
        # F6a: the old regex backtracked exponentially (0.36 s at 20 repetitions); 30 repetitions must stay fast
        import time
        bad = 'echo "::error::' + "}}$url_file" * 30 + '`'
        good = 'echo "::error::${RUNNER_NAME} is missing $url_file and ${CI_FED_DB}"'
        started = time.perf_counter()
        self.assertFalse(allowed_url_file_line(bad))
        self.assertLess(time.perf_counter() - started, 0.05)
        self.assertTrue(allowed_url_file_line(good))
        for line in ('echo "::notice::$(cat $url_file)"', 'echo "::error::`id` $url_file"',
                     'echo "::error::$HOME $url_file"', 'echo "::error::x" ; printenv',
                     'echo "::error::' + BANG + ' env $url_file"'):
            with self.subTest(line=line):
                self.assertFalse(allowed_url_file_line(line))

    def test_loader_tails_and_array_calls_are_pinned_8187(self):
        # F7: psql meta-commands reaching a shell, chained commands, and the "${PSQL[@]}" array calls
        text = (WORKFLOWS / "cert-postgres-age.yml").read_text(encoding="utf-8")
        run = "python3 -I " + HELPER + ' run --url-file "$url_file" --database "$CI_FED_DB" -- psql'
        anchor = '          if [ ! -f "$url_file" ]; then'
        psql_array = '"${PSQL[@]}"'
        mutants = {
            "meta shell escape env": "          if " + run + " -c '" + BANG + " env'; then",
            "meta shell escape printenv": "          if " + run + ' -c "' + BANG + ' printenv"; then',
            "chained printenv": "          if " + run + " -c x; printenv",
            "chained and": "          " + run + ' -c x && cat "$HOME/.ai-memory-ci-fed-url"',
            "chained or": "          " + run + " -c x || printenv",
            "piped on": "          " + run + " -c x | sh",
            "psql lookalike": "          if " + run + ".py -c x; then",
            "array meta shell escape": "          " + psql_array + " -c '" + BANG + " env'",
            "array chained printenv": "          " + psql_array + " -c x; printenv",
            "array piped to sh": "          " + psql_array + " -c x | sh",
            "array rewrapped": "          P2=(" + psql_array + ")",
            "array output on a file": "          " + psql_array + ' -c x > "$RUNNER_TEMP/o"',
            "server side program": "          " + psql_array + ' -c "COPY t TO PROGRAM \'printenv\'"',
        }
        for name, add in mutants.items():
            with self.subTest(mutant=name):
                edited = text.replace(anchor, add + "\n" + anchor, 1)
                self.assertIs(edited != text, True, "the mutation did not apply")
                self.assertTrue(workflow_problems(edited), f"mutant not caught: {name}")

    def test_environment_dumps_are_rejected_in_every_shared_workflow_8187(self):
        # F8: ci.yml already rejects these; the shared workflows must too
        anchor = '          if [ ! -f "$url_file" ]; then'
        extra = {"env piped to base64": "env | base64", "printenv piped to base64": "printenv | base64",
                 "xtrace": "set -x", "xtrace by option": "set -o xtrace", "printenv chain": "true; printenv",
                 "bare env": "env", "export -p": "export -p"}
        for name in SHARED_TIER:
            text = (WORKFLOWS / name).read_text(encoding="utf-8")
            self.assertEqual(len(workflow_problems(text)), 0)
            for label, line in extra.items():
                with self.subTest(workflow=name, mutant=label):
                    edited = text.replace(anchor, "          " + line + "\n" + anchor, 1)
                    if edited == text:
                        edited = text.replace("      - name:", "      - run: " + line + "\n      - name:", 1)
                    self.assertIs(edited != text, True, "the mutation did not apply")
                    self.assertTrue(workflow_problems(edited), f"mutant not caught: {label}")

    def test_environment_dump_forms_are_all_rejected_8187(self):
        # r5 F9: process-environment reads, absolute paths, dumps in conditions, one-line steps, interpreters
        ci_text = CI_YML.read_text(encoding="utf-8")
        ci_anchor = 'echo "::notice::[enterprise-fed] created'
        anchor = '          if [ ! -f "$url_file" ]; then'
        for label, line in DUMP_MUTANTS.items():
            with self.subTest(workflow="ci.yml", mutant=label):
                edited = sub_once(ci_text, ci_anchor, line + "\n          " + ci_anchor)
                self.assertTrue(url_leaks(edited), f"mutant not caught: {label}")
            for name in SHARED_TIER:
                text = (WORKFLOWS / name).read_text(encoding="utf-8")
                with self.subTest(workflow=name, mutant=label):
                    edited = text.replace(anchor, "          " + line + "\n" + anchor, 1)
                    self.assertIs(edited != text, True, "the mutation did not apply")
                    self.assertTrue(workflow_problems(edited), f"mutant not caught: {label}")
                with self.subTest(workflow=name, mutant=label, form="one-line step"):
                    edited = text.replace("      - name:", "      - run: " + line + "\n      - name:", 1)
                    self.assertIs(edited != text, True, "the mutation did not apply")
                    self.assertTrue(workflow_problems(edited), f"mutant not caught: {label}")
        for name in SHARED_TIER:
            self.assertEqual(len(workflow_problems((WORKFLOWS / name).read_text(encoding="utf-8"))), 0)
        self.assertEqual(len(url_leaks(ci_text)), 0)

    def test_a_yaml_workflow_naming_the_tier_secret_is_checked_8187(self):
        scratch = ROOT / ".local-runs" / "r3"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch, prefix="wf-") as raw:
            directory = Path(raw)
            (directory / "scratch-tier.yaml").write_text("steps:\n  - run: cat ~/.ai-memory-ci-fed-url\n", encoding="utf-8")
            (directory / "other.yml").write_text("steps:\n  - run: echo hi\n", encoding="utf-8")
            self.assertIs(tier_workflows(directory) == ["scratch-tier.yaml"], True)


# r6 F10: the reviewers' dump forms that the command-word detector passes.  Each is placed in a post-export step.
F10_MUTANTS = {
    "busybox env": "busybox env",
    "sh -c env": "sh -c env",
    "bash -c printenv": "bash -c 'printenv'",
    "env redirect then cat": "env>out; cat out",
    "printenv redirect": "printenv>log",
    "variable holds the command": 'e=env; $e',
    "timeout env": "timeout 5 env",
    "nice printenv": "nice -n 1 printenv",
    "xargs env": "echo | xargs env",
    "eval printenv": "eval printenv",
    "eval concatenated": 'eval "print""env"',
    "proc environ through a variable": "f=environ; cat " + PROC + "self/$f",
    "python here-doc": "python3 - <<'PYEOF'\nimport os\nprint(os.environ)\nPYEOF",
    "perl here-doc": "perl <<'PLEOF'\nprint %ENV;\nPLEOF",
    "awk ENVIRON": "awk 'BEGIN{for(k in ENVIRON)print k\"=\"ENVIRON[k]}'",
    "jq env": "jq -n env",
    "jq dollar ENV": "jq -n '$ENV'",
    "busybox env piped": "busybox env | base64",
    "sh -c env piped": "sh -c env | base64",
    "bash -c printenv piped": "bash -c 'printenv' | base64",
    "env redirect then base64": "env>out; base64 out",
    "printenv short redirect": "printenv>o",
    "declare -xp": "declare -xp | base64",
    "typeset -px": "typeset -px | base64",
    "xargs after a pipe": "true | xargs env | base64",
    "timeout env piped": "timeout 5 env | base64",
    "nice printenv piped": "nice printenv | base64",
    "sudo -E env": "sudo -E env | base64",
    "find exec env": "find . -maxdepth 0 -exec env \\; | base64",
    "eval env piped": "eval env | base64",
    "quoted letters": "p''rintenv | base64",
    "word split on a continuation": "prin\\\ntenv | base64",
    "interpreter continued": "python3 -c \\\n'import os; print(os.environ)'",
    "proc split on a continuation": "cat " + PROC + "self/env\\\niron",
}


def inject_run_line(text, step, mutant):
    """``text`` with ``mutant`` (may span lines) as the first line of the step's ``run: |`` block, or None."""
    _job, _name, _body, first, end = step
    lines = text.split("\n")
    for k in range(first, end):
        if re.match(r"^\s+(?:- )?run:\s*[|>][-+]?\s*$", lines[k]) and k + 1 < end:
            pad = " " * indent_of(lines[k + 1])
            lines[k + 1:k + 1] = [pad + part for part in mutant.split("\n")]
            return "\n".join(lines)
    return None


def pin_targets(workflow, text):
    """The post-export steps (with a ``run: |`` block) that the mutation tests edit: all of the two shared workflows,
    and the four that matter most in ci.yml."""
    keys = [k for k, _ in post_export_steps(workflow, text)]
    wanted = ("Configure enterprise-fed tier", "pg_isolated_binary live cells", "Run tests (impact-aware)",
              "Cleanup enterprise-fed ephemeral db")
    chosen = []
    for step in workflow_steps(text):
        key_name = f"{workflow}:{step[0]}:{step[1]}"
        if not any(key == key_name or key.startswith(key_name + "#") for key in keys):
            continue
        if workflow == "ci.yml" and not any(w in step[1] for w in wanted):
            continue
        if inject_run_line(text, step, "true") is not None:
            chosen.append(step)
    return chosen


def section_end(text):
    """Index (in ``text.split("\\n")``) just past the last line of the ``jobs:`` section."""
    lines = text.split("\n")
    head = next(i for i, ln in enumerate(lines) if re.match(r"^jobs:\s*$", ln))
    for i in range(head + 1, len(lines)):
        if lines[i].strip() and not lines[i].startswith((" ", "#")):
            return i
    return len(lines)


def tier_job(workflow, text):
    """Name of the one job of the workflow that exports the tier URL (found on the real text)."""
    return post_export_steps(workflow, text)[0][0].split(":")[1]


def job_steps(workflow, text):
    return [s for s in workflow_steps(text) if s[0] == tier_job(workflow, text)]


def splice(text, at, new_lines):
    lines = text.split("\n")
    return "\n".join(lines[:at] + new_lines + lines[at:])


EXPORT_LINE = 'python3 -I ' + HELPER + ' github-env --url-file "$url_file" --database "$CI_FED_DB"'
PRE_EXPORT_HOOKS = {
    "BASH_ENV": 'echo "BASH_ENV=$RUNNER_TEMP/hook.sh" >> "$GITHUB_ENV"',
    "LD_PRELOAD": 'echo "LD_PRELOAD=$RUNNER_TEMP/hook.so" >> "$GITHUB_ENV"',
    "NODE_OPTIONS": 'echo "NODE_OPTIONS=--require $RUNNER_TEMP/hook.js" >> "$GITHUB_ENV"',
    "PATH file": 'echo "$RUNNER_TEMP/shim" >> "$GITHUB_PATH"',
}


class TestExportJobIsPinned8187(unittest.TestCase):
    """r7 F11: the complete job that exports the tier URL is pinned, every line of it, and so is the set of jobs."""

    @classmethod
    def setUpClass(cls):
        cls.texts = {wf: (WORKFLOWS / wf).read_text(encoding="utf-8") for wf in PIN_WORKFLOWS}
        cls.pins = load_job_pins()

    def caught(self, workflow, edited, label):
        self.assertTrue(tier_pin_problems(workflow, edited, self.pins), f"{workflow}: mutant not caught: {label}")

    def test_the_real_workflows_match_their_pins(self):
        for wf, text in self.texts.items():
            with self.subTest(workflow=wf):
                self.assertEqual(len(tier_pin_problems(wf, text, self.pins)), 0)
                self.assertTrue(self.pins[SECONDARY].get(wf, {}).get("pinned"), "no job is pinned for this workflow")

    def test_a_changed_line_is_never_echoed_into_a_problem_8187_f24(self):
        sentinel = "SENTINEL-F24-9f3a"
        echo = "found " + chr(39)
        seen = {"job": 0, "workflow-level": 0}
        for wf, text in self.texts.items():
            for step in pin_targets(wf, text)[:1]:
                edited = inject_run_line(text, step, f"echo {sentinel}")
                problems = job_pin_problems(wf, edited, self.pins[SECONDARY])
                hits = [p for p in problems if re.search(re.escape(wf) + " job " + job_re(step[0]) + " ", p) and "differs from the pin" in p]
                with self.subTest(workflow=wf, site="job"):
                    self.assertTrue(hits, "the job-level difference is reported with its key path")
                    seen["job"] += 1
                    self.assertTrue(not ([p for p in problems if sentinel in p or echo in p]))
            lines = text.split("\n")
            at = next((i for i, ln in enumerate(lines) if ln.startswith("env:")), None)
            if at is None:
                continue
            lines.insert(at + 1, f"  F24_KEY: {sentinel}")
            problems = job_pin_problems(wf, "\n".join(lines), self.pins[SECONDARY])
            with self.subTest(workflow=wf, site="workflow-level"):
                self.assertTrue([p for p in problems if f"{wf}: the workflow-level env: block differs" in p])
                seen["workflow-level"] += 1
                self.assertTrue(not ([p for p in problems if sentinel in p or echo in p]))
        self.assertGreater(seen["job"], 0)
        self.assertGreater(seen["workflow-level"], 0)

    def test_the_pin_table_holds_exactly_the_jobs_that_name_the_tier(self):
        assert_same(self, sorted(self.pins[SECONDARY]), sorted(PIN_WORKFLOWS), "secondary pin workflow set")
        for wf, text in self.texts.items():
            jobs, problems = job_layout(text)
            self.assertEqual(problems, [])
            assert_same(self, self.pins[SECONDARY][wf]["jobs"], [j[0] for j in jobs], f"{wf} pinned job list")
            for name, block in tier_blocks(jobs):
                label = ty.name_label(name, self.pins[SECONDARY][wf]["pinned"])
                assert_same(self, self.pins[SECONDARY][wf]["pinned"][name], pin_entry(block), f"{wf} pin of {label}")
            assert_same(self, sorted(self.pins[SECONDARY][wf]["pinned"]), sorted(n for n, _ in tier_blocks(jobs)),
                        f"{wf} pinned job set")

    def test_every_dump_form_after_the_export_fails_the_pin(self):
        forms = {**DUMP_MUTANTS, **F10_MUTANTS}
        self.assertGreaterEqual(len(forms), 57)
        for wf, text in self.texts.items():
            targets = pin_targets(wf, text)
            self.assertTrue(targets, f"{wf}: no post-export step with a run block to mutate")
            for position, step in enumerate(targets):
                for label, line in forms.items():
                    with self.subTest(workflow=wf, step=position, mutant=label):
                        edited = inject_run_line(text, step, line)
                        self.assertIs(edited is not None, True)
                        self.assertIs(edited != text, True, "the mutation did not apply")
                        self.caught(wf, edited, label)

    def test_a_second_job_with_four_space_steps_that_exports_and_dumps_fails_8187_f11a(self):
        for wf, text in self.texts.items():
            at = section_end(text)
            steps_four = ["  second:", "    runs-on: ubuntu-latest", "    steps:", "    - name: Export",
                          "      run: |", "        " + EXPORT_LINE, "    - name: Dump", "      run: printenv | base64"]
            nested_job = ["    nested:", "      runs-on: ubuntu-latest", "      steps:", "      - run: |",
                          "          " + EXPORT_LINE, "      - run: busybox env | base64"]
            for label, new in (("four-space steps", steps_four), ("job key at four spaces", nested_job),
                               ("six-space steps", [ln.replace("    ", "      ", 1) if i else ln
                                                    for i, ln in enumerate(steps_four)])):
                with self.subTest(workflow=wf, shape=label):
                    self.caught(wf, splice(text, at, new), label)

    def test_a_split_or_disguised_export_in_a_new_job_is_still_found_8187_f12a(self):
        splits = {
            "split inside the file name": ["python3 -I scripts/ci/tier_cred\\", "ential.py github-env --url-file \"$url_file\""],
            "split inside the verb": ["python3 -I " + HELPER + " github-\\", "env --url-file \"$url_file\""],
            "empty expansion": ["python3 -I scripts/ci/tier_credential${E}.py github-env --url-file \"$url_file\""],
            "backslash inside the name": ["python3 -I scripts/ci/tier_cre\\dential.py github-env --url-file \"$url_file\""],
            "empty quotes": ["python3 -I scripts/ci/tier_cred''ential.py github-env --url-file \"$url_file\""],
            "here-doc": ["bash <<'EOS'", EXPORT_LINE, "EOS"],
        }
        for wf, text in self.texts.items():
            at = section_end(text)
            for label, call in splits.items():
                new = ["  second:", "    runs-on: ubuntu-latest", "    steps:", "      - name: Export", "        run: |",
                       *["          " + part for part in call], "      - name: Dump", "        run: printenv | base64"]
                with self.subTest(workflow=wf, form=label):
                    problems = tier_pin_problems(wf, splice(text, at, new), self.pins)
                    self.assertTrue(any_match(problems, job_re("second"), "not pinned"), "%d problem lines" % len(problems))

    def test_workflow_level_env_and_defaults_are_pinned_8187_f12b(self):
        for wf, text in self.texts.items():
            lines = text.split("\n")
            head = next(i for i, ln in enumerate(lines) if ln.rstrip() == "jobs:")
            for label, new in (("env hook", ["env:", "  BASH_ENV: /dev/null/hook"]),
                               ("env hook, other var", ["env:", "  LD_PRELOAD: /dev/null/hook.so"]),
                               ("defaults shell", ["defaults:", "  run:", "    shell: bash -x {0}"])):
                with self.subTest(workflow=wf, edit=label):
                    self.caught(wf, splice(text, head, new), label)
            top = next((i for i, ln in enumerate(lines) if ln.rstrip() in ("env:", "defaults:")), None)
            if top is not None:
                with self.subTest(workflow=wf, edit="added key to the existing top-level block"):
                    self.caught(wf, splice(text, top + 1, ["  BASH_ENV: /dev/null/hook"]), "existing block")

    def test_keys_after_a_column_zero_comment_stay_pinned_8187_f11b(self):
        for wf, text in self.texts.items():
            for position, step in enumerate(pin_targets(wf, text)):
                pad = " " * (indent_of(step[2].split("\n")[0]) + 2)
                for label, keys in (("env", [pad + "env:", pad + "  BASH_ENV: x"]),
                                    ("shell", [pad + "shell: bash -x {0}"]),
                                    ("with", [pad + "with:", pad + "  key: value"])):
                    with self.subTest(workflow=wf, step=position, keys=label):
                        self.caught(wf, splice(text, step[4], ["# a comment at column zero"] + keys), label)

    def test_a_pre_export_step_cannot_plant_a_hook_8187_f11c(self):
        for wf, text in self.texts.items():
            first = job_steps(wf, text)[0]
            pad = " " * indent_of(first[2].split("\n")[0])
            for label, line in PRE_EXPORT_HOOKS.items():
                with self.subTest(workflow=wf, hook=label):
                    step = [pad + "- name: Prepare", pad + "  run: " + line]
                    self.caught(wf, splice(text, first[3], step), label)

    def test_job_level_keys_steps_names_and_jobs_are_all_pinned(self):
        for wf, text in self.texts.items():
            name = tier_job(wf, text)
            lines = text.split("\n")
            key = next(i for i, ln in enumerate(lines) if ln.rstrip() == f"  {name}:")
            steps_found = job_steps(wf, text)
            with self.subTest(workflow=wf, edit="job env"):
                self.caught(wf, splice(text, key + 1, ["    env:", "      PLANTED: value"]), "job env")
            with self.subTest(workflow=wf, edit="job container"):
                self.caught(wf, splice(text, key + 1, ["    container: ubuntu:latest"]), "container")
            with self.subTest(workflow=wf, edit="job services"):
                self.caught(wf, splice(text, key + 1, ["    services: {}"]), "services")
            with self.subTest(workflow=wf, edit="job defaults"):
                self.caught(wf, splice(text, key + 1, ["    defaults:", "      run:", "        shell: sh"]), "defaults")
            with self.subTest(workflow=wf, edit="runs-on"):
                at = next(i for i in range(key, len(lines)) if lines[i].startswith("    runs-on:"))
                self.caught(wf, "\n".join(lines[:at] + [lines[at] + " # edited"] + lines[at + 1:]), "runs-on")
            with self.subTest(workflow=wf, edit="step reordered"):
                a, b = steps_found[0], steps_found[1]
                swapped = lines[:a[3]] + lines[b[3]:b[4]] + lines[a[3]:a[4]] + lines[b[4]:]
                self.assertIs(swapped != lines, True)
                self.caught(wf, "\n".join(swapped), "reordered")
            for place, step in enumerate((steps_found[0], steps_found[-1])):
                if step[2].lstrip().startswith("- name:"):
                    with self.subTest(workflow=wf, edit="renamed step, same body", place=place):
                        self.caught(wf, text.replace("- name: " + step[1], "- name: " + step[1] + " v2", 1), "renamed")
            with self.subTest(workflow=wf, edit="job renamed"):
                renamed = lines[:key] + [lines[key].replace(name, name + "-renamed")] + lines[key + 1:]
                self.caught(wf, "\n".join(renamed), "job renamed")
            with self.subTest(workflow=wf, edit="job added"):
                added = ["  extra:", "    runs-on: ubuntu-latest", "    steps:", "      - run: echo hello"]
                self.caught(wf, splice(text, section_end(text), added), "job added")
            with self.subTest(workflow=wf, edit="step removed"):
                victim = steps_found[-1]
                self.caught(wf, "\n".join(lines[:victim[3]] + lines[victim[4]:]), "removed")

    def test_a_job_that_does_not_name_the_tier_can_be_edited_freely(self):
        checked = 0
        for wf, text in self.texts.items():
            jobs, _ = job_layout(text)
            tier = {n for n, _ in tier_blocks(jobs)}
            lines = text.split("\n")
            for name, first, _end, _block in jobs:
                if name in tier:
                    continue
                with self.subTest(workflow=wf, job=ty.opaque(name, "job[?]")):
                    edited = "\n".join(lines[:first + 1] + ["    # edited freely"] + lines[first + 1:])
                    self.assertEqual(len(tier_pin_problems(wf, edited, self.pins)), 0)
                    checked += 1
        self.assertGreater(checked, 0, "no job outside the tier job to edit")

    def test_the_failure_message_names_the_workflow_job_step_and_first_differing_line(self):
        wf = "cert-postgres-age.yml"
        text = self.texts[wf]
        step = next(s for s in pin_targets(wf, text) if "Cleanup" in s[1])
        edited = inject_run_line(text, step, "printenv | base64")
        message = "\n".join(tier_pin_problems(wf, edited, self.pins))
        index = [s[3] for s in job_steps(wf, text)].index(step[3])
        for part in (wf, "line ", f"step {index}"):
            self.assertIs(part in message, True)
        self.assertTrue(re.search(job_re(step[0]), message))
        self.assertTrue(re.search(rf"step {index} \(step\[\d+\] len=\d+\)", message))
        self.assertIs("printenv | base64" not in message, True)  # r13 F24: the changed line is never echoed

    def test_continuations_are_joined_before_the_environment_scan(self):
        extra = {"word split": "prin\\\ntenv | base64", "interpreter continued": "python3 -c \\\n'print(os.environ)'",
                 "path split": "cat " + PROC + "self/env\\\niron", "plain still caught": "cat \\\n" + PROC + "self/environ"}
        anchor = '          if [ ! -f "$url_file" ]; then'
        for name in SHARED_TIER:
            text = self.texts[name]
            for label, line in extra.items():
                with self.subTest(workflow=name, mutant=label):
                    pad = "          "
                    edited = text.replace(anchor, pad + line.replace("\n", "\n" + pad) + "\n" + anchor, 1)
                    self.assertIs(edited != text, True)
                    self.assertTrue(workflow_problems(edited), f"mutant not caught: {label}")
        ci_anchor = 'echo "::notice::[enterprise-fed] created'
        ci_text = self.texts["ci.yml"]
        for label, line in extra.items():
            with self.subTest(workflow="ci.yml", mutant=label):
                pad = "          "
                edited = sub_once(ci_text, ci_anchor, pad + line.replace("\n", "\n" + pad) + "\n" + pad + ci_anchor)
                self.assertTrue(url_leaks(edited), f"mutant not caught: {label}")
        self.assertIs(joined_lines(["prin\\", "  tenv x", "echo ok"]) == ["printenv x", "echo ok"], True)


SCRATCH_ROOT = ROOT / ".local-runs" / "r8-tests"
LINT_RUNS_ON = "    runs-on: ubuntu-latest\n    steps:\n"
USERINFO_SAMPLE = "post" + "gres://" + "someuser" + ":" + "somepass" + "@host.invalid/db"


def before_jobs(text, lines):
    """``text`` with ``lines`` inserted as workflow-level lines just above ``jobs:``."""
    rows = text.split("\n")
    at = next(i for i, ln in enumerate(rows) if ln.rstrip() == "jobs:")
    return "\n".join(rows[:at] + lines + rows[at:])


def set_runs_on(text, job, value):
    """``text`` with the ``runs-on`` line of ``job`` replaced by the YAML ``value``."""
    rows = text.split("\n")
    key = next(i for i, ln in enumerate(rows) if ln.rstrip() == f"  {job}:")
    at = next(i for i in range(key, len(rows)) if rows[i].startswith("    runs-on:"))
    return "\n".join(rows[:at] + ["    runs-on: " + value] + rows[at + 1:])


def add_step(text, job, step_lines):
    """``text`` with ``step_lines`` (already indented as list items) appended to the steps of ``job``."""
    rows = text.split("\n")
    key = next(i for i, ln in enumerate(rows) if ln.rstrip() == f"  {job}:")
    end = next((i for i in range(key + 1, len(rows)) if re.match(r"^  [A-Za-z0-9_-]+:\s*(?:#.*)?$", rows[i])), len(rows))
    while end > key and not rows[end - 1].strip():
        end -= 1
    return "\n".join(rows[:end] + step_lines + rows[end:])


class TestStrictLoaderPins8187(unittest.TestCase):
    """r8: the tier workflows are read by a strict YAML loader and pinned as canonical JSON (security F13-F17, code F13-F15)."""

    @classmethod
    def setUpClass(cls):
        cls.texts = {wf: (WORKFLOWS / wf).read_text(encoding="utf-8") for wf in PIN_WORKFLOWS}
        cls.pins = load_job_pins()
        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)

    def caught(self, workflow, edited, label):
        self.assertTrue(tier_pin_problems(workflow, edited, self.pins), f"{workflow}: mutant not caught: {label}")

    def tree(self, extra=None, replace=None):
        """A scratch repository root holding the three real workflows, ``replace`` edits and ``extra`` files."""
        holder = tempfile.TemporaryDirectory(dir=SCRATCH_ROOT, prefix="root-")
        self.addCleanup(holder.cleanup)
        root = Path(holder.name)
        (root / ".github" / "workflows").mkdir(parents=True)
        for path in WORKFLOWS.glob("*.y*ml"):
            body = (replace or {}).get(path.name, path.read_text(encoding="utf-8"))
            (root / ".github" / "workflows" / path.name).write_text(body, encoding="utf-8")
        for rel, body in (extra or {}).items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
        return root

    # --- the loader -------------------------------------------------------------------------------------------

    def test_the_real_workflows_load_strictly_and_match_both_pin_sections(self):
        for wf, text in self.texts.items():
            with self.subTest(workflow=wf):
                data, problems = ty.parse_workflow(text)
                self.assertEqual(problems, [])
                self.assertEqual(len(primary_pin_problems(wf, text, self.pins[PRIMARY])), 0)
                self.assertEqual(len(tier_pin_problems(wf, text, self.pins)), 0)
                assert_same(self, self.pins[PRIMARY][wf], ty.build_pins(data), f"{wf} primary pin")
        self.assertEqual(len(repo_problems(ROOT, self.pins)), 0)

    def test_the_loader_refuses_duplicate_keys_after_normalisation(self):
        base = "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n"
        forms = {
            "plain repeat": base + "name: y\n",
            "quoted repeat": base + "'name': y\n",
            "double quoted repeat": base + '"jobs":\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n',
            "space before the colon": "defaults:\n  run:\n    shell: sh\n" + base + "defaults :\n  run:\n    shell: bash\n",
            "defaults repeat": "defaults:\n  run:\n    shell: bash\n'defaults':\n  run:\n    shell: sh\n" + base,
            "on spelled twice": base + "'on': pull_request\n",
            "env repeat": 'env:\n  A: "1"\n"env":\n  A: "2"\n' + base,
            "job repeat": base + "  a:\n    runs-on: ubuntu-latest\n    steps: []\n",
            "step key repeat": base.replace("steps: []", "steps:\n      - run: a\n        run: b"),
        }
        for label, text in forms.items():
            with self.subTest(form=label):
                data, problems = ty.parse_workflow(text)
                self.assertIs(data is None, True, f"duplicate key accepted: {label}")
                self.assertTrue(problems)

    def test_the_loader_refuses_anchors_aliases_merge_keys_and_odd_keys(self):
        base = "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n"
        forms = {
            "anchor on run-name": "run-name: &rn lint\n" + base,
            "alias of run-name": "run-name: &rn lint\n" + base.replace("name: x", "name: *rn"),
            "anchor only on a step": base.replace("steps: []", "steps:\n      - &s\n        run: a"),
            "merge key": base.replace("steps: []", "steps: []\n    <<:\n      timeout-minutes: 5"),
            "merge key with alias": "x: &m\n  a: 1\n" + base.replace("steps: []", "steps: []\n    <<: *m"),
            "integer key": base + "1: x\n",
            "boolean key": base + "true: x\n",
            "null key": base + "~: x\n",
            "list key": base + "? [a, b]\n: x\n",
        }
        for label, text in forms.items():
            with self.subTest(form=label):
                data, problems = ty.parse_workflow(text)
                self.assertIs(data is None, True, f"accepted: {label}")
                self.assertTrue(problems)

    def test_on_is_read_as_a_string_and_the_top_level_key_set_is_closed(self):
        data, problems = ty.parse_workflow("name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n")
        self.assertEqual(problems, [])
        assert_has(self, "on", data, "the loaded workflow keeps the string key on")
        self.assertIs(True not in data, True, "the loaded workflow has no boolean key")
        for key in ("x-anchors", "extra", "Jobs", "env2"):
            with self.subTest(key=key):
                text = f"name: x\non: push\n{key}: 1\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n"
                data, problems = ty.parse_workflow(text)
                self.assertTrue(any("closed set" in p for p in problems), problems)

    # --- the r7 PASS cases: workflow-level keys and the jobs mapping --------------------------------------------

    def test_a_quoted_or_padded_workflow_level_key_is_caught_8187_f13(self):
        forms = {
            "single-quoted defaults": ["'defaults':", "  run:", "    shell: bash -x {0}"],
            "space before the colon": ["defaults :", "  run:", "    shell: bash -x {0}"],
            "double-quoted env repeat": ['"env":', "  BASH_ENV: /dev/null/hook"],
            "env hook": ["env:", "  BASH_ENV: /dev/null/hook"],
            "quoted run-name": ["'run-name': renamed"],
            "padded permissions": ["permissions :", "  contents: write"],
        }
        for wf, text in self.texts.items():
            for label, lines in forms.items():
                with self.subTest(workflow=wf, form=label):
                    edited = before_jobs(text, lines)
                    self.assertIs(edited != text, True, "the edit changed nothing")
                    self.caught(wf, edited, label)

    def test_a_repeated_jobs_key_with_a_split_export_and_dump_is_caught_8187_f13(self):
        tail = ['"jobs":', "  second:", "    runs-on: ubuntu-latest", "    steps:", "      - run: |",
                "          python3 -I scripts/ci/tier_cred\\", "          ential.py github-env --url-file \"$url_file\"",
                "      - run: printenv | base64"]
        for wf, text in self.texts.items():
            with self.subTest(workflow=wf):
                edited = text.rstrip("\n") + "\n" + "\n".join(tail) + "\n"
                self.caught(wf, edited, "repeated jobs key")
                self.assertTrue(any("does not load strictly" in p or "duplicate" in p.lower()
                                    for p in tier_pin_problems(wf, edited, self.pins)))

    def test_an_anchor_alias_or_merge_key_is_caught_8187_f15(self):
        for wf, text in self.texts.items():
            lint = "lint" if wf == "ci.yml" else tier_job_of(text)
            forms = {
                "run-name anchored": before_jobs(text, ["run-name: &rn dump"]),
                "run-name aliased from a job": add_step(before_jobs(text, ["run-name: &rn dump"]), lint,
                                                        ["      - name: *rn", "        run: echo ok"]),
                "merge key at the workflow level": before_jobs(text, ["<<:", "  name: x"]),
                "merge key in a job": add_step(text, lint, ["      - run: echo ok", "        <<:", "          name: x"]),
                "alias in a step": add_step(text, lint, ["      - &s", "        run: echo ok"]),
            }
            for label, edited in forms.items():
                with self.subTest(workflow=wf, form=label):
                    self.assertIs(edited != text, True)
                    self.caught(wf, edited, label)

    # --- discovery on normalised loader output (security F14) -------------------------------------------------

    def test_a_new_workflow_that_names_the_tier_file_in_disguise_is_found_8187_f14(self):
        back = chr(92)
        names = {
            "escaped": "cat ~/.ai-memory-ci-" + back + "fed-url",
            "empty single quotes": "cat ~/.ai-memory-ci-fed''-url",
            "empty double quotes": 'cat ~/.ai-memory-ci-fed""-url',
            "empty expansion": "cat ~/.ai-memory-ci-fed${E}-url",
            "split over a continuation": "cat ~/.ai-memory-ci-" + back + "\n          fed-url",
            "escaped variable name": "echo $AI_MEMORY_CI_" + back + "FED_URL",
            "plain": "cat ~/.ai-memory-ci-fed-url",
        }
        for label, line in names.items():
            body = "name: new\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          " + line + "\n"
            with self.subTest(form=label):
                root = self.tree(extra={".github/workflows/new.yml": body})
                self.assertEqual(tier_workflows(root / ".github" / "workflows").count("new.yml"), 1)
                self.assertTrue(any("new.yml" in p for p in repo_problems(root, self.pins)), label)

    def test_a_composite_action_that_names_the_tier_file_is_caught_8187_f14(self):
        body = "name: a\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: cat ~/.ai-memory-ci-fed-url\n"
        padded = body.replace("ci-fed-url", "ci-fed''-url")
        for label, text in (("plain", body), ("padded", padded)):
            for where in (".github/actions/read/action.yml", ".github/actions/deep/nest/action.yaml"):
                with self.subTest(form=label, path=where):
                    root = self.tree(extra={where: text})
                    self.assertTrue(any("action" in p for p in repo_problems(root, self.pins)), (label, where))

    def test_a_local_action_or_reusable_workflow_call_in_a_tier_workflow_is_refused_8187_f16(self):
        for wf, text in self.texts.items():
            lint = "lint" if wf == "ci.yml" else tier_job_of(text)
            for label, step in (("composite action", ["      - uses: ./.github/actions/read"]),
                                ("composite action, quoted", ["      - uses: './.github/actions/read'"])):
                with self.subTest(workflow=wf, form=label):
                    self.caught(wf, add_step(text, lint, step), label)
            reusable = text.rstrip("\n") + "\n  called:\n    uses: ./.github/workflows/other.yml\n"
            with self.subTest(workflow=wf, form="reusable workflow"):
                self.caught(wf, reusable, "reusable")

    # --- a non-tier job on the tier runner (security F16) ---------------------------------------------------

    def test_a_non_tier_job_on_a_self_hosted_label_is_caught_8187_f16(self):
        body_forms = {
            "runtime-built name": ['      - run: |', '          p="$HOME/.ai-memory-"; cat "${p}ci-fed-url"'],
            "runtime-built variable": ['      - run: |', '          v="AI_MEMORY_CI_FED"; printf %s "${!v}_URL"'],
            "sourced script": ['      - run: . ./scripts/some-script.sh'],
            "glob": ['      - run: cat ~/.ai-memory-ci-f*'],
            "reusable workflow": [],
            "composite action": ['      - uses: ./.github/actions/read'],
            "no body at all": [],
        }
        labels = ["[self-hosted]", "self-hosted", "[self-hosted, linux-fed]", "[linux-fed]", "[Self-Hosted]",
                  "${{ fromJSON('[\"self-hosted\"]') }}", "${{ inputs.runner }}", "{ group: fleet }"]
        text = self.texts["ci.yml"]
        for label, step in body_forms.items():
            edited = set_runs_on(text, "lint", "[self-hosted]")
            if step:
                edited = add_step(edited, "lint", step)
            with self.subTest(form=label):
                self.caught("ci.yml", edited, label)
        for value in labels:
            with self.subTest(runs_on=value):
                self.caught("ci.yml", set_runs_on(text, "lint", value), value)

    def test_a_job_that_calls_a_reusable_workflow_is_refused(self):
        text = self.texts["ci.yml"].rstrip("\n") + "\n  reuse:\n    uses: owner/repo/.github/workflows/x.yml@v1\n"
        self.caught("ci.yml", text, "external reusable workflow job")

    def test_a_self_hosted_job_in_another_workflow_is_refused_unless_listed_8187_f16(self):
        body = "name: o\non: push\njobs:\n  j:\n    runs-on: [self-hosted, linux-fed]\n    steps:\n      - run: echo hi\n"
        root = self.tree(extra={".github/workflows/other.yml": body})
        self.assertTrue(any("other.yml" in p and "j" in p for p in repo_problems(root, self.pins)))
        root = self.tree(extra={".github/workflows/other.yml": body.replace("[self-hosted, linux-fed]", "ubuntu-latest")})
        self.assertEqual(len(repo_problems(root, self.pins)), 0)

    def test_an_unparsable_workflow_is_a_problem_not_skipped_8187_f18(self):
        body = "name: o\non: push\njobs:\n  j:\n    runs-on:\t[self-hosted]\n    steps:\n      - run: echo hi\n"
        root = self.tree(extra={".github/workflows/broken.yml": body})
        problems = repo_problems(root, self.pins)
        self.assertTrue(any("broken.yml" in p and "Error" in p for p in problems), "%d problem lines" % len(problems))
        self.assertTrue(not (any("echo hi" in p for p in problems)))

    def test_a_job_level_uses_is_a_problem_in_every_other_workflow_8187_f18(self):
        for value in ("owner/repo/.github/workflows/x.yml@v1", "./other/x.yml", "./.github/workflows/x.yml"):
            body = "name: o\non: push\njobs:\n  j:\n    uses: %s\n" % value
            root = self.tree(extra={".github/workflows/reuse.yml": body})
            with self.subTest(uses=value):
                self.assertTrue(any("reuse.yml job j" in p and "uses" in p for p in repo_problems(root, self.pins)))

    def test_a_workflow_without_a_jobs_mapping_is_a_problem_8187_f18(self):
        for label, body in (("missing", "name: o\non: push\n"), ("list", "name: o\non: push\njobs:\n  - a\n"),
                            ("scalar", "name: o\non: push\njobs: none\n")):
            root = self.tree(extra={".github/workflows/nojobs.yml": body})
            with self.subTest(jobs=label):
                self.assertTrue(any("nojobs.yml" in p and "jobs" in p for p in repo_problems(root, self.pins)))

    def test_the_self_hosted_exemption_is_bound_to_its_label_sets_8187_f18a(self):
        name = "session-boot-lifetime.yml"
        text = (WORKFLOWS / name).read_text(encoding="utf-8")
        self.assertEqual(len(repo_problems(self.tree(), self.pins)), 0)
        mutants = {
            "macos-fed moved to the tier label": text.replace('["self-hosted","macos-fed"]', '["self-hosted","linux-fed"]'),
            "extra self-hosted leg": text.replace("          - os: macos-fed\n",
                '          - os: other\n            runner: \'["self-hosted","linux-fed"]\'\n          - os: macos-fed\n'),
            "runs-on no longer the matrix lookup": text.replace("${{ fromJSON(matrix.runner) }}", "[self-hosted, linux-fed]"),
        }
        for label, body in mutants.items():
            with self.subTest(mutant=label):
                self.assertIs(body != text, True)
                problems = repo_problems(self.tree(replace={name: body}), self.pins)
                self.assertTrue(any(name in p and "lifetime-tests" in p for p in problems), "%d problem lines" % len(problems))

    # --- r10: runs-on resolves no expression at all; exemptions are rows keyed by (workflow, job) ------------

    @staticmethod
    def matrix_workflow(matrix, runs_on="${{ matrix.os }}", job="j"):
        """A one-job workflow whose ``runs-on`` is ``runs_on`` and whose matrix lines (8-space indent) are ``matrix``."""
        return ("name: m\non: push\njobs:\n  %s:\n    runs-on: %s\n    strategy:\n      matrix:\n%s"
                "    steps:\n      - run: echo hi\n" % (job, runs_on, matrix))

    R10_MATRICES = {
        "key is an expression, include hosted": "        os: ${{ fromJSON(needs.a.outputs.os) }}\n"
                                                "        include:\n          - os: ubuntu-latest\n",
        "include is an expression, key hosted": "        os: [ubuntu-latest]\n"
                                                "        include: ${{ fromJSON(needs.a.outputs.inc) }}\n",
        "exclude present": "        os: [ubuntu-latest]\n        exclude:\n          - os: ubuntu-latest\n",
        "fromJSON of a variable": "        os: ${{ fromJSON(vars.OSES) }}\n",
        "nested list in os": "        os: [[ubuntu-latest, self-hosted]]\n",
        "mapping in the os list": "        os:\n          - {group: fleet}\n",
        "include entry is not a mapping": "        os: [ubuntu-latest]\n        include:\n          - ubuntu-latest\n",
        "expression inside an include value": "        os: [ubuntu-latest]\n        include:\n"
                                              "          - os: ubuntu-latest\n            extra: ${{ inputs.x }}\n",
        "plain hosted matrix, but no exemption row": "        os: [ubuntu-latest]\n",
    }

    def test_a_matrix_runs_on_resolves_nothing_outside_an_exemption_row_8187_f19(self):
        for label, matrix in self.R10_MATRICES.items():
            with self.subTest(matrix=label):
                root = self.tree(extra={".github/workflows/m.yml": self.matrix_workflow(matrix)})
                self.assertTrue(any("m.yml" in p and "job j" in p for p in repo_problems(root, self.pins)), label)

    def test_runs_on_with_an_expression_or_a_group_is_refused_8187_f19(self):
        hosted = "        os: [ubuntu-latest]\n"
        for runs_on in ("${{ inputs.runner }}", "${{ fromJSON(vars.X) }}", "{group: fleet}",
                        "{group: fleet, labels: [ubuntu-latest]}", "{labels: ['${{ inputs.runner }}']}",
                        "[ubuntu-latest, '${{ inputs.runner }}']", "[ubuntu-latest, {a: b}]", "[ubuntu-latest, 1]"):
            with self.subTest(runs_on=runs_on):
                root = self.tree(extra={".github/workflows/m.yml": self.matrix_workflow(hosted, runs_on=runs_on)})
                self.assertTrue(any("m.yml" in p and "job j" in p for p in repo_problems(root, self.pins)), runs_on)

    def test_a_pinned_workflow_non_tier_job_with_a_matrix_expression_is_caught_8187_f19(self):
        text = self.texts["ci.yml"]
        for label in ("key is an expression, include hosted", "include is an expression, key hosted", "exclude present"):
            matrix = self.R10_MATRICES[label]
            value = "${{ matrix.os }}\n    strategy:\n      matrix:\n" + matrix.rstrip("\n")
            with self.subTest(matrix=label):
                self.caught("ci.yml", set_runs_on(text, "lint", value), label)
        self.caught("ci.yml", set_runs_on(text, "lint", "${{ inputs.runner }}"), "expression")

    def test_the_exemption_key_is_the_workflow_and_job_pair_8187_f19(self):
        body = ("name: copy\non: push\njobs:\n  mobile-cross-compile:\n    runs-on: ${{ matrix.os }}\n    strategy:\n"
                "      matrix:\n        include:\n          - target: aarch64-apple-ios\n            os: macos-latest\n"
                "          - target: aarch64-linux-android\n            os: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        root = self.tree(extra={".github/workflows/copy.yml": body})
        self.assertTrue(any_match(repo_problems(root, self.pins), r"copy\.yml job " + job_re("mobile-cross-compile")))
        life = (WORKFLOWS / "session-boot-lifetime.yml").read_text(encoding="utf-8")
        root = self.tree(extra={".github/workflows/copy2.yml": life})
        self.assertTrue(any_match(repo_problems(root, self.pins), r"copy2\.yml job " + job_re("lifetime-tests")))

    def test_a_row_whose_job_is_gone_is_a_stale_problem_8187_f19(self):
        for name, job in (("release.yml", "release"), ("session-boot-lifetime.yml", "lifetime-tests")):
            text = (WORKFLOWS / name).read_text(encoding="utf-8")
            renamed = text.replace("\n  %s:\n" % job, "\n  %s-renamed:\n" % job, 1)
            with self.subTest(workflow=name):
                self.assertIs(renamed != text, True)
                problems = repo_problems(self.tree(replace={name: renamed}), self.pins)
                self.assertTrue(any(name in p and job in p and "stale" in p for p in problems), "%d problem lines" % len(problems))

    def test_the_exempt_label_sets_must_equal_the_pinned_sets_8187_f19(self):
        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        leg = "          - target: x86_64-unknown-linux-gnu\n"
        drift = release.replace(leg, "          - target: x86_64-pc-windows-msvc\n            os: windows-latest\n" + leg, 1)
        self.assertIs(drift != release, True)
        problems = repo_problems(self.tree(replace={"release.yml": drift}), self.pins)
        self.assertTrue(any_match(problems, r"release\.yml job " + job_re("release")), "%d problem lines" % len(problems))
        ci = self.texts["ci.yml"]
        leg = "          - target: aarch64-apple-ios\n"
        drift = ci.replace(leg, "          - target: t\n            os: windows-latest\n" + leg, 1)
        self.assertIs(drift != ci, True)
        self.caught("ci.yml", drift, "mobile-cross-compile gains a windows leg")
        removed = ci.replace(leg + "            os: macos-latest\n", "", 1)
        self.assertIs(removed != ci, True, "the removal changed nothing")
        self.caught("ci.yml", removed, "mobile-cross-compile loses a leg")
        life = (WORKFLOWS / "session-boot-lifetime.yml").read_text(encoding="utf-8")
        reordered = life.replace('\'["self-hosted","macos-fed"]\'', '\'["macos-fed","self-hosted"]\'')
        self.assertIs(reordered != life, True)
        problems = repo_problems(self.tree(replace={"session-boot-lifetime.yml": reordered}), self.pins)
        self.assertTrue(any_match(problems, job_re("lifetime-tests")), "%d problem lines" % len(problems))

    def test_the_exemption_table_has_exactly_the_three_real_rows_8187_f19(self):
        table = globals().get("RUNS_ON_EXEMPT", {})
        self.assertEqual(sorted(table), [("ci.yml", "mobile-cross-compile"), ("release.yml", "release"),
                                         ("session-boot-lifetime.yml", "lifetime-tests")])
        for key, (reason, pinned, label_sets) in table.items():
            self.assertTrue(reason and pinned.startswith("${{"), key)
            for labels in label_sets:
                if key[1] != "lifetime-tests":
                    self.assertTrue(all(ty.HOSTED_LABEL.match(label) for label in labels), (key, labels))
        self.assertEqual(len(repo_problems(ROOT, self.pins)), 0)
        self.assertFalse(hasattr(ty, "MATRIX_REF"), "the matrix lookup branch is deleted")

    def test_a_step_added_to_the_pinned_exempt_job_is_caught_8187_f20(self):
        name = "session-boot-lifetime.yml"
        text = (WORKFLOWS / name).read_text(encoding="utf-8")
        steps = {
            "glob over home dotfiles": ["      - run: cat \"$HOME\"/.ai-*"],
            "third-party action": ["      - uses: someone/their-action@v1"],
        }
        for label, step in steps.items():
            with self.subTest(step=label):
                problems = repo_problems(self.tree(replace={name: add_step(text, "lifetime-tests", step)}), self.pins)
                self.assertTrue(any(name in p and "lifetime-tests" in p and "step" in p for p in problems), "%d problem lines" % len(problems))
        edited = text.replace("AI_MEMORY_NO_CONFIG: '1'", "AI_MEMORY_NO_CONFIG: '0'", 1)
        self.assertIs(edited != text, True)
        problems = repo_problems(self.tree(replace={name: edited}), self.pins)
        self.assertTrue(any(name in p and "lifetime-tests" in p for p in problems), "%d problem lines" % len(problems))

    def test_the_exempt_workflow_level_keys_are_pinned_8187_f21(self):
        name = "session-boot-lifetime.yml"
        text = (WORKFLOWS / name).read_text(encoding="utf-8")
        self.assertEqual(len(repo_problems(self.tree(), self.pins)), 0)
        mutants = {
            "env entry added": (text.replace("\nenv:\n", "\nenv:\n  BASH_ENV: ./hook\n", 1), "env"),
            "defaults.run.shell added": (text.replace("\nenv:\n", "\ndefaults:\n  run:\n    shell: bash -x\nenv:\n", 1),
                                         "defaults"),
            "env value edited": (text.replace('CARGO_INCREMENTAL: "0"', 'CARGO_INCREMENTAL: "1"', 1), "env"),
            "on gains an event": (text.replace("\non:\n", "\non:\n  pull_request:\n", 1), "on"),
        }
        for label, (body, key) in mutants.items():
            with self.subTest(mutant=label):
                self.assertIs(body != text, True)
                problems = repo_problems(self.tree(replace={name: body}), self.pins)
                self.assertTrue(any(name in p and "workflow-level" in p and re.search(key_re(key), p) for p in problems), "%d problem lines" % len(problems))
                self.assertTrue(not (any("bash -x" in p or "./hook" in p for p in problems)))

    def test_the_exempt_pin_section_carries_the_workflow_keys_8187_f21(self):
        entry = self.pins[EXEMPT]["session-boot-lifetime.yml"]
        data, _ = ty.parse_workflow((WORKFLOWS / "session-boot-lifetime.yml").read_text(encoding="utf-8"))
        assert_same(self, sorted(entry["workflow_keys"]), sorted(k for k in data if k != "jobs"),
                    "session-boot-lifetime.yml workflow key list")
        assert_same(self, entry["workflow_keys"], ty.build_pins(data)["workflow_keys"],
                    "session-boot-lifetime.yml workflow key pin")
        assert_same(self, sorted(entry["jobs"]), ["lifetime-tests"], "session-boot-lifetime.yml exempt job set")

    def test_the_pin_loader_and_module_docstrings_name_every_section_8187_f23(self):
        keys = json.loads(JOB_PINS_FILE.read_text(encoding="utf-8")).keys()
        for position, key in enumerate(keys):
            with self.subTest(section=position):
                self.assertIs(key in load_job_pins.__doc__, True)
        for position, text in enumerate((" ".join((__doc__ or "").split()),
                                         " ".join(Path(ty.__file__).read_text(encoding="utf-8").replace("# ", " ").split()))):
            with self.subTest(text=position):
                self.assertIs("the exempt job and every workflow-level key except ``jobs`` of its workflow" in text, True)

    def test_both_workflow_key_comparisons_use_one_shared_helper_8187_f23(self):
        module = sys.modules[__name__]
        self.assertTrue(callable(getattr(module, "workflow_key_problems", None)))
        sentinel = ["SHARED-HELPER-CALLED"]
        exempt_name = "session-boot-lifetime.yml"
        exempt_text = (WORKFLOWS / exempt_name).read_text(encoding="utf-8")
        text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        with unittest.mock.patch.object(module, "workflow_key_problems", return_value=sentinel):
            exempt = exempt_workflow_key_problems(exempt_name, exempt_text, self.pins)
            primary = primary_pin_problems("ci.yml", text, self.pins[PRIMARY])
        self.assertIs(sentinel[0] in exempt, True)
        self.assertIs(sentinel[0] in primary, True)

    def test_hosted_labels_and_non_tier_edits_are_not_flagged(self):
        text = self.texts["ci.yml"]
        for value in ("ubuntu-latest", "ubuntu-22.04", "macos-14", "windows-latest", "ubuntu-24.04-arm"):
            with self.subTest(runs_on=value):
                self.assertEqual(len(tier_pin_problems("ci.yml", set_runs_on(text, "lint", value), self.pins)), 0)
        edited = add_step(text, "lint", ["      - run: echo a freely edited non-tier step"])
        self.assertEqual(len(tier_pin_problems("ci.yml", edited, self.pins)), 0)
        self.assertEqual(len(tier_pin_problems("ci.yml", before_jobs(text, ["# a comment above jobs"]), self.pins)), 0)

    # --- pins: structure, failure messages, determinism ------------------------------------------------------

    def test_the_primary_pins_cover_every_tier_job_workflow_key_and_the_job_list(self):
        for wf, text in self.texts.items():
            data, _ = ty.parse_workflow(text)
            entry = self.pins[PRIMARY][wf]
            assert_same(self, entry["job_names"], sorted(data["jobs"]), f"{wf} job name list")
            assert_same(self, sorted(entry["tier_jobs"]), ty.tier_job_names(data), f"{wf} tier job list")
            assert_same(self, sorted(entry["workflow_keys"]), sorted(k for k in data if k != "jobs"),
                        f"{wf} workflow key list")
            self.assertTrue(entry["tier_jobs"])
            for name, pinned in entry["tier_jobs"].items():
                self.assertEqual(len(pinned["steps"]), len(data["jobs"][name]["steps"]))
        assert_same(self, sorted(self.pins[PRIMARY]), sorted(PIN_WORKFLOWS), "primary pin workflow set")

    def test_the_failure_message_names_workflow_job_step_and_first_differing_key_path_8187_f17(self):
        wf = "cert-postgres-age.yml"
        text = self.texts[wf]
        data, _ = ty.parse_workflow(text)
        job = ty.tier_job_names(data)[0]
        steps = data["jobs"][job]["steps"]
        index = next(i for i, s in enumerate(steps) if isinstance(s.get("run"), str) and "Cleanup" in str(s.get("name", "")))
        step = steps[index]
        edited = add_step_run(text, step["run"], "printenv | base64 # " + USERINFO_SAMPLE)
        message = "\n".join(primary_pin_problems(wf, edited, self.pins[PRIMARY]))
        for part in (wf, f"step {index}"):
            self.assertIs(part in message, True)
        self.assertTrue(re.search(job_re(job), message))
        self.assertTrue(re.search(rf"steps\[{index}\]\.{key_re('run')}", message))
        self.assertTrue(re.search(step_ref(index, step["name"]), message))
        self.assertIs("somepass" not in message, True)
        self.assertIs("printenv" not in message, True, "the message names the key path, not the changed line")
        again = "\n".join(tier_pin_problems(wf, edited, self.pins))
        self.assertIs("somepass" not in again, True)
        self.assertIs("someuser" not in again, True)

    def test_a_job_level_key_difference_names_the_job_key(self):
        wf = "postgres-ignored.yml"
        data, _ = ty.parse_workflow(self.texts[wf])
        job = ty.tier_job_names(data)[0]
        rows = self.texts[wf].split("\n")
        key = next(i for i, ln in enumerate(rows) if ln.rstrip() == f"  {job}:")
        edited = "\n".join(rows[:key + 1] + ["    container: ubuntu:latest"] + rows[key + 1:])
        message = "\n".join(primary_pin_problems(wf, edited, self.pins[PRIMARY]))
        self.assertTrue(re.search(job_re(job), message))
        self.assertTrue(re.search(r"job\." + key_re("container"), message))

    def test_job_names_and_workflow_keys_are_pinned(self):
        for wf, text in self.texts.items():
            data, _ = ty.parse_workflow(text)
            with self.subTest(workflow=wf, edit="job added"):
                added = text.rstrip("\n") + "\n  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
                self.assertTrue(any("set of jobs" in p for p in primary_pin_problems(wf, added, self.pins[PRIMARY])))
            with self.subTest(workflow=wf, edit="permissions changed"):
                self.caught(wf, text.replace("permissions:\n", "permissions:\n  id-token: write\n", 1), "permissions")
            with self.subTest(workflow=wf, edit="trigger changed"):
                self.caught(wf, text.replace("\non:\n", "\non:\n  workflow_dispatch:\n", 1), "on")
            with self.subTest(workflow=wf, edit="concurrency removed"):
                self.assertTrue(any(re.search(key_re("concurrency"), p) for p in primary_pin_problems(
                    wf, re.sub(r"(?ms)^concurrency:.*?(?=^[a-z])", "", text, count=1), self.pins[PRIMARY])))

    def test_the_pin_data_file_is_regenerated_byte_identically(self):
        built = json.dumps({PRIMARY: {wf: ty.build_pins(ty.parse_workflow(t)[0]) for wf, t in self.texts.items()},
                            SECONDARY: self.pins[SECONDARY], EXEMPT: exempt_pins()}, indent=1, sort_keys=True) + "\n"
        assert_same(self, JOB_PINS_FILE.read_text(encoding="utf-8"), built,
                    "the pin data file differs from the regeneration: run --write-pins and commit the data file")
        outputs = []
        for number in range(2):
            out = SCRATCH_ROOT / f"pins-{number}.json"
            result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--write-pins", "--out", str(out)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr[-300:])
            outputs.append(out.read_bytes())
        assert_same(self, outputs[0], outputs[1], "two regenerations of the pin data differ")
        assert_same(self, outputs[0], JOB_PINS_FILE.read_bytes(), "the regenerated pin data differs from the data file")

    # --- the dependency and the CI job ----------------------------------------------------------------------

    def test_a_missing_yaml_module_fails_and_never_skips(self):
        code = ("import sys; sys.modules['yaml'] = None; sys.path.insert(0, %r); import %s"
                % (str(Path(__file__).resolve().parent), "%s"))
        for module in ("tier_yaml_8187", "test_ci_tier_password_check_6181"):
            with self.subTest(module=module):
                result = subprocess.run([sys.executable, "-I", "-c", code % module], capture_output=True, text=True,
                                        check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("requirements-ci.txt", result.stderr)
        source = Path(__file__).read_text(encoding="utf-8") + (Path(__file__).parent / "tier_yaml_8187.py").read_text(encoding="utf-8")
        for needle in ("skip" + "Unless", "Skip" + "Test", "importor" + "skip", "self.skip" + "Test"):
            self.assertIs(needle not in source, True)

    def test_requirements_pin_one_package_with_hashes_only(self):
        rows = [ln.rstrip() for ln in (Path(__file__).parent / "requirements-ci.txt").read_text(encoding="utf-8").split("\n")
                if ln.strip() and not ln.startswith("#")]
        self.assertTrue(rows[0].startswith("PyYAML==") and rows[0].endswith("\\"), "the first requirement row is the PyYAML pin")
        hashes = [r.strip() for r in rows[1:]]
        self.assertGreaterEqual(len(hashes), 10)
        for row in hashes:
            self.assertTrue(re.search(r"^--hash=sha256:[0-9a-f]{64}( \\)?$", row))
        self.assertTrue(not (hashes[-1].endswith("\\")))
        self.assertEqual(len(set(hashes)), len(hashes))

    def test_ci_runs_the_tier_modules_in_a_github_hosted_job_8187_f13(self):
        data, problems = ty.parse_workflow(self.texts["ci.yml"])
        self.assertEqual(problems, [])
        job = data["jobs"]["tier-credential-pins"]
        self.assertIs(job["runs-on"] == "ubuntu-latest", True)
        self.assertIs("needs" not in job, True, "the pins must run on a docs-only PR as well")
        self.assertIs("if" not in job, True)
        runs = [s["run"] for s in job["steps"] if isinstance(s.get("run"), str)]
        self.assertTrue(any("pip install --require-hashes --no-deps -r scripts/test/requirements-ci.txt" in r for r in runs))
        self.assertTrue(any("python3 -I -m unittest discover -s scripts/test -p 'test_*tier*.py'" in r for r in runs))
        found = sorted(p.name for p in (Path(__file__).parent).glob("test_*tier*.py"))
        self.assertEqual(found, ["test_check_tier_password_6181.py", "test_ci_tier_password_check_6181.py",
                                 "test_tier_credential_8187.py"], "the CI glob must match exactly the tier modules")


def tier_job_of(text):
    data, _ = ty.parse_workflow(text)
    return ty.tier_job_names(data)[0]


def add_step_run(text, run_text, extra_line):
    """``text`` with ``extra_line`` appended as the last line of the ``run`` block whose text is ``run_text``."""
    first = run_text.rstrip("\n").split("\n")[-1]
    rows = text.split("\n")
    at = max(i for i, ln in enumerate(rows) if ln.strip() == first.strip())
    pad = rows[at][:len(rows[at]) - len(rows[at].lstrip())]
    return "\n".join(rows[:at + 1] + [pad + extra_line] + rows[at + 1:])


def write_pins(out=None):
    """Regenerate all three sections (primary, secondary_text, exempt_jobs) of the pin data file from the real workflows (deterministic, sorted)."""
    try:
        table = pins_for({workflow: (WORKFLOWS / workflow).read_text(encoding="utf-8") for workflow in PIN_WORKFLOWS})
    except ValueError as exc:
        sys.exit(str(exc))
    table[EXEMPT] = exempt_pins()
    target = JOB_PINS_FILE if out is None else Path(out)
    target.write_text(json.dumps(table, indent=1, sort_keys=True) + "\n", encoding="utf-8")


class TestNoWorkflowFragmentIsEchoed8187R14(unittest.TestCase):
    """r14 F25, F26: a problem line names the workflow, job, step label, line number, key path and rule, never text of the
    workflow (the module docstring promises no value echo)."""

    @classmethod
    def setUpClass(cls):
        cls.texts = {wf: (WORKFLOWS / wf).read_text(encoding="utf-8") for wf in PIN_WORKFLOWS}
        cls.pins = load_job_pins()

    def unnamed_edit(self, workflow, text, sentinel):
        """``text`` with the head of a named post-export step replaced by an unnamed one whose first line and run block
        carry the sentinel, and the step index, or ``(None, None)`` when no step fits."""
        for step in pin_targets(workflow, text):
            lines = text.split("\n")
            if not lines[step[3]].lstrip().startswith("- name:"):
                continue
            edited = inject_run_line(text, step, f"echo {sentinel}")
            lines = edited.split("\n")
            pad = lines[step[3]][:indent_of(lines[step[3]])]
            lines[step[3]] = f"{pad}- x-note: {sentinel}"
            data = ty.load_strict("\n".join(lines))
            job = data["jobs"][step[0]]
            index = next(i for i, s in enumerate(job["steps"]) if s.get("x-note") == sentinel)
            return "\n".join(lines), index
        return None, None

    def test_an_unnamed_step_is_labelled_by_position_never_by_its_text_8187_f25(self):
        sentinel = "SENTINEL-F25-7c1d"
        checked = 0
        for wf, text in self.texts.items():
            edited, index = self.unnamed_edit(wf, text, sentinel)
            if edited is None:
                continue
            checked += 1
            problems = tier_pin_problems(wf, edited, self.pins)
            with self.subTest(workflow=wf):
                self.assertTrue(problems, "the edited step must differ from its pins")
                self.assertEqual(len([p for p in problems if sentinel in p]), 0)
                primary = [p for p in problems if re.search(step_ref(index), p) and "differs from the pin at" in p]
                self.assertTrue([p for p in primary if re.search(rf"steps\[{index}\]\.", p)], "%d problem lines" % len(problems))
                self.assertTrue([p for p in job_pin_problems(wf, edited, self.pins[SECONDARY])
                                 if re.search(step_ref(index), p) and "differs from the pin at line" in p])
        self.assertGreater(checked, 0)

    def test_a_named_step_prints_its_position_and_length_only_8187_f25(self):
        self.assertEqual(str(ty.step_label({"name": "Build the thing", "run": "echo x"}, 3)), "step[3] len=15")
        self.assertEqual(str(ty.step_label({"id": "build", "run": "echo x"}, 3)), "step[3] len=5")
        self.assertEqual(str(ty.step_label({"run": "echo x"}, 3)), "step[3] len=0")
        self.assertEqual(str(ty.step_label({"uses": "actions/checkout@v4"}, 0)), "step[0] len=0")
        self.assertEqual(str(ty.step_label("not a mapping", 2)), "step[2] len=0")

    def planted(self, template):
        return template % "postgres://u:SENTINEL-F26-2b9e@h/db"

    def test_argv_and_url_leak_messages_name_the_rule_and_the_line_never_the_line_8187_f26(self):
        sentinel = "SENTINEL-F26-2b9e"
        text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        at = next(i for i, ln in enumerate(text.splitlines()) if CONFIGURE in ln)
        cases = {
            "argv": (argv_problems, "psql %s -c 'select 1'", "configure step line 2: psql argv carries a credential"),
            "url leak": (url_leaks, "echo $url_file %s", "configure step line 2: the tier URL is used outside the reviewed lines"),
            "continued": (url_leaks, "printenv \\\n          %s", "configure step line 2: a continued line dumps"),
        }
        for label, (function, template, expected) in cases.items():
            edited = splice(text, at + 1, ["          " + part for part in self.planted(template).split("\n")])
            with self.subTest(site=label):
                problems = function(edited)
                self.assertEqual(len([p for p in problems if sentinel in p or "postgres://" in p]), 0)
                self.assertTrue([p for p in problems if p.startswith(expected)], "%d problem lines" % len(problems))

    def test_workflow_problems_name_the_line_number_and_rule_only_8187_f26(self):
        sentinel = "SENTINEL-F26-2b9e"
        text = self.texts[SHARED_TIER[0]]
        lines = text.split("\n")
        lines.insert(section_end(text), "      run: psql postgres://u:%s@h/db -c 'select 1'" % sentinel)
        problems = workflow_problems("\n".join(lines))
        self.assertEqual(len([p for p in problems if sentinel in p or "postgres://" in p]), 0)
        self.assertTrue([p for p in problems if re.match(r"line \d+: psql without the loader$", p)], "%d problem lines" % len(problems))

    def test_a_workflow_that_does_not_load_names_the_rule_never_its_text_8187_f26(self):
        sentinel = "SENTINEL-F26-2b9e"
        for label, doc in {"unterminated": f'key: "{sentinel}\n', "tab": f"key:\n\t{sentinel}: 1\n",
                           "tag": f"key: !!python/object:os.system {sentinel}\n",
                           "non-string key": f"? [{sentinel}]\n: 1\n", "duplicate": "a: 1\na: 2\n"}.items():
            data, problems = ty.parse_workflow(doc)
            with self.subTest(document=label):
                self.assertIs(data is None, True)
                self.assertEqual([p for p in problems if sentinel in p], [])
                self.assertTrue(problems and problems[0].startswith("the workflow does not load strictly: "), problems)

    def test_the_checker_sources_slice_no_workflow_line_8187_f26(self):
        wide = {path.name: [int(n) for n in re.findall(r"\[:(\d+)\]", path.read_text(encoding="utf-8")) if int(n) >= 40]
                for path in (Path(__file__), Path(__file__).with_name("tier_yaml_8187.py"))}
        # r23: the 60-character cut went with the deny-list predicate; no checker slice is wide
        self.assertEqual(len(wide["tier_yaml_8187.py"]), 0)
        self.assertEqual(len(wide[Path(__file__).name]), 0)


def step_head_rows(block):
    """Row indexes of the ``- `` heads of the steps of a job block, read independently of ``step_label`` (r15 oracle)."""
    rows = block.split("\n")
    at = next((i for i, ln in enumerate(rows) if ln.strip() == "steps:"), None)
    if at is None:
        return []
    item = next((indent_of(ln) for ln in rows[at + 1:] if not comment_or_blank(ln)), 0)
    return [i for i in range(at + 1, len(rows)) if indent_of(rows[i]) == item and rows[i].lstrip().startswith("- ")]


class TestStepLabelIsTheStepsOwnKey8187R15(unittest.TestCase):
    """r15 F27, F28: the text view labels a step by the value of its own top-level ``name:``/``id:`` key only, and the
    loader-failure message carries the rule and the line, never author text."""

    SENTINELS = ("SENTINEL-F27-with", "SENTINEL-F27-env", "SENTINEL-F27-run", "SENTINEL-F27-comment")

    @classmethod
    def setUpClass(cls):
        cls.texts = {wf: (WORKFLOWS / wf).read_text(encoding="utf-8") for wf in PIN_WORKFLOWS}
        cls.pins = load_job_pins()

    def planted_step(self, named, env_first=False):
        head = ["      - name: real  # SENTINEL-F27-comment"] if named else ["      - uses: actions/checkout@v4"]
        body = ["        with:", "          name: SENTINEL-F27-with", "        env:", "          id: SENTINEL-F27-env",
                "        run: |", "          name: SENTINEL-F27-run"]
        if env_first and named:
            return ["      - env:", "          id: SENTINEL-F27-env", "        name: real  # SENTINEL-F27-comment",
                    "        with:", "          name: SENTINEL-F27-with", "        run: |", "          name: SENTINEL-F27-run"]
        return head + body

    def test_only_the_steps_own_name_key_reaches_a_message_8187_f27(self):
        checked = 0
        for wf, text in self.texts.items():
            target = next(iter(pin_targets(wf, text)), None)
            if target is None:
                continue
            for variant, named, env_first in (("named", True, False), ("named env first", True, True),
                                              ("unnamed", False, False)):
                edited = splice(text, target[3], self.planted_step(named, env_first))
                data = ty.load_strict(edited)
                job_steps = data["jobs"][target[0]]["steps"]
                index = next(i for i, s in enumerate(job_steps) if "SENTINEL-F27-env" in json.dumps(s))
                want = "real" if named else ""
                problems = tier_pin_problems(wf, edited, self.pins) + job_pin_problems(wf, edited, self.pins[SECONDARY])
                with self.subTest(workflow=wf, step=variant):
                    checked += 1
                    self.assertTrue(problems)
                    for sentinel in self.SENTINELS:
                        self.assertEqual(len([p for p in problems if sentinel in p]), 0)
                    self.assertTrue([p for p in problems if re.search(step_ref(index, want), p)], "%d problem lines" % len(problems))
        self.assertGreater(checked, 0)

    def test_the_text_view_labels_agree_with_the_loaded_view_on_every_workflow_8187_f27(self):
        compared = 0
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            jobs, problems = job_layout(text)
            if problems:
                continue
            try:
                data = ty.load_lenient(text)
            except Exception:  # noqa: BLE001  (a workflow the loader cannot read has no loaded labels to compare)
                continue
            for name, _first, _end, block in jobs:
                steps = ((data.get("jobs") or {}).get(name) or {}).get("steps")
                heads = step_head_rows(block)
                if not isinstance(steps, list):
                    continue
                with self.subTest(workflow=path.name, job=ty.opaque(name, "job[?]")):
                    self.assertEqual(len(heads), len(steps))
                    for index, row in enumerate(heads):
                        self.assertEqual(step_label(block, row, steps)[1], ty.step_label(steps[index], index), (index,))
                        compared += 1
        self.assertGreater(compared, 100)

    def test_the_label_is_the_value_of_the_top_level_key_only_8187_f27(self):
        block = "\n".join(["  job:", "    steps:", "      - uses: x", "        name: \"Quoted # name\"  # tail",
                           "        with:", "          name: deep", "      - id: build", "        run: |",
                           "          name: nope", "      - run: echo", "        env:", "          id: nope"])
        steps = ty.load_strict(block)["job"]["steps"]
        heads = step_head_rows(block)
        self.assertEqual([(n, str(label)) for n, label in (step_label(block, h, steps) for h in heads)],
                         [(0, "step[0] len=13"), (1, "step[1] len=5"), (2, "step[2] len=0")])

    def test_a_document_that_does_not_load_labels_a_step_by_position_8187_f30(self):
        block = "\n".join(["  job:", "    steps:", "      - run: \"x", "        name: SENTINEL-F30-none\"", "      - id: b"])
        for steps in (None, "not a list", []):
            with self.subTest(steps=steps):
                self.assertEqual([(n, str(label)) for n, label in (step_label(block, h, steps) for h in step_head_rows(block))],
                                 [(0, "step[0] len=0"), (1, "step[1] len=0")])

    def test_a_local_tag_or_tab_does_not_put_author_text_in_the_load_failure_8187_f28(self):
        sentinel = "SENTINEL-F28"
        docs = {"local tag": f"key: !<{sentinel}> x\n", "local tag in a list": f"a:\n  - !<{sentinel}> x\n",
                "tab": f"key: x\n\t{sentinel}: 1\n"}
        for label, doc in docs.items():
            with self.subTest(document=label):
                with self.assertRaises(Exception) as caught:
                    ty.load_strict(doc)
                self.assertNotIn(sentinel, str(caught.exception))  # r24 sec F4: the loader itself no longer carries it
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                message = ty.load_failure(caught.exception)
                self.assertNotIn(sentinel, message)
                self.assertRegex(message, r"^\w+ at line \d+$")
                data, problems = ty.parse_workflow(doc)
                self.assertIs(data is None, True)
                self.assertEqual([p for p in problems if sentinel in p], [])

    def test_the_pure_python_fallback_loader_failure_carries_no_author_text_8187_f28(self):
        # the loader the code falls back to when libyaml is absent prints the offending source line in str(exc)
        sentinel = "SENTINEL-F28"
        docs = {"local tag": f"key: !<{sentinel}> x\n", "tab": f"key: x\n\t{sentinel}: 1\n",
                "unterminated": f'key: "{sentinel}\n'}
        for label, doc in docs.items():
            with self.subTest(document=label):
                with self.assertRaises(ty.yaml.YAMLError) as caught:
                    ty.yaml.load(doc, Loader=ty.yaml.SafeLoader)
                self.assertIs(sentinel in str(caught.exception), True, "the pure-Python message carries the author text")
                message = ty.load_failure(caught.exception)
                self.assertNotIn(sentinel, message)
                self.assertRegex(message, r"^\w+ at line \d+$")


class TestStepLabelComesFromTheLoadedDocument8187R16(unittest.TestCase):
    """r16 F30: a row at the step key column that continues a quoted scalar or a flow collection is value text; the text
    view takes its label from the loaded document, so no source row can become a label."""

    S1, S2, S3, S4 = "SENTINEL-F30-dq", "SENTINEL-F30-sq", "SENTINEL-F30-flow", "SENTINEL-F30-after"

    @classmethod
    def setUpClass(cls):
        cls.texts = {wf: (WORKFLOWS / wf).read_text(encoding="utf-8") for wf in PIN_WORKFLOWS}
        cls.pins = load_job_pins()

    def cases(self):
        return {
            "double-quoted run": ([f'      - run: "echo one', f'        name: {self.S1}"'], None),
            "single-quoted run": (["      - run: 'echo one", f"        name: {self.S2}'"], None),
            "flow mapping with": (["      - uses: actions/checkout@v4", "        with: {a: 1,", f"        name: {self.S3}}}"],
                                  None),
            "named step after a continuation": ([f'      - run: "echo one', f'        name: {self.S4}"',
                                                 "        name: real label"], "real label"),
        }

    def test_a_continuation_row_at_the_key_column_never_reaches_a_message_8187_f30(self):
        sentinels = (self.S1, self.S2, self.S3, self.S4)
        checked = 0
        for wf, text in self.texts.items():
            target = next(iter(pin_targets(wf, text)), None)
            if target is None:
                continue
            for variant, (planted, real) in self.cases().items():
                edited = splice(text, target[3], planted)
                job_steps = ty.load_strict(edited)["jobs"][target[0]]["steps"]
                index = next(i for i, step in enumerate(job_steps)
                             if any(x in json.dumps(step) for x in sentinels))
                problems = tier_pin_problems(wf, edited, self.pins) + job_pin_problems(wf, edited, self.pins[SECONDARY])
                with self.subTest(workflow=wf, step=variant):
                    checked += 1
                    self.assertTrue(problems)
                    for sentinel in sentinels:
                        self.assertEqual(len([p for p in problems if sentinel in p]), 0)
                    self.assertTrue([p for p in problems if re.search(step_ref(index, real or ""), p)], (index,))
        self.assertGreater(checked, 0)


    def test_a_userinfo_shaped_step_name_is_masked_in_both_views_8187_f31(self):
        sentinel = "SENTINEL-F31-pw"
        planted = [f"      - name: https://user:{sentinel}@dbhost/db", "        run: echo one"]
        checked = 0
        for wf, text in self.texts.items():
            target = next(iter(pin_targets(wf, text)), None)
            if target is None:
                continue
            edited = splice(text, target[3], planted)
            job_steps = ty.load_strict(edited)["jobs"][target[0]]["steps"]
            index = next(i for i, step in enumerate(job_steps) if sentinel in json.dumps(step))
            views = {"loaded": tier_pin_problems(wf, edited, self.pins),
                     "text": job_pin_problems(wf, edited, self.pins[SECONDARY])}
            for view, problems in views.items():
                with self.subTest(workflow=wf, view=view):
                    checked += 1
                    self.assertEqual(len([p for p in problems if sentinel in p or "dbhost" in p]), 0)
                    self.assertTrue([p for p in problems if re.search(step_any(index), p)])
        self.assertGreater(checked, 0)


    def test_a_userinfo_past_the_label_cut_is_masked_in_both_views_8187_f33(self):
        """F33: the mask runs before the 60-character cut, so an ``@`` past character 60 still hides the userinfo."""
        sentinel = "SENTINEL-F33-pw"
        cases = {
            "at-past-60": (f"the staging database lives at https://ciuser:{sentinel}-{'x' * 40}@dbhost/db",
                           "the staging database lives at https://***"),
            "password-over-60": (f"https://ciuser:{sentinel}-{'y' * 70}@dbhost/db", "https://***"),
            "prefix-and-password-over-60": (f"see https://ciuser:{sentinel}-{'z' * 70}@dbhost/db",
                                            "see https://***"),
        }
        checked = 0
        for wf, text in self.texts.items():
            target = next(iter(pin_targets(wf, text)), None)
            if target is None:
                continue
            for variant, (name, label) in cases.items():
                self.assertGreaterEqual(name.index("@"), 70)
                edited = splice(text, target[3], [f"      - name: {name}", "        run: echo one"])
                job_steps = ty.load_strict(edited)["jobs"][target[0]]["steps"]
                index = next(i for i, step in enumerate(job_steps) if sentinel in json.dumps(step))
                views = {"loaded": tier_pin_problems(wf, edited, self.pins),
                         "text": job_pin_problems(wf, edited, self.pins[SECONDARY])}
                for view, problems in views.items():
                    with self.subTest(workflow=wf, variant=variant, view=view):
                        checked += 1
                        self.assertEqual(len([p for p in problems if sentinel in p or "ciuser" in p or "dbhost" in p]), 0)
                        self.assertTrue([p for p in problems if re.search(step_any(index), p)])
        self.assertGreater(checked, 0)


    def test_a_userinfo_broken_by_a_line_break_or_a_slash_never_reaches_a_message_8187_f34(self):
        """F34: a userinfo split by a line break, folding whitespace or ``/`` is not matched by the mask, so the label falls
        back to ``step[<index>]``; no ``scheme://user:`` and no password fragment may reach a message."""
        sentinel = "SENTINEL-F34-pw"
        user = "f34user"
        cases = {
            "literal block": ["      - name: |", f"          https://{user}:{sentinel}-pa", "          ss@dbhost/db"],
            "folded block": ["      - name: >", f"          https://{user}:{sentinel}-pa", "          ss@dbhost/db"],
            "escaped newline": [f'      - name: "https://{user}:{sentinel}-pa\\nss@dbhost/db"'],
            "plain continuation": [f"      - name: https://{user}:{sentinel}-pa", "          ss@dbhost/db"],
            "break before the at sign": ["      - name: |", f"          https://{user}:{sentinel}-{'x' * 20}",
                                         "          @dbhost/db"],
            "slash in the password": [f"      - name: https://{user}:{sentinel}/pw@dbhost/db"],
            "at sign in the password": [f"      - name: https://{user}:{sentinel}@pw@dbhost/db"],
            # F37: a scheme with no `//` is not masked, so only the whole-value `@` check keeps these off the line; the
            # `@` sits past character 60 (m4b, m6) or on the next physical line (m4a)
            "no-slash scheme, at sign past 60": [f"      - name: postgresql:{user}:{sentinel}-{'x' * 60}@dbhost/db"],
            "no-slash scheme, at sign on the next line": ["      - name: |", f"          postgresql:{user}:{sentinel}-pa",
                                                          "          ss@dbhost/db"],
            "no-slash scheme, at sign past 60 on a second line": [
                "      - name: |", f"          postgresql:{user}:{sentinel}-{'y' * 60}", "          @dbhost/db"],
        }
        checked = 0
        for wf, text in self.texts.items():
            target = next(iter(pin_targets(wf, text)), None)
            if target is None:
                continue
            for variant, planted in cases.items():
                edited = splice(text, target[3], planted + ["        run: echo one"])
                job_steps = ty.load_strict(edited)["jobs"][target[0]]["steps"]
                index = next(i for i, step in enumerate(job_steps) if sentinel in json.dumps(step))
                views = {"loaded": tier_pin_problems(wf, edited, self.pins),
                         "text": job_pin_problems(wf, edited, self.pins[SECONDARY])}
                for view, problems in views.items():
                    with self.subTest(workflow=wf, variant=variant, view=view):
                        checked += 1
                        self.assertTrue(problems)
                        self.assertEqual(len([p for p in problems if sentinel in p or user in p
                                         or "://" in p.replace("://***", "") or "dbhost" in p]), 0)
                        labelled = [p for p in problems if re.search(step_any(index), p)]
                        self.assertTrue(labelled)
        self.assertGreater(checked, 0)

    def test_a_url_shaped_job_key_never_reaches_a_message_8187_f34(self):
        """F34: a job key shaped like a URL with ``/``, ``@`` or a space in the password is printed as ``job[<n>]``."""
        sentinel = "SENTINEL-F34-jk"
        user = "f34jobuser"
        keys = {
            "slash": f"https://{user}:{sentinel}/pw@dbhost/db",
            "at sign": f"https://{user}:{sentinel}@pw@dbhost/db",
            "space": f"https://{user}:{sentinel} pw@dbhost/db",
        }
        checked = 0
        for wf, text in self.texts.items():
            target = next(iter(pin_targets(wf, text)), None)
            if target is None:
                continue
            job = target[0]
            head = f"\n  {job}:"
            self.assertEqual(text.count(head), 1)
            for variant, key in keys.items():
                edited = text.replace(head, f'\n  "{key}":')
                self.assertIs(sentinel in json.dumps(ty.load_strict(edited)["jobs"]), True)
                views = {"loaded": tier_pin_problems(wf, edited, self.pins),
                         "text": job_pin_problems(wf, edited, self.pins[SECONDARY])}
                for view, problems in views.items():
                    with self.subTest(workflow=wf, variant=variant, view=view):
                        checked += 1
                        self.assertTrue(problems)
                        self.assertEqual(len([p for p in problems if sentinel in p or user in p
                                         or "://" in p.replace("://***", "") or "dbhost" in p]), 0)
        self.assertGreater(checked, 0)


# --------------------------------------------------------------------------------------------------------------------
# r23 (3-agent vote (6def5ab6), 3-0): the echo class is closed by construction, and the gates below prove it.
#
# Every author- or pin-derived value that a problem line, a failure message, a log record or an exception could carry
# travels as a ``ty.Opaque`` that prints only ``label[<n>] len=<N>``.  Three module-level gates keep it that way:
#   1. the canary-injection test (``canary_run``): every field of a workflow and of the pins becomes a unique
#      ``CANARY-<24hex>`` marker, wrapped in each probe shape the earlier rounds broke the deny-list with, every routed
#      site runs in both views on the pass and the fail path, and stdout, stderr, log records, warnings, exception text
#      and the returned problem lines are searched for any 8-hex window of any marker (after decoding the probe shapes);
#   2. the AST taint test (``TaintScan``): no ``assert*`` call or ``subTest`` parameter of this module receives a value
#      derived from a workflow or a pin without a wrapper (a raw compare restored through a helper and a list is red);
#   3. the wrapper itself: ``raw()`` is called in ``ty.same`` only, and ``Opaque`` never returns its text from any
#      string protocol.

CANARY_SCRATCH = Path(__file__).resolve().parents[2] / ".local-runs"  # repo-local and gitignored: never the system temp dir
CANARY_FORCE_FAIL = True  # the mutant "fail-path forcing dropped" sets this False; the coverage assertions then go red
CANARY_BLIND = "\u034f\ufe0f\u3164\uffa0\u00ad"
CANARY_SHAPES = {
    "plain": lambda m: m,
    "percent-encoded": lambda m: "".join("%%%02X" % ord(c) for c in m),
    "fullwidth": lambda m: "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in m),
    "format-characters": lambda m: "\u200b".join(m),
    "soft-hyphen": lambda m: "\u00ad".join(m),
    "invisible-fillers": lambda m: "\u034f\ufe0f\u3164\uffa0".join(m[i:i + 3] for i in range(0, len(m), 3)),
    "key-suffix": lambda m: "X_KEY_" + m,
    "account-key": lambda m: "AccountKey=" + m,
    "flag-password": lambda m: "--password " + m,
    "bracket-key": lambda m: "creds[password]=" + m,
    "quoted-keyword": lambda m: 'password="%s"' % m,
    "keyword-space-value": lambda m: "password " + m,
    "multi-line": lambda m: "first\n%s\nlast" % m,
    "userinfo-url": lambda m: "https://user:%s@host/db" % m,
    "step-label-shaped": lambda m: "step[3] " + m,
    "job-label-shaped": lambda m: "job[2]=" + m,
}
# keys whose children are author-chosen names (job ids, env and input names ...); the other keys are GitHub's own
CANARY_AUTHOR_MAPS = frozenset(("jobs", "env", "with", "outputs", "services", "permissions", "secrets"))


CANARY_SENTINEL = "MK"  # r24 F42f: a marker is this non-hex prefix plus 24 hex digits, matched per line after decoding


def canary_decode(text):
    """``text`` the way a reader would decode it: probe-shape blind characters removed, percent-decoded twice, NFKC,
    format characters removed, lower case."""
    text = "".join(c for c in text if c not in CANARY_BLIND)
    text = urllib.parse.unquote(urllib.parse.unquote(text))
    text = unicodedata.normalize("NFKC", text)
    return "".join(c for c in text if unicodedata.category(c) != "Cf" and c not in CANARY_BLIND).lower()


def canary_hits(text, windows, size=8):
    """The registered markers (hex digests) of which ``text`` shows an 8-hex window.  The text is decoded, split into lines,
    and only the hex run that follows the sentinel on a line is read, so constant text and the hex digits of two adjacent
    lines cannot form a hit (r23 matched windows across a line break and across unrelated digits)."""
    found = set()
    pattern = re.compile(re.escape(CANARY_SENTINEL.lower()) + r"([0-9a-f]+)")
    for line in canary_decode(text).split("\n"):
        for match in pattern.finditer(line):
            digits = match.group(1)
            for start in range(len(digits) - size + 1):
                digest = windows.get(digits[start:start + size])
                if digest is not None:
                    found.add(digest)
    return found


def canary_digest(seed, counter):
    return hashlib.sha256(b"r24-canary-%d-%d" % (seed, counter)).hexdigest()[:24]


def canary_window_table(digests, size=8):
    return {digest[i:i + size]: digest for digest in digests for i in range(len(digest) - size + 1)}


class CanaryListHandler(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.chunks = []

    def emit(self, record):
        self.chunks.append(record.getMessage())
        self.chunks.append(str(record.__dict__.get("exc_text", "")))
        self.chunks.append(repr(record.args))


class CanaryRun:
    """One canary run over a module ``mod`` that exposes the checker (``mod.ty`` and the problem functions): the markers
    it minted, every channel it captured and the leaks, coverage and pass/fail results."""

    def __init__(self, mod, seed=0, foreign_seed=None):
        self.mod = mod
        self.ty = mod.ty
        self.seed = seed
        self.counter = 0
        self.stray = []        # (shape, scenario) whose output showed a marker of the OTHER seed (a false positive)
        self.foreign = {} if foreign_seed is None else canary_window_table(canary_digest(foreign_seed, n) for n in range(1, 20001))
        self.fail_views = {}   # (shape, view) -> fail-path observations (r24 sec F2)
        self.fail_families = {}  # (shape, view, scenario family) -> fail-path observations
        self.fail_sites = {}  # (shape, scenario family) -> fail-path observations of any view (r25 code C2)
        self.kind = {}      # marker hex -> kind
        self.names = {}     # (shape, original) -> marker (names are shared between the workflow and its pins)
        self.windows = {}   # 8-hex window -> marker hex
        self.leaks = []     # (shape, scenario, kind)
        self.calls = 0
        self.pass_calls = 0
        self.fail_calls = 0
        self.unexpected = []   # pass-path scenarios that returned problems
        self.silent = []       # fail-path scenarios that returned none
        self.errors = []       # scenarios that raised
        self.skipped = []
        self.problem_lines = 0
        self.label_forms = set()
        self.by_shape = {}
        self.texts = {wf: (mod.WORKFLOWS / wf).read_text(encoding="utf-8") for wf in mod.PIN_WORKFLOWS}
        self.datas = {wf: self.ty.load_strict(text) for wf, text in self.texts.items()}
        self.pins = mod.load_job_pins()
        self.keep_jobs = frozenset()  # job ids an exact RUNS_ON_EXEMPT row names stay as they are, so the rows still apply

    def mint(self, kind, shape, memo=None):
        self.counter += 1
        digest = canary_digest(self.seed, self.counter)
        self.kind[digest] = kind
        self.windows.update(canary_window_table([digest]))
        return shape(CANARY_SENTINEL + digest)

    def name(self, original, kind, shape_name, shape):
        key = (shape_name, original)
        if key not in self.names:
            self.names[key] = self.mint(kind, shape)
        return self.names[key]

    def observe(self, shape_name, scenario, call, *args, expect=None):
        """Run ``call(*args)`` capturing every channel; scan it for markers; record the pass/fail expectation.  Each capture
        line carries a ``# canary-channel: <name>`` comment: the harness mutants of ``HARNESS_MUTANTS`` replace those lines,
        and ``canary_controls`` seeds a marker through every channel to prove each one is live (r24 sec F1, F3)."""
        out, err = io.StringIO(), io.StringIO()
        handler = CanaryListHandler()
        logger = logging.getLogger()
        old_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        chunks = []
        result = None
        try:
            with warnings.catch_warnings(record=True) as caught, contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                warnings.simplefilter("always")
                try:
                    result = call(*args)
                except Exception as exc:  # noqa: BLE001  (the exception text is one of the channels under test)
                    self.errors.append((shape_name, scenario, type(exc).__name__))
                    chunks += [str(exc), repr(exc), repr(exc.args)]  # canary-channel: exception
                    chunks += [*traceback.format_exception(type(exc), exc, exc.__traceback__), traceback.format_exc()]  # canary-channel: exception-chain
            chunks += [str(w.message) for w in caught]  # canary-channel: warning
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        chunks += [out.getvalue(), err.getvalue()]  # canary-channel: stdout-stderr
        chunks += handler.chunks  # canary-channel: log
        if isinstance(result, list):
            for line in result:
                if not isinstance(line, str):
                    self.errors.append((shape_name, scenario, "non-str problem line"))
                chunks += [str(line), repr(line)]  # canary-channel: problem-line
                self.label_forms.update(re.findall(r"\b(?:job|step|key|pin)\[(?:\d+|\?)\] len=\d+", str(line)))
            self.problem_lines += len(result)
        self.calls += 1
        view = scenario.rsplit("/", 1)[-1]
        if expect == "pass":
            self.pass_calls += 1
            if result:
                self.unexpected.append((shape_name, scenario))
        elif expect == "fail":
            self.fail_calls += 1
            site = (shape_name, scenario.split("/", 1)[0])
            self.fail_sites[site] = self.fail_sites.get(site, 0) + 1
            if view in ("loaded", "text"):
                self.fail_views[(shape_name, view)] = self.fail_views.get((shape_name, view), 0) + 1
                family = scenario.split("/", 1)[0]
                key = (shape_name, view, family)
                self.fail_families[key] = self.fail_families.get(key, 0) + 1
            if not result:
                self.silent.append((shape_name, scenario))
        text = "\n".join(chunks)
        for digest in sorted(canary_hits(text, self.windows)):
            self.leaks.append((shape_name, scenario, self.kind[digest]))
            self.by_shape[shape_name] = self.by_shape.get(shape_name, 0) + 1
        if self.foreign and canary_hits(text, self.foreign):
            self.stray.append((shape_name, scenario))
        return result

    def views(self, shape_name, scenario, wf, text, pins_primary, pins_secondary, expect, expect_text="same"):
        """Both views of one workflow text: the loaded view (``primary_pin_problems``) and the text view
        (``job_pin_problems``; ``expect_text`` differs only where the text view is not meant to see the fault)."""
        mod = self.mod
        self.observe(shape_name, scenario + "/loaded", mod.primary_pin_problems, wf, text, pins_primary, expect=expect)
        self.observe(shape_name, scenario + "/text", mod.job_pin_problems, wf, text, pins_secondary,
                     expect=expect if expect_text == "same" else expect_text)


def canary_dump(tree):
    """Block-style YAML of ``tree`` with sequences indented and multi-line strings as literal blocks, like the real files."""
    yaml = ty.yaml

    class Dumper(yaml.SafeDumper):
        def increase_indent(self, flow=False, indentless=False):
            return super().increase_indent(flow, False)

    def literal(dumper, value):
        return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)

    Dumper.add_representer(str, literal)
    return yaml.dump(tree, Dumper=Dumper, sort_keys=False, default_flow_style=False, allow_unicode=True, width=10 ** 9)


def canary_tree(run, node, shape_name, shape, mode, parent="", fresh=True):
    """``node`` with its author-chosen text replaced by markers.  Mode ``names``: job ids, step names, env and input names
    and every ``name``/``id`` value are replaced, every other string keeps its text and gets a marker appended (a run
    block stays a recognisable tier step).  Mode ``all``: every key outside GitHub's own and every string is replaced."""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if isinstance(key, str) and not (parent == "jobs" and key in run.keep_jobs) and (parent in CANARY_AUTHOR_MAPS or mode == "all" and parent != "" and key not in ("jobs", "steps")):
                new = run.name(key, "job" if parent == "jobs" else "key", shape_name, shape)
            else:
                new = key
            out[new] = canary_tree(run, value, shape_name, shape, mode, key if isinstance(key, str) else "", fresh)
        return out
    if isinstance(node, list):
        return [canary_tree(run, item, shape_name, shape, mode, parent, fresh) for item in node]
    if isinstance(node, str):
        if mode == "all" or parent in ("name", "id"):
            return run.mint("step" if parent == "name" else "value", shape)
        if parent == "run":
            return node + "\necho " + run.mint("run", shape)
        return node
    return node


def canary_pin_tree(run, node, shape_name, shape, keys):
    """The pin data with every string value replaced by a marker, and (``keys``) every key too."""
    if isinstance(node, dict):
        return {(run.name(k, "pin", shape_name, shape) if keys and isinstance(k, str) else k):
                canary_pin_tree(run, v, shape_name, shape, keys) for k, v in node.items()}
    if isinstance(node, list):
        return [canary_pin_tree(run, v, shape_name, shape, keys) for v in node]
    if isinstance(node, str):
        return run.mint("pin", shape)
    return node


def pins_for(texts, mod=None):
    """The ``primary`` and ``secondary_text`` pin sections of ``{workflow: text}``, built the way ``--write-pins`` builds them
    (raises ``ValueError`` for a text the strict loader or the layout reader refuses)."""
    mod = sys.modules[__name__] if mod is None else mod
    table = {mod.PRIMARY: {}, mod.SECONDARY: {}}
    for workflow, raw in texts.items():
        data, bad = mod.ty.parse_workflow(raw)
        if bad:
            raise ValueError("%s: %d load problems" % (workflow, len(bad)))
        found, layout_bad = mod.job_layout(raw)
        if layout_bad:
            raise ValueError("%s: %d layout problems" % (workflow, len(layout_bad)))
        table[mod.PRIMARY][workflow] = mod.ty.build_pins(data)
        table[mod.SECONDARY][workflow] = {
            "jobs": [j[0] for j in found],
            "pinned": {name: mod.pin_entry(block) for name, block in mod.tier_blocks(found)},
            "workflow": {key: mod.pin_entry(block) for key, block in sorted(mod.workflow_level_blocks(raw).items())}}
    return table


def canary_loader_faults(run, shape_name, shape):
    """Documents the strict loader and the layout reader refuse, each carrying markers in the text the refusal is about."""

    def value():
        return json.dumps(run.mint("value", shape))

    def key(name):
        return json.dumps(run.name(name, "key", shape_name, shape))

    duplicate = key("duplicate")
    anchor = run.mint("key", lambda marker: marker)
    return {
        "duplicate-key": "%s: 1\n%s: 2\n" % (duplicate, duplicate),
        "plain-anchor": "base: &%s 1\nother: *%s\n" % (anchor, anchor),
        "merge-key": "jobs:\n  <<: {%s: %s}\n" % (key("merge"), value()),
        "non-string-key": "1: %s\n" % value(),
        "sequence-document": "- %s\n- %s\n" % (value(), value()),
        "no-jobs": "name: %s\n" % value(),
        "jobs-not-a-mapping": "name: x\njobs: %s\n" % value(),
        "job-not-a-mapping": "name: x\njobs:\n  %s: %s\n" % (key("j1"), value()),
        "job-level-uses": "name: x\njobs:\n  %s:\n    uses: %s\n" % (key("j2"), value()),
        "unterminated-quote": 'name: "%s\njobs: {\n' % run.mint("value", shape),
        "tab-indent": "name: x\njobs:\n\t%s: 1\n" % key("j3"),
        "extra-top-level-key": "%s: %s\n" % (key("extra"), value()),
        "duplicate-job": "name: x\njobs:\n  %s:\n    runs-on: a\n  %s:\n    runs-on: b\n" % ((run.name("dup-job", "key", shape_name, shape),) * 2),
        # r24 sec F4: the tag, the %TAG directive and the escape sequence are text the parser quotes back in its errors
        "local-tag": "name: x\nenv:\n  X_TAG: !%s v\n" % run.mint("tag", shape),
        "tag-directive": "%%TAG !e! tag:%s,2000:\n---\nname: x\n" % run.mint("tag", shape),
        "bad-escape": 'name: x\nenv:\n  X_ESC: "%s\\q"\n' % run.mint("tag", shape),
        # r25 sec S1: a standard tag's constructor calls int(), float() or a table lookup, which raise ValueError / KeyError
        "std-int-value": "name: x\nenv:\n  X_INT: !!int %s\n" % run.mint("tag", shape),
        "std-float-value": "name: x\nenv:\n  X_FLT: !!float %s\n" % run.mint("tag", shape),
        "std-bool-value": "name: x\nenv:\n  X_BOOL: !!bool %s\n" % run.mint("tag", shape),
        "std-int-key": "name: x\nenv:\n  !!int %s: v\n" % run.mint("tag", shape),
    }


def canary_diff_scenarios(run, shape_name, shape, wf, text):
    """Marker keys on either side of a job pin: the text has an extra job or step key, the pin names a key the job lacks, and
    the secondary pins name a workflow-level block the text lacks (the ``first_difference`` and ``name_label`` arms)."""
    mod = run.mod
    pins = run.pins
    job = sorted(pins[mod.PRIMARY][wf]["tier_jobs"])[0]
    zero = "0" * 64
    for where in ("job", "step"):
        data = copy.deepcopy(run.datas[wf])
        holder = data["jobs"][job] if where == "job" else data["jobs"][job]["steps"][0]
        holder[run.name("extra-" + where + "-key", "key", shape_name, shape)] = "x"
        run.views(shape_name, "fail-text-extra-%s-key/%s" % (where, wf), wf, canary_dump(data), pins[mod.PRIMARY],
                  pins[mod.SECONDARY], "fail")
        edited = copy.deepcopy(pins[mod.PRIMARY])
        entry = edited[wf]["tier_jobs"][job]
        target = entry if where == "job" else entry["steps"][0]
        target["keys"][run.name("pin-" + where + "-key", "key", shape_name, shape)] = zero
        target["sha256"] = entry["sha256"] = zero
        run.views(shape_name, "fail-pin-extra-%s-key/%s" % (where, wf), wf, text, edited, pins[mod.SECONDARY], "fail", None)
    blocks = copy.deepcopy(pins[mod.SECONDARY])
    blocks[wf].setdefault("workflow", {})[run.name("pin-block", "key", shape_name, shape)] = mod.pin_entry("x: 1")
    run.observe(shape_name, "fail-pin-extra-block/" + wf + "/text", mod.job_pin_problems, wf, text, blocks, expect="fail")


def canary_scenarios(run, shape_name, shape):
    """Every routed site of the checker for one probe shape: pass and fail paths, loaded and text views."""
    mod = run.mod
    ty_mod = run.ty
    pins = run.pins
    for mode in ("names", "all"):
        for wf in mod.PIN_WORKFLOWS:
            run.keep_jobs = frozenset(job for workflow, job in getattr(mod, "RUNS_ON_EXEMPT", {}) if workflow == wf)
            text1 = canary_dump(canary_tree(run, run.datas[wf], shape_name, shape, mode))
            text2 = canary_dump(canary_tree(run, run.datas[wf], shape_name, shape, mode))
            try:
                own = pins_for({wf: text1}, mod)
            except (ValueError, ty_mod.StrictYamlError, ty_mod.yaml.YAMLError):
                own = None
                run.skipped.append((shape_name, "self-pins/" + mode))
            tag = "%s/%s" % (mode, wf)
            if own is not None:
                # mode "all" renames keys GitHub reads (runs-on, run, uses ...), so its own-pin result is not pinned to a side
                run.views(shape_name, "pass-own-pins/" + tag, wf, text1, own[mod.PRIMARY], own[mod.SECONDARY],
                          "pass" if mode == "names" else None)
                if CANARY_FORCE_FAIL:
                    run.views(shape_name, "fail-other-values/" + tag, wf, text2, own[mod.PRIMARY], own[mod.SECONDARY], "fail")
                    run.views(shape_name, "fail-real-text-own-pins/" + tag, wf, run.texts[wf], own[mod.PRIMARY], own[mod.SECONDARY], "fail")
            if CANARY_FORCE_FAIL:
                run.views(shape_name, "fail-real-pins/" + tag, wf, text1, pins[mod.PRIMARY], pins[mod.SECONDARY], "fail")
    for wf in mod.PIN_WORKFLOWS:
        text = run.texts[wf]
        run.views(shape_name, "pass-real/" + wf, wf, text, pins[mod.PRIMARY], pins[mod.SECONDARY], "pass")
        if not CANARY_FORCE_FAIL:
            continue
        targets = mod.pin_targets(wf, text)
        for step in ([targets[0], targets[-1]] if len(targets) > 1 else targets):
            marked = shape(run.mint("run", shape))
            injected = mod.inject_run_line(text, step, "echo " + marked)
            run.views(shape_name, "fail-injected-run/" + wf, wf, injected, pins[mod.PRIMARY], pins[mod.SECONDARY], "fail")
            if step[2].lstrip().startswith("- name:"):
                renamed = text.replace("- name: " + step[1], "- name: " + json.dumps(shape(run.mint("step", shape))), 1)
                run.views(shape_name, "fail-renamed-step/" + wf, wf, renamed, pins[mod.PRIMARY], pins[mod.SECONDARY], "fail")
                lines = injected.split("\n")
                pad = lines[step[3]][:mod.indent_of(lines[step[3]])]
                lines[step[3]] = "%s- x-note: %s" % (pad, json.dumps(shape(run.mint("key", shape))))
                run.views(shape_name, "fail-unnamed-step/" + wf, wf, "\n".join(lines), pins[mod.PRIMARY], pins[mod.SECONDARY], "fail")
        for keys in (False, True):
            marked_pins = {mod.PRIMARY: canary_pin_tree(run, pins[mod.PRIMARY], shape_name, shape, keys),
                           mod.SECONDARY: canary_pin_tree(run, pins[mod.SECONDARY], shape_name, shape, keys)}
            run.views(shape_name, "fail-marked-pins-%s/%s" % ("keys" if keys else "values", wf), wf, text,
                      marked_pins[mod.PRIMARY], marked_pins[mod.SECONDARY], "fail")
        canary_diff_scenarios(run, shape_name, shape, wf, text)
        for fault, doc in canary_loader_faults(run, shape_name, shape).items():
            suffix = fault == "extra-top-level-key"
            run.views(shape_name, "fail-%s/%s" % (fault, wf), wf, text + "\n" + doc if suffix else doc,
                      pins[mod.PRIMARY], pins[mod.SECONDARY], "fail", None if suffix else "same")
    if not CANARY_FORCE_FAIL:
        return
    ci = run.texts["ci.yml"]
    at = next(i for i, ln in enumerate(ci.splitlines()) if mod.CONFIGURE in ln)
    for label, function, template in (("argv", mod.argv_problems, "psql %s -c 'select 1'"),
                                      ("url", mod.url_leaks, "echo $url_file %s"),
                                      ("continued", mod.url_leaks, "printenv \\\n          %s")):
        planted = template % shape(run.mint("run", shape))
        edited = mod.splice(ci, at + 1, ["          " + part for part in planted.split("\n")])
        run.observe(shape_name, "fail-legacy-" + label, function, edited, expect="fail")
    planted = mod.splice(ci, at + 1, ["          echo " + shape(run.mint("run", shape))])
    run.observe(shape_name, "fail-legacy-wiring", mod.wiring_problems, planted, expect=None)
    run.observe(shape_name, "fail-legacy-workflow", mod.workflow_problems, planted, expect=None)
    run.observe(shape_name, "pass-legacy-wiring", mod.wiring_problems, ci, expect="pass")
    canary_repo_scenario(run, shape_name, shape)


def canary_repo_scenario(run, shape_name, shape):
    """The repository level: a tree of the real workflows plus workflows whose jobs, runners and keys are markers."""
    mod = run.mod
    ty_mod = run.ty
    run.keep_jobs = frozenset()
    CANARY_SCRATCH.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(CANARY_SCRATCH)) as raw_root:
        root = Path(raw_root)
        target = root / ".github" / "workflows"
        shutil.copytree(mod.WORKFLOWS, target)
        run.observe(shape_name, "pass-repo-real-tree", mod.repo_problems, root, run.pins, expect="pass")
        if not CANARY_FORCE_FAIL:
            return
        data = {"name": run.mint("value", shape), "on": "push", "jobs": {
            run.name("job-a", "job", shape_name, shape): {"runs-on": run.mint("value", shape), "steps": [{"run": "echo hi"}]},
            run.name("job-b", "job", shape_name, shape): {"uses": run.mint("value", shape)},
            run.name("job-c", "job", shape_name, shape): "not a mapping " + run.mint("value", shape)}}
        (target / "canary-a.yml").write_text(canary_dump(data), encoding="utf-8")
        (target / "canary-b.yml").write_text("jobs: %s\n" % json.dumps(run.mint("value", shape)), encoding="utf-8")
        (target / "canary-c.yml").write_text("jobs: {\n  %s: [\n" % json.dumps(run.mint("key", shape)), encoding="utf-8")
        (target / "canary-d.yml").write_text("name: x\nenv:\n  TIER: $\x7b{ secrets.CI_FED_URL }} %s\n" % run.mint("value", shape),
                                              encoding="utf-8")
        (target / "canary-e.yml").write_text("name: x\non: push\nenv:\n  !!int %s: v\njobs: {}\n" % run.mint("tag", shape),
                                              encoding="utf-8")  # r25 sec S1: only the lenient loader reads this one
        (target / "canary-f.yml").write_text("name: x\non: push\nenv:\n  X_INT: !!int %s\njobs: {}\n" % run.mint("tag", shape),
                                              encoding="utf-8")
        for workflow, _job in mod.self_hosted_rows():
            exempt = ty_mod.load_lenient((target / workflow).read_text(encoding="utf-8"))
            (target / workflow).write_text(canary_dump(canary_tree(run, exempt, shape_name, shape, "names")), encoding="utf-8")
        run.observe(shape_name, "fail-repo-marker-tree", mod.repo_problems, root, run.pins, expect="fail")
        marked = {mod.PRIMARY: canary_pin_tree(run, run.pins[mod.PRIMARY], shape_name, shape, True),
                  mod.SECONDARY: canary_pin_tree(run, run.pins[mod.SECONDARY], shape_name, shape, True),
                  mod.EXEMPT: canary_pin_tree(run, run.pins[mod.EXEMPT], shape_name, shape, True)}
        run.observe(shape_name, "fail-repo-marker-pins", mod.repo_problems, root, marked, expect="fail")
        for workflow, job in mod.self_hosted_rows():
            exempt = ty_mod.load_lenient((mod.WORKFLOWS / workflow).read_text(encoding="utf-8"))
            exempt["jobs"][job]["strategy"]["matrix"] = {run.name("matrix-key", "key", shape_name, shape): "scalar"}
            (target / workflow).write_text(canary_dump(exempt), encoding="utf-8")
        run.observe(shape_name, "fail-repo-marker-matrix", mod.repo_problems, root, run.pins, expect="fail")


def canary_wrapper_scenario(run, shape_name, shape):
    """The wrapper itself under every protocol a message could go through, including a failing unittest assertion."""
    ty_mod = run.ty
    if not hasattr(ty_mod, "Opaque"):
        return
    a = ty_mod.Opaque(shape(run.mint("value", shape)), "key[0]")
    b = ty_mod.Opaque(shape(run.mint("value", shape)), "key[1]")
    case = unittest.TestCase()

    def protocols():
        logging.getLogger("canary").warning("%s %r %s", a, a, b)
        print(a, repr(b), "%s %r %10s" % (a, b, a), "{} {!r} {:>20}".format(a, b, a), f"{a} {b!r} {a:>30}")
        print(str(a), repr([a, b]), str({a: b}), str((a, b)), bytes(a), json.dumps(str(a)))
        for failing in (lambda: case.assertEqual(a, b), lambda: case.assertNotEqual(a, a), lambda: case.assertIn(a, [b]),
                        lambda: case.assertEqual([a], [b]), lambda: case.assertDictEqual({a: a}, {b: b}),
                        lambda: case.assertEqual(a, b, "msg %s" % a), lambda: case.assertEqual({a, b}, {b})):
            try:
                failing()
            except AssertionError as exc:
                print(str(exc))
                logging.getLogger("canary").error("failed: %s", exc)
        left, right = shape(run.mint("value", shape)), shape(run.mint("value", shape))
        unknown = ty_mod.job_label(left, {})   # the "job[?]" arm: a name that is not one of the jobs
        known = ty_mod.job_label(left, {left: 1, right: 2})
        for failing in (lambda: case.assertEqual(ty_mod.opaque(left, "key[0]"), ty_mod.opaque(right, "key[0]"), "differs: key[0]"),
                        lambda: case.assertEqual(unknown, known), lambda: case.assertEqual(known, ty_mod.job_label(right, {left: 1, right: 2}))):
            try:
                failing()
            except AssertionError as exc:
                print(str(exc))
                logging.getLogger("canary").error("failed: %s", exc)
        try:
            raise ValueError(a)
        except ValueError as exc:
            print(str(exc), repr(exc))
        return [str(a), repr(b), str(unknown), str(known)]

    run.observe(shape_name, "wrapper-protocols", protocols, expect=None)


def canary_run(mod, shapes=None, seed=0, foreign_seed=None):
    """Drive every routed site of ``mod`` with every probe shape; the returned ``CanaryRun`` holds the leaks and the coverage.
    ``seed`` picks the marker family; ``foreign_seed`` registers a second family whose markers must NOT show (``run.stray``)."""
    run = mod.CanaryRun(mod, seed, foreign_seed)  # the harness of ``mod`` itself: a mutated copy runs its own mutated harness
    for shape_name, shape in (shapes or mod.CANARY_SHAPES).items():
        mod.canary_scenarios(run, shape_name, shape)
        mod.canary_wrapper_scenario(run, shape_name, shape)
    return run


def canary_controls(run):
    """One seeded positive control per capture channel: ``{name: effect(marker)}``.  Each effect writes its marker through
    exactly that channel (or, for the exception pair, through the chain only), so a harness that stopped capturing the
    channel shows no leak for it."""

    def control_exception(marker):
        raise ValueError(marker)

    def control_chain(marker):
        raise RuntimeError("outer") from ValueError(marker)

    def control_context(marker):
        try:
            raise ValueError(marker)
        except ValueError:
            raise RuntimeError("outer")  # noqa: B904  (the implicit __context__ is the path under test)

    def control_warning(marker):
        warnings.warn(marker)

    def control_notes(marker):
        exc = ValueError("outer")
        exc.add_note(marker)  # the marker lives in ``__notes__`` only: not in str, args, the cause or the context
        raise exc

    controls = {
        "print": lambda marker: print("seen", marker),
        "stderr": lambda marker: print(marker, file=sys.stderr),
        "log": lambda marker: logging.getLogger("canary").warning("seen %s", marker),
        "warning": control_warning,
        "problem-line": lambda marker: ["problem line " + marker],
        "exception": control_exception,
        "exception-chain": control_chain,
        "exception-context": control_context,
    }
    if sys.version_info >= (3, 11):  # PEP 678 notes exist from 3.11 (r25 sec S3)
        controls["exception-notes"] = control_notes
    return controls


def canary_control_failures(mod):
    """The controls of ``mod`` (a loaded copy of this module, possibly a mutant) that its ``observe`` did NOT report as a leak."""
    run = mod.CanaryRun(mod)
    failures = []
    for name, effect in mod.canary_controls(run).items():
        marker = run.mint("control", mod.CANARY_SHAPES["plain"])
        before = len(run.leaks)
        run.observe("plain", "control/" + name, effect, marker)
        if len(run.leaks) == before:
            failures.append(name)
    return failures


# the scenario families each fail-path guard gates (r25 code C2): every shape must reach every family of every guard
CANARY_GUARDED_FAMILIES = {
    "real-pins fail view": ("fail-real-pins",),
    "post-pass tail": (
        "fail-injected-run", "fail-renamed-step", "fail-unnamed-step", "fail-marked-pins-keys", "fail-marked-pins-values",
        "fail-text-extra-job-key", "fail-text-extra-step-key", "fail-pin-extra-block", "fail-pin-extra-job-key",
        "fail-pin-extra-step-key",
        "fail-bad-escape", "fail-duplicate-job", "fail-duplicate-key", "fail-extra-top-level-key", "fail-job-level-uses",
        "fail-job-not-a-mapping", "fail-jobs-not-a-mapping", "fail-local-tag", "fail-merge-key", "fail-no-jobs",
        "fail-non-string-key", "fail-plain-anchor", "fail-sequence-document", "fail-std-bool-value", "fail-std-float-value",
        "fail-std-int-key", "fail-std-int-value", "fail-tab-indent", "fail-tag-directive", "fail-unterminated-quote"),
    "legacy scenarios": ("fail-legacy-argv", "fail-legacy-continued", "fail-legacy-url"),
    "repository scenario": ("fail-repo-marker-matrix", "fail-repo-marker-pins", "fail-repo-marker-tree"),
}
# families only the shapes whose own pins could be built reach (the own-pins fail views)
CANARY_GUARDED_FAMILIES_PLAIN = {"own-pins fail views": ("fail-other-values", "fail-real-text-own-pins")}


def canary_coverage_failures(run, shapes):
    """Fail-path coverage holes of ``run`` (r24 sec F2, r25 sec S4 and code C2): a shape and view with no fail-path
    observation, or a guarded family that never ran for a shape.  Every family of every guard is counted on its own (other
    fail scenarios keep a bare count above zero when one guard is forced off), and a hole names its guard."""
    failures = []
    for shape in shapes:
        for view in ("loaded", "text"):
            if run.fail_views.get((shape, view), 0) == 0:
                failures.append("%s/%s: no fail-path observation" % (shape, view))
        groups = dict(CANARY_GUARDED_FAMILIES)
        if shape == "plain":
            groups.update(CANARY_GUARDED_FAMILIES_PLAIN)
        for guard, families in groups.items():
            for family in families:
                if run.fail_sites.get((shape, family), 0) == 0:
                    failures.append("%s: guard '%s' family %s never ran" % (shape, guard, family))
    return failures


# ---- r23 AST taint scanner (3-agent vote (6def5ab6)) ----
TAINT_SOURCES = frozenset((
    "read_text", "read_bytes", "load_job_pins", "load_strict", "load_lenient", "parse_workflow", "pin_targets",
    "job_layout", "workflow_steps", "job_steps", "tier_job", "tier_blocks", "post_export_steps", "build_pins",
    "exempt_pins", "pin_entry", "loads", "workflow_level_blocks", "tier_job_names", "leaf_strings", "normalised_leaves",
    "normalised_code", "normalise_shell", "uses_references", "tier_workflows"))
# (r24: ``canonical_json``, ``dumps`` and ``safe_dump`` are no longer sources: they carry what their argument carries, so a
# tainted argument taints the result and an Opaque or a literal does not)
# calls whose result is a bool, a count or a positional label: a value that went through one is "wrapped" (r23 F41-a)
TAINT_SAFE_CALLS = frozenset((
    "len", "bool", "any", "all", "isinstance", "hasattr", "callable", "id", "opaque", "Opaque", "same", "any_match",
    "load_failure", "matches_markers", "names_tier", "names_the_tier",
    "step_head_rows", "assert_same",
    "assert_has", "range", "enumerate_count", "job_re", "step_ref", "step_any", "key_re", "digest",
    "count", "index", "find", "startswith", "endswith", "isdigit",
    # these return line numbers (ints) and nothing else
    "opaque_escape_lines", "tainted_assert_lines", "raw_operand_comparisons",
    # a canary run object, a loaded variant module and the marker digests carry no author text; the run's ``texts``,
    # ``datas`` and ``pins`` attributes do and are sources below (``TAINT_ATTRS``)
    "canary_run", "CanaryRun", "load_variant", "canary_hits", "canary_control_failures", "canary_coverage_failures"))
TAINT_ATTRS = frozenset(("texts", "datas", "pins"))
# r24 sec F5: a Match object from ``search``/``match``/``fullmatch`` holds the text it matched, so it is tainted like the text
# (only ``bool(...)`` of it is clear); the three names left the safe list
TAINT_SAFE_SUFFIXES = ("_label", "_re", "_ref")
# problem lines are labels-only by construction, but an assert that compares or prints them would echo a leaked line on
# failure, so they stay tainted like any other value derived from a workflow
TAINT_PROBLEM_SUFFIXES = ("_problems", "_problem")
# a tuple-returning source whose listed positions hold labels only
TAINT_SAFE_POSITIONS = {"job_layout": {1}, "parse_workflow": {1}}
ASSERT_PREFIX = "assert"
# names that hold repo paths or test-written constants (workflow file names, mutant labels), public by construction
PUBLIC_NAMES = frozenset(("wf", "workflow", "workflow_name", "path"))
# containers keyed by test-written constants: the KEY of ``.items()`` over them is public
STATIC_KEYED = frozenset(("mutants", "forms", "texts", "DUMP_MUTANTS", "F10_MUTANTS", "cases", "shapes", "views", "keys", "variants",
                          "positional_cases"))
# calls that print their arguments into a failure report besides the assert* family (``subTest`` parameters, ``fail``)
ECHO_CALLS = frozenset(("subTest", "fail", "skipTest", "addCleanup"))
WRAPPED_ASSERTS = frozenset(("assert_same", "assert_has"))
# r24 sec F5: print and logging write their arguments out; a tainted argument is a finding like an assert operand
PRINT_CALLS = frozenset(("print", "pprint", "warn"))
LOG_BASES = frozenset(("logging", "logger", "log", "LOG"))
LOG_METHODS = frozenset(("debug", "info", "warning", "error", "critical", "exception", "log"))


def call_name(node):
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def static_keyed(node):
    """True for a container named in ``STATIC_KEYED`` (``mutants``, ``self.texts``, ``forms`` ...)."""
    return (isinstance(node, ast.Name) and node.id in STATIC_KEYED) or (
        isinstance(node, ast.Attribute) and node.attr in STATIC_KEYED) or (
        isinstance(node, ast.Call) and call_name(node) in STATIC_KEYED)


def is_safe_call(name):
    return name in TAINT_SAFE_CALLS or name.endswith(TAINT_SAFE_SUFFIXES)


class TaintScan:
    """Taint analysis of one module source (r23 F41-a): which ``assert*`` calls receive an argument derived from a loaded
    workflow or pin value without a wrapper.  Names bound from the loaders, from any helper that returns them, through
    assignments, containers, comprehensions and helper parameters are tainted; a call to a wrapper (``opaque``, ``len``,
    a ``*_label`` or ``*_problems`` function, a comparison that yields a bool) clears it.  ``follow_helpers=False`` is the
    mutant that stops at helper boundaries."""

    def __init__(self, source, follow_helpers=True):
        self.tree = ast.parse(source)
        self.follow = follow_helpers
        self.functions = {n.name: n for n in ast.walk(self.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.params = {name: set() for name in self.functions}
        self.returns = set()
        self.attrs = set()
        self.flagged = set()
        self.closure = {}       # function name -> the enclosing scope's live environment (a closure sees later binds too)
        self.lambdas = {}       # name -> (Lambda node, environment at the assignment): a local lambda is a helper too
        self.aliases = {}       # name -> the assert or echo method it was bound to (``eq = self.assertEqual``)
        self.leaked_public = set()  # r24 sec F5: a PUBLIC_NAMES name that was ever assigned or passed a tainted value

    def tainted(self, node, env):
        t = self.tainted
        if node is None or isinstance(node, (ast.Constant, ast.Compare)):
            return False
        if isinstance(node, ast.Lambda):
            if any(t(default, env) for default in [*node.args.defaults, *node.args.kw_defaults] if default is not None):
                return True
            hidden = {a.arg for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]}
            return t(node.body, set(env) - hidden)  # r25 sec S2: ``[lambda: body]`` yields author text when called
        if isinstance(node, ast.Name):
            return node.id in env and (node.id not in PUBLIC_NAMES or node.id in self.leaked_public)
        if isinstance(node, ast.Attribute):
            if node.attr in TAINT_ATTRS:
                return True
            return (node.attr in self.attrs and (node.attr not in PUBLIC_NAMES or node.attr in self.leaked_public)) \
                or t(node.value, env)
        if isinstance(node, ast.UnaryOp):
            return False if isinstance(node.op, ast.Not) else t(node.operand, env)
        if isinstance(node, ast.Call):
            return self.call_tainted(node, env)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            inner = set(env)
            for gen in node.generators:
                if t(gen.iter, inner):
                    self.bind_iter(gen.target, gen.iter, inner)
            parts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            return any(t(part, inner) for part in parts)
        return any(t(child, env) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr))

    def call_tainted(self, node, env):
        name = call_name(node)
        if is_safe_call(name):
            return False
        args = [*node.args, *(kw.value for kw in node.keywords)]
        if name in TAINT_SOURCES or name.endswith(TAINT_PROBLEM_SUFFIXES) or name in ("url_leaks", "first_difference", "where_differs"):
            return True
        base = node.func.value if isinstance(node.func, ast.Attribute) else None
        lam = self.lambda_of(node)
        if lam is not None:
            return self.lambda_result(lam, node, env)
        if isinstance(node.func, ast.Name) and node.func.id in env:
            return True  # a callable bound from tainted material (``functools.partial(f, text)``) yields it
        if isinstance(node.func, (ast.Subscript, ast.Call)) and self.tainted(node.func, env):
            return True  # r25 sec S2: ``fs[0]()`` where the container holds a tainted callable
        if self.follow and name in self.functions:
            self.pass_params(self.functions[name], node, env)
            return name in self.returns
        return any(self.tainted(a, env) for a in args) or (base is not None and self.tainted(base, env))

    def lambda_of(self, node):
        """``(Lambda, defining environment)`` of the callee of ``node`` when it is a local lambda, called by name or inline."""
        if isinstance(node.func, ast.Lambda):
            return node.func, None
        if isinstance(node.func, ast.Name) and node.func.id in self.lambdas:
            return self.lambdas[node.func.id]
        return None

    def lambda_result(self, lam, node, env):
        """Whether calling the lambda with the arguments of ``node`` yields tainted material."""
        lambda_node, inner = self.lambda_env(lam, node, env)
        return self.tainted(lambda_node.body, inner)

    def lambda_calls(self, lam, node, env):
        """Visit every call inside the lambda body as it runs with the arguments of ``node`` (an assert in it sees them)."""
        lambda_node, inner = self.lambda_env(lam, node, env)
        for child in ast.walk(lambda_node.body):
            if isinstance(child, ast.Call):
                self.visit_call(child, inner, False)

    def lambda_env(self, lam, node, env):
        lambda_node, defined = lam
        names = [a.arg for a in lambda_node.args.args]
        inner = (set(env if defined is None else defined) | set(env)) - set(names)  # a parameter hides an outer name
        for position, arg in enumerate(node.args):
            if self.tainted(arg, env):
                if position < len(names):
                    inner.add(names[position])
                elif lambda_node.args.vararg is not None:
                    inner.add(lambda_node.args.vararg.arg)
        for kw in node.keywords:
            if self.tainted(kw.value, env):
                inner.add(kw.arg if kw.arg in names else getattr(lambda_node.args.kwarg, "arg", kw.arg))
        supplied = {kw.arg for kw in node.keywords}
        positional = [a.arg for a in [*lambda_node.args.posonlyargs, *lambda_node.args.args]]
        defaulted = list(zip(positional[len(positional) - len(lambda_node.args.defaults):], lambda_node.args.defaults))
        defaulted += [(a.arg, d) for a, d in zip(lambda_node.args.kwonlyargs, lambda_node.args.kw_defaults) if d is not None]
        for position, (name, default) in enumerate(defaulted):
            given = name in supplied or (name in positional and positional.index(name) < len(node.args))
            if not given and self.tainted(default, env):
                inner.add(name)  # r25 sec S2: ``lambda v=body: v`` called bare
        return lambda_node, inner

    def pass_params(self, func, node, env):
        names = [a.arg for a in [*func.args.posonlyargs, *func.args.args] if a.arg not in ("self", "cls")]
        known = {*names, *(a.arg for a in func.args.kwonlyargs)}
        for position, arg in enumerate(node.args):
            if isinstance(arg, ast.Starred):
                arg = arg.value
            if self.tainted(arg, env):
                if position < len(names):
                    self.add_param(func.name, names[position])
                elif func.args.vararg is not None:
                    self.add_param(func.name, func.args.vararg.arg)
        for kw in node.keywords:
            if self.tainted(kw.value, env):
                if kw.arg in known:
                    self.add_param(func.name, kw.arg)
                elif func.args.kwarg is not None:
                    self.add_param(func.name, func.args.kwarg.arg)

    def add_param(self, function, name):
        self.params[function].add(name)
        if name in PUBLIC_NAMES:
            self.leaked_public.add(name)

    def bind(self, target, env):
        for sub in ast.walk(target):
            if isinstance(sub, ast.Name):
                if sub.id not in ("self", "cls"):  # ``cls.text = tainted`` taints the attribute, never ``cls`` itself
                    env.add(sub.id)
            elif isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id in ("self", "cls"):
                self.attrs.add(sub.attr)

    def bind_iter(self, target, iterable, env):
        """Bind a loop target; the position of ``enumerate(...)`` is an int, never author text."""
        if isinstance(iterable, ast.Call) and isinstance(target, ast.Tuple) and len(target.elts) == 2 and (
                call_name(iterable) == "enumerate"
                or (call_name(iterable) == "items" and static_keyed(iterable.func.value))):
            self.bind(target.elts[1], env)
        else:
            self.bind(target, env)

    def assign(self, node, env):
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        pairs = [(target, value) for target in targets]
        for target in targets:
            if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)) \
                    and len(target.elts) == len(value.elts):
                pairs += list(zip(target.elts, value.elts))  # r25 sec S2: ``eq, ne = self.assertEqual, self.assertNotEqual``
        for target, source in pairs:
            if isinstance(target, ast.Name):
                if isinstance(source, ast.Lambda):
                    self.lambdas[target.id] = (source, env)
                if self.echo_method(source) is not None:
                    self.aliases[target.id] = self.echo_method(source)
        if not self.tainted(value, env):
            return
        for target in targets:
            if isinstance(target, ast.Name) and target.id in PUBLIC_NAMES:
                self.leaked_public.add(target.id)  # r24 sec F5: a public name rebound to author text is author text
            if isinstance(target, ast.Attribute) and target.attr in PUBLIC_NAMES:
                self.leaked_public.add(target.attr)
            safe = TAINT_SAFE_POSITIONS.get(call_name(value), set()) if isinstance(value, ast.Call) else set()
            if safe and isinstance(target, ast.Tuple):
                for position, element in enumerate(target.elts):
                    if position not in safe:
                        self.bind(element, env)
            else:
                self.bind(target, env)

    def walk(self, body, env, scope):
        for stmt in body:
            for node in ast.walk(stmt):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not stmt:
                    pass
            self.statement(stmt, env, scope)

    def echo_method(self, node):
        """The assert or echo method an expression denotes: ``self.assertX``, ``getattr(self, "assertX")`` (any non-constant
        name counts), a name bound to one, or ``functools.partial`` of one; None for anything else."""
        if isinstance(node, ast.Attribute):
            return node.attr if node.attr.startswith(ASSERT_PREFIX) or node.attr in ECHO_CALLS else None
        if isinstance(node, ast.Name):
            return node.id if node.id in PRINT_CALLS else self.aliases.get(node.id)  # ``partial(print, text)()`` (r25 code C4)
        if isinstance(node, ast.Call):
            if call_name(node) == "getattr" and len(node.args) >= 2:
                name = node.args[1]
                if isinstance(name, ast.Constant) and isinstance(name.value, str):
                    return name.value if name.value.startswith(ASSERT_PREFIX) or name.value in ECHO_CALLS else None
                return "getattr"
            if call_name(node) == "partial" and node.args:
                return self.echo_method(node.args[0])
        return None

    def operands_tainted(self, test, env):
        """A bare ``assert``: pytest prints the operands of a failing comparison, so each operand counts."""
        if isinstance(test, ast.Compare):
            return any(self.tainted(part, env) for part in [test.left, *test.comparators])
        if isinstance(test, ast.BoolOp):
            return any(self.operands_tainted(part, env) for part in test.values)
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.operands_tainted(test.operand, env)
        return self.tainted(test, env)

    def statement(self, stmt, env, scope):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.closure[stmt.name] = env  # the function sees this scope as it stands when it is called
            positional = [*stmt.args.posonlyargs, *stmt.args.args]
            for arg, default in zip(positional[len(positional) - len(stmt.args.defaults):], stmt.args.defaults):
                if self.tainted(default, env):
                    self.add_param(stmt.name, arg.arg)
            for arg, default in zip(stmt.args.kwonlyargs, stmt.args.kw_defaults):
                if default is not None and self.tainted(default, env):
                    self.add_param(stmt.name, arg.arg)
            return  # analysed on its own, with its own environment
        if isinstance(stmt, ast.Raise) and (self.tainted(stmt.exc, env) or self.tainted(stmt.cause, env)):
            self.flagged.add(stmt.lineno)  # r24 sec F5, r25 sec S2: an exception (or its cause) built from author text prints it
        if isinstance(stmt, ast.Assert) and (self.operands_tainted(stmt.test, env) or self.tainted(stmt.msg, env)):
            self.flagged.add(stmt.lineno)
        if isinstance(stmt, ast.ClassDef):
            self.walk(stmt.body, set(env), scope)
            return
        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and getattr(stmt, "value", None) is not None:
            self.assign(stmt, env)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            if self.tainted(stmt.iter, env):
                self.bind_iter(stmt.target, stmt.iter, env)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is not None and self.tainted(item.context_expr, env):
                    self.bind(item.optional_vars, env)
        elif isinstance(stmt, ast.Return):
            if scope is not None and self.tainted(stmt.value, env):
                self.returns.add(scope)
        # calls anywhere in the statement: asserts, method calls that taint their receiver, helper parameters
        for node in ast.walk(stmt):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not stmt:
                continue
            if isinstance(node, ast.Call):
                self.visit_call(node, env)
        for block in (getattr(stmt, "body", None), getattr(stmt, "orelse", None), getattr(stmt, "finalbody", None)):
            for child in block if isinstance(block, list) and not isinstance(stmt, ast.ClassDef) else ():
                self.statement(child, env, scope)
        for handler in getattr(stmt, "handlers", []) or []:
            for child in handler.body:
                self.statement(child, env, scope)

    def echo_target(self, node):
        """The assert, echo, print or logging method a call invokes (see ``echo_method``), else None."""
        func = node.func
        if isinstance(func, ast.Name) and func.id in PRINT_CALLS:
            return func.id
        if isinstance(func, ast.Attribute):
            if func.attr in ("write", "writelines") and isinstance(func.value, ast.Attribute) \
                    and func.value.attr in ("stdout", "stderr"):
                return func.attr  # r25 sec S2 and code C4: ``sys.stdout.write(text)`` echoes like print
            if func.attr in PRINT_CALLS or (func.attr in LOG_METHODS and isinstance(func.value, ast.Name)
                                            and func.value.id in LOG_BASES):
                return func.attr
            return self.echo_method(func)
        return self.echo_method(func)

    def visit_call(self, node, env, follow_lambda=True):
        name = call_name(node)
        lam = self.lambda_of(node) if follow_lambda else None
        if lam is not None:
            self.lambda_calls(lam, node, env)
        if name in WRAPPED_ASSERTS:
            # the wrapper compares raw operands and reports only its label: the label argument must not be tainted
            label = node.args[3] if len(node.args) > 3 else next((kw.value for kw in node.keywords if kw.arg == "label"), None)
            if label is not None and self.tainted(label, env):
                self.flagged.add(node.lineno)
        elif self.echo_target(node) is not None:
            target = self.echo_target(node)
            args = [*node.args, *(kw.value for kw in node.keywords)]
            if isinstance(node.func, ast.Call) and call_name(node.func) == "partial":
                args += [*node.func.args[1:], *(kw.value for kw in node.func.keywords)]
            if target == "assertTrue" and args and isinstance(node.func, ast.Attribute):
                args = args[1:]  # a failing assertTrue prints a FALSY first operand: empty text, never a value
            if any(self.tainted(a, env) for a in args):
                self.flagged.add(node.lineno)
        elif name in ("append", "extend", "add", "update", "insert", "setdefault", "add_note") and isinstance(node.func, ast.Attribute) \
                and isinstance(node.func.value, ast.Name):
            if any(self.tainted(a, env) for a in node.args):
                env.add(node.func.value.id)
        elif self.follow and name in self.functions:
            self.pass_params(self.functions[name], node, env)

    def state(self):
        return (sorted(self.returns), sorted(self.attrs), {k: sorted(v) for k, v in self.params.items()},
                sorted(self.leaked_public))

    def run(self):
        for _ in range(6):
            before = self.state()
            self.flagged = set()
            self.walk(self.tree.body, set(), None)
            for name, func in self.functions.items():
                env = set(self.params[name]) | set(self.closure.get(name, ()))
                for _pass in range(2):
                    self.walk(func.body, env, name)
            after = self.state()
            if before == after:
                break
        return sorted(self.flagged)


def tainted_assert_lines(source, follow_helpers=True):
    """Sorted line numbers of the ``assert*`` calls in ``source`` with an unwrapped tainted argument."""
    return TaintScan(source, follow_helpers).run()


# ---- r24 sec F6: no path to the raw text outside the wrapper class ----
OPAQUE_PRIVATE = frozenset("".join(parts) for parts in (("_", "raw"), ("_", "RAW"), ("__get", "state__"), ("_regis", "try"), ("__glob", "als__")))  # spelled in parts
OPAQUE_NAMESPACES = ("vars", "globals", "locals")


def folded_string(node):
    """The string a constant, or a ``+`` chain of constants, spells; None for anything else (r25 code C5: ``'_' + 'RAW'``)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = folded_string(node.left), folded_string(node.right)
        return None if left is None or right is None else left + right
    return None


def opaque_escape_lines(source, allowed=("Opaque",)):
    """Sorted line numbers in ``source`` that reach the raw text of an ``Opaque`` by a path other than ``Opaque.raw()``:
    an attribute ``._raw`` or ``.__getstate__``, a read of the registry name ``_RAW``, a string constant that names one of
    them (also when built from constants joined with ``+``), a ``from m import _RAW``, a subscript of ``vars()`` /
    ``globals()`` / ``locals()`` / ``__dict__`` whose key is not a constant string, the finalizer registry (``_registry``)
    and a function's ``__globals__``, or ``getattr``/``hasattr``/``setattr``/``delattr`` with a name that is not a constant
    string.  Code inside a class or function named in ``allowed`` (the wrapper itself; the probes that try every path) is
    exempt."""
    tree = ast.parse(source)
    found = set()

    def visit(node, exempt):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in allowed:
            exempt = True
        if not exempt:
            if isinstance(node, ast.Attribute) and node.attr in OPAQUE_PRIVATE:
                found.add(node.lineno)
            elif isinstance(node, ast.Name) and node.id in OPAQUE_PRIVATE and not isinstance(node.ctx, ast.Store):
                found.add(node.lineno)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in OPAQUE_PRIVATE:
                found.add(node.lineno)
            elif isinstance(node, ast.BinOp) and folded_string(node) in OPAQUE_PRIVATE:
                found.add(node.lineno)
            elif isinstance(node, ast.ImportFrom) and any(alias.name in OPAQUE_PRIVATE for alias in node.names):
                found.add(node.lineno)
            elif isinstance(node, ast.Subscript) and (
                    (isinstance(node.value, ast.Call) and call_name(node.value) in OPAQUE_NAMESPACES)
                    or (isinstance(node.value, ast.Attribute) and node.value.attr == "__dict__")) \
                    and not (isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str)):
                found.add(node.lineno)
            elif isinstance(node, ast.Call) and call_name(node) in ("getattr", "hasattr", "setattr", "delattr") \
                    and len(node.args) >= 2 and not (isinstance(node.args[1], ast.Constant)
                                                     and isinstance(node.args[1].value, str)):
                found.add(node.lineno)
        for child in ast.iter_child_nodes(node):
            visit(child, exempt)

    visit(tree, False)
    return sorted(found)


def raw_unwrap_lines(source, allowed=()):
    """Sorted line numbers in ``source`` that unwrap an ``Opaque``: a ``.raw()`` call, or ``getattr(x, "raw")`` (also with the
    name built from constants), outside the functions named in ``allowed`` (r25 code C5)."""
    tree = ast.parse(source)
    found = set()

    def visit(node, exempt):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in allowed:
            exempt = True
        if not exempt and isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "raw":
                found.add(node.lineno)
            elif call_name(node) in ("getattr", "hasattr") and len(node.args) >= 2 and folded_string(node.args[1]) == "raw":
                found.add(node.lineno)
        for child in ast.iter_child_nodes(node):
            visit(child, exempt)

    visit(tree, False)
    return sorted(found)


class TestOpaqueIsFailClosed8187R23(unittest.TestCase):
    """r23: the wrapper prints a positional label and a length through every string protocol, never the text."""

    SECRET = "CANARY-0123456789abcdef01234567"

    def test_every_string_protocol_prints_the_label_and_the_length_only(self):
        value = ty.Opaque(self.SECRET, "key[3]")
        shown = "key[3] len=%d" % len(self.SECRET)
        self.assertTrue(str(value) == shown and repr(value) == shown and format(value) == shown)
        self.assertTrue(format(value, ">40") == shown and format(value, "x") == shown)
        self.assertTrue(f"{value}" == shown and f"{value!r}" == shown and f"{value:>40}" == shown)
        self.assertTrue("%s" % value == shown and "%r" % value == shown and "{}".format(value) == shown)
        self.assertTrue(bytes(value) == shown.encode("ascii") and str([value]) == "[" + shown + "]")
        self.assertEqual(json.dumps(str(value)), json.dumps(shown))
        self.assertTrue(self.SECRET not in repr({value: value}) and self.SECRET not in str((value, value)))

    def test_a_label_shaped_author_text_prints_as_its_own_label_and_is_told_apart_by_equality_only(self):
        shaped = ty.Opaque("step[3]", "step[0]")
        self.assertEqual(str(shaped), "step[0] len=7")
        self.assertTrue(shaped == ty.Opaque("step[3]", "key[9]") and shaped != ty.Opaque("step[4]", "step[0]"))

    def test_equality_and_hash_compare_the_raw_text_and_a_plain_string_never_equals_the_wrapper(self):
        a, b, c = ty.Opaque("x", "key[0]"), ty.Opaque("x", "key[1]"), ty.Opaque("y", "key[0]")
        self.assertTrue(a == b and hash(a) == hash(b) and a != c and len({a, b, c}) == 2)
        self.assertTrue(a != "x" and "x" != a and a != None)  # noqa: E711  (the comparison itself is the check)
        self.assertTrue(ty.same(a, b) and ty.same(a, "x") and ty.same("x", a) and not ty.same(a, c))

    def test_a_label_must_be_a_positional_label(self):
        for bad in ("hunter2", "key", "key[x]", "key[1] len=4", "key[1]\n", "pwd[1]", ""):
            with self.subTest(label_length=len(bad)):
                with self.assertRaises(ValueError):
                    ty.Opaque("x", bad)

    def test_length_of_a_value_without_a_length_is_zero_and_copies_do_not_leak(self):
        import copy
        import pickle
        self.assertTrue(str(ty.Opaque(None, "key[0]")) == "key[0] len=0" and str(ty.Opaque(12345, "key[0]")) == "key[0] len=0")
        value = ty.Opaque(self.SECRET, "key[2]")
        self.assertTrue(copy.copy(value) is value and copy.deepcopy(value) is value)
        revived = pickle.loads(pickle.dumps(value))
        self.assertTrue(str(revived) == "key[2] len=0" and self.SECRET.encode() not in pickle.dumps(value))

    def test_the_label_helpers_return_wrappers_with_positions(self):
        jobs = {"b": 1, "a": 2}
        self.assertTrue(str(ty.job_label("a", jobs)) == "job[0] len=1" and str(ty.job_label("zzz", jobs)) == "job[?] len=3")
        self.assertEqual(str(ty.name_label("b", ["a", "c"])), "key[1] len=1")
        self.assertEqual(str(ty.key_label("hunter2", 4)), "key[4] len=7")
        self.assertEqual(str(ty.step_label({"name": "n" * 9}, 2)), "step[2] len=9")
        self.assertEqual(str(ty.step_label({"run": "x"}, 5)), "step[5] len=0")

    def test_raw_is_called_only_inside_same(self):
        """The places that unwrap are the bool helper ``ty.same`` and ``Opaque.__eq__`` / ``__hash__`` (both return a bool or
        an int, never text); no other code (checker, tests) calls ``.raw()``."""
        for path in (Path(ty.__file__), Path(__file__)):
            allowed = ("same", "__eq__", "__hash__") if path.name == "tier_yaml_8187.py" else ()
            with self.subTest(file=path.name):
                self.assertEqual(raw_unwrap_lines(path.read_text(encoding="utf-8"), allowed=allowed), [])


class TestNoRoutedSiteCanEchoAuthorText8187R23(unittest.TestCase):
    """r23 canary gate (3-agent vote (6def5ab6)): every field of the workflows and of the pins is a unique marker, wrapped in
    every probe shape of rounds 17 to 22; no marker reaches stdout, stderr, a log record, a warning, an exception or a
    returned problem line, on the pass and the fail path of both views."""

    @classmethod
    def setUpClass(cls):
        cls.run_ = canary_run(sys.modules[__name__])

    def test_no_marker_reaches_any_channel(self):
        run = self.run_
        self.assertEqual(len(run.leaks), 0, "%d marker leaks" % len(run.leaks))

    def test_every_probe_shape_leaks_zero_markers(self):
        for shape in CANARY_SHAPES:
            with self.subTest(shape=shape):
                self.assertIs(self.run_.by_shape.get(shape, 0) == 0, True)

    def test_no_scenario_raised_and_pass_and_fail_paths_behaved(self):
        run = self.run_
        self.assertEqual(run.errors, [], "%d scenarios raised: %s" % (len(run.errors), sorted({e[2] for e in run.errors})))
        self.assertEqual(run.unexpected, [], "%d pass-path scenarios returned problems: %s" % (
            len(run.unexpected), sorted({(shape, scenario) for shape, scenario in run.unexpected})[:6]))
        self.assertEqual(run.silent, [], "%d fail-path scenarios returned none: %s" % (
            len(run.silent), sorted({scenario for _shape, scenario in run.silent})[:8]))

    def test_the_fail_path_was_forced_in_both_views_for_every_shape(self):
        run = self.run_
        self.assertTrue(CANARY_FORCE_FAIL, "fail-path forcing is switched off")
        shapes = len(CANARY_SHAPES)
        self.assertGreaterEqual(run.fail_calls, shapes * 60)
        self.assertGreaterEqual(run.pass_calls, shapes * 8)
        self.assertGreaterEqual(run.problem_lines, shapes * 100)
        self.assertGreaterEqual(run.counter, shapes * 200)

    def test_every_label_form_appeared(self):
        """Per-site driving is proven by ``TestEveryRoutedSiteIsDriven8187R24`` (one source mutant per routed site)."""
        run = self.run_
        forms = {re.sub(r"\[.*", "", form) for form in run.label_forms}
        self.assertLessEqual({"job", "step", "key"}, forms, "label forms seen: %s" % sorted(forms))
        # a job id the layout reader cannot read plainly has no pins of its own (that refusal is itself a fail path the
        # scenarios drive against the real pins); the shapes whose ids stay plain must all have run on their own pins
        self.assertLessEqual(len(run.skipped), len(CANARY_SHAPES) * 6, "%d self-pin scenarios were skipped" % len(run.skipped))
        self.assertEqual([s for s in run.skipped if s[0] in ("plain", "key-suffix")], [], "a plain-id self-pin scenario was skipped")


class TestNoAssertCanEchoAuthorText8187R23(unittest.TestCase):
    """r23 AST taint gate (3-agent vote (6def5ab6)): no ``assert*`` call, ``subTest`` parameter or ``fail`` in this module
    receives a value derived from a workflow or a pin without a wrapper."""

    HELPER_AND_LIST = (
        "import unittest\n"
        "def load(paths):\n"
        "    return [p.read_text() for p in paths]\n"
        "def first(rows):\n"
        "    return rows[0]\n"
        "class T(unittest.TestCase):\n"
        "    def test(self):\n"
        "        row = first(load(['a']))\n"
        "        self.assertEqual([row], ['x'])\n")
    CLEAN = (
        "import unittest\n"
        "class T(unittest.TestCase):\n"
        "    def test(self):\n"
        "        text = path.read_text()\n"
        "        data = load_strict(text)\n"
        "        self.assertTrue(text == 'x', 'differs')\n"
        "        self.assertTrue(len(text) == 3 and ty.same(data, {}))\n"
        "        self.assertEqual(ty.opaque(text, 'key[0]'), ty.opaque('x', 'key[0]'))\n"
        "        assert_same(self, data, {}, 'the data')\n"
        "        self.assertTrue(data)\n"
        "        for position, item in enumerate(data):\n"
        "            self.assertEqual(position, 0)\n")
    DIRTY = {
        "direct": "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        t = p.read_text()\n        self.assertEqual(t, 'x')\n",
        "not-in": "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        t = p.read_text()\n        self.assertNotIn('x', t)\n",
        "message": "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        t = p.read_text()\n        self.assertTrue(ok, f'{t}')\n",
        "falsy-assert": "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        t = p.read_text()\n        self.assertFalse(t)\n",
        "container": "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        t = p.read_text()\n        rows = [t]\n        self.assertEqual(rows, [])\n",
        "comprehension": "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        t = p.read_text()\n        self.assertIn('a', [x for x in t.split()])\n",
        "subtest": "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        d = load_strict(p.read_text())\n        for name in d['jobs']:\n            with self.subTest(job=name):\n                pass\n",
        "problem-lines": "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        self.assertEqual(tier_pin_problems(w, t, p), [])\n",
        "wrapped-label": "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        t = p.read_text()\n        assert_same(self, t, 'x', f'differs {t}')\n",
    }

    def test_no_assert_in_this_module_receives_a_raw_workflow_or_pin_value(self):
        flagged = tainted_assert_lines(Path(__file__).read_text(encoding="utf-8"))
        self.assertEqual(flagged, [], "%d asserts receive an unwrapped value; lines %s" % (len(flagged), flagged[:12]))

    def test_the_scanner_flags_each_echo_shape_and_clears_the_wrapped_forms(self):
        for name, source in self.DIRTY.items():
            with self.subTest(shape=name):
                self.assertEqual(len(tainted_assert_lines(source)), 1)
        self.assertEqual(tainted_assert_lines(self.CLEAN), [])

    def test_the_scanner_follows_helpers_so_a_raw_compare_restored_through_a_helper_and_a_list_is_red(self):
        self.assertEqual(len(tainted_assert_lines(self.HELPER_AND_LIST)), 1)
        self.assertEqual(tainted_assert_lines(self.HELPER_AND_LIST, follow_helpers=False), [], "the stop-at-the-helper scanner is the mutant this gate exists to catch")

    def test_the_default_scan_follows_helpers(self):
        self.assertTrue(TaintScan("x = 1").follow)

F40E_BYTES = 1 << 20
F40E_RATIO_MAX = 3.0
F40E_CAP_SECONDS = 20.0


def f40e_big(shape):
    """A value of about 1 MiB in ``shape`` (a ``CANARY_SHAPES`` entry or the identity for plain letters)."""
    unit = len(shape("a" * 64)) / 64.0
    return shape("a" * int(F40E_BYTES / unit))


def f40e_edit(text, step, value):
    """``text`` with the step name, one env value and one run line of ``step`` replaced by ``value``."""
    out = text.replace("- name: " + step[1], "- name: " + json.dumps(value, ensure_ascii=False), 1)
    out = inject_run_line(out, step, "echo " + value)
    lines = out.split("\n")
    at = next((i for i in range(step[3], len(lines)) if lines[i].strip() == "env:"), None)
    if at is None:
        raise ValueError("the step has no env block")
    pad = " " * (indent_of(lines[at]) + 2)
    return "\n".join(lines[:at + 1] + [pad + "X_BIG: " + json.dumps(value, ensure_ascii=False)] + lines[at + 1:])


class TestExportCallScanIsLinear8187R23(unittest.TestCase):
    """sec F40-e (r23): ``EXPORT_CALL`` is a linear scan equal to the old regex on the probe cases.  The whole-checker
    time gate is ``TestCheckerTimeIsLinear8187R24`` (a linearity ratio plus a cap, not a host-speed budget)."""

    def test_the_export_call_scan_is_linear_and_matches_the_regex(self):
        old = re.compile(r"tier_credential\.py\s+github-env\b.*--url-file")
        cases = (
            "", "tier_credential.py github-env --url-file x", "tier_credential.py github-env\n--url-file",
            "tier_credential.py github-env a\nb --url-file", "tier_credential.py   github-envx --url-file",
            "tier_credential.py github-env tier_credential.py github-env --url-file",
            "tier_credential.py github-env tier_credential.py github-env\n--url-file tier_credential.py github-env",
            "tier_credential.py\ngithub-env --url-file", "x --url-file tier_credential.py github-env")
        for case in cases:
            self.assertEqual(bool(old.search(case)), bool(ty.EXPORT_CALL.search(case)), "a case differs")
        unit = "tier_credential.py github-env "
        start = time.perf_counter()
        self.assertTrue(not ty.EXPORT_CALL.search(unit * (F40E_BYTES // len(unit))))
        self.assertTrue(ty.EXPORT_CALL.search(unit * (F40E_BYTES // len(unit)) + "--url-file"))
        self.assertLess(time.perf_counter() - start, 1.0)




# ---- r24 (code review round 23, F42a-g; 3-agent vote (6def5ab6), option B stands) ----
# decision: remove printable and fail closed on every routed site over extending the deny-list because a deny-list fails
# open on every shape nobody listed and did so in rounds 20, 21 and 22 (3-agent vote (6def5ab6), 3-0)
# decision: an id-keyed private registry over a slot because every slot or dict attribute is one getattr away from a message
# decision: a linearity ratio plus a 20 s cap over a tight absolute budget because the finding is super-linear regex
# behaviour, not host speed

TY_PATH = Path(ty.__file__)
THIS_PATH = Path(__file__)
ROUTED_HELPERS = frozenset(("key_label", "name_label", "job_label", "step_label", "Opaque", "opaque"))


def routed_sites(source, in_test_file):
    """``{key: (kind, lineno, col, helper)}`` for every call of a label helper in ``source`` whose first argument is not a
    constant (a constant has nothing to leak).  In the checker module that is every call; in this file it is the checker part
    only (``load_job_pins`` up to the first test class), never a test class, a canary scenario or an assert helper."""
    tree = ast.parse(source)
    kind = "test" if in_test_file else "ty"
    low, high = 0, 10 ** 9
    if in_test_file:
        low = next(n.lineno for n in tree.body if isinstance(n, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "JOB_PINS_FILE" for target in n.targets))
        high = next(n.lineno for n in tree.body if isinstance(n, ast.ClassDef) and n.lineno > low)
    sites = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and call_name(node) in ROUTED_HELPERS and node.args):
            continue
        if isinstance(node.args[0], ast.Constant) or not low <= node.lineno < high:
            continue
        if kind == "ty" and isinstance(node.func, ast.Attribute):
            continue
        if kind == "test" and call_name(node) == "step_label" and isinstance(node.func, ast.Name):
            continue  # the module-local tuple wrapper: its own label comes from the routed ``ty.step_label`` inside it
        sites[(kind, node.lineno, node.col_offset)] = call_name(node)
    ordered, seen = {}, {}
    for (site_kind, lineno, col), helper in sorted(sites.items(), key=lambda item: item[0][1:]):
        seen[lineno] = seen.get(lineno, 0) + 1
        suffix = "" if seen[lineno] == 1 else "#%d" % seen[lineno]
        ordered["%s:%d%s %s" % (site_kind, lineno, suffix, helper)] = (site_kind, lineno, col, helper)
    return ordered


def splice_call(source, node):
    """``source`` with the call ``node`` replaced by its first argument: the one-site mutant (byte offsets, as ``ast`` counts)."""
    data = source.encode("utf-8")
    starts = [0] + [m.end() for m in re.finditer(b"\n", data)]
    begin = starts[node.lineno - 1] + node.col_offset
    end = starts[node.end_lineno - 1] + node.end_col_offset
    argument = ast.get_source_segment(source, node.args[0])
    return (data[:begin] + ("(" + argument + ")").encode("utf-8") + data[end:]).decode("utf-8")


def load_variant(ty_source, test_source):
    """A fresh copy of this module executed against a (possibly mutated) checker module; ``sys.modules`` is restored."""
    saved = {name: sys.modules.get(name) for name in ("tier_yaml_8187", "canary_variant_6181")}
    try:
        variant_ty = types.ModuleType("tier_yaml_8187")
        variant_ty.__file__ = str(TY_PATH)
        sys.modules["tier_yaml_8187"] = variant_ty
        exec(compile(ty_source, str(TY_PATH), "exec"), variant_ty.__dict__)
        variant = types.ModuleType("canary_variant_6181")
        variant.__file__ = str(THIS_PATH)
        sys.modules["canary_variant_6181"] = variant
        exec(compile(test_source, str(THIS_PATH), "exec"), variant.__dict__)
        return variant
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def site_mutant_leaks(task):
    """Leaks the plain-shape canary reports when the one routed site ``task`` hands its raw argument on (0 = a survivor)."""
    kind, lineno, col, _helper = task
    ty_source = TY_PATH.read_text(encoding="utf-8")
    test_source = THIS_PATH.read_text(encoding="utf-8")
    source = test_source if kind == "test" else ty_source
    node = next(n for n in ast.walk(ast.parse(source))
                if isinstance(n, ast.Call) and (n.lineno, n.col_offset) == (lineno, col))
    mutated = splice_call(source, node)
    variant = load_variant(ty_source if kind == "test" else mutated, mutated if kind == "test" else test_source)
    return len(canary_run(variant, {"plain": CANARY_SHAPES["plain"]}).leaks)


def run_site_mutants(tasks):
    """``site_mutant_leaks`` over ``tasks``, forked across the cores when the platform can fork, in order otherwise."""
    try:
        context = multiprocessing.get_context("fork")
        with concurrent.futures.ProcessPoolExecutor(max_workers=min(8, os.cpu_count() or 1), mp_context=context) as pool:
            return list(pool.map(site_mutant_leaks, tasks))
    except (ValueError, OSError, NotImplementedError):
        return [site_mutant_leaks(task) for task in tasks]


class TestEveryRoutedSiteIsDriven8187R24(unittest.TestCase):
    """r24 F42g (code r23): the canary has to reach EVERY routed site, not just most of them.  Each site is mutated alone (its
    helper call replaced by the bare argument) and the plain-shape canary runs on that variant; a site whose mutant leaves
    the canary green is a survivor.  This replaces the per-helper call count, which a single driven site satisfied."""

    SITES = None
    LEAKS = None

    @classmethod
    def setUpClass(cls):
        cls.SITES = {**routed_sites(TY_PATH.read_text(encoding="utf-8"), False),
                     **routed_sites(THIS_PATH.read_text(encoding="utf-8"), True)}
        cls.LEAKS = dict(zip(cls.SITES, run_site_mutants(list(cls.SITES.values()))))

    def test_the_enumeration_covers_both_files(self):
        kinds = {site[0] for site in self.SITES.values()}
        self.assertEqual(kinds, {"ty", "test"})
        self.assertGreaterEqual(len(self.SITES), 30)

    def test_each_routed_site_mutant_is_red(self):
        survivors = []
        for key in self.SITES:
            with self.subTest(site=key):
                if self.LEAKS[key] == 0:
                    survivors.append(key)
                self.assertGreater(self.LEAKS[key], 0)
        self.assertEqual(len(survivors), 0)


# ---- r24 F42a: the taint scanner, one mutant per echo shape ----
TAINT_HEAD = "import unittest, functools\nclass T(unittest.TestCase):\n    def test(self):\n        text = p.read_text()\n"
TAINT_SHAPES = {
    "control direct": TAINT_HEAD + "        self.assertEqual(text, 'x')\n",
    "helper + list": TestNoAssertCanEchoAuthorText8187R23.HELPER_AND_LIST,
    "dict comprehension": TAINT_HEAD + "        d = {k: v for k, v in enumerate(text.split())}\n        self.assertEqual(d, {})\n",
    "dict comprehension over items":
        TAINT_HEAD + "        d = {k: v for k, v in load_strict(text).items()}\n        self.assertEqual(d, {})\n",
    "lambda": TAINT_HEAD + "        f = lambda: text\n        self.assertEqual(f(), 'x')\n",
    "lambda param": TAINT_HEAD + "        f = lambda v: v\n        self.assertEqual(f(text), 'x')\n",
    "default argument": TAINT_HEAD + "        def g(v=text):\n            return v\n        self.assertEqual(g(), 'x')\n",
    "functools.partial": TAINT_HEAD + "        h = functools.partial(str.strip, text)\n        self.assertEqual(h(), 'x')\n",
    "closure": TAINT_HEAD + "        def inner():\n            return text\n        self.assertEqual(inner(), 'x')\n",
    "*args helper": "import unittest\ndef first(*rows):\n    return rows[0]\nclass T(unittest.TestCase):\n    def test(self):\n"
                    "        text = p.read_text()\n        self.assertEqual(first(text), 'x')\n",
    "**kwargs helper": "import unittest\ndef first(**rows):\n    return rows['a']\nclass T(unittest.TestCase):\n    def test(self):\n"
                       "        text = p.read_text()\n        self.assertEqual(first(a=text), 'x')\n",
    "msg= keyword": TAINT_HEAD + "        self.assertTrue(False, msg=text)\n",
    "assertRaises msg": TAINT_HEAD + "        with self.assertRaises(ValueError, msg=text):\n            pass\n",
    "raise AssertionError": TAINT_HEAD + "        raise AssertionError(text)\n",
    "bare assert statement": TAINT_HEAD + "        assert text == 'x', text\n",
    "subscript": TAINT_HEAD + "        self.assertEqual(text[0:5], 'x')\n",
    "f-string": TAINT_HEAD + "        self.assertEqual(f'{text}', 'x')\n",
    "walrus": TAINT_HEAD + "        self.assertEqual((y := text), 'x')\n",
    "tuple unpack swap": TAINT_HEAD + "        a, b = 'x', text\n        self.assertEqual(b, 'x')\n",
    "starred list": TAINT_HEAD + "        rows = [*text.split()]\n        self.assertEqual(rows, [])\n",
    "ternary": TAINT_HEAD + "        self.assertEqual(text if ok else '', 'x')\n",
    "global via module": TAINT_HEAD + "        global G\n        G = text\n        self.assertEqual(G, 'x')\n",
}


class TestTaintScanFlagsEveryEchoShape8187R24(unittest.TestCase):
    """r24 F42a: the reviewer's 22-shape corpus is this test's own mutant table; the scanner has to be red on all 22
    (at r23 it missed the lambda, default-argument, partial, closure, *args, **kwargs, raise and bare-assert shapes)."""

    def test_the_corpus_has_the_22_shapes(self):
        self.assertEqual(len(TAINT_SHAPES), 22)

    def test_each_shape_is_flagged(self):
        survivors = []
        for name, source in TAINT_SHAPES.items():
            with self.subTest(shape=name):
                flagged = tainted_assert_lines(source)
                if not flagged:
                    survivors.append(name)
                self.assertGreater(len(flagged), 0)
        self.assertEqual(survivors, [])

    def test_the_wrapped_forms_of_the_new_shapes_stay_clean(self):
        clean = (
            TAINT_HEAD + "        f = lambda v: len(v)\n        self.assertEqual(f(text), 3)\n",
            TAINT_HEAD + "        def g(v=3):\n            return v\n        self.assertEqual(g(), 3)\n",
            TAINT_HEAD + "        def inner():\n            return len(text)\n        self.assertEqual(inner(), 3)\n",
            TAINT_HEAD + "        assert len(text) == 3, 'length'\n",
            TAINT_HEAD + "        raise AssertionError('the file changed')\n",
            "import unittest\ndef first(*rows):\n    return len(rows)\nclass T(unittest.TestCase):\n    def test(self):\n"
            "        text = p.read_text()\n        self.assertEqual(first(text), 1)\n")
        for position, source in enumerate(clean):
            with self.subTest(shape=position):
                self.assertEqual(tainted_assert_lines(source), [])


# ---- r24 F42b: every way to pull the raw text out of an Opaque ----
PROBE_MARK = "MKfeedfacecafe0123456789ab"


def probe_text(fn):
    try:
        out = fn()
        return out if isinstance(out, str) else repr(out)
    except Exception as exc:  # noqa: BLE001  (the exception text is a channel under test)
        return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def opaque_probe_paths(o, p, case):
    """The 63 channels: the 62 of the r23 review's ``probe_opaque.py`` (46 value paths and 16 failing assertions) plus the
    ``weakref.finalize`` registry walk of the r24 code review."""
    paths = {
        "str": lambda: str(o), "repr": lambda: repr(o), "format spec": lambda: format(o, "!<99"), "fstring !a": lambda: f"{o!a}",
        "percent %s %r %a": lambda: "%s %r %a" % (o, o, o), "percent %d": lambda: "%d" % o, "bytes": lambda: bytes(o),
        "__dict__": lambda: o.__dict__, "vars": lambda: vars(o), "getattr _raw (slot read)": lambda: getattr(o, "_raw"),
        "__getstate__": lambda: o.__getstate__(), "__reduce_ex__(2)": lambda: o.__reduce_ex__(2),
        "__reduce_ex__(4)": lambda: o.__reduce_ex__(4), "pickle p0": lambda: pickle.dumps(o, 0),
        "pickle p5": lambda: pickle.dumps(o, 5), "copy": lambda: repr(copy.copy(o)), "deepcopy": lambda: repr(copy.deepcopy([o])),
        "json.dumps": lambda: json.dumps(o), "json.dumps default=str": lambda: json.dumps([o], default=str),
        "json.dumps default=vars": lambda: json.dumps([o], default=lambda x: x.__getstate__()),
        "dataclasses.asdict": lambda: dataclasses.asdict(o), "pprint": lambda: pprint.pformat({"a": [o, p]}),
        "iter": lambda: list(o), "getitem": lambda: o[0], "add": lambda: o + "s", "radd": lambda: "s" + o,
        "contains str": lambda: "C" in o, "str contains opaque": lambda: o in "MKFEED", "len": lambda: len(o),
        "lt": lambda: sorted([o, p]), "join": lambda: ",".join([o]), "int": lambda: int(o), "hash": lambda: str(hash(o)),
        "dir": lambda: dir(o),
        "logging %s": lambda: logging.LogRecord("x", 10, "f", 1, "%s %r", (o, o), None).getMessage(),
        "exception arg": lambda: str(ValueError(o)), "exception repr": lambda: repr(KeyError(o)),
        "KeyError on dict lookup": lambda: {}[o], "ValueError list.index": lambda: [].index(o),
        "set repr": lambda: repr({o, p}), "dict repr": lambda: repr({o: p}),
        "traceback locals": lambda: "".join(
            traceback.TracebackException(ValueError, ValueError("x"), None, capture_locals=True).format()),
        "__init_subclass__ subclass str": lambda: str(type("S", (ty.Opaque,), {})(PROBE_MARK, "key[1]")),
        "object.__repr__": lambda: object.__repr__(o),
        "weakref finalize registry": lambda: [(f.__self__, a) for f, a in
                                              [(i.func, i.args) for i in weakref.finalize._registry.values()]
                                              if a and a[0] == id(o)],
        "eq with str": lambda: str(o == PROBE_MARK), "same": lambda: str(ty.same(o, PROBE_MARK)),
    }
    asserts = {
        "assertEqual long": lambda: case.assertEqual(o, p), "assertNotEqual": lambda: case.assertNotEqual(o, o),
        "assertIn list": lambda: case.assertIn(o, [p]), "assertNotIn": lambda: case.assertNotIn(o, [o]),
        "assertListEqual": lambda: case.assertListEqual([o, o], [o, p]),
        "assertDictEqual": lambda: case.assertDictEqual({"k": o}, {"k": p}),
        "assertSetEqual": lambda: case.assertSetEqual({o}, {p}), "assertTupleEqual": lambda: case.assertTupleEqual((o,), (p,)),
        "assertCountEqual": lambda: case.assertCountEqual([o], [p]), "assertIs": lambda: case.assertIs(o, p),
        "assertIsNone": lambda: case.assertIsNone(o), "assertFalse": lambda: case.assertFalse(o),
        "assertSequenceEqual": lambda: case.assertSequenceEqual([o], [p]),
        "assertMultiLineEqual str": lambda: case.assertEqual(str(o), str(p)),
        "assertIsInstance": lambda: case.assertIsInstance(o, str), "assertGreater": lambda: case.assertGreater(o, p),
    }
    return paths, asserts


class TestOpaqueHoldsNoReachableText8187R24(unittest.TestCase):
    """r24 F42b: 62 probe paths, all label-only (at r23 three returned the raw text: the ``_raw`` slot read,
    ``object.__getstate__`` and ``json.dumps(default=vars)``)."""

    def rows(self):
        case = unittest.TestCase()
        case.maxDiff = None
        o = ty.Opaque(PROBE_MARK, "key[3]")
        p = ty.Opaque(PROBE_MARK + "-other-" + "x" * 900, "key[4]")
        paths, asserts = opaque_probe_paths(o, p, case)
        rows = {name: probe_text(fn) for name, fn in paths.items()}
        for name, fn in asserts.items():
            try:
                fn()
                rows[name] = ""
            except Exception as exc:  # noqa: BLE001  (a TypeError of an ordering assert is a channel too)
                rows[name] = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        return rows

    def test_63_paths(self):
        self.assertEqual(len(self.rows()), 63)

    def test_no_path_returns_the_text(self):
        raw = []
        for name, text in self.rows().items():
            with self.subTest(path=name):
                leaked = "feedfacecafe" in text or PROBE_MARK in text or PROBE_MARK.encode().hex() in text
                if leaked:
                    raw.append(name)
                self.assertFalse(leaked)
        self.assertEqual(raw, [])

    def test_a_failing_assert_prints_the_label_and_length_only(self):
        o = ty.Opaque(PROBE_MARK, "key[3]")
        p = ty.Opaque(PROBE_MARK + "x", "key[4]")
        with self.assertRaises(AssertionError) as caught:
            unittest.TestCase().assertEqual(o, p)
        shown = str(caught.exception)
        self.assertIn("key[3] len=26", shown)
        self.assertIn("key[4] len=27", shown)
        self.assertNotIn("feedface", shown)
        self.assertNotIn("MK", shown)


# ---- r24 F42f: the leak detector matches a sentinel-prefixed marker, per line ----
class TestLeakDetectorHasNoFalsePositives8187R24(unittest.TestCase):
    """r24 F42f: markers carry a fixed non-hex prefix and the detector matches that form per line, so constant text and
    adjacent label lines cannot form a hit across a line break."""

    DIGEST = "00525ecedb000000000000ab"

    def windows(self):
        return {self.DIGEST[i:i + 8]: self.DIGEST for i in range(len(self.DIGEST) - 7)}

    def test_the_sentinel_is_a_non_hex_prefix(self):
        self.assertTrue(CANARY_SENTINEL)
        self.assertFalse(any(c in "0123456789abcdef" for c in CANARY_SENTINEL.lower()))

    def test_constant_text_is_not_a_hit(self):
        for text in ("ci.yml: line 525: unrecognised job key", "a\nb\nc\nd\ne\nf\n0\n1", "525ecedb 25ecedbe",
                     "job[0] len=8\nkey[3] len=1\nstep[2] len=4"):
            with self.subTest(text_class=len(text)):
                self.assertEqual(canary_hits(text, self.windows()), set())

    def test_a_marker_in_every_probe_shape_is_a_hit(self):
        marker = CANARY_SENTINEL + self.DIGEST
        for name, shape in CANARY_SHAPES.items():
            with self.subTest(shape=name):
                self.assertEqual(canary_hits("lead " + shape(marker) + " tail", self.windows()), {self.DIGEST})

    def test_a_partial_marker_is_a_hit(self):
        self.assertEqual(canary_hits("x " + CANARY_SENTINEL + self.DIGEST[:12] + " y", self.windows()), {self.DIGEST})

    def test_a_second_seed_run_is_clean_and_has_no_cross_seed_hit(self):
        """The plain and four more shapes under seed 1: no leak, and none of seed 0's windows appears either."""
        shapes = {name: CANARY_SHAPES[name] for name in ("plain", "percent-encoded", "multi-line", "userinfo-url", "fullwidth")}
        run = canary_run(sys.modules[__name__], shapes, seed=1, foreign_seed=0)
        self.assertEqual(run.leaks, [])
        self.assertEqual(run.stray, [])
        self.assertEqual(run.errors, [])


# ---- r24 F42c and F42e: hygiene gates over this module ----
class TestFailingAssertsPrintLabelsOnly8187R24(unittest.TestCase):
    """r24 F42e (CodeQL ``py/imprecise-assert``): the converted asserts keep failing output label-only.  A failing probe of
    each converted form carries a marker in every operand; its message holds the label and no marker."""

    def failure(self, call):
        try:
            call()
        except AssertionError as exc:
            return str(exc)
        return None

    def test_each_converted_form_fails_with_a_label_only_message(self):
        case = unittest.TestCase()
        left, right = CANARY_SENTINEL + "a1b2c3d4e5f60718293a4b5c", CANARY_SENTINEL + "0f1e2d3c4b5a69788796a5b4"
        calls = {
            "assert_same": lambda: assert_same(case, left, right, "probe label"),
            "assert_has": lambda: assert_has(case, left, [right], "probe label"),
            "assertIs-compare": lambda: case.assertIs(left == right, True, "probe label"),
            "len-compare": lambda: case.assertEqual(len([left, right]), 0, "probe label"),
        }
        for name, call in sorted(calls.items()):
            with self.subTest(form=name):
                message = self.failure(call)
                self.assertIs(message is not None, True, "the probe did not fail")
                self.assertIs("probe label" in message or "len" in message or "2 != 0" in message, True)
                self.assertEqual(canary_hits(message, canary_window_table([left[len(CANARY_SENTINEL):], right[len(CANARY_SENTINEL):]])), set())

    def test_no_converted_assert_is_an_imprecise_single_compare(self):
        tree = ast.parse(THIS_PATH.read_text(encoding="utf-8"))
        found = [node.lineno for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                 and node.func.attr in ("assertTrue", "assertFalse") and node.args and isinstance(node.args[0], ast.Compare)
                 and len(node.args[0].ops) == 1]
        self.assertEqual(found, [], "assertTrue/assertFalse of one comparison remain")


class TestModuleHygiene8187R24(unittest.TestCase):
    """r24: no ``tempfile`` call without ``dir=`` (F42c) and no ``assertTrue``/``assertFalse`` of a comparison (F42e,
    CodeQL ``py/imprecise-assert``)."""

    def calls(self, predicate):
        tree = ast.parse(THIS_PATH.read_text(encoding="utf-8"))
        return sorted(node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call) and predicate(node))

    def test_every_tempfile_call_names_a_repo_local_dir(self):
        def bare(node):
            func = node.func
            return (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "tempfile"
                    and not any(kw.arg == "dir" for kw in node.keywords))
        self.assertEqual(self.calls(bare), [])

    def test_no_assert_true_or_false_wraps_a_single_comparison(self):
        def imprecise(node):
            return (isinstance(node.func, ast.Attribute) and node.func.attr in ("assertTrue", "assertFalse") and node.args
                    and isinstance(node.args[0], ast.Compare) and len(node.args[0].ops) == 1)
        self.assertEqual(self.calls(imprecise), [])


# ---- r24 F42d: linearity ratio plus an absolute cap ----
def f40e_measure(case, name, shape, nbytes):
    """Seconds for the four-call round (both views, pass and fail) on a workflow whose step name, env value and run text are
    each ``nbytes`` of ``shape``; the problem lines are checked for length and echo on the way."""
    unit = len(shape("a" * 64)) / 64.0
    value = shape("a" * int(nbytes / unit))
    edited = f40e_edit(case.text, case.step, value)
    own = pins_for({case.workflow: edited})
    calls = ((primary_pin_problems, case.pins[PRIMARY]), (job_pin_problems, case.pins[SECONDARY]),
             (primary_pin_problems, own[PRIMARY]), (job_pin_problems, own[SECONDARY]))
    start = time.perf_counter()
    for position, (fn, pins) in enumerate(calls):
        problems = fn(case.workflow, edited, pins)
        case.assertIs(len(problems) > 0, position < 2)  # the first two calls use the real pins and must fail
        case.assertLess(max([len(line) for line in problems] + [0]), 600)
        case.assertEqual(len([line for line in problems if value[:32] in line]), 0)
    return time.perf_counter() - start


class TestCheckerTimeIsLinear8187R24(unittest.TestCase):
    """r24 F42d: the finding is super-linear regex behaviour, not host speed, so the gate is the 2 MiB / 1 MiB wall-time ratio
    (named ``F40E_RATIO_MAX``) plus an absolute cap per shape (named ``F40E_CAP_SECONDS``)."""

    workflow = "ci.yml"

    @classmethod
    def setUpClass(cls):
        cls.text = (WORKFLOWS / cls.workflow).read_text(encoding="utf-8")
        cls.pins = load_job_pins()
        cls.step = pin_targets(cls.workflow, cls.text)[0]

    def test_the_constants_are_named(self):
        self.assertEqual(F40E_RATIO_MAX, 3.0)
        self.assertEqual(F40E_CAP_SECONDS, 20.0)

    def test_letters_scale_linearly(self):
        shape = CANARY_SHAPES["plain"]
        f40e_measure(self, "warm", shape, 1 << 16)
        one = min(f40e_measure(self, "letters", shape, 1 << 20) for _ in range(2))
        two = f40e_measure(self, "letters", shape, 2 << 20)
        self.assertLess(two / max(one, 0.05), F40E_RATIO_MAX)
        self.assertLess(two, F40E_CAP_SECONDS)

    def test_every_probe_shape_is_under_the_cap_at_one_mebibyte(self):
        for name, shape in sorted(CANARY_SHAPES.items()):
            with self.subTest(shape=name):
                self.assertLess(f40e_measure(self, name, shape, F40E_BYTES), F40E_CAP_SECONDS)


# ---- r24 security F1-F3: every capture channel has a positive control, every harness mutant is red ----
FORCE_FLAG = "CANARY_FORCE" + "_FAIL"  # spelled in parts so the mutant table below is not itself a replacement target
GUARD_SITE_MUTANTS = {
    # name: (text of the site, its replacement); each text is found exactly once in the module
    "own-pins fail views (guard)": ("                if %s:\n                    run.views(shape_name, \"fail-other-values/" % FORCE_FLAG,
                                    "                if False:\n                    run.views(shape_name, \"fail-other-values/"),
    "real-pins fail view (guard)": ("            if %s:\n                run.views(shape_name, \"fail-real-pins/" % FORCE_FLAG,
                                    "            if False:\n                run.views(shape_name, \"fail-real-pins/"),
    "post-pass tail (continue)": ("        if not %s:\n            continue" % FORCE_FLAG, "        if True:\n            continue"),
    "legacy scenarios (return)": ("    if not %s:\n        return\n    ci = run.texts" % FORCE_FLAG,
                                  "    if True:\n        return\n    ci = run.texts"),
    "repository scenario (return)": ("        if not %s:\n            return\n        data = {" % FORCE_FLAG,
                                     "        if True:\n            return\n        data = {"),
}
FLAG_SITE_MUTANT = ("%s = True  #" % FORCE_FLAG, "%s = False  #" % FORCE_FLAG)
FORCING_SITE_MUTANTS = {**GUARD_SITE_MUTANTS, "flag switched off": FLAG_SITE_MUTANT}


# r26 code C1: the real-pins fail scenario runs in ONE view only (the other view's call is replaced).  Each text is found once;
# the family name is split so this table is not a second occurrence of the site it replaces
VIEW_SITE_FAMILY = '"fail-real' + '-pins/" + tag'
VIEW_SITE_CALL = "run.views(shape_name, %s, wf, text1, pins[mod.PRIMARY], pins[mod.SECONDARY], \"fail\")" % VIEW_SITE_FAMILY
VIEW_SITE_MUTANTS = {
    "text view of the real-pins fail scenario": (
        VIEW_SITE_CALL,
        "run.observe(shape_name, %s + \"/loaded\", mod.primary_pin_problems, wf, text1, pins[mod.PRIMARY], expect=\"fail\")"
        % VIEW_SITE_FAMILY),
    "loaded view of the real-pins fail scenario": (
        VIEW_SITE_CALL,
        "run.observe(shape_name, %s + \"/text\", mod.job_pin_problems, wf, text1, pins[mod.SECONDARY], expect=\"fail\")"
        % VIEW_SITE_FAMILY),
}


# r26 sec F2: the text view of each of the three families the r24 gate counted per view is skipped, one mutant each (the site
# is the text-view call of ``CanaryRun.views``; the text is split so this table is not a second occurrence of it)
TEXT_VIEW_SITE = '        self.observe(shape_name, scenario + "/te' + 'xt", mod.job_pin_problems'
TEXT_VIEW_FAMILIES = ("fail-real" + "-pins", "fail-other" + "-values", "fail-real-text" + "-own-pins")
TEXT_VIEW_MUTANTS = {
    family: (TEXT_VIEW_SITE, "        if scenario.split('/', 1)[0] == %r:\n            return\n%s" % (family, TEXT_VIEW_SITE))
    for family in TEXT_VIEW_FAMILIES}


CHANNEL_LINE = re.compile(r"^(?P<indent>\s*).*# canary-channel: (?P<name>[a-z-]+)$", re.M)
HARNESS_MUTANTS = {
    "drop exception capture": ("channel", ("exception", "exception-chain"), "controls"),
    "drop exception chain walk": ("channel", ("exception-chain",), "controls"),
    "drop stdout and stderr capture": ("channel", ("stdout-stderr",), "controls"),
    "drop log capture": ("channel", ("log",), "controls"),
    "drop warning capture": ("channel", ("warning",), "controls"),
    "drop problem-line scan": ("channel", ("problem-line",), "controls"),
    "fail-path forcing removed, flag kept": ("text", "if CANARY_FORCE_FAIL:", "coverage"),
    "chain -> str(cause), str(context)": ("chain-str", "exception-chain", "controls"),  # r25 sec S3: the notes channel is lost
    "notes stripped before formatting": ("notes-strip", "exception-chain", "controls"),  # r25 code C3
    # r25 code C2: one row per fail-path guard, each red on its own
    **{"guard removed: " + name: ("site", pair, "coverage") for name, pair in GUARD_SITE_MUTANTS.items()},
    "notes stripped from the cause chain": ("cause-notes-strip", "exception-chain", "controls"),  # r26 code C4
    # r26 code C1: one row per view of the real-pins fail scenario, each red on its own
    **{"view dropped: " + name: ("site", pair, "coverage") for name, pair in VIEW_SITE_MUTANTS.items()},
    # r26 sec F2: the text view skipped for each of the three per-view families
    **{"text view skipped: " + family: ("site", pair, "coverage") for family, pair in TEXT_VIEW_MUTANTS.items()},
    # r26 sec F3: a note on a chain link is lost (cause, context, both)
    "notes stripped from the context chain": ("context-notes-strip", "exception-chain", "controls"),
    "notes stripped from both chain links": ("link-notes-strip", "exception-chain", "controls"),
}


def harness_mutant_source(source, kind, what):
    """``source`` with the capture lines of the channels in ``what`` dropped (each marked line becomes ``pass``), or the
    fail-path guard forced off with its flag kept."""
    if kind == "site":
        old, new = what
        if source.count(old) != 1:
            raise AssertionError("the guard text is not in the module exactly once")
        return source.replace(old, new)
    if kind == "notes-strip":
        def strip(match):
            if match.group("name") != what:
                return match.group(0)
            return match.group("indent") + "exc.__dict__.pop('__notes__', None)\n" + match.group(0)
        return CHANNEL_LINE.sub(strip, source)
    if kind in ("cause-notes-strip", "context-notes-strip", "link-notes-strip"):
        links = {"cause-notes-strip": ("__cause__",), "context-notes-strip": ("__context__",),
                 "link-notes-strip": ("__cause__", "__context__")}[kind]

        def strip_links(match):
            if match.group("name") != what:
                return match.group(0)
            pops = "".join("getattr(exc.%s, '__dict__', {}).pop('__notes__', None)\n%s" % (link, match.group("indent"))
                           for link in links)
            return match.group("indent") + pops + match.group(0).lstrip()
        return CHANNEL_LINE.sub(strip_links, source)
    if kind == "chain-str":
        def narrow(match):
            if match.group("name") != what:
                return match.group(0)
            return match.group("indent") + "chunks += [str(exc.__cause__), str(exc.__context__)]  # canary-channel: " + what
        return CHANNEL_LINE.sub(narrow, source)
    if kind == "channel":
        count = [0]

        def drop(match):
            if match.group("name") not in what:
                return match.group(0)
            count[0] += 1
            return match.group("indent") + "pass"
        mutated = CHANNEL_LINE.sub(drop, source)
        if count[0] == 0:
            raise AssertionError("no capture line is marked with that channel")
        return mutated
    if what not in source:
        raise AssertionError("the guard text is not in the module")
    return source.replace(what, "if False:")


class TestCanaryHarnessIsProven8187R24(unittest.TestCase):
    """r24 sec F1, F2, F3 (security r23, check 3): the exception chain, stdout and stderr, log, warning and problem-line
    channels each have a seeded positive control, and the fail-path forcing is proven by a per-view count; dropping any of
    them makes the harness red."""

    def test_the_unmutated_harness_passes_every_control(self):
        self.assertEqual(canary_control_failures(sys.modules[__name__]), [])

    def test_every_capture_channel_has_a_seeded_control(self):
        names = set(canary_controls(CanaryRun(sys.modules[__name__])))
        expected = {"print", "stderr", "log", "warning", "problem-line", "exception", "exception-chain", "exception-context"}
        if sys.version_info >= (3, 11):
            expected.update(("exception-notes", "exception-cause-notes", "exception-context-notes"))  # r25 sec S3, r26 code C4, sec F3
        self.assertEqual(names, expected)

    def test_each_harness_mutant_is_red(self):
        ty_source = TY_PATH.read_text(encoding="utf-8")
        test_source = THIS_PATH.read_text(encoding="utf-8")
        for name, (kind, what, check) in HARNESS_MUTANTS.items():
            with self.subTest(mutant=name):
                if kind in ("chain-str", "notes-strip", "cause-notes-strip", "context-notes-strip", "link-notes-strip") \
                        and sys.version_info < (3, 11):
                    continue  # exception notes exist from Python 3.11; the control is registered from there too
                variant = load_variant(ty_source, harness_mutant_source(test_source, kind, what))
                if check == "controls":
                    failures = canary_control_failures(variant)
                else:
                    failures = canary_coverage_failures(canary_run(variant, {"plain": CANARY_SHAPES["plain"]}), ["plain"])
                self.assertGreater(len(failures), 0)

    def test_the_real_canary_counts_fail_path_observations_per_view_and_shape(self):
        run = canary_run(sys.modules[__name__], {"plain": CANARY_SHAPES["plain"], "multi-line": CANARY_SHAPES["multi-line"]})
        self.assertEqual(canary_coverage_failures(run, ["plain", "multi-line"]), [])
        for shape in ("plain", "multi-line"):
            for view in ("loaded", "text"):
                self.assertIs(run.fail_views.get((shape, view), 0) > 0, True, "%s/%s" % (shape, view))


# ---- r24 security F4: YAML tags, %TAG directives and bad escapes are seeded; no loader call prints author text ----
TAG_PLANTS = {
    "local tag": lambda marker: "X_TAG: !%s v" % marker,
    "bad escape": lambda marker: 'X_ESC: "%s\\q"' % marker,
    "tag directive": lambda marker: "%TAG !e! tag:" + marker + ",2000:",
    # r25 sec S1: standard tags whose constructors call Python builtins (the escaping exceptions are not YAMLError)
    "std int value": lambda marker: "X_INT: !!int " + marker,
    "std float value": lambda marker: "X_FLT: !!float " + marker,
    "std bool value": lambda marker: "X_BOOL: !!bool " + marker,
    "std int key": lambda marker: "!!int " + marker + ": v",
}


def plant_tag(text, kind, marker):
    """``text`` (a workflow) with the tag-field marker planted: an env entry carrying a local tag or a bad escape, or a ``%TAG``
    directive ahead of the document."""
    if kind == "tag directive":
        return TAG_PLANTS[kind](marker) + "\n---\n" + text
    out, done = [], False
    for line in text.split("\n"):
        out.append(line)
        if not done and line.strip() == "env:":
            out.append(line[:len(line) - len(line.lstrip())] + "  " + TAG_PLANTS[kind](marker))
            done = True
    return "\n".join(out)


class TestNoLoaderCallPrintsAuthorText8187R24(unittest.TestCase):
    """r24 sec F4 (security r23, ``attack_tag.py`` rebuilt): a marker in a YAML tag, a ``%TAG`` directive or a bad escape
    reaches no exception text, log record, stdout, stderr or problem line, through the loaders and both views."""

    def test_the_canary_seeds_tags_and_directives(self):
        run = CanaryRun(sys.modules[__name__])
        faults = canary_loader_faults(run, "plain", CANARY_SHAPES["plain"])
        for name in ("local-tag", "tag-directive", "bad-escape"):
            self.assertIs(name in faults, True, name)

    def test_each_plant_is_refused_without_the_marker_in_any_channel(self):
        run = CanaryRun(sys.modules[__name__])
        raised = []
        for kind in TAG_PLANTS:
            for shape_name in ("plain", "percent-encoded", "fullwidth", "format-characters"):
                shape = CANARY_SHAPES[shape_name]
                text = plant_tag(run.texts["ci.yml"], kind, run.mint("tag", shape))
                for loader in (ty.load_strict, ty.load_lenient):
                    before = len(run.errors)
                    run.observe(shape_name, "tag/%s/%s" % (kind, loader.__name__), loader, text)
                    raised.append(len(run.errors) > before)
                run.views(shape_name, "tag-view/" + kind, "ci.yml", text, run.pins[PRIMARY], run.pins[SECONDARY], None)
        self.assertEqual(run.leaks, [])
        self.assertGreater(sum(raised), 0, "no plant was refused by a loader")

    def test_a_loader_failure_names_the_class_and_the_line_only(self):
        for kind in ("local tag", "bad escape"):
            text = plant_tag("a:\n  env:\n    K: v\n", kind, "MKsecretsecret")
            for loader in (ty.load_strict, ty.load_lenient):
                with self.subTest(plant=kind, loader=loader.__name__):
                    with self.assertRaises(ValueError) as caught:
                        loader(text)
                    shown = "".join(traceback.format_exception(type(caught.exception), caught.exception,
                                                               caught.exception.__traceback__))
                    self.assertNotIn("MKsecret", shown)
                    self.assertIsNone(caught.exception.__cause__)
                    self.assertIsNone(caught.exception.__context__)
                    self.assertRegex(str(caught.exception), r"^\w+(?: at line \d+)?$")


# ---- r24 security F5: more taint shapes ----
TAINT_SEC_SHAPES = {
    "getattr assert": TAINT_HEAD + "        getattr(self, 'assertEqual')(text, 'x')\n",
    "bound alias": TAINT_HEAD + "        eq = self.assertEqual\n        eq(text, 'x')\n",
    "re.search Match": TAINT_HEAD + "        import re\n        self.assertIsNone(re.search('.+', text))\n",
    "print": TAINT_HEAD + "        print(text)\n",
    "raise ValueError": TAINT_HEAD + "        raise ValueError(text)\n",
    "partial of an assert": TAINT_HEAD + "        functools.partial(self.assertEqual, text)('x')\n",
    "lambda direct call": TAINT_HEAD + "        self.assertEqual((lambda t: t)(text), 'x')\n",
    "closure": TAINT_HEAD + "        def inner():\n            self.assertEqual(text, 'x')\n        inner()\n",
    "assigned lambda": TAINT_HEAD + "        check = lambda t: self.assertEqual(t, 'x')\n        check(text)\n",
    "default argument": TAINT_HEAD + "        def probe(v=text):\n            self.assertEqual(v, 'x')\n        probe()\n",
    "public name path": TAINT_HEAD + "        path = text\n        self.assertEqual(path, 'x')\n",
    "public name workflow": TAINT_HEAD + "        workflow = text\n        self.assertEqual(workflow, 'x')\n",
}


class TestTaintScanSeesTheSecurityShapes8187R24(unittest.TestCase):
    """r24 sec F5 (security r23, check 4): getattr-built and aliased assert methods, Match objects, and print, raise and bare
    assert operands are scanned like any assert."""

    def test_each_shape_is_flagged(self):
        for name, source in TAINT_SEC_SHAPES.items():
            with self.subTest(shape=name):
                self.assertGreater(len(tainted_assert_lines(source)), 0)

    def test_a_match_object_that_is_only_tested_for_truth_is_clean(self):
        source = TAINT_HEAD + "        import re\n        self.assertEqual(bool(re.search('a', text)), True)\n"
        self.assertEqual(tainted_assert_lines(source), [])


# ---- r24 security F6 and F7: the raw text has no path outside Opaque; the docstring states the file-name exception ----
class TestNoPathToTheRawTextOutsideOpaque8187R24(unittest.TestCase):
    """r24 sec F6 (security r23, check 1) and F7."""

    DIRTY = {
        "attribute": "x = wrapped._raw\n",
        "getattr": "x = getattr(wrapped, '_raw')\n",
        "getattr dynamic prefix": "x = getattr(wrapped, '_' + 'raw')\n",
        "getstate": "x = wrapped.__getstate__()\n",
        "slot descriptor": "x = Opaque._raw.__get__(wrapped)\n",
    }
    CLEAN = "x = wrapped.raw\ny = str(wrapped)\nclass Opaque:\n    def raw(self):\n        return self._raw\n"

    def test_the_gate_refuses_each_path(self):
        for name, source in self.DIRTY.items():
            with self.subTest(path=name):
                self.assertGreater(len(opaque_escape_lines(source)), 0)

    def test_the_gate_allows_the_class_itself(self):
        self.assertEqual(opaque_escape_lines(self.CLEAN), [])

    def test_neither_file_reaches_for_the_raw_text(self):
        for path in (TY_PATH, THIS_PATH):
            with self.subTest(file=path.name):
                # the probe function is the one place that tries every path on purpose; nothing else may
                self.assertEqual(opaque_escape_lines(path.read_text(encoding="utf-8"),
                                                     allowed=OPAQUE_GATE_ALLOWED), [])

    def test_the_module_docstring_states_the_file_name_exception(self):
        self.assertIn("repo_problems", ty.__doc__)
        self.assertIn("file name", ty.__doc__)


# ---- r24 F42a: the r22 decision pins, restored (the AST taint scan binds names to loaders; this one is by NAME) ----
RAW_OPERAND = re.compile(r"\bentry\b|\bdata\b|\bpinned\b|\boutputs\b|read_text|read_bytes|JOB_PINS_FILE|build_pins|"
                         r"self\.pins\b|\.texts\b|workflow_keys|job_names|tier_jobs")
COMPARE_FAMILY = frozenset(("assertEqual", "assertNotEqual", "assertIn", "assertNotIn", "assertCountEqual",
                            "assertListEqual", "assertDictEqual", "assertSequenceEqual"))


def raw_operand_comparisons(source):
    """The line numbers of the ``assertEqual`` family calls in ``source`` whose first two operands are raw workflow or pin
    data by NAME (r22 F40-a).  Exempt: a comparison with ``[]`` (already labelled problem lines), a ``len(...)`` operand and
    an operand wrapped by ``opaque`` or ``same``; everything else goes through ``assert_same`` / ``assert_has``."""
    lines = []
    wrappers = ("len", "opaque", "same")
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in COMPARE_FAMILY):
            continue
        operands = node.args[:2]
        if any(isinstance(arg, ast.List) and not arg.elts for arg in operands):
            continue
        exempt = lambda arg: isinstance(arg, ast.Call) and call_name(arg) in wrappers
        if any(RAW_OPERAND.search(ast.get_source_segment(source, arg) or "") for arg in operands if not exempt(arg)):
            lines.append(node.lineno)
    return lines


class TestNoRawWorkflowOperandIsCompared8187R22(unittest.TestCase):
    """r22 F40-a, restored by r24 F42a: the AST taint scan follows values from the loaders, so a comparison of a name the
    scan never saw bound (``entry``, ``data``, ``pinned``) is only caught by name.  The allowed set is zero in both files."""

    ALLOWED = 0

    def test_neither_file_compares_raw_workflow_or_pin_text_with_assertEqual_8187_f40a(self):
        for path in (THIS_PATH, TY_PATH):
            with self.subTest(file=path.name):
                found = raw_operand_comparisons(path.read_text(encoding="utf-8"))
                self.assertEqual(len(found), self.ALLOWED)

    def test_the_scanner_counts_a_restored_raw_comparison_8187_f40a(self):
        raw = 'class T:\n    def t(self):\n        self.assertEqual(entry["job_names"], sorted(data["jobs"]))\n'
        self.assertEqual(raw_operand_comparisons(raw), [3])
        mixed = "self.assertIn('on', data)\nself.assertEqual(f(data), [])\n"
        self.assertEqual(raw_operand_comparisons(mixed), [1])
        exempt = "self.assertEqual(len(data), 3)\nassert_same(self, data, 1, 'x')\nself.assertEqual(ty.opaque(data, 'key[0]'), 1)\n"
        self.assertEqual(raw_operand_comparisons(exempt), [])


# ---- r24 F42g (3): the positional labels the r19, r20 and r22 pins printed by position, in opaque form ----
POS_MARK = "MK" + "feed0123456789abcdef01"


def has_line(problems, pattern):
    """True when one line of ``problems`` matches ``pattern`` (a bool, so an assert on it prints no problem text)."""
    return any(re.search(pattern, line) for line in problems)


def positional_cases():
    """``{site: (problems, [pattern, ...])}``: one fault per label-printing site family, the marker planted in the text the
    fault is about; each pattern names the label family and the length of the marker."""
    n = len(POS_MARK)
    wf = "ci.yml"
    text = (WORKFLOWS / wf).read_text(encoding="utf-8")
    pins = load_job_pins()
    target = pin_targets(wf, text)[0]
    job = target[0]
    head = "\n  %s:" % job
    pad = " " * (indent_of(text.split("\n")[target[3]]) + 2)
    copy_ = lambda: json.loads(json.dumps(pins))
    cases = {}
    dup = text.rstrip("\n") + '\n"%s": 1\n"%s": 2\n' % (POS_MARK, POS_MARK)
    cases["duplicate top-level key (r19 F36)"] = (
        primary_pin_problems(wf, dup, pins[PRIMARY]), [r"the mapping key key\[\d+\] len=%d appears twice" % n])
    extra = text.rstrip("\n") + '\n"%s": 1\n' % POS_MARK
    cases["extra top-level key (r19 F36)"] = (
        primary_pin_problems(wf, extra, pins[PRIMARY]),
        [r"top-level keys outside the closed set: key\[0\] len=%d" % n, r"a workflow-level key key\[0\] len=%d was added" % n])
    job_edit = text.replace(head, '%s\n    "%s": 1' % (head, POS_MARK))
    cases["job key, loaded view (r19 F36)"] = (
        primary_pin_problems(wf, job_edit, pins[PRIMARY]),
        [r"job\[\d+\] len=\d+ job-level keys: differs from the pin at job\.key\[0\] len=%d" % n])
    cases["job key, text view (r19 F36)"] = (
        job_pin_problems(wf, job_edit, pins[SECONDARY]), [r"job key\[\d+\] len=\d+ job-level keys: differs from the pin at line \d+"])
    step_edit = splice(text, target[3] + 1, ['%s"%s": 1' % (pad, POS_MARK)])
    cases["step key, loaded view (r19 F36)"] = (
        primary_pin_problems(wf, step_edit, pins[PRIMARY]),
        [r"step \d+ \(step\[\d+\] len=\d+\): differs from the pin at steps\[\d+\]\.key\[1\] len=%d" % n])
    cases["step key, text view (r19 F36)"] = (
        job_pin_problems(wf, step_edit, pins[SECONDARY]), [r"step \d+ \(step\[\d+\] len=\d+\): differs from the pin at line \d+"])
    row = next(iter(ty.RUNS_ON_EXEMPT.values()))
    matrix = {"runs-on": row[1], "strategy": {"matrix": {ty.RUNS_ON_FORMS[row[1]][0]: ["ubuntu-latest"], POS_MARK: 1}}}
    cases["matrix key (r19 F36)"] = ([ty.exemption_problem(row, matrix)], [r"^matrix\.key\[1\] len=%d is not a list" % n])
    removed_job = copy_()
    entry = removed_job[PRIMARY][wf]["tier_jobs"]
    first = next(iter(entry))
    entry[first]["sha256"] = "0" * 64
    entry[first]["keys"][POS_MARK] = "0" * 64
    cases["removed pinned job key (r20 F38)"] = (
        primary_pin_problems(wf, text, removed_job[PRIMARY]), [r"differs from the pin at job\.key\[\d+\] len=%d \(removed\)" % n])
    removed_step = copy_()
    entry = removed_step[PRIMARY][wf]["tier_jobs"]
    first = next(iter(entry))
    index = next(i for i, step in enumerate(entry[first]["steps"]) if "keys" in step)
    entry[first]["sha256"] = "0" * 64
    entry[first]["steps"][index]["sha256"] = "0" * 64
    entry[first]["steps"][index]["keys"][POS_MARK] = "0" * 64
    cases["removed pinned step key (r20 F38)"] = (
        primary_pin_problems(wf, text, removed_step[PRIMARY]),
        [r"differs from the pin at steps\[%d\]\.key\[\d+\] len=%d \(removed\)" % (index, n)])
    gone = copy_()
    primary = gone[PRIMARY][wf]
    primary["job_names"] = sorted([*primary["job_names"], POS_MARK])
    primary["job_names_sha256"] = "0" * 64
    primary["tier_jobs"][POS_MARK] = json.loads(json.dumps(next(iter(primary["tier_jobs"].values()))))
    secondary = gone[SECONDARY][wf]
    secondary["jobs"] = [*secondary["jobs"], POS_MARK]
    secondary["pinned"][POS_MARK] = json.loads(json.dumps(next(iter(secondary["pinned"].values()))))
    for view, problems in (("loaded", primary_pin_problems(wf, text, gone[PRIMARY])),
                           ("text", job_pin_problems(wf, text, gone[SECONDARY]))):
        cases["pinned job that is gone, %s view (r20 F38)" % view] = (
            problems, [r"missing \[key\[\d+\] len=%d\]" % n, r"job key\[\d+\] len=%d: pinned job is missing" % n])
    block = copy_()
    block[SECONDARY][wf]["workflow"][POS_MARK] = next(iter(block[SECONDARY][wf]["workflow"].values()))
    cases["pinned workflow-level block key (r22 F39a)"] = (
        job_pin_problems(wf, text, block[SECONDARY]), [r"the pinned workflow-level key\[\d+\] len=%d: block is missing" % n])
    named = splice(text, target[3], ["      - name: %s" % POS_MARK, "        run: echo one"])
    cases["an inserted step's name (r14 F27)"] = (
        primary_pin_problems(wf, named, pins[PRIMARY]), [r"step \d+ \(step\[\d+\] len=%d\)" % n])
    return cases


class TestEveryLabelIsPositional8187R24(unittest.TestCase):
    """r24 F42g (3): the r19, r20 and r22 pins that checked a fault is "printed by position" were removed with ``printable``;
    this is each of them in opaque form: the fault is reported, the marker planted in the text it is about is nowhere in a
    line, and the label family, position and length are the contract."""

    def test_every_site_family_is_covered(self):
        self.assertEqual(len(positional_cases()), 13)

    def test_no_line_carries_the_marker_and_each_names_its_label(self):
        for site, (problems, patterns) in positional_cases().items():
            with self.subTest(site=site):
                self.assertGreater(len(problems), 0)
                self.assertIs(has_line(problems, re.escape(POS_MARK)), False)
                self.assertIs(has_line(problems, "feed0123456789abcdef01"), False)
                for pattern in patterns:
                    self.assertIs(has_line(problems, pattern), True)


# ---- r25 code C5: the opaque gate's four bypasses ----
OPAQUE_GATE_ALLOWED = ("Opaque", "_forget", "opaque_probe_paths", "opaque_finalizer_funcs")  # the wrapper and the two probes that try every path


def opaque_finalizer_funcs(o):
    """The functions of the ``weakref`` finalizers registered for ``o`` (the registry walk of the r24 code review)."""
    return [info.func for info in weakref.finalize._registry.values() if info.args and info.args[0] == id(o)]


class TestOpaqueGateClosesTheBypasses8187R25(unittest.TestCase):
    """r25 code C5 (code r24, finding 5): the from-import, the vars-of-module lookup with a built name, the ``getattr(x, 'raw')``
    call and the ``weakref.finalize`` registry walk each reach the raw text past the r24 gate; the gate refuses all four, and the
    finalizer's function no longer carries the registry (the walk returns label-only)."""

    DIRTY = {
        "from-import": "from tier_yaml_8187 import " + "_" + "RAW\n",
        "vars of module": "x = vars(ty)['_' + 'RA' + 'W']\n",
        "globals lookup": "x = globals()[name]\n",
        "finalize registry": "import weakref\nx = weakref.finalize._registry\n",
        "finalizer function globals": "x = fin.func.__globals__\n",
    }

    def test_the_gate_refuses_each_bypass(self):
        for name, source in self.DIRTY.items():
            with self.subTest(path=name):
                self.assertGreater(len(opaque_escape_lines(source)), 0)

    def test_the_raw_call_gate_refuses_getattr_raw(self):
        for source in ("x = getattr(w, 'raw')()\n", "x = getattr(w, 'r' + 'aw')()\n", "x = w.raw()\n"):
            with self.subTest(source=source):
                self.assertGreater(len(raw_unwrap_lines(source)), 0)
        self.assertEqual(raw_unwrap_lines("class Opaque:\n    def same(self, w):\n        return w.raw()\n", allowed=("same",)), [])

    def test_both_files_pass_the_extended_gates(self):
        for path in (TY_PATH, THIS_PATH):
            with self.subTest(file=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertEqual(opaque_escape_lines(source, allowed=OPAQUE_GATE_ALLOWED), [])

    def test_the_finalizer_function_carries_no_registry(self):
        o = ty.Opaque(PROBE_MARK, "key[5]")
        funcs = opaque_finalizer_funcs(o)
        self.assertEqual(len(funcs), 1)
        self.assertIs(hasattr(funcs[0], "__self__"), False)


# ---- r25 security S1: the loaders raise StrictYamlError only ----
LOADER_PLANTS = {
    "int tag": "env:\n  X: !!int @@\n",
    "int tag 0x": "env:\n  X: !!int 0x@@\n",
    "int tag 0o": "env:\n  X: !!int 0o@@\n",
    "int tag sexagesimal": "env:\n  X: !!int 1:@@\n",
    "float tag": "env:\n  X: !!float @@\n",
    "bool tag": "env:\n  X: !!bool @@\n",
    "timestamp tag": "env:\n  X: !!timestamp 2001-13-45\n",
    "binary tag": "env:\n  X: !!binary @@===\n",
    "set of mapping key": "env:\n  X: !!set {@@: [1]}\n",
    "omap bad": "env:\n  X: !!omap [@@]\n",
    "pairs bad": "env:\n  X: !!pairs [@@]\n",
    "null tag": "env:\n  X: !!null @@\n",
    "str key int tag": "env:\n  !!int @@: v\n",
}
LOADER_BASE = "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"


def loader_escape_rows(mark):
    """``(escapes, leaking, total)`` of the r24 review's ``loader_escape.py``: every plant through ``load_strict``,
    ``load_lenient`` and ``parse_workflow``; an escape is anything raised other than ``StrictYamlError``, a leak is the marker
    in the text of what was raised (str, repr, args, formatted chain) or in a returned problem line."""
    escapes = leaking = total = 0
    for plant in LOADER_PLANTS.values():
        doc = plant.replace("@@", mark) + LOADER_BASE
        for function in (ty.load_strict, ty.load_lenient, ty.parse_workflow):
            total += 1
            try:
                result = function(doc)
                shown = " ".join(result[1]) if function is ty.parse_workflow else ""
            except ty.StrictYamlError as exc:
                shown = "".join([str(exc), repr(exc), repr(exc.args), *traceback.format_exception(type(exc), exc, exc.__traceback__)])
            except Exception as exc:  # noqa: BLE001  (the probe classifies every escape)
                escapes += 1
                shown = "".join([str(exc), repr(exc), repr(exc.args), *traceback.format_exception(type(exc), exc, exc.__traceback__)])
            leaking += mark.lower() in shown.lower()
    return escapes, leaking, total


class TestLoadersRaiseOnlyStrictYamlError8187R25(unittest.TestCase):
    """r25 sec S1 (security r24, ``loader_escape.py`` and ``attack_inttag.py`` rebuilt): a standard tag whose constructor calls
    a Python builtin raises ValueError or KeyError, not a YAMLError; the loaders convert every exception to
    ``StrictYamlError`` (class and line only), so no caller sees the author text."""

    def test_39_loader_paths_raise_only_the_checkers_own_error_and_leak_nothing(self):
        escapes, leaking, total = loader_escape_rows("MKzq7Vx")
        self.assertEqual((total, escapes, leaking), (39, 0, 0))

    def test_a_standard_tag_planted_in_a_copy_of_the_workflows_prints_nothing(self):
        run = CanaryRun(sys.modules[__name__], seed=24024)
        CANARY_SCRATCH.mkdir(parents=True, exist_ok=True)
        for kind in ("std int value", "std float value", "std bool value", "std int key"):
            with tempfile.TemporaryDirectory(dir=str(CANARY_SCRATCH)) as raw_root:
                root = Path(raw_root)
                target = root / ".github" / "workflows"
                shutil.copytree(WORKFLOWS, target)
                planted = plant_tag(run.texts["ci.yml"], kind, run.mint("tag", CANARY_SHAPES["plain"]))
                (target / "ci.yml").write_text(planted, encoding="utf-8")
                (target / "extra.yml").write_text(plant_tag("name: x\non: push\nenv:\n  A: b\njobs: {}\n", kind,
                                                            run.mint("tag", CANARY_SHAPES["plain"])), encoding="utf-8")
                run.observe("plain", "std/%s/repo" % kind, repo_problems, root, run.pins, expect=None)
                run.observe("plain", "std/%s/names" % kind, names_the_tier, planted, expect=None)
                run.observe("plain", "std/%s/discovery" % kind, tier_workflows, target, expect=None)
                run.observe("plain", "std/%s/pins" % kind, tier_pin_problems, "ci.yml", planted, run.pins, expect=None)
                run.observe("plain", "std/%s/parse" % kind, ty.parse_workflow, planted, expect=None)
        self.assertEqual(run.leaks, [])
        self.assertEqual(run.errors, [])

    def test_the_canary_seeds_every_standard_tag_plant(self):
        faults = canary_loader_faults(CanaryRun(sys.modules[__name__]), "plain", CANARY_SHAPES["plain"])
        for name in ("std-int-value", "std-float-value", "std-bool-value", "std-int-key"):
            self.assertIs(name in faults, True, name)
        self.assertGreaterEqual(len([k for k in TAG_PLANTS if k.startswith("std ")]), 4)

    def test_the_docstring_claim_is_true_for_every_standard_tag(self):
        for tag in ("int", "float", "bool"):
            for function in (ty.load_strict, ty.load_lenient):
                with self.subTest(tag=tag, loader=function.__name__):
                    with self.assertRaises(ty.StrictYamlError) as caught:
                        function("a: !!%s MKsecretsecret\n" % tag)
                    self.assertIsNone(caught.exception.__cause__)
                    self.assertNotIn("MKsecret", str(caught.exception) + repr(caught.exception.args))


# ---- r25 security S2: the reviewer's 18-variant TaintScan corpus ----
TAINT_R25_HEAD = ("import unittest, functools, re, traceback\nfrom functools import partial as P\nclass T(unittest.TestCase):\n"
                  "    def test(self):\n        body = load_job_pins()\n")
TAINT_R25_SHAPES = {
    "lambda in list": TAINT_R25_HEAD + "        fs = [lambda: body]\n        self.assertEqual(fs[0](), 'x')\n",
    "lambda kw default": TAINT_R25_HEAD + "        f = lambda v=body: v\n        self.assertEqual(f(), 'x')\n",
    "nested def default": TAINT_R25_HEAD + "        def g(*, v=body):\n            return v\n        self.assertIn(g(), ['x'])\n",
    "partial aliased import": TAINT_R25_HEAD + "        q = P(str.lower, body)\n        self.assertEqual(q(), 'x')\n",
    "partial keyword": TAINT_R25_HEAD + "        q = functools.partial(dict, a=body)\n        self.assertEqual(q(), {})\n",
    "closure two levels": TAINT_R25_HEAD + "        def outer():\n            def inner():\n                return body\n"
                                           "            return inner()\n        self.assertEqual(outer(), 'x')\n",
    "alias via tuple": TAINT_R25_HEAD + "        eq, ne = self.assertEqual, self.assertNotEqual\n        eq(body, 'x')\n",
    "getattr built name": TAINT_R25_HEAD + "        getattr(self, 'assert' + 'Equal')(body, 'x')\n",
    "match group": TAINT_R25_HEAD + "        m = re.match('(.*)', str(body))\n        self.assertEqual(m.group(1), 'x')\n",
    "match in list": TAINT_R25_HEAD + "        ms = [re.fullmatch('.*', str(body))]\n        self.assertIsNone(ms[0])\n",
    "print file=": TAINT_R25_HEAD + "        import sys\n        print('x', body, file=sys.stderr)\n",
    "raise from": TAINT_R25_HEAD + "        raise RuntimeError('x') from ValueError(body)\n",
    "assert msg only": TAINT_R25_HEAD + "        assert False, body\n",
    "assert operand only": TAINT_R25_HEAD + "        assert body == 'x'\n",
    "self.fail": TAINT_R25_HEAD + "        self.fail(body)\n",
    "add_note": TAINT_R25_HEAD + "        e = ValueError('x')\n        e.add_note(body)\n        raise e\n",
    "logging": TAINT_R25_HEAD + "        import logging\n        logging.warning('%s', body)\n",
    "sys.stdout.write": TAINT_R25_HEAD + "        import sys\n        sys.stdout.write(str(body))\n",
    "sys.stdout.write bare": TAINT_R25_HEAD + "        import sys\n        sys.stdout.write(body)\n",
    "partial of print": TAINT_R25_HEAD + "        functools.partial(print, body)()\n",
}
TAINT_R25_CLEAN = {
    "len only": TAINT_R25_HEAD + "        self.assertEqual(len(body), 3)\n",
    "bool match": TAINT_R25_HEAD + "        self.assertIs(bool(re.search('a', str(body))), True)\n",
    "opaque wrapped": TAINT_R25_HEAD + "        self.assertEqual(opaque(body, 'pin[0]'), opaque('x', 'pin[1]'))\n",
}


class TestTaintScanFlagsTheSecurityR24Variants8187R25(unittest.TestCase):
    """r25 sec S2 (security r24, ``taint_probe.py`` rebuilt): the reviewer's own 18 variants of the echo families plus the code lens's two (20), next to the
    22-shape corpus of ``TestTaintScanFlagsEveryEchoShape8187R24``; 20 of 20 red, the 3 clean controls stay clean."""

    def test_the_corpus_has_20_shapes_and_3_controls(self):
        self.assertEqual((len(TAINT_R25_SHAPES), len(TAINT_R25_CLEAN)), (20, 3))

    def test_each_variant_is_flagged(self):
        survivors = []
        for name, source in TAINT_R25_SHAPES.items():
            with self.subTest(shape=name):
                if not tainted_assert_lines(source):
                    survivors.append(name)
        self.assertEqual(survivors, [])

    def test_each_clean_control_stays_clean(self):
        for name, source in TAINT_R25_CLEAN.items():
            with self.subTest(shape=name):
                self.assertEqual(tainted_assert_lines(source), [])

    def test_the_22_shape_corpus_is_still_red(self):
        self.assertEqual([name for name, source in TAINT_SHAPES.items() if not tainted_assert_lines(source)], [])


# ---- r25 security S3 and S4: the notes channel is controlled; every forcing site is counted on its own ----
class TestEveryForcingSiteIsCounted8187R25(unittest.TestCase):
    """r25 sec S4 (security r24, forcing-site mutants rebuilt): removing any one of the six fail-path forcing sites turns the
    per-site coverage gate red; at r24 three of them left the gate green (the total fail-call count stayed above its floor)."""

    def test_the_six_sites_are_found_once_each(self):
        source = THIS_PATH.read_text(encoding="utf-8")
        self.assertEqual(len(FORCING_SITE_MUTANTS), 6)
        for name, (old, _new) in FORCING_SITE_MUTANTS.items():
            with self.subTest(site=name):
                self.assertEqual(source.count(old), 1)

    def test_the_unmutated_run_has_no_coverage_hole(self):
        run = canary_run(sys.modules[__name__], {"plain": CANARY_SHAPES["plain"]})
        self.assertEqual(canary_coverage_failures(run, ["plain"]), [])

    def test_every_forcing_site_mutant_is_red(self):
        ty_source = TY_PATH.read_text(encoding="utf-8")
        test_source = THIS_PATH.read_text(encoding="utf-8")
        survivors = []
        for name, (old, new) in FORCING_SITE_MUTANTS.items():
            with self.subTest(site=name):
                self.assertEqual(test_source.count(old), 1)
                variant = load_variant(ty_source, test_source.replace(old, new))
                failures = canary_coverage_failures(canary_run(variant, {"plain": CANARY_SHAPES["plain"]}), ["plain"])
                if not failures:
                    survivors.append(name)
                self.assertGreater(len(failures), 0)
        self.assertEqual(survivors, [])


# ---- r26 code C1-C6 (code r25): the sink table, the opaque snippets, the view gate and the cause-notes control ----
# the 26 output-sink shapes of the code r25 review's ``probes.py`` (check 3), verbatim; the first 19 were red at r25 head
TAINT_R26_SHAPES = {
    "lambda stored in a dict": TAINT_HEAD + "        d = {'k': lambda: text}\n        self.assertEqual(d['k'](), 'x')\n",
    "lambda in list, called later": TAINT_HEAD + "        fs = []\n        fs.append(lambda: text)\n        self.assertEqual(fs[0](), 'x')\n",
    "lambda kw-only default": TAINT_HEAD + "        f = lambda *, v=text: v\n        self.assertIn(f(), [])\n",
    "assert alias tuple unpack (3)": TAINT_HEAD + "        a, b, c = self.assertTrue, self.assertEqual, self.assertIn\n        b(text, 'x')\n",
    "raise from (name)": TAINT_HEAD + "        cause = ValueError(text)\n        raise RuntimeError('x') from cause\n",
    "add_note then raise": TAINT_HEAD + "        err = KeyError('k')\n        err.add_note(str(text))\n        raise err\n",
    "stdout.write(str())": TAINT_HEAD + "        import sys\n        sys.stdout.write('%s\\n' % text)\n",
    "stdout.write(text)": TAINT_HEAD + "        import sys\n        sys.stdout.write(text)\n",
    "partial(print, text)()": TAINT_HEAD + "        functools.partial(print, 'a', text)()\n",
    "os.write": TAINT_HEAD + "        import os\n        os.write(1, text.encode())\n",
    "print(file=stream)": TAINT_HEAD + "        import io\n        s = io.StringIO()\n        print(text, file=s)\n",
    "logging.Logger.log": TAINT_HEAD + "        import logging\n        logging.getLogger('x').log(40, text)\n",
    "logger var .log": TAINT_HEAD + "        import logging\n        logger = logging.getLogger('x')\n        logger.log(40, text)\n",
    "warnings.warn": TAINT_HEAD + "        import warnings\n        warnings.warn(text)\n",
    "sys.excepthook": TAINT_HEAD + "        import sys\n        sys.excepthook(ValueError, ValueError(text), None)\n",
    "traceback.print_exc": TAINT_HEAD + "        import traceback\n        try:\n            raise ValueError(text)\n"
                          "        except ValueError:\n            traceback.print_exc()\n",
    "traceback.print_exception": TAINT_HEAD + "        import traceback\n        traceback.print_exception(ValueError(text))\n",
    "f-string assert message": TAINT_HEAD + "        assert len(text) == 0, f'got {text}'\n",
    "stderr alias write": TAINT_HEAD + "        import sys\n        out = sys.stderr\n        out.write(text)\n",
    "sys.__stdout__.write": TAINT_HEAD + "        import sys\n        sys.__stdout__.write(text)\n",
    "print(*list)": TAINT_HEAD + "        print(*[text])\n",
    "pprint.pprint": TAINT_HEAD + "        import pprint\n        pprint.pprint(text)\n",
    "logging.log module fn": TAINT_HEAD + "        import logging\n        logging.log(40, text)\n",
    "subTest msg": TAINT_HEAD + "        with self.subTest(text):\n            pass\n",
    "assertEqual msg kw from text": TAINT_HEAD + "        self.assertEqual(1, 1, msg=text)\n",
    "bound write method": TAINT_HEAD + "        import sys\n        w = sys.stdout.write\n        w(text)\n",
}
TAINT_R26_MISSED_AT_R25 = (
    "os.write", "logging.Logger.log", "sys.excepthook", "traceback.print_exception", "stderr alias write", "sys.__stdout__.write",
    "bound write method")
TAINT_R26_CLEAN = {
    "len": TAINT_HEAD + "        self.assertEqual(len(text), 3)\n",
    "lambda param shadows": TAINT_HEAD + "        f = lambda text: 1\n        self.assertEqual(f(0), 1)\n",
    "write constant": TAINT_HEAD + "        import sys\n        sys.stdout.write('ok')\n",
    "raise constant from None": TAINT_HEAD + "        raise RuntimeError('x') from None\n",
    "logger constant": TAINT_HEAD + "        import logging\n        logging.getLogger('x').log(40, 'ok')\n",
    "excepthook constant": TAINT_HEAD + "        import sys\n        sys.excepthook(ValueError, ValueError('ok'), None)\n",
    "write of a length": TAINT_HEAD + "        import os\n        os.write(1, b'%d' % len(text))\n",
}

# the 16 gate snippets of the code r25 review's ``probes.py`` (check 6), verbatim; the first 8 were refused at r25 head
OPAQUE_R26_SNIPPETS = {
    "from tier_yaml_8187 import _RAW": "from tier_yaml_8187 import " + "_" + "RAW\n",
    "vars(ty)['_' + 'RAW']": "x = vars(ty)['_' + 'R' + 'AW']\n",
    "getattr(w, 'raw')()": "x = getattr(w, 'raw')()\n",
    "weakref.finalize._registry walk": "import weakref\nx = list(weakref.finalize._registry.values())\n",
    "f.__globals__": "x = f.__globals__\n",
    "object.__getattribute__ built name": "x = object.__getattribute__(ty, '_' + 'RAW')\n",
    "operator.attrgetter('_RAW')": "import operator\nx = operator.attrgetter('_R' + 'AW')(ty)\n",
    "Opaque.raw unbound (call)": "x = ty.Opaque.raw(w)\n",
    "vars(ty).values() walk": "x = [v for v in vars(ty).values() if isinstance(v, dict)]\n",
    "ty.__dict__.values() walk": "x = [v for v in ty.__dict__.values() if isinstance(v, dict)]\n",
    "gc.get_objects walk": "import gc\nx = [d for d in gc.get_objects() if isinstance(d, dict)]\n",
    "inspect.getmembers(ty)": "import inspect\nx = dict(inspect.getmembers(ty))\n",
    "sys.modules lookup .__dict__ values": "import sys\nx = list(sys.modules['tier_yaml_8187'].__dict__.values())\n",
    "bound method alias m = w.raw; m()": "m = w.raw\nx = m()\n",
    "methodcaller('raw')": "import operator\nx = operator.methodcaller('raw')(w)\n",
    "Opaque.raw.__get__(w)()": "x = ty.Opaque.raw.__get__(w)()\n",
}
OPAQUE_R26_PASSED_AT_R25 = (
    "vars(ty).values() walk", "ty.__dict__.values() walk", "gc.get_objects walk", "inspect.getmembers(ty)",
    "sys.modules lookup .__dict__ values", "bound method alias m = w.raw; m()", "methodcaller('raw')", "Opaque.raw.__get__(w)()")
# forms the positive gate accepts: a public name of the checker module, ``sys.modules[__name__]``, a constant name, a stdlib import
OPAQUE_R26_ACCEPTED = {
    "public name of the module": "x = ty.parse_workflow(text)\ny = ty.Opaque(text, 'key[0]')\nz = ty.__file__\n",
    "module table of this module": "import sys\nm = sys.modules[__name__]\n",
    "constant getattr": "x = getattr(w, 'label', None)\n",
    "stdlib imports": "import json, re, weakref\nfrom pathlib import Path\nx = json.dumps({})\n",
    "exception chain": "try:\n    pass\nexcept ValueError as exc:\n    x = exc.__cause__, exc.__context__, exc.__traceback__\n",
}


def opaque_refusals(source):
    """Line numbers refused by the two source gates together (the review counts a snippet refused when either gate refuses it)."""
    return sorted({*opaque_escape_lines(source, allowed=OPAQUE_GATE_ALLOWED), *raw_unwrap_lines(source)})


class TestTaintScanFollowsEveryOutputSink8187R26(unittest.TestCase):
    """r26 code C2 (code r25, finding 2): the 26 sink shapes of the review's probe are this test's own table; each is red, and
    each of the seven the r25 scanner missed (fd write, inline logger, exception hook, ``print_exception``, a stream alias, a
    dunder stream, a bound ``write``) is named."""

    def test_the_table_has_26_shapes_and_the_seven_named_survivors(self):
        self.assertEqual(len(TAINT_R26_SHAPES), 26)
        self.assertEqual(sorted(set(TAINT_R26_MISSED_AT_R25) - set(TAINT_R26_SHAPES)), [])
        self.assertEqual(len(TAINT_R26_MISSED_AT_R25), 7)

    def test_every_shape_is_flagged(self):
        survivors = []
        for name, source in TAINT_R26_SHAPES.items():
            with self.subTest(shape=name):
                if not tainted_assert_lines(source):
                    survivors.append(name)
        self.assertEqual(survivors, [])

    def test_each_of_the_seven_previously_missed_shapes_is_red_on_its_own(self):
        for name in TAINT_R26_MISSED_AT_R25:
            with self.subTest(shape=name):
                self.assertGreater(len(tainted_assert_lines(TAINT_R26_SHAPES[name])), 0)

    def test_each_clean_control_stays_clean(self):
        for name, source in TAINT_R26_CLEAN.items():
            with self.subTest(shape=name):
                self.assertEqual(tainted_assert_lines(source), [])

    def test_both_shipped_files_have_no_tainted_line(self):
        for path in (TY_PATH, THIS_PATH):
            with self.subTest(file=path.name):
                self.assertEqual(tainted_assert_lines(path.read_text(encoding="utf-8")), [])


class TestOpaqueGateEnumeratesTheAcceptedPaths8187R26(unittest.TestCase):
    """r26 code C3 (code r25, finding 3): the 16 snippets of the review's probe are refused, among them the 8 the r25 gates
    passed.  The gate names what it accepts (public names of the checker module, ``sys.modules[__name__]``, constant
    attribute names, listed imports) and refuses everything else, so the next spelling of a namespace walk is refused too."""

    def test_the_table_has_16_snippets_and_the_eight_named_survivors(self):
        self.assertEqual(len(OPAQUE_R26_SNIPPETS), 16)
        self.assertEqual(len(OPAQUE_R26_PASSED_AT_R25), 8)
        self.assertEqual(sorted(set(OPAQUE_R26_PASSED_AT_R25) - set(OPAQUE_R26_SNIPPETS)), [])

    def test_every_snippet_is_refused(self):
        survivors = []
        for name, source in OPAQUE_R26_SNIPPETS.items():
            with self.subTest(snippet=name):
                if not opaque_refusals(source):
                    survivors.append(name)
        self.assertEqual(survivors, [])

    def test_each_of_the_eight_previously_passing_snippets_is_refused_on_its_own(self):
        for name in OPAQUE_R26_PASSED_AT_R25:
            with self.subTest(snippet=name):
                self.assertGreater(len(opaque_refusals(OPAQUE_R26_SNIPPETS[name])), 0)

    def test_the_accepted_paths_are_not_refused(self):
        for name, source in OPAQUE_R26_ACCEPTED.items():
            with self.subTest(path=name):
                self.assertEqual(opaque_refusals(source), [])

    def test_both_shipped_files_pass_the_enumerating_gates(self):
        for path in (TY_PATH, THIS_PATH):
            with self.subTest(file=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertEqual(opaque_escape_lines(source, allowed=OPAQUE_GATE_ALLOWED), [])
                allowed = ("same", "__eq__", "__hash__") if path == TY_PATH else ()
                self.assertEqual(raw_unwrap_lines(source, allowed=allowed), [])


class TestEveryFailScenarioRunsInEveryView8187R26(unittest.TestCase):
    """r26 code C1 (code r25, finding 1): the gate counts each guarded family per view again.  A mutant that runs the real-pins
    fail scenario in one view only (either) is red, and the views each family really runs in are the table's."""

    def test_the_views_each_family_runs_in_are_the_tables(self):
        run = canary_run(sys.modules[__name__], {"plain": CANARY_SHAPES["plain"]})
        families = {family for guarded in (CANARY_GUARDED_FAMILIES, CANARY_GUARDED_FAMILIES_PLAIN)
                    for names in guarded.values() for family in names}
        for family in sorted(families):
            with self.subTest(family=family):
                seen = tuple(view for view in CANARY_BOTH_VIEWS if run.fail_families.get(("plain", view, family), 0) > 0)
                self.assertEqual(seen, CANARY_FAMILY_VIEWS.get(family, CANARY_BOTH_VIEWS))

    def test_the_view_mutants_are_in_the_harness_table_and_found_once(self):
        source = THIS_PATH.read_text(encoding="utf-8")
        for name, (old, _new) in VIEW_SITE_MUTANTS.items():
            with self.subTest(mutant=name):
                self.assertIn("view dropped: " + name, HARNESS_MUTANTS)
                self.assertEqual(source.count(old), 1)

    def test_each_view_mutant_is_red_and_names_the_view(self):
        ty_source = TY_PATH.read_text(encoding="utf-8")
        test_source = THIS_PATH.read_text(encoding="utf-8")
        for name, (old, new) in VIEW_SITE_MUTANTS.items():
            with self.subTest(mutant=name):
                variant = load_variant(ty_source, test_source.replace(old, new))
                failures = canary_coverage_failures(canary_run(variant, {"plain": CANARY_SHAPES["plain"]}), ["plain"])
                self.assertEqual(len(failures), 1)
                self.assertIn("family fail-real-pins never ran", failures[0])


class TestNotesOnTheCauseAreCaptured8187R26(unittest.TestCase):
    """r26 code C4 (code r25, finding 4): a note attached to the ``__cause__`` of the raised exception has its own seeded
    control, and the harness mutant that strips the notes of the cause chain is red."""

    @unittest.skipIf(sys.version_info < (3, 11), "exception notes exist from Python 3.11")
    def test_the_cause_notes_control_exists_and_is_live(self):
        names = set(canary_controls(CanaryRun(sys.modules[__name__])))
        self.assertIn("exception-cause-notes", names)
        self.assertEqual(canary_control_failures(sys.modules[__name__]), [])

    @unittest.skipIf(sys.version_info < (3, 11), "exception notes exist from Python 3.11")
    def test_stripping_the_notes_of_the_cause_chain_is_red(self):
        variant = load_variant(TY_PATH.read_text(encoding="utf-8"),
                               harness_mutant_source(THIS_PATH.read_text(encoding="utf-8"), "cause-notes-strip", "exception-chain"))
        self.assertEqual(canary_control_failures(variant), ["exception-cause-notes"])

# r26 sec F1: the 44 output-call shapes of the security r25 review's ``taint_probe.py`` (check 3), verbatim except that the two
# ``assertTrue`` lambda shapes are spelled with ``assertEqual`` (``assertTrue(x)`` fails only on a falsy ``x``, which carries no
# text, so it is not a sink by design; the review's own confirmation run uses ``assertEqual`` for the same shapes)
TAINT_R26_SEC_HEAD = ('import unittest, functools, re, traceback, sys, os, logging, warnings, pprint\n'
    'from functools import partial as P\n'
    'class T(unittest.TestCase):\n'
    '    def test(self):\n'
    '        body = load_job_pins()\n')
TAINT_R26_SEC_SHAPES = {
    'r24-1 lambda in dict': TAINT_R26_SEC_HEAD + "        fs = {'a': lambda: body}\n        self.assertEqual(fs['a'](), 'x')\n",
    'r24-1 lambda in tuple': TAINT_R26_SEC_HEAD + "        fs = (lambda: body,)\n        self.assertEqual(fs[0](), 'x')\n",
    'r24-2 lambda positional default': TAINT_R26_SEC_HEAD + "        f = lambda a, v=body: v\n        self.assertEqual(f(1), 'x')\n",
    'r24-3 alias by list unpack': TAINT_R26_SEC_HEAD + "        [eq] = [self.assertEqual]\n        eq(body, 'x')\n",
    'r24-3 alias by starred unpack': TAINT_R26_SEC_HEAD + "        eq, *_ = (self.assertEqual, 1)\n        eq(body, 'x')\n",
    'r24-4 raise from str()': TAINT_R26_SEC_HEAD + "        raise KeyError('k') from RuntimeError(str(body))\n",
    'r24-4 raise from bound exc': TAINT_R26_SEC_HEAD + "        cause = ValueError(body)\n        raise KeyError('k') from cause\n",
    'r24-5 add_note f-string': TAINT_R26_SEC_HEAD + "        err = RuntimeError('x')\n        err.add_note(f'{body}')\n        raise err\n",
    'r24-5 __notes__ assignment': TAINT_R26_SEC_HEAD + "        err = RuntimeError('x')\n        err.__notes__ = [body]\n        raise err\n",
    'r24-6 stderr.write repr': TAINT_R26_SEC_HEAD + '        sys.stderr.write(repr(body))\n',
    'r24-6 aliased stream write': TAINT_R26_SEC_HEAD + '        out = sys.stdout\n        out.write(body)\n',
    'c4 stdout.write bare': TAINT_R26_SEC_HEAD + '        sys.stdout.write(body)\n',
    'c4 partial(print)(text)': TAINT_R26_SEC_HEAD + '        functools.partial(print)(body)\n',
    'c4 P(print, text)()': TAINT_R26_SEC_HEAD + '        P(print, body)()\n',
    'os.write': TAINT_R26_SEC_HEAD + '        os.write(2, body.encode())\n',
    'print file= keyword first': TAINT_R26_SEC_HEAD + '        print(file=sys.stderr, *[body])\n',
    'print sep=': TAINT_R26_SEC_HEAD + "        print('a', 'b', sep=body)\n",
    'print end=': TAINT_R26_SEC_HEAD + "        print('a', end=body)\n",
    'Logger.log': TAINT_R26_SEC_HEAD + "        logging.getLogger('x').log(30, body)\n",
    'bound logger var .log': TAINT_R26_SEC_HEAD + "        lg = logging.getLogger('x')\n        lg.log(30, '%s', body)\n",
    'warnings.warn': TAINT_R26_SEC_HEAD + '        warnings.warn(body)\n',
    'warnings.warn_explicit': TAINT_R26_SEC_HEAD + "        warnings.warn_explicit(body, UserWarning, 'f', 1)\n",
    'sys.excepthook': TAINT_R26_SEC_HEAD + '        sys.excepthook(ValueError, ValueError(body), None)\n',
    'traceback.print_exc after raise': TAINT_R26_SEC_HEAD + '        try:\n            raise ValueError(body)\n        except ValueError:\n            traceback.print_exc()\n',
    'traceback.print_exception': TAINT_R26_SEC_HEAD + '        traceback.print_exception(ValueError(body))\n',
    'assert stmt f-string msg': TAINT_R26_SEC_HEAD + "        assert len(body) == 3, f'{body}'\n",
    'assertTrue f-string msg': TAINT_R26_SEC_HEAD + "        self.assertTrue(False, f'{body!r}')\n",
    'assert msg .format': TAINT_R26_SEC_HEAD + "        self.assertTrue(False, '{}'.format(body))\n",
    'fail percent': TAINT_R26_SEC_HEAD + "        self.fail('%s' % (body,))\n",
    'assertEqual starred': TAINT_R26_SEC_HEAD + "        self.assertEqual(*[body, 'x'])\n",
    'assertEqual double-star': TAINT_R26_SEC_HEAD + "        self.assertEqual(**{'first': body, 'second': 'x'})\n",
    'sys.exit(text)': TAINT_R26_SEC_HEAD + '        sys.exit(body)\n',
    'raise SystemExit(text)': TAINT_R26_SEC_HEAD + '        raise SystemExit(body)\n',
    'input(prompt)': TAINT_R26_SEC_HEAD + '        input(body)\n',
    'writelines': TAINT_R26_SEC_HEAD + '        sys.stdout.writelines([body])\n',
    'pprint.pprint': TAINT_R26_SEC_HEAD + '        pprint.pprint(body)\n',
    'stdout.buffer.write': TAINT_R26_SEC_HEAD + '        sys.stdout.buffer.write(body.encode())\n',
    'sys.__stderr__.write': TAINT_R26_SEC_HEAD + '        sys.__stderr__.write(body)\n',
    'msg= keyword': TAINT_R26_SEC_HEAD + '        self.assertTrue(False, msg=body)\n',
    'subTest kw': TAINT_R26_SEC_HEAD + '        with self.subTest(v=body):\n            pass\n',
    'plain raise': TAINT_R26_SEC_HEAD + '        raise ValueError(body)\n',
    'walrus': TAINT_R26_SEC_HEAD + "        if (v := body):\n            self.assertEqual(v, 'x')\n",
    'for target': TAINT_R26_SEC_HEAD + "        for v in [body]:\n            self.assertEqual(v, 'x')\n",
    'with as': TAINT_R26_SEC_HEAD + "        with open(body) as fh:\n            self.assertEqual(fh, 'x')\n",
}
TAINT_R26_SEC_CLEAN = {
    'len only': TAINT_R26_SEC_HEAD + '        self.assertEqual(len(body), 3)\n',
    'bool search': TAINT_R26_SEC_HEAD + "        self.assertIs(bool(re.search('a', str(body))), True)\n",
    'opaque wrapped': TAINT_R26_SEC_HEAD + "        self.assertEqual(opaque(body, 'pin[0]'), opaque('x', 'pin[1]'))\n",
    'constant print': TAINT_R26_SEC_HEAD + "        print('done', len(body))\n",
    'compare only': TAINT_R26_SEC_HEAD + "        self.assertTrue(body == 'x')\n",
}
# the 15 of the 44 the r25 scanner passed (13 real sinks and the two ``assertTrue`` spellings above)
TAINT_R26_SEC_PASSED_AT_R25 = (
    'r24-1 lambda in tuple',
    'r24-2 lambda positional default',
    'r24-6 aliased stream write',
    'c4 P(print, text)()',
    'os.write',
    'Logger.log',
    'bound logger var .log',
    'warnings.warn_explicit',
    'sys.excepthook',
    'traceback.print_exception',
    'sys.exit(text)',
    'input(prompt)',
    'stdout.buffer.write',
    'sys.__stderr__.write',
    'walrus')

# r26 sec F1: the 21 bypass snippets of the security r25 review's ``opaque_r25.py`` (check 6), verbatim (the private name is spelled
# in parts so this table does not contain it)
OPAQUE_R26_SEC_SNIPPETS = {
    'from-import': 'from tier_yaml_8187 import _' 'RAW as R\n',
    'vars built name': "x = vars(ty)['_' + 'RAW']\n",
    'getattr raw': "x = getattr(w, 'raw')()\n",
    'finalize registry': 'import weakref\nx = weakref.finalize._registry\n',
    'func globals': 'x = f.__globals__\n',
    'getattr nonconstant': 'x = getattr(ty, n)\n',
    'object.__getattribute__ raw': "x = object.__getattribute__(w, 'raw')()\n",
    'w.__getattribute__ raw': "x = w.__getattribute__('raw')()\n",
    'operator.methodcaller raw': "import operator\nx = operator.methodcaller('raw')(w)\n",
    'operator.attrgetter raw': "import operator\nx = operator.attrgetter('raw')(w)()\n",
    'bound method alias': 'f = w.raw\nx = f()\n',
    'type dict raw': "x = type(w).__dict__['raw'](w)\n",
    'vars(ty).get(name)': 'x = vars(ty).get(n)\n',
    'vars(ty).values() walk': 'x = [v for v in vars(ty).values() if isinstance(v, dict)]\n',
    'inspect.getmembers': 'import inspect\nx = inspect.getmembers(ty)\n',
    'join-built name': "x = vars(ty)[''.join(['_', 'R', 'AW'])]\n",
    'attrgetter join-built': "import operator\nx = operator.attrgetter(''.join(['_', 'RAW']))(ty)\n",
    'gc.get_referents func': 'import gc\nx = gc.get_referents(ty.Opaque.raw)\n',
    'gc.get_referrers': 'import gc\nx = gc.get_referrers(value)\n',
    'sys.modules dict': "import sys\nx = sys.modules['tier_yaml_8187'].__dict__\n",
    'closure cells': 'x = ty.Opaque.raw.__code__.co_names\n',
}
OPAQUE_R26_SEC_PASSED_AT_R25 = (
    'object.__getattribute__ raw',
    'w.__getattribute__ raw',
    'operator.methodcaller raw',
    'operator.attrgetter raw',
    'bound method alias',
    'type dict raw',
    'vars(ty).get(name)',
    'vars(ty).values() walk',
    'inspect.getmembers',
    'attrgetter join-built',
    'gc.get_referents func',
    'gc.get_referrers',
    'sys.modules dict',
    'closure cells')


class TestTaintScanFollowsEverySecurityShape8187R26(unittest.TestCase):
    """r26 sec F1 (security r25, finding 1; code r25 C2 widened): the 44 output-call shapes of the security review's probe are
    this test's own table, each red, with the 15 the r25 scanner passed named and the 5 clean controls clean."""

    def test_the_table_has_44_shapes_5_controls_and_the_named_survivors(self):
        self.assertEqual(len(TAINT_R26_SEC_SHAPES), 44)
        self.assertEqual(len(TAINT_R26_SEC_CLEAN), 5)
        self.assertEqual(len(TAINT_R26_SEC_PASSED_AT_R25), 15)
        self.assertEqual(sorted(set(TAINT_R26_SEC_PASSED_AT_R25) - set(TAINT_R26_SEC_SHAPES)), [])

    def test_every_shape_is_flagged(self):
        survivors = []
        for name, source in TAINT_R26_SEC_SHAPES.items():
            with self.subTest(shape=name):
                if not tainted_assert_lines(source):
                    survivors.append(name)
        self.assertEqual(survivors, [])

    def test_each_previously_passing_shape_is_red_on_its_own(self):
        for name in TAINT_R26_SEC_PASSED_AT_R25:
            with self.subTest(shape=name):
                self.assertGreater(len(tainted_assert_lines(TAINT_R26_SEC_SHAPES[name])), 0)

    def test_each_clean_control_stays_clean(self):
        for name, source in TAINT_R26_SEC_CLEAN.items():
            with self.subTest(shape=name):
                self.assertEqual(tainted_assert_lines(source), [])


class TestOpaqueGateRefusesEverySecurityBypass8187R26(unittest.TestCase):
    """r26 sec F1 (security r25, finding 1; code r25 C3 widened): the 21 bypass snippets of the security review's probe are this
    test's own table, each refused, with the 14 the r25 gates passed named."""

    def test_the_table_has_21_snippets_and_the_named_survivors(self):
        self.assertEqual(len(OPAQUE_R26_SEC_SNIPPETS), 21)
        self.assertEqual(len(OPAQUE_R26_SEC_PASSED_AT_R25), 14)
        self.assertEqual(sorted(set(OPAQUE_R26_SEC_PASSED_AT_R25) - set(OPAQUE_R26_SEC_SNIPPETS)), [])

    def test_every_snippet_is_refused(self):
        survivors = []
        for name, source in OPAQUE_R26_SEC_SNIPPETS.items():
            with self.subTest(snippet=name):
                if not opaque_refusals(source):
                    survivors.append(name)
        self.assertEqual(survivors, [])

    def test_each_previously_passing_snippet_is_refused_on_its_own(self):
        for name in OPAQUE_R26_SEC_PASSED_AT_R25:
            with self.subTest(snippet=name):
                self.assertGreater(len(opaque_refusals(OPAQUE_R26_SEC_SNIPPETS[name])), 0)


class TestEveryFamilyRunsInEveryView8187R26(unittest.TestCase):
    """r26 sec F2 (security r25, finding 2): skipping the text view of ``fail-real-pins``, ``fail-other-values`` or
    ``fail-real-text-own-pins`` is red, one mutant each."""

    def test_the_three_families_have_a_text_view_in_the_unmutated_run(self):
        run = canary_run(sys.modules[__name__], {"plain": CANARY_SHAPES["plain"]})
        for family in TEXT_VIEW_FAMILIES:
            with self.subTest(family=family):
                self.assertGreater(run.fail_families.get(("plain", "text", family), 0), 0)

    def test_each_text_view_mutant_is_in_the_harness_table_found_once_and_red(self):
        ty_source = TY_PATH.read_text(encoding="utf-8")
        test_source = THIS_PATH.read_text(encoding="utf-8")
        for family, (old, new) in TEXT_VIEW_MUTANTS.items():
            with self.subTest(family=family):
                self.assertIn("text view skipped: " + family, HARNESS_MUTANTS)
                self.assertEqual(test_source.count(old), 1)
                variant = load_variant(ty_source, test_source.replace(old, new))
                failures = canary_coverage_failures(canary_run(variant, {"plain": CANARY_SHAPES["plain"]}), ["plain"])
                self.assertGreater(len(failures), 0)
                self.assertTrue(all("family %s never ran" % family in line for line in failures), failures)


class TestNotesOnEveryChainLinkAreCaptured8187R26(unittest.TestCase):
    """r26 sec F3 (security r25, finding 3): a note on the ``__cause__`` and a note on the implicit ``__context__`` each have a
    seeded control, and the mutants that strip the notes of the context chain and of both links are red."""

    @unittest.skipIf(sys.version_info < (3, 11), "exception notes exist from Python 3.11")
    def test_both_chain_controls_exist_and_are_live(self):
        names = set(canary_controls(CanaryRun(sys.modules[__name__])))
        self.assertTrue({"exception-cause-notes", "exception-context-notes"} <= names)
        self.assertEqual(canary_control_failures(sys.modules[__name__]), [])

    @unittest.skipIf(sys.version_info < (3, 11), "exception notes exist from Python 3.11")
    def test_each_link_strip_is_red_for_its_own_control(self):
        ty_source = TY_PATH.read_text(encoding="utf-8")
        test_source = THIS_PATH.read_text(encoding="utf-8")
        wanted = {"cause-notes-strip": ["exception-cause-notes"], "context-notes-strip": ["exception-context-notes"],
                  "link-notes-strip": ["exception-cause-notes", "exception-context-notes"]}
        for kind, controls in wanted.items():
            with self.subTest(kind=kind):
                variant = load_variant(ty_source, harness_mutant_source(test_source, kind, "exception-chain"))
                self.assertEqual(sorted(canary_control_failures(variant)), controls)


if __name__ == "__main__":
    if "--write-pins" in sys.argv[1:]:
        # regenerate all three pin sections from the workflows; the diff of the data file is what a reviewer reads
        flags = sys.argv[1:]
        write_pins(flags[flags.index("--out") + 1] if "--out" in flags else None)
        sys.exit(0)
    sys.exit(unittest.main())
