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
workflow, job, step index, step name or id and the first differing key path, and mask ``scheme://user:pass@``.

Residual (documented, #8187 umbrella item): the URL file is provisioned by the operator in the runner user's home
and stays there between jobs, on both self-hosted runner classes (linux-fed and macos-fed).  Code run there by the
pinned tier jobs or by the pinned exempt job ``lifetime-tests`` can read it, and no check in this repository can stop
that: the checks here pin which jobs, steps and labels this repository's workflows may use on those runners, they do
not isolate the file.  Closing it needs a per-job credential at the operator's runner, the operator item #6181.

Needs PyYAML (``python3 -m pip install --require-hashes --no-deps -r scripts/test/requirements-ci.txt``); a missing
module is an import error of this module, never a skip.
"""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

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
    except ty.yaml.YAMLError:
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
    return owner, f"step[{owner}]"


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
            problems.append(f"{workflow}: the pinned workflow-level {key}: block is missing")
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
    name, and the first differing key path (``steps[3].run``), never the changed value; every message is masked.
    A non-tier job must run on a GitHub-hosted label, and no local action or reusable workflow may be called.
    """
    data, found = ty.parse_workflow(text)
    problems = [f"{workflow}: {p}" for p in found]
    if data is None or not isinstance(data.get("jobs"), dict):
        return [ty.mask_userinfo(p) for p in problems]
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
    return [ty.mask_userinfo(p) for p in problems]


def tier_pin_problems(workflow, text, pins=None):
    """Primary (loader, canonical JSON) problems first, then the secondary whole-job text pin of r7."""
    pins = load_job_pins() if pins is None else pins
    return primary_pin_problems(workflow, text, pins[PRIMARY]) + [
        ty.mask_userinfo(p) for p in job_pin_problems(workflow, text, pins[SECONDARY])]


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
        except ty.yaml.YAMLError as exc:
            found.append(f"{name}: the workflow does not load ({type(exc).__name__}); an unparsable workflow is refused")
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
        except ty.yaml.YAMLError:
            pass  # reported above as an unparsable workflow
    actions = root / ".github" / "actions"
    for path in sorted([*actions.rglob("action.yml"), *actions.rglob("action.yaml")]) if actions.is_dir() else []:
        if names_the_tier(path.read_text(encoding="utf-8")):
            found.append(f"{path.relative_to(root)}: a local action names the tier secret")
    return [ty.mask_userinfo(p) for p in found]

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
        self.assertEqual(sorted(set(tier_workflows()) - covered), [],
                         "a workflow names the tier secret but no pin covers it: route it through tier_credential.py")
        self.assertEqual(sorted(covered - set(tier_workflows())), [], "a covered workflow no longer names the tier")

    def test_the_shared_tier_workflows_never_put_the_url_on_argv_or_in_github_env(self):
        for name in SHARED_TIER:
            with self.subTest(workflow=name):
                self.assertEqual(workflow_problems((WORKFLOWS / name).read_text(encoding="utf-8")), [])

    def test_the_local_only_workflows_hold_no_tier_url(self):
        for name, literal in LOCAL_ONLY.items():
            text = (WORKFLOWS / name).read_text(encoding="utf-8")
            self.assertNotIn("ai-memory-ci-fed-url", text)
            for line in code_lines(text):
                if TIER_MARKERS.search(line):
                    self.assertIn(literal, line, "only a literal throwaway local database may name the variable")

    def test_each_mutant_of_a_shared_workflow_is_caught(self):
        text = (WORKFLOWS / "cert-postgres-age.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow_problems(text), [])
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
                self.assertNotEqual(edited, text, "the mutation did not apply")
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
                self.assertNotEqual(edited, text, "the mutation did not apply")
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
                self.assertNotEqual(edited, text, "the mutation did not apply")
                self.assertTrue(workflow_problems(edited), f"mutant not caught: {name}")

    def test_environment_dumps_are_rejected_in_every_shared_workflow_8187(self):
        # F8: ci.yml already rejects these; the shared workflows must too
        anchor = '          if [ ! -f "$url_file" ]; then'
        extra = {"env piped to base64": "env | base64", "printenv piped to base64": "printenv | base64",
                 "xtrace": "set -x", "xtrace by option": "set -o xtrace", "printenv chain": "true; printenv",
                 "bare env": "env", "export -p": "export -p"}
        for name in SHARED_TIER:
            text = (WORKFLOWS / name).read_text(encoding="utf-8")
            self.assertEqual(workflow_problems(text), [])
            for label, line in extra.items():
                with self.subTest(workflow=name, mutant=label):
                    edited = text.replace(anchor, "          " + line + "\n" + anchor, 1)
                    if edited == text:
                        edited = text.replace("      - name:", "      - run: " + line + "\n      - name:", 1)
                    self.assertNotEqual(edited, text, "the mutation did not apply")
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
                    self.assertNotEqual(edited, text, "the mutation did not apply")
                    self.assertTrue(workflow_problems(edited), f"mutant not caught: {label}")
                with self.subTest(workflow=name, mutant=label, form="one-line step"):
                    edited = text.replace("      - name:", "      - run: " + line + "\n      - name:", 1)
                    self.assertNotEqual(edited, text, "the mutation did not apply")
                    self.assertTrue(workflow_problems(edited), f"mutant not caught: {label}")
        for name in SHARED_TIER:
            self.assertEqual(workflow_problems((WORKFLOWS / name).read_text(encoding="utf-8")), [])
        self.assertEqual(url_leaks(ci_text), [])

    def test_a_yaml_workflow_naming_the_tier_secret_is_checked_8187(self):
        scratch = ROOT / ".local-runs" / "r3"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch, prefix="wf-") as raw:
            directory = Path(raw)
            (directory / "scratch-tier.yaml").write_text("steps:\n  - run: cat ~/.ai-memory-ci-fed-url\n", encoding="utf-8")
            (directory / "other.yml").write_text("steps:\n  - run: echo hi\n", encoding="utf-8")
            self.assertEqual(tier_workflows(directory), ["scratch-tier.yaml"])


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
                self.assertEqual(tier_pin_problems(wf, text, self.pins), [])
                self.assertTrue(self.pins[SECONDARY].get(wf, {}).get("pinned"), "no job is pinned for this workflow")

    def test_a_changed_line_is_never_echoed_into_a_problem_8187_f24(self):
        sentinel = "SENTINEL-F24-9f3a"
        echo = "found " + chr(39)
        seen = {"job": 0, "workflow-level": 0}
        for wf, text in self.texts.items():
            for step in pin_targets(wf, text)[:1]:
                edited = inject_run_line(text, step, f"echo {sentinel}")
                problems = job_pin_problems(wf, edited, self.pins[SECONDARY])
                hits = [p for p in problems if f"{wf} job {step[0]} " in p and "differs from the pin" in p]
                with self.subTest(workflow=wf, site="job"):
                    self.assertTrue(hits, "the job-level difference is reported with its key path")
                    seen["job"] += 1
                    self.assertFalse([p for p in problems if sentinel in p or echo in p])
            lines = text.split("\n")
            at = next((i for i, ln in enumerate(lines) if ln.startswith("env:")), None)
            if at is None:
                continue
            lines.insert(at + 1, f"  F24_KEY: {sentinel}")
            problems = job_pin_problems(wf, "\n".join(lines), self.pins[SECONDARY])
            with self.subTest(workflow=wf, site="workflow-level"):
                self.assertTrue([p for p in problems if f"{wf}: the workflow-level env: block differs" in p])
                seen["workflow-level"] += 1
                self.assertFalse([p for p in problems if sentinel in p or echo in p])
        self.assertGreater(seen["job"], 0)
        self.assertGreater(seen["workflow-level"], 0)

    def test_the_pin_table_holds_exactly_the_jobs_that_name_the_tier(self):
        self.assertEqual(sorted(self.pins[SECONDARY]), sorted(PIN_WORKFLOWS))
        for wf, text in self.texts.items():
            jobs, problems = job_layout(text)
            self.assertEqual(problems, [])
            self.assertEqual(self.pins[SECONDARY][wf]["jobs"], [j[0] for j in jobs])
            for name, block in tier_blocks(jobs):
                self.assertEqual(self.pins[SECONDARY][wf]["pinned"][name], pin_entry(block), f"{wf}:{name}")
            self.assertEqual(sorted(self.pins[SECONDARY][wf]["pinned"]), sorted(n for n, _ in tier_blocks(jobs)))

    def test_every_dump_form_after_the_export_fails_the_pin(self):
        forms = {**DUMP_MUTANTS, **F10_MUTANTS}
        self.assertGreaterEqual(len(forms), 57)
        for wf, text in self.texts.items():
            targets = pin_targets(wf, text)
            self.assertTrue(targets, f"{wf}: no post-export step with a run block to mutate")
            for step in targets:
                for label, line in forms.items():
                    with self.subTest(workflow=wf, step=step[1], mutant=label):
                        edited = inject_run_line(text, step, line)
                        self.assertIsNotNone(edited)
                        self.assertNotEqual(edited, text, "the mutation did not apply")
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
                    self.assertTrue(any("second" in p and "not pinned" in p for p in problems), problems)

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
            for step in pin_targets(wf, text):
                pad = " " * (indent_of(step[2].split("\n")[0]) + 2)
                for label, keys in (("env", [pad + "env:", pad + "  BASH_ENV: x"]),
                                    ("shell", [pad + "shell: bash -x {0}"]),
                                    ("with", [pad + "with:", pad + "  key: value"])):
                    with self.subTest(workflow=wf, step=step[1], keys=label):
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
                self.assertNotEqual(swapped, lines)
                self.caught(wf, "\n".join(swapped), "reordered")
            for where, step in (("first", steps_found[0]), ("last", steps_found[-1])):
                if step[2].lstrip().startswith("- name:"):
                    with self.subTest(workflow=wf, edit=f"renamed {where} step, same body"):
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
                with self.subTest(workflow=wf, job=name):
                    edited = "\n".join(lines[:first + 1] + ["    # edited freely"] + lines[first + 1:])
                    self.assertEqual(tier_pin_problems(wf, edited, self.pins), [])
                    checked += 1
        self.assertGreater(checked, 0, "no job outside the tier job to edit")

    def test_the_failure_message_names_the_workflow_job_step_and_first_differing_line(self):
        wf = "cert-postgres-age.yml"
        text = self.texts[wf]
        step = next(s for s in pin_targets(wf, text) if "Cleanup" in s[1])
        edited = inject_run_line(text, step, "printenv | base64")
        message = "\n".join(tier_pin_problems(wf, edited, self.pins))
        index = [s[3] for s in job_steps(wf, text)].index(step[3])
        for part in (wf, step[0], step[1], "line ", f"step {index}"):
            self.assertIn(part, message)
        self.assertNotIn("printenv | base64", message)  # r13 F24: the changed line is never echoed

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
                    self.assertNotEqual(edited, text)
                    self.assertTrue(workflow_problems(edited), f"mutant not caught: {label}")
        ci_anchor = 'echo "::notice::[enterprise-fed] created'
        ci_text = self.texts["ci.yml"]
        for label, line in extra.items():
            with self.subTest(workflow="ci.yml", mutant=label):
                pad = "          "
                edited = sub_once(ci_text, ci_anchor, pad + line.replace("\n", "\n" + pad) + "\n" + pad + ci_anchor)
                self.assertTrue(url_leaks(edited), f"mutant not caught: {label}")
        self.assertEqual(joined_lines(["prin\\", "  tenv x", "echo ok"]), ["printenv x", "echo ok"])


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
                self.assertEqual(primary_pin_problems(wf, text, self.pins[PRIMARY]), [])
                self.assertEqual(tier_pin_problems(wf, text, self.pins), [])
                self.assertEqual(self.pins[PRIMARY][wf], ty.build_pins(data))
        self.assertEqual(repo_problems(ROOT, self.pins), [])

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
                self.assertIsNone(data, f"duplicate key accepted: {label}")
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
                self.assertIsNone(data, f"accepted: {label}")
                self.assertTrue(problems)

    def test_on_is_read_as_a_string_and_the_top_level_key_set_is_closed(self):
        data, problems = ty.parse_workflow("name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n")
        self.assertEqual(problems, [])
        self.assertIn("on", data)
        self.assertNotIn(True, data)
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
                    self.assertNotEqual(edited, text)
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
                    self.assertNotEqual(edited, text)
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
        self.assertEqual(repo_problems(root, self.pins), [])

    def test_an_unparsable_workflow_is_a_problem_not_skipped_8187_f18(self):
        body = "name: o\non: push\njobs:\n  j:\n    runs-on:\t[self-hosted]\n    steps:\n      - run: echo hi\n"
        root = self.tree(extra={".github/workflows/broken.yml": body})
        problems = repo_problems(root, self.pins)
        self.assertTrue(any("broken.yml" in p and "Error" in p for p in problems), problems)
        self.assertFalse(any("echo hi" in p for p in problems), problems)

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
        self.assertEqual(repo_problems(self.tree(), self.pins), [])
        mutants = {
            "macos-fed moved to the tier label": text.replace('["self-hosted","macos-fed"]', '["self-hosted","linux-fed"]'),
            "extra self-hosted leg": text.replace("          - os: macos-fed\n",
                '          - os: other\n            runner: \'["self-hosted","linux-fed"]\'\n          - os: macos-fed\n'),
            "runs-on no longer the matrix lookup": text.replace("${{ fromJSON(matrix.runner) }}", "[self-hosted, linux-fed]"),
        }
        for label, body in mutants.items():
            with self.subTest(mutant=label):
                self.assertNotEqual(body, text)
                problems = repo_problems(self.tree(replace={name: body}), self.pins)
                self.assertTrue(any(name in p and "lifetime-tests" in p for p in problems), problems)

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
        self.assertTrue(any("copy.yml job mobile-cross-compile" in p for p in repo_problems(root, self.pins)))
        life = (WORKFLOWS / "session-boot-lifetime.yml").read_text(encoding="utf-8")
        root = self.tree(extra={".github/workflows/copy2.yml": life})
        self.assertTrue(any("copy2.yml job lifetime-tests" in p for p in repo_problems(root, self.pins)))

    def test_a_row_whose_job_is_gone_is_a_stale_problem_8187_f19(self):
        for name, job in (("release.yml", "release"), ("session-boot-lifetime.yml", "lifetime-tests")):
            text = (WORKFLOWS / name).read_text(encoding="utf-8")
            renamed = text.replace("\n  %s:\n" % job, "\n  %s-renamed:\n" % job, 1)
            with self.subTest(workflow=name):
                self.assertNotEqual(renamed, text)
                problems = repo_problems(self.tree(replace={name: renamed}), self.pins)
                self.assertTrue(any(name in p and job in p and "stale" in p for p in problems), problems)

    def test_the_exempt_label_sets_must_equal_the_pinned_sets_8187_f19(self):
        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        leg = "          - target: x86_64-unknown-linux-gnu\n"
        drift = release.replace(leg, "          - target: x86_64-pc-windows-msvc\n            os: windows-latest\n" + leg, 1)
        self.assertNotEqual(drift, release)
        problems = repo_problems(self.tree(replace={"release.yml": drift}), self.pins)
        self.assertTrue(any("release.yml job release" in p for p in problems), problems)
        ci = self.texts["ci.yml"]
        leg = "          - target: aarch64-apple-ios\n"
        drift = ci.replace(leg, "          - target: t\n            os: windows-latest\n" + leg, 1)
        self.assertNotEqual(drift, ci)
        self.caught("ci.yml", drift, "mobile-cross-compile gains a windows leg")
        removed = ci.replace(leg + "            os: macos-latest\n", "", 1)
        self.assertNotEqual(removed, ci)
        self.caught("ci.yml", removed, "mobile-cross-compile loses a leg")
        life = (WORKFLOWS / "session-boot-lifetime.yml").read_text(encoding="utf-8")
        reordered = life.replace('\'["self-hosted","macos-fed"]\'', '\'["macos-fed","self-hosted"]\'')
        self.assertNotEqual(reordered, life)
        problems = repo_problems(self.tree(replace={"session-boot-lifetime.yml": reordered}), self.pins)
        self.assertTrue(any("lifetime-tests" in p for p in problems), problems)

    def test_the_exemption_table_has_exactly_the_three_real_rows_8187_f19(self):
        table = globals().get("RUNS_ON_EXEMPT", {})
        self.assertEqual(sorted(table), [("ci.yml", "mobile-cross-compile"), ("release.yml", "release"),
                                         ("session-boot-lifetime.yml", "lifetime-tests")])
        for key, (reason, pinned, label_sets) in table.items():
            self.assertTrue(reason and pinned.startswith("${{"), key)
            for labels in label_sets:
                if key[1] != "lifetime-tests":
                    self.assertTrue(all(ty.HOSTED_LABEL.match(label) for label in labels), (key, labels))
        self.assertEqual(repo_problems(ROOT, self.pins), [])
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
                self.assertTrue(any(name in p and "lifetime-tests" in p and "step" in p for p in problems), problems)
        edited = text.replace("AI_MEMORY_NO_CONFIG: '1'", "AI_MEMORY_NO_CONFIG: '0'", 1)
        self.assertNotEqual(edited, text)
        problems = repo_problems(self.tree(replace={name: edited}), self.pins)
        self.assertTrue(any(name in p and "lifetime-tests" in p for p in problems), problems)

    def test_the_exempt_workflow_level_keys_are_pinned_8187_f21(self):
        name = "session-boot-lifetime.yml"
        text = (WORKFLOWS / name).read_text(encoding="utf-8")
        self.assertEqual(repo_problems(self.tree(), self.pins), [])
        mutants = {
            "env entry added": (text.replace("\nenv:\n", "\nenv:\n  BASH_ENV: ./hook\n", 1), "env"),
            "defaults.run.shell added": (text.replace("\nenv:\n", "\ndefaults:\n  run:\n    shell: bash -x\nenv:\n", 1),
                                         "defaults"),
            "env value edited": (text.replace('CARGO_INCREMENTAL: "0"', 'CARGO_INCREMENTAL: "1"', 1), "env"),
            "on gains an event": (text.replace("\non:\n", "\non:\n  pull_request:\n", 1), "on"),
        }
        for label, (body, key) in mutants.items():
            with self.subTest(mutant=label):
                self.assertNotEqual(body, text)
                problems = repo_problems(self.tree(replace={name: body}), self.pins)
                self.assertTrue(any(name in p and "workflow-level" in p and key in p for p in problems), problems)
                self.assertFalse(any("bash -x" in p or "./hook" in p for p in problems), problems)

    def test_the_exempt_pin_section_carries_the_workflow_keys_8187_f21(self):
        entry = self.pins[EXEMPT]["session-boot-lifetime.yml"]
        data, _ = ty.parse_workflow((WORKFLOWS / "session-boot-lifetime.yml").read_text(encoding="utf-8"))
        self.assertEqual(sorted(entry["workflow_keys"]), sorted(k for k in data if k != "jobs"))
        self.assertEqual(entry["workflow_keys"], ty.build_pins(data)["workflow_keys"])
        self.assertEqual(sorted(entry["jobs"]), ["lifetime-tests"])

    def test_the_pin_loader_and_module_docstrings_name_every_section_8187_f23(self):
        keys = json.loads(JOB_PINS_FILE.read_text(encoding="utf-8")).keys()
        for key in keys:
            with self.subTest(key=key):
                self.assertIn(key, load_job_pins.__doc__)
        for label, text in (("test module", " ".join((__doc__ or "").split())),
                            ("tier_yaml_8187", " ".join(
                                Path(ty.__file__).read_text(encoding="utf-8").replace("# ", " ").split()))):
            with self.subTest(text=label):
                self.assertIn("the exempt job and every workflow-level key except ``jobs`` of its workflow", text)

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
        self.assertIn(sentinel[0], exempt)
        self.assertIn(sentinel[0], primary)

    def test_hosted_labels_and_non_tier_edits_are_not_flagged(self):
        text = self.texts["ci.yml"]
        for value in ("ubuntu-latest", "ubuntu-22.04", "macos-14", "windows-latest", "ubuntu-24.04-arm"):
            with self.subTest(runs_on=value):
                self.assertEqual(tier_pin_problems("ci.yml", set_runs_on(text, "lint", value), self.pins), [])
        edited = add_step(text, "lint", ["      - run: echo a freely edited non-tier step"])
        self.assertEqual(tier_pin_problems("ci.yml", edited, self.pins), [])
        self.assertEqual(tier_pin_problems("ci.yml", before_jobs(text, ["# a comment above jobs"]), self.pins), [])

    # --- pins: structure, failure messages, determinism ------------------------------------------------------

    def test_the_primary_pins_cover_every_tier_job_workflow_key_and_the_job_list(self):
        for wf, text in self.texts.items():
            data, _ = ty.parse_workflow(text)
            entry = self.pins[PRIMARY][wf]
            self.assertEqual(entry["job_names"], sorted(data["jobs"]))
            self.assertEqual(sorted(entry["tier_jobs"]), ty.tier_job_names(data))
            self.assertEqual(sorted(entry["workflow_keys"]), sorted(k for k in data if k != "jobs"))
            self.assertTrue(entry["tier_jobs"])
            for name, pinned in entry["tier_jobs"].items():
                self.assertEqual(len(pinned["steps"]), len(data["jobs"][name]["steps"]))
        self.assertEqual(sorted(self.pins[PRIMARY]), sorted(PIN_WORKFLOWS))

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
        for part in (wf, job, f"step {index}", f"steps[{index}].run", step["name"][:20]):
            self.assertIn(part, message)
        self.assertNotIn("somepass", message)
        self.assertNotIn("printenv", message, "the message names the key path, not the changed line")
        again = "\n".join(tier_pin_problems(wf, edited, self.pins))
        self.assertNotIn("somepass", again)
        self.assertNotIn("someuser", again)

    def test_a_job_level_key_difference_names_the_job_key(self):
        wf = "postgres-ignored.yml"
        data, _ = ty.parse_workflow(self.texts[wf])
        job = ty.tier_job_names(data)[0]
        rows = self.texts[wf].split("\n")
        key = next(i for i, ln in enumerate(rows) if ln.rstrip() == f"  {job}:")
        edited = "\n".join(rows[:key + 1] + ["    container: ubuntu:latest"] + rows[key + 1:])
        message = "\n".join(primary_pin_problems(wf, edited, self.pins[PRIMARY]))
        self.assertIn(job, message)
        self.assertIn("job.container", message)

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
                self.assertTrue(any("concurrency" in p for p in primary_pin_problems(
                    wf, re.sub(r"(?ms)^concurrency:.*?(?=^[a-z])", "", text, count=1), self.pins[PRIMARY])))

    def test_the_pin_data_file_is_regenerated_byte_identically(self):
        built = json.dumps({PRIMARY: {wf: ty.build_pins(ty.parse_workflow(t)[0]) for wf, t in self.texts.items()},
                            SECONDARY: self.pins[SECONDARY], EXEMPT: exempt_pins()}, indent=1, sort_keys=True) + "\n"
        self.assertEqual(JOB_PINS_FILE.read_text(encoding="utf-8"), built, "run --write-pins and commit the data file")
        outputs = []
        for number in range(2):
            out = SCRATCH_ROOT / f"pins-{number}.json"
            result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--write-pins", "--out", str(out)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr[-300:])
            outputs.append(out.read_bytes())
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0], JOB_PINS_FILE.read_bytes())

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
            self.assertNotIn(needle, source)

    def test_requirements_pin_one_package_with_hashes_only(self):
        rows = [ln.rstrip() for ln in (Path(__file__).parent / "requirements-ci.txt").read_text(encoding="utf-8").split("\n")
                if ln.strip() and not ln.startswith("#")]
        self.assertTrue(rows[0].startswith("PyYAML==") and rows[0].endswith("\\"), rows[0])
        hashes = [r.strip() for r in rows[1:]]
        self.assertGreaterEqual(len(hashes), 10)
        for row in hashes:
            self.assertRegex(row, r"^--hash=sha256:[0-9a-f]{64}( \\)?$")
        self.assertFalse(hashes[-1].endswith("\\"))
        self.assertEqual(len(set(hashes)), len(hashes))

    def test_ci_runs_the_tier_modules_in_a_github_hosted_job_8187_f13(self):
        data, problems = ty.parse_workflow(self.texts["ci.yml"])
        self.assertEqual(problems, [])
        job = data["jobs"]["tier-credential-pins"]
        self.assertEqual(job["runs-on"], "ubuntu-latest")
        self.assertNotIn("needs", job, "the pins must run on a docs-only PR as well")
        self.assertNotIn("if", job)
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
    table = {PRIMARY: {}, SECONDARY: {}}
    for workflow in PIN_WORKFLOWS:
        raw = (WORKFLOWS / workflow).read_text(encoding="utf-8")
        data, bad = ty.parse_workflow(raw)
        if bad:
            sys.exit(f"{workflow}: {bad[0]}")
        found, layout_bad = job_layout(raw)
        if layout_bad:
            sys.exit(f"{workflow}: {layout_bad[0]}")
        table[PRIMARY][workflow] = ty.build_pins(data)
        table[SECONDARY][workflow] = {"jobs": [j[0] for j in found],
                                      "pinned": {name: pin_entry(block) for name, block in tier_blocks(found)},
                                      "workflow": {key: pin_entry(block) for key, block in sorted(
                                          workflow_level_blocks(raw).items())}}
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
                self.assertEqual([p for p in problems if sentinel in p], [])
                primary = [p for p in problems if f"step {index} (step[{index}])" in p and "differs from the pin at" in p]
                self.assertTrue([p for p in primary if re.search(rf"steps\[{index}\]\.", p)], problems)
                self.assertTrue([p for p in job_pin_problems(wf, edited, self.pins[SECONDARY])
                                 if f"step {index} (step[{index}])" in p and "differs from the pin at line" in p])
        self.assertGreater(checked, 0)

    def test_a_named_step_keeps_its_name_as_label_8187_f25(self):
        self.assertEqual(ty.step_label({"name": "Build the thing", "run": "echo x"}, 3), "Build the thing")
        self.assertEqual(ty.step_label({"id": "build", "run": "echo x"}, 3), "build")
        self.assertEqual(ty.step_label({"run": "echo x"}, 3), "step[3]")
        self.assertEqual(ty.step_label({"uses": "actions/checkout@v4"}, 0), "step[0]")
        self.assertEqual(ty.step_label("not a mapping", 2), "step[2]")

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
                self.assertEqual([p for p in problems if sentinel in p or "postgres://" in p], [])
                self.assertTrue([p for p in problems if p.startswith(expected)], problems)

    def test_workflow_problems_name_the_line_number_and_rule_only_8187_f26(self):
        sentinel = "SENTINEL-F26-2b9e"
        text = self.texts[SHARED_TIER[0]]
        lines = text.split("\n")
        lines.insert(section_end(text), "      run: psql postgres://u:%s@h/db -c 'select 1'" % sentinel)
        problems = workflow_problems("\n".join(lines))
        self.assertEqual([p for p in problems if sentinel in p or "postgres://" in p], [])
        self.assertTrue([p for p in problems if re.match(r"line \d+: psql without the loader$", p)], problems)

    def test_a_workflow_that_does_not_load_names_the_rule_never_its_text_8187_f26(self):
        sentinel = "SENTINEL-F26-2b9e"
        for label, doc in {"unterminated": f'key: "{sentinel}\n', "tab": f"key:\n\t{sentinel}: 1\n",
                           "tag": f"key: !!python/object:os.system {sentinel}\n",
                           "non-string key": f"? [{sentinel}]\n: 1\n", "duplicate": "a: 1\na: 2\n"}.items():
            data, problems = ty.parse_workflow(doc)
            with self.subTest(document=label):
                self.assertIsNone(data)
                self.assertEqual([p for p in problems if sentinel in p], [])
                self.assertTrue(problems and problems[0].startswith("the workflow does not load strictly: "), problems)

    def test_the_checker_sources_slice_no_workflow_line_8187_f26(self):
        wide = {path.name: [int(n) for n in re.findall(r"\[:(\d+)\]", path.read_text(encoding="utf-8")) if int(n) >= 40]
                for path in (Path(__file__), Path(__file__).with_name("tier_yaml_8187.py"))}
        # the only wide slice left cuts a step NAME (a label the author chose) to 60 characters, in the loaded view only;
        # the checker reads no source row for a label (F30), so it holds none
        self.assertEqual(wide["tier_yaml_8187.py"], [60])
        self.assertEqual(wide[Path(__file__).name], [])


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
                want = "real" if named else f"step[{index}]"
                problems = tier_pin_problems(wf, edited, self.pins) + job_pin_problems(wf, edited, self.pins[SECONDARY])
                with self.subTest(workflow=wf, step=variant):
                    checked += 1
                    self.assertTrue(problems)
                    for sentinel in self.SENTINELS:
                        self.assertEqual([p for p in problems if sentinel in p], [], sentinel)
                    self.assertTrue([p for p in problems if f"step {index} ({want})" in p], problems)
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
                with self.subTest(workflow=path.name, job=name):
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
        self.assertEqual([step_label(block, h, steps) for h in heads],
                         [(0, "Quoted # name"), (1, "build"), (2, "step[2]")])

    def test_a_document_that_does_not_load_labels_a_step_by_position_8187_f30(self):
        block = "\n".join(["  job:", "    steps:", "      - run: \"x", "        name: SENTINEL-F30-none\"", "      - id: b"])
        for steps in (None, "not a list", []):
            with self.subTest(steps=steps):
                self.assertEqual([step_label(block, h, steps) for h in step_head_rows(block)],
                                 [(0, "step[0]"), (1, "step[1]")])

    def test_a_local_tag_or_tab_does_not_put_author_text_in_the_load_failure_8187_f28(self):
        sentinel = "SENTINEL-F28"
        docs = {"local tag": f"key: !<{sentinel}> x\n", "local tag in a list": f"a:\n  - !<{sentinel}> x\n",
                "tab": f"key: x\n\t{sentinel}: 1\n"}
        for label, doc in docs.items():
            with self.subTest(document=label):
                with self.assertRaises(Exception) as caught:
                    ty.load_strict(doc)
                if label.startswith("local tag"):
                    self.assertIn(sentinel, str(caught.exception), "the parser message carries the author text here")
                message = ty.load_failure(caught.exception)
                self.assertNotIn(sentinel, message)
                self.assertRegex(message, r"^\w+ at line \d+$")
                data, problems = ty.parse_workflow(doc)
                self.assertIsNone(data)
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
                self.assertIn(sentinel, str(caught.exception), "the pure-Python message carries the author text")
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
                want = real or f"step[{index}]"
                problems = tier_pin_problems(wf, edited, self.pins) + job_pin_problems(wf, edited, self.pins[SECONDARY])
                with self.subTest(workflow=wf, step=variant):
                    checked += 1
                    self.assertTrue(problems)
                    for sentinel in sentinels:
                        self.assertEqual([p for p in problems if sentinel in p], [], sentinel)
                    self.assertTrue([p for p in problems if f"step {index} ({want})" in p], (index, want))
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
                    self.assertEqual([p for p in problems if sentinel in p or "dbhost" in p], [])
                    self.assertTrue([p for p in problems if f"step {index} (https://***)" in p
                                     or f"step {index} (step[{index}])" in p], (view, index))
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
                        self.assertEqual([p for p in problems if sentinel in p or "ciuser" in p or "dbhost" in p], [])
                        self.assertTrue([p for p in problems if f"step {index} ({label})" in p
                                         or f"step {index} (step[{index}])" in p], (view, index))
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
                        self.assertEqual([p for p in problems if sentinel in p or user in p
                                          or "://" in p.replace("://***", "") or "dbhost" in p], [])
                        labelled = [p for p in problems if re.search(
                            r"step %d \((?:step\[%d\]|[^)@]*\*\*\*[^)@]*)\)" % (index, index), p)]
                        self.assertTrue(labelled, (view, index))
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
            self.assertEqual(text.count(head), 1, (wf, job))
            for variant, key in keys.items():
                edited = text.replace(head, f'\n  "{key}":')
                self.assertIn(sentinel, json.dumps(ty.load_strict(edited)["jobs"]))
                views = {"loaded": tier_pin_problems(wf, edited, self.pins),
                         "text": job_pin_problems(wf, edited, self.pins[SECONDARY])}
                for view, problems in views.items():
                    with self.subTest(workflow=wf, variant=variant, view=view):
                        checked += 1
                        self.assertTrue(problems)
                        self.assertEqual([p for p in problems if sentinel in p or user in p
                                          or "://" in p.replace("://***", "") or "dbhost" in p], [])
        self.assertGreater(checked, 0)


class TestEveryAuthorKeyIsPrintable8187R19(unittest.TestCase):
    """r19 F36: every author key that reaches a message goes through ``ty.printable`` with a positional fallback
    (``key[<n>]``); the line mask is a second layer with no look-ahead that author text can satisfy."""

    USER = "f36user"
    SENTINEL = "SENTINEL-F36-pw"

    @classmethod
    def setUpClass(cls):
        cls.texts = {wf: (WORKFLOWS / wf).read_text(encoding="utf-8") for wf in PIN_WORKFLOWS}
        cls.pins = load_job_pins()

    def shapes(self):
        sentinel, user = self.SENTINEL, self.USER
        return {
            "space": f"https://{user}:{sentinel} pw@dbhost/db",
            "slash": f"https://{user}:{sentinel}/pw@dbhost/db",
            "at sign": f"https://{user}:{sentinel}@pw@dbhost/db",
            "star colon": f"https://***:{sentinel}@dbhost/db",
            "star slash": f"https://***/{sentinel}@dbhost/db",
            "star dot space": f"https://***. {sentinel} pw@dbhost/db",
            "no scheme": f"{user}:{sentinel} pw@dbhost/db",
        }

    def leaks(self, problems):
        return [p for p in problems if self.SENTINEL in p or self.USER in p or "dbhost" in p
                or "://" in p.replace("://***", "")]

    def assert_clean(self, problems, view):
        self.assertTrue(problems, view)
        self.assertEqual(self.leaks(problems), [], view)
        self.assertTrue([p for p in problems if "key[" in p or "://***" in p], (view, problems))

    def test_a_duplicate_top_level_key_is_printed_by_position_8187_f36(self):
        checked = 0
        for wf, text in self.texts.items():
            for variant, key in self.shapes().items():
                edited = text.rstrip("\n") + f'\n"{key}": 1\n"{key}": 2\n'
                with self.subTest(workflow=wf, shape=variant):
                    checked += 1
                    self.assert_clean(primary_pin_problems(wf, edited, self.pins[PRIMARY]), "loaded")
        self.assertGreater(checked, 0)

    def test_an_extra_top_level_key_is_printed_by_position_8187_f36(self):
        """Covers the closed-set message of ``parse_workflow`` and the ``workflow_key_problems`` "added" message."""
        checked = 0
        for wf, text in self.texts.items():
            for variant, key in self.shapes().items():
                edited = text.rstrip("\n") + f'\n"{key}": 1\n'
                self.assertIn(self.SENTINEL, json.dumps(ty.load_strict(edited)))
                problems = primary_pin_problems(wf, edited, self.pins[PRIMARY])
                with self.subTest(workflow=wf, shape=variant):
                    checked += 1
                    self.assert_clean(problems, "loaded")
                    self.assertTrue([p for p in problems if "top-level keys outside the closed set" in p])
                    self.assertTrue([p for p in problems if "was added and is not pinned" in p])
        self.assertGreater(checked, 0)

    def test_a_job_key_and_a_step_key_are_printed_by_position_8187_f36(self):
        checked = 0
        for wf, text in self.texts.items():
            target = next(iter(pin_targets(wf, text)), None)
            if target is None:
                continue
            job = target[0]
            head = f"\n  {job}:"
            self.assertEqual(text.count(head), 1, (wf, job))
            lines = text.split("\n")
            step_head = lines[target[3]]
            self.assertTrue(step_head.lstrip().startswith("- name:"), (wf, step_head))
            pad = " " * (indent_of(step_head) + 2)
            for variant, key in self.shapes().items():
                job_edit = text.replace(head, f'{head}\n    "{key}": 1')
                step_edit = splice(text, target[3] + 1, [f'{pad}"{key}": 1'])
                for site, edited, want in (("job key", job_edit, "job.key["), ("step key", step_edit, "].key[")):
                    self.assertIn(self.SENTINEL, json.dumps(ty.load_strict(edited)["jobs"]))
                    problems = primary_pin_problems(wf, edited, self.pins[PRIMARY])
                    with self.subTest(workflow=wf, shape=variant, site=site):
                        checked += 1
                        self.assert_clean(problems, "loaded")
                        self.assertTrue([p for p in problems if "differs from the pin at" in p
                                         and (want in p or "://***" in p)], (site, problems))
        self.assertGreater(checked, 0)

    def test_a_matrix_key_is_printed_by_position_8187_f36(self):
        row = next(iter(ty.RUNS_ON_EXEMPT.values()))
        pinned = row[1]
        field = ty.RUNS_ON_FORMS[pinned][0]
        for variant, key in self.shapes().items():
            job = {"runs-on": pinned, "strategy": {"matrix": {field: ["ubuntu-latest"], key: 1}}}
            with self.subTest(shape=variant):
                why = ty.exemption_problem(row, job)
                self.assertTrue(why)
                self.assertEqual(self.leaks([why]), [])
                self.assertRegex(why, r"^matrix\.(?:key\[\d+\]|https://\*\*\*) is not a list of plain scalars$")

    def test_a_userinfo_that_starts_with_the_mask_token_is_masked_in_both_views_8187_f36(self):
        """The ``***:``-prefixed userinfo that the r18 look-ahead let through, planted in a step name."""
        checked = 0
        for wf, text in self.texts.items():
            target = next(iter(pin_targets(wf, text)), None)
            if target is None:
                continue
            for variant in ("star colon", "star slash"):
                name = self.shapes()[variant]
                edited = splice(text, target[3], [f"      - name: {name}", "        run: echo one"])
                job_steps = ty.load_strict(edited)["jobs"][target[0]]["steps"]
                index = next(i for i, step in enumerate(job_steps) if self.SENTINEL in json.dumps(step))
                views = {"loaded": tier_pin_problems(wf, edited, self.pins),
                         "text": job_pin_problems(wf, edited, self.pins[SECONDARY])}
                for view, problems in views.items():
                    with self.subTest(workflow=wf, shape=variant, view=view):
                        checked += 1
                        self.assertTrue(problems)
                        self.assertEqual(self.leaks(problems), [])
                        self.assertTrue([p for p in problems if f"step {index} (https://***)" in p
                                         or f"step {index} (step[{index}])" in p], (view, index))
        self.assertGreater(checked, 0)

    def test_the_line_mask_is_a_second_layer_with_no_look_ahead_8187_f36(self):
        sentinel = self.SENTINEL
        for text in (f"x https://***:{sentinel}@dbhost/db y", f"x https://***/{sentinel}@dbhost y",
                     f"x https://***@{sentinel}@dbhost y", f"x https://***){sentinel}@dbhost y"):
            with self.subTest(text=text):
                masked = ty.mask_userinfo(text)
                self.assertNotIn(sentinel, masked)
                self.assertNotIn("dbhost", masked)
        self.assertEqual(ty.mask_userinfo("step 3 (https://***): differs"), "step 3 (https://***): differs")


class TestEveryPinSourcedNameIsPrintable8187R20(unittest.TestCase):
    """r20 F38: a key or job name that comes from the PIN data takes the same positional-label rule as a live author
    key (``key[<n>]``), because ``--write-pins`` writes the pin file from the author's workflow."""

    USER = "f38user"
    SENTINEL = "SENTINEL-F38-pw"
    LABEL = r"(?:key\[\d+\]|https://\*\*\*)"

    @classmethod
    def setUpClass(cls):
        cls.texts = {wf: (WORKFLOWS / wf).read_text(encoding="utf-8") for wf in PIN_WORKFLOWS}

    def pins(self):
        return json.loads(json.dumps(load_job_pins()))

    def shapes(self):
        sentinel, user = self.SENTINEL, self.USER
        return {
            "space": f"https://{user}:{sentinel} pw@dbhost/db",
            "slash": f"https://{user}:{sentinel}/pw@dbhost/db",
            "at sign": f"https://{user}:{sentinel}@pw@dbhost/db",
            "star colon": f"https://***:{sentinel}@dbhost/db",
            "no scheme": f"{user}:{sentinel} pw@dbhost/db",
            "postgresql": f"postgresql:{user}:{sentinel}@dbhost",
        }

    def leaks(self, problems):
        return [p for p in problems if self.SENTINEL in p or self.USER in p or "dbhost" in p
                or "://" in p.replace("://***", "")]

    def assert_clean(self, problems, view, want):
        self.assertTrue(problems, view)
        self.assertEqual(self.leaks(problems), [], view)
        self.assertTrue([p for p in problems if re.search(want, p)], (view, want, problems))

    def test_a_removed_pinned_job_key_is_printed_by_position_8187_f38(self):
        checked = 0
        for wf, text in self.texts.items():
            for variant, key in self.shapes().items():
                pins = self.pins()
                entry = pins[PRIMARY][wf]["tier_jobs"]
                job = next(iter(entry))
                entry[job]["sha256"] = "0" * 64
                entry[job]["keys"][key] = "0" * 64
                with self.subTest(workflow=wf, shape=variant):
                    checked += 1
                    self.assert_clean(primary_pin_problems(wf, text, pins[PRIMARY]), "loaded",
                                      r"differs from the pin at job\." + self.LABEL + r" \(removed\)")
        self.assertEqual(checked, 3 * len(self.shapes()))

    def test_a_removed_pinned_step_key_is_printed_by_position_8187_f38(self):
        checked = 0
        for wf, text in self.texts.items():
            for variant, key in self.shapes().items():
                pins = self.pins()
                entry = pins[PRIMARY][wf]["tier_jobs"]
                job = next(iter(entry))
                index = next(i for i, step in enumerate(entry[job]["steps"]) if "keys" in step)
                entry[job]["sha256"] = "0" * 64
                entry[job]["steps"][index]["sha256"] = "0" * 64
                entry[job]["steps"][index]["keys"][key] = "0" * 64
                with self.subTest(workflow=wf, shape=variant):
                    checked += 1
                    self.assert_clean(primary_pin_problems(wf, text, pins[PRIMARY]), "loaded",
                                      rf"differs from the pin at steps\[{index}\]\." + self.LABEL + r" \(removed\)")
        self.assertEqual(checked, 3 * len(self.shapes()))

    def test_a_pinned_job_name_that_is_gone_is_printed_by_position_8187_f38(self):
        """Checker :948 (``gone``) and :955 (a pinned tier job that is missing), loaded view; the text view's pin."""
        checked = 0
        for wf, text in self.texts.items():
            for variant, key in self.shapes().items():
                pins = self.pins()
                primary = pins[PRIMARY][wf]
                primary["job_names"] = sorted([*primary["job_names"], key])
                primary["job_names_sha256"] = "0" * 64
                primary["tier_jobs"][key] = json.loads(json.dumps(next(iter(primary["tier_jobs"].values()))))
                secondary = pins[SECONDARY][wf]
                secondary["jobs"] = [*secondary["jobs"], key]
                secondary["pinned"][key] = json.loads(json.dumps(next(iter(secondary["pinned"].values()))))
                with self.subTest(workflow=wf, shape=variant):
                    checked += 1
                    loaded = primary_pin_problems(wf, text, pins[PRIMARY])
                    self.assert_clean(loaded, "loaded", r"missing \['" + self.LABEL)
                    self.assert_clean(loaded, "loaded", r" job " + self.LABEL + r": pinned job is missing")
                    seen = job_pin_problems(wf, text, pins[SECONDARY])
                    self.assert_clean(seen, "text", r"missing \['" + self.LABEL)
                    self.assert_clean(seen, "text", r" job " + self.LABEL + r": pinned job is missing")
        self.assertEqual(checked, 3 * len(self.shapes()))

    def test_the_whole_workflow_set_has_no_leak_on_the_pinned_shapes_8187_f38(self):
        """Every message of the real tier check on a pin file that carries each shape in every pin-sourced place."""
        for variant, key in self.shapes().items():
            pins = self.pins()
            for wf in PIN_WORKFLOWS:
                primary = pins[PRIMARY][wf]
                job = next(iter(primary["tier_jobs"]))
                primary["tier_jobs"][job]["sha256"] = "0" * 64
                primary["tier_jobs"][job]["keys"][key] = "0" * 64
            with self.subTest(shape=variant):
                found = [p for wf in PIN_WORKFLOWS for p in tier_pin_problems(wf, self.texts[wf], pins)]
                self.assertTrue(found)
                self.assertEqual(self.leaks(found), [])


class TestFallbackDecidedOnTheRawValue8187R20(TestEveryAuthorKeyIsPrintable8187R19):
    """r20 F38-security: ``printable`` decides the fallback on the RAW joined value before any mask, because a later
    ``scheme://`` token can swallow the at sign of an earlier credential.  The r19 sites run again with the four
    absorbed-at-sign shapes, and the step-name and job-name sites run with every shape in both views."""

    USER = "f38suser"
    SENTINEL = "SENTINEL-F38S-pw"

    def shapes(self):
        sentinel, user = self.SENTINEL, self.USER
        return {
            "no double slash then token": f"postgresql:{user}:{sentinel}a://b@dbhost/db",
            "whitespace then token": f"postgresql:{user}:{sentinel} pw a://b@dbhost/db",
            "double slash whitespace then token": f"https://{user}:{sentinel} pw a://b@dbhost/db",
            "tail before token": f"{user}:{sentinel} pwtail a://b@dbhost/db",
            "space": f"https://{user}:{sentinel} pw@dbhost/db",
            "star colon": f"https://***:{sentinel}@dbhost/db",
            "star slash": f"https://***/{sentinel}@dbhost/db",
            "no scheme": f"{user}:{sentinel} pw@dbhost/db",
        }

    def test_the_four_absorbed_at_sign_shapes_fall_back_before_any_mask_8187_f38s(self):
        for variant, value in self.shapes().items():
            with self.subTest(shape=variant):
                label = ty.printable(value, "key[7]")
                self.assertEqual(label, "key[7]")

    def test_a_value_that_never_carried_the_tokens_is_still_printed_8187_f38s(self):
        self.assertEqual(ty.printable("Run the unit tests", "step[1]"), "Run the unit tests")
        self.assertEqual(ty.printable("a   b\tc", "step[1]"), "a b c")

    def test_a_step_name_and_a_job_name_print_no_fragment_in_both_views_8187_f38s(self):
        checked = 0
        for wf, text in self.texts.items():
            target = next(iter(pin_targets(wf, text)), None)
            if target is None:
                continue
            for variant, name in self.shapes().items():
                step_edit = splice(text, target[3], [f"      - name: {name}", "        run: echo one"])
                job_edit = text.replace("\njobs:\n", f'\njobs:\n  "{name}":\n    runs-on: ubuntu-latest\n'
                                        '    steps:\n      - run: echo hi\n', 1)
                self.assertIn(self.SENTINEL, json.dumps(ty.load_strict(step_edit)))
                self.assertIn(self.SENTINEL, json.dumps(ty.load_strict(job_edit)))
                for site, edited in (("step name", step_edit), ("job name", job_edit)):
                    views = {"loaded": tier_pin_problems(wf, edited, self.pins),
                             "text": job_pin_problems(wf, edited, self.pins[SECONDARY])}
                    for view, problems in views.items():
                        with self.subTest(workflow=wf, shape=variant, site=site, view=view):
                            checked += 1
                            self.assertTrue(problems)
                            self.assertEqual(self.leaks(problems), [])
        self.assertEqual(checked, 3 * len(self.shapes()) * 4)


if __name__ == "__main__":
    if "--write-pins" in sys.argv[1:]:
        # regenerate all three pin sections from the workflows; the diff of the data file is what a reviewer reads
        flags = sys.argv[1:]
        write_pins(flags[flags.index("--out") + 1] if "--out" in flags else None)
        sys.exit(0)
    sys.exit(unittest.main())
