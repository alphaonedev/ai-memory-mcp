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
import tempfile
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
            if dumps_environment(s):
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


WORKFLOWS = ROOT / ".github/workflows"
BANG = chr(92) + "!"  # a psql shell escape: backslash then bang
# the discovery list: every workflow that names the tier secret or its environment variable (#8187 security F2)
TIER_MARKERS = re.compile(r"AI_MEMORY_CI_FED_URL|AI_MEMORY_TEST_POSTGRES_URL|pg_ci_url_file|ai-memory-ci-fed-url")
# workflows that read the tier URL file: pinned by wiring_problems above (ci.yml) or workflow_problems below
SHARED_TIER = ("cert-postgres-age.yml", "postgres-ignored.yml")
# coverage.yml names the variable only for its own throwaway local database (a literal localhost test credential)
LOCAL_ONLY = {"coverage.yml": "postgres://ai_memory:ai_memory_test@localhost:5432/"}
URL_VARS = re.compile(r"\$\{?(?:base_url|new_url|head|q|AI_MEMORY_TEST_POSTGRES_URL|AI_MEMORY_TEST_AGE_URL)\b")
GITHUB_ENV_LINE = 'python3 -I ' + HELPER + ' github-env --url-file "$url_file" --database "$CI_FED_DB"'


def code_lines(text):
    """The non-comment lines of a workflow, stripped."""
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


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
    lines = code_lines(text)
    for line in lines:
        if re.search(r"AI_MEMORY_TEST_(?:POSTGRES|AGE)_URL=", line):
            problems.append("URL written to GITHUB_ENV by hand: " + line[:60])
        if dumps_environment(line):
            problems.append("a line dumps the environment: " + line[:60])
        if XTRACE.search(line):
            problems.append("a line traces the shell: " + line[:60])
        if (URL_FILE_MENTION.search(line) or PSQL_ARRAY_MENTION.search(line)) and not allowed_url_file_line(line):
            problems.append("tier credential line is not an allowed form: " + line[:60])
        if re.search(r"\bpsql\b", line) and ("tier_credential.py run" not in line or "--url-file" not in line):
            if not message_echo(line):
                problems.append("psql without the loader: " + line[:60])
        if re.search(r"\bpsql\b", line) and URL_VARS.search(line):
            problems.append("psql line carries a URL variable: " + line[:60])
        if re.search(r"\b(?:base_url|new_url)\s*=", line) or re.search(r"\bcat\s+\"?\$\{?url_file", line):
            problems.append("URL read into a shell variable: " + line[:60])
    if not any(ln.startswith(GITHUB_ENV_LINE) and "--age-url" in ln for ln in lines):
        problems.append("the masked github-env hand-off (with --age-url) is missing")
    return problems


def tier_workflows(directory=WORKFLOWS):
    """Names of the workflows (``*.yml`` and ``*.yaml``) whose text matches the discovery list."""
    paths = [*Path(directory).glob("*.yml"), *Path(directory).glob("*.yaml")]
    return sorted(p.name for p in paths if TIER_MARKERS.search(p.read_text(encoding="utf-8")))


# r6 F10: the post-export steps are pinned as exact text (the loader-call allowlist and dumps_environment stay as the
# second and third gates).  The pins live in a data file next to this module: ci.yml alone has ~90 KB of such steps.
PINS_FILE = Path(__file__).with_name("tier_post_export_pins_8187.json")
PIN_WORKFLOWS = ("ci.yml", *SHARED_TIER)
JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
STEP_LINE = re.compile(r"^      - ")
EXPORT_CALL = re.compile(r"tier_credential\.py\s+github-env\b.*--url-file")


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


def load_pins():
    """The pinned post-export step bodies, ``{workflow:job:step-name: exact body text}``."""
    import json
    return json.loads(PINS_FILE.read_text(encoding="utf-8"))


def pin_problems(workflow, text, pins=None):
    """STUB (red commit): the real check follows in the fix commit."""
    return []


def joined_lines(lines):
    """STUB (red commit)."""
    return [ln.strip() for ln in lines]


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


class TestPostExportStepsArePinned8187(unittest.TestCase):
    """r6 F10: every step that runs with the exported tier URL in its environment is pinned as exact text."""

    @classmethod
    def setUpClass(cls):
        cls.texts = {wf: (WORKFLOWS / wf).read_text(encoding="utf-8") for wf in PIN_WORKFLOWS}
        cls.pins = load_pins()

    def test_the_real_workflows_match_their_pins(self):
        for wf, text in self.texts.items():
            with self.subTest(workflow=wf):
                self.assertEqual(pin_problems(wf, text, self.pins), [])
                self.assertTrue(post_export_steps(wf, text), "no post-export step found: the export call moved")

    def test_the_pin_table_holds_exactly_the_post_export_steps(self):
        expected = {}
        for wf, text in self.texts.items():
            expected.update(dict(post_export_steps(wf, text)))
        self.assertEqual(list(self.pins), list(expected))
        for key, body in self.pins.items():
            with self.subTest(step=key):
                self.assertEqual(body, expected[key])
                self.assertTrue(key.split(":", 1)[0] in PIN_WORKFLOWS)

    def test_every_dump_form_in_a_post_export_step_fails_the_pin(self):
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
                        self.assertTrue(pin_problems(wf, edited, self.pins), f"mutant not caught: {label}")

    def test_a_new_post_export_step_fails_the_pin(self):
        new_step = ["      - name: Harmless looking addition", "        run: echo hello"]
        for wf, text in self.texts.items():
            steps_found = workflow_steps(text)
            posts = [s for s in steps_found if f"{wf}:{s[0]}:{s[1]}" in self.pins]
            self.assertTrue(posts)
            lines = text.split("\n")
            for label, at in (("after the first post-export step", posts[0][4]),
                              ("after the last post-export step", posts[-1][4])):
                with self.subTest(workflow=wf, where=label):
                    edited = "\n".join(lines[:at] + new_step + lines[at:])
                    problems = pin_problems(wf, edited, self.pins)
                    self.assertTrue(any("Harmless looking addition" in p and "not in the pin" in p for p in problems),
                                    problems)

    def test_a_removed_or_renamed_post_export_step_fails_the_pin(self):
        for wf, text in self.texts.items():
            steps_found = workflow_steps(text)
            posts = [s for s in steps_found if f"{wf}:{s[0]}:{s[1]}" in self.pins]
            victim = posts[-1]
            lines = text.split("\n")
            with self.subTest(workflow=wf, edit="removed"):
                edited = "\n".join(lines[:victim[3]] + lines[victim[4]:])
                self.assertTrue(pin_problems(wf, edited, self.pins))
            if victim[2].lstrip().startswith("- name:"):
                with self.subTest(workflow=wf, edit="renamed"):
                    edited = text.replace("- name: " + victim[1], "- name: " + victim[1] + " v2", 1)
                    self.assertTrue(pin_problems(wf, edited, self.pins))

    def test_a_pre_export_step_is_not_rejected_by_the_pin(self):
        checked = 0
        for wf, text in self.texts.items():
            steps_found = workflow_steps(text)
            export_job = post_export_steps(wf, text)[0][0].split(":")[1]
            pinned = {s[3] for s in steps_found if f"{wf}:{s[0]}:{s[1]}" in self.pins}
            pre = [s for s in steps_found if s[0] == export_job and s[3] not in pinned
                   and s[3] < min(pinned) and s[2].lstrip().startswith("- name:")]
            for step in pre:
                with self.subTest(workflow=wf, step=step[1]):
                    edited = text.replace("- name: " + step[1], "- name: " + step[1] + " (edited)", 1)
                    self.assertNotEqual(edited, text)
                    self.assertEqual(pin_problems(wf, edited, self.pins), [])
                    checked += 1
        self.assertGreater(checked, 0, "no pre-export step in any tier workflow to exercise")

    def test_the_failure_message_names_the_workflow_job_step_and_first_differing_line(self):
        wf = "cert-postgres-age.yml"
        text = self.texts[wf]
        step = next(s for s in pin_targets(wf, text) if "Cleanup" in s[1])
        edited = inject_run_line(text, step, "printenv | base64")
        message = "\n".join(pin_problems(wf, edited, self.pins))
        for part in (wf, step[0], step[1], "printenv | base64", "line "):
            self.assertIn(part, message)

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


if __name__ == "__main__":
    if "--write-pins" in sys.argv[1:]:
        # regenerate the pin table from the workflows; the diff of the data file is what a reviewer reads
        import json
        table = {}
        for workflow in PIN_WORKFLOWS:
            table.update(dict(post_export_steps(workflow, (WORKFLOWS / workflow).read_text(encoding="utf-8"))))
        PINS_FILE.write_text(json.dumps(table, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        sys.exit(0)
    sys.exit(unittest.main())
