#!/usr/bin/env python3
"""Parallel mutation sweep for scripts/check_release_features.py (issue 6062).

Port of the guard's own ``--mutation-sweep`` to a multiprocessing pool with one
result line per mutant:

    <id> RED|SURVIVES|EQUIVALENT|OTHER-DEFECT <killer test name | note>

Row 0 is the control: the unmutated guard must be GREEN. Rows 1.. are every
refusal call neutralised in turn (``x.bad(...)``) and every CONDITION_MUTANTS
entry. A mutant is RED when ``--self-test`` fails with a named case
(``self-test FAIL: '<name>'`` on stderr); the first named case is the killer.
A mutant that crashes the guard with a traceback is RED too (killer "crash: <error>").
A mutant that fails without naming a case or a traceback, or whose anchor is not found exactly
once, is an OTHER-DEFECT. A survivor is SURVIVES unless it is listed in
EQUIVALENT_MUTANTS below, where it prints EQUIVALENT (and is RED if killed).

Equivalent mutants live here, not in CONDITION_MUTANTS, because the guard's own
sweep treats every survivor as a failure.

Usage: mutation_sweep_release_features.py [--jobs N] [--root DIR] [--out FILE] [--limit N]
Exit 0 when the control is green and SURVIVES = 0 and OTHER-DEFECTS = 0.
"""
import argparse
import multiprocessing
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUARD = HERE.parent / "check_release_features.py"
sys.path.insert(0, str(GUARD.parent))

def _job(*lines):
    """A one-step workflow whose `run:` is the given lines."""
    return "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n" + "".join("          " + x + "\n" for x in lines)


def _env_job(env_lines):
    return ("jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo build --locked\n        env:\n"
            + env_lines)


_FETCH = "curl -fsSL -o f https://x.example/f"
_CHECK = 'echo "' + "ab" * 32 + '  f" | sha256sum -c -'

# Round 10 (code r9 F1): name -> workflow text that the unmutated guard REFUSES. A mutant that makes the guard accept one
# of these is killed by it even when `--self-test` stays green; the sweep prints the name as the killer.
OBSERVATIONS = {
    "env RUSTFLAGS key with no value": _env_job("          RUSTFLAGS:\n"),
    "env RUSTFLAGS block scalar folding to empty": _env_job("          RUSTFLAGS: >-\n\n"),
    "checksum && then a consumer on the next line": _job(_FETCH, _CHECK + " &&", "tar xzf f"),
    "checksum && then a comment then a consumer": _job(_FETCH, _CHECK + " && # c", "tar xzf f"),
    "checksum && then a consumer in a command substitution": _job(_FETCH, _CHECK + " && x=$(tar xzf f)"),
    "digest text with a command substitution": _job(_FETCH, 'echo "$(true) f" | sha256sum -c -', "tar xzf f"),
    "digest text with backticks": _job(_FETCH, 'echo "`true` f" | sha256sum -c -', "tar xzf f"),
    "function env then env -i": _job("env() { :; }", "env -i cargo build --locked"),
    "function env then env -": _job("env() { :; }", "env - cargo build --locked"),
    "function env then env --ignore-environment": _job("env() { :; }", "env --ignore-environment cargo build --locked"),
}

# Round 11 (code r10 F1, F2): a quoted span inside `${...}` and the body of an unquoted here-document are expanded by bash.
OBSERVATIONS.update({
    "heredoc body ${X@P}": _job("X='$(./f)'", "cat <<E", "${X@P}", "E"),
    "heredoc body command substitution": _job("cat <<E", "$(./f)", "E"),
    "heredoc body backticks": _job("cat <<E", "`./f`", "E"),
    "quoted default word ${Y@P}": _job("Y='$(./f)'", 'echo ${X:-"${Y@P}"}'),
    "quoted default word command substitution": _job('echo ${X:-"$(./f)"}'),
    "single-quoted default word command substitution": _job("echo \"${X:-'$(./f)'}\""),
})

# Round 11 (sec r10 F2): a quoted value holding an array subscript with a substitution is re-evaluated by bash.
OBSERVATIONS.update({
    "subscript with a command substitution": _job("X='a[$(./f)]'", "echo $(( X ))"),
    "subscript with a backtick": _job("X='a[`./f`]'", "echo $(( X ))"),
    "subscript with a transformation": _job("X='a[${Y@P}]'", "echo $(( X ))"),
    "env value with a subscript substitution": _env_job("          X: 'a[$(./f)]'\n"),
})

# Round 10 (sec r9 F1): `${name@<op>}` re-evaluates the value, so every operator letter (and one unknown letter) in four
# placements is a step text the guard refuses. Row C18 of the security review is `echo "${X@P}"` shaped.
TRANSFORM_OPS = ("P", "E", "Q", "A", "a", "K", "k", "U", "u", "L", "Z")
TRANSFORM_PLACES = {
    "bare": "echo ${X@%s}",
    "in double quotes": 'echo "${X@%s}"',
    "with an array subscript": "echo ${A[@]@%s}",
    "nested in a command substitution": "echo $(echo ${X@%s})",
}
for _op in TRANSFORM_OPS:
    for _place, _shape in TRANSFORM_PLACES.items():
        OBSERVATIONS["parameter transformation @%s %s" % (_op, _place)] = _job(_shape % _op)

# Round 10 (code r9 F1): the shapes the reviewer named that are NOT observable. name -> (workflow text, errors at head);
# the unmutated guard and the "unreadable RUSTFLAGS value allowed" mutant give the same count for each, so none of them
# can kill the mutant.
UNOBSERVABLE = {
    "env RUSTFLAGS empty string": (_env_job("          RUSTFLAGS: ''\n"), 0),
    "env RUSTFLAGS tilde": (_env_job("          RUSTFLAGS: ~\n"), 0),
    "env RUSTFLAGS flow sequence": (_env_job("          RUSTFLAGS: [a, b]\n"), 0),
    "env RUSTFLAGS flow mapping": (_env_job("          RUSTFLAGS: {a: b}\n"), 1),
}


def load_guard_module(path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("check_release_features_obs", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def error_counts(path, tree, docs):
    """{name: error count} of ``docs`` ({name: workflow text}) under the guard module at ``path``."""
    mod = load_guard_module(path)
    tree = Path(tree)
    tree.mkdir(parents=True, exist_ok=True)
    return {name: len(mod.r5_errors(doc, None, tree)) for name, doc in docs.items()}


def accepted_observations(path, tree):
    """Names of the OBSERVATIONS the guard module at ``path`` accepts (the unmutated guard accepts none)."""
    return [n for n, c in error_counts(path, tree, OBSERVATIONS).items() if c == 0]


def mutate(text, old, new):
    """The guard text with ``old`` replaced once above CONDITION_MARKER, or None when the anchor is not found exactly once."""
    import check_release_features as G

    cut = text.index(G.CONDITION_MARKER + "\n")
    head, tail = text[:cut], text[cut:]
    return (head.replace(old, new, 1) + tail) if head.count(old) == 1 else None


# (description, anchor, replacement): mutants that cannot change behaviour. Round 10 (code r9 F1): a row stays here only
# with the observation attempts that failed to tell it from the guard, named in a comment above it. The four rows of
# Round 9 were each tried against OBSERVATIONS; all four were observable, so they are EXTRA_MUTANTS rows now and the
# table is empty. `decision: prove each equivalent row by an attempted observation over keeping the label because the
# reviewer found one of four labels wrong`.
EQUIVALENT_MUTANTS = ()

# (description, anchor, replacement): mutants the guard's own table does not hold; each must be RED. The five that follow
# survive `--self-test` and are killed by a named OBSERVATIONS workflow (the killer column shows `observation: <name>`).
EXTRA_MUTANTS = (
    (
        "literal matrix value not scanned",
        "for label, variant in matrix_variants(raw, ctx):",
        "for label, variant in []:",
    ),
    (
        "chain chain needs the &&",
        'chained = chain is not None and chain[0] == k - 1 and info["prev"] == "&&"',
        "chained = chain is not None and chain[0] == k - 1",
    ),
    (
        "substitution in the checklist allowed",
        'if not alit and ("$(" in arg or "`" in arg):',
        "if False:",
    ),
    (
        "env -i allowed",
        'if word == "env" and any(a in ("-i", "--ignore-environment", "-") for a in texts):',
        "if False:",
    ),
    (
        "parameter transformation allowed",
        'elif c == "@" and j == op and s[j + 1:j + 2] != "" and s[j + 1] in TRANSFORM_LETTERS:',
        "elif False:",
    ),
    (
        "quoted span in a braced expansion not scanned",
        "j = self.quoted_span(j)",
        "j = s.find(c, j + 1) + 1",
    ),
    (
        "command substitution in a quoted span allowed",
        '''            elif c == "`" or s[j:j + 2] == "$(":
                raise ShellError("command substitution inside `${...}`")
            elif s[j:j + 2] == "${":
                j = self.braced(j + 2)
                continue
            j += 1
        raise ShellError("unterminated quote in `${...}`")''',
        '''            elif False:
                raise ShellError("command substitution inside `${...}`")
            elif s[j:j + 2] == "${":
                j = self.braced(j + 2)
                continue
            j += 1
        raise ShellError("unterminated quote in `${...}`")''',
    ),
    (
        "nested expansion in a quoted span not scanned",
        '''            elif s[j:j + 2] == "${":
                j = self.braced(j + 2)
                continue
            j += 1
        raise ShellError("unterminated quote in `${...}`")''',
        '''            elif False:
                j = self.braced(j + 2)
                continue
            j += 1
        raise ShellError("unterminated quote in `${...}`")''',
    ),
    (
        "transformation operator read at any position",
        'elif c == "@" and j == op and s[j + 1:j + 2] != "" and s[j + 1] in TRANSFORM_LETTERS:',
        'elif c == "@" and s[j + 1:j + 2] != "" and s[j + 1] in TRANSFORM_LETTERS:',
    ),
    (
        "transformation after a subscript allowed",
        "                if not sub:\n                    op = j + 1",
        "                if not sub:\n                    pass",
    ),
    (
        "transformation after an indirection prefix allowed",
        'op = j + 1 if s[j:j + 1] in ("!", "#") and s[j + 1:j + 2] not in ("", "}") else j',
        "op = j",
    ),
    (
        "unquoted here-document body not scanned",
        "self.words.append(text if quoted else self.heredoc_text(text))",
        "self.words.append(text)",
    ),
    (
        "quoted here-document body scanned",
        "self.words.append(text if quoted else self.heredoc_text(text))",
        "self.words.append(self.heredoc_text(text))",
    ),
    (
        "backslash in a here-document body not an escape",
        'if c == "\\\\" and self.i + 1 < self.n:\n                    out.append(self.s[self.i + 1])',
        "if False:\n                    out.append(self.s[self.i + 1])",
    ),
    (
        "pending here-documents shared with a nested scan",
        "self.s, self.n, self.i, self.pending = body, len(body), 0, []",
        "self.s, self.n, self.i = body, len(body), 0",
    ),
    (
        'transformation letters narrowed to one',
        'TRANSFORM_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"',
        'TRANSFORM_LETTERS = "P"',
    ),
    (
        'subscript holding a substitution allowed in a word',
        'if SUBSCRIPT_SUBST_RE.search(word):',
        'if False:',
    ),
    (
        'env value with a subscript substitution allowed',
        'if vtext is not None and SUBSCRIPT_SUBST_RE.search(vtext):',
        'if False:',
    ),
    (
        "unreadable RUSTFLAGS value allowed",
        "(value is None or RUSTFLAGS_BAD_RE.search(value) is not None)",
        "(value is not None and RUSTFLAGS_BAD_RE.search(value) is not None)",
    ),
    # Round 12 (code r11 F1-F3): one mutant per new rule site; every one must be RED.
    (
        'r12 F1: delimiter shape not enforced',
        'm = HEREDOC_DELIM_RE.fullmatch(raw)',
        'm = HEREDOC_DELIM_RE.fullmatch(raw) or raw',
    ),
    (
        'r12 F1: delimiter quote not noticed',
        'return raw.strip("\'\\"\\\\"), raw[0] in "\'\\"\\\\"',
        'return raw.strip("\'\\"\\\\"), False',
    ),
    (
        'r12 F1: delimiter shape accepts any text',
        'HEREDOC_DELIM_RE = re.compile(r"\\\\[A-Za-z0-9_]+|\'[A-Za-z0-9_]+\'|\\"[A-Za-z0-9_]+\\"|[A-Za-z0-9_]+")',
        'HEREDOC_DELIM_RE = re.compile(r".+")',
    ),
    (
        'r12 F1: delimiter word ends only at a blank',
        'HEREDOC_DELIM_END = " \\t\\n;&|()<>"',
        'HEREDOC_DELIM_END = " \\t\\n"',
    ),
    (
        'r12 F1: backslash delimiter form dropped',
        'HEREDOC_DELIM_RE = re.compile(r"\\\\[A-Za-z0-9_]+|',
        'HEREDOC_DELIM_RE = re.compile(r"',
    ),
    (
        'r12 F1: single-quote delimiter form dropped',
        "|'[A-Za-z0-9_]+'|",
        '|',
    ),
    (
        'r12 F2: subscript rule stops at the first bracket',
        'SUBSCRIPT_SUBST_RE = re.compile(r"\\[.*(?:\\$\\(|`|\\$\\{[^}]*@[A-Za-z])", re.S)',
        'SUBSCRIPT_SUBST_RE = re.compile(r"\\[[^\\]]*(?:\\$\\(|`|\\$\\{[^}]*@[A-Za-z])")',
    ),
    (
        'r12 F2: subscript rule ignores a command substitution',
        'SUBSCRIPT_SUBST_RE = re.compile(r"\\[.*(?:\\$\\(|`|\\$\\{[^}]*@[A-Za-z])", re.S)',
        'SUBSCRIPT_SUBST_RE = re.compile(r"\\[.*(?:`|\\$\\{[^}]*@[A-Za-z])", re.S)',
    ),
    (
        'r12 F2: subscript rule ignores a backtick',
        'SUBSCRIPT_SUBST_RE = re.compile(r"\\[.*(?:\\$\\(|`|\\$\\{[^}]*@[A-Za-z])", re.S)',
        'SUBSCRIPT_SUBST_RE = re.compile(r"\\[.*(?:\\$\\(|\\$\\{[^}]*@[A-Za-z])", re.S)',
    ),
    (
        'r12 F2: subscript rule ignores a transformation',
        'SUBSCRIPT_SUBST_RE = re.compile(r"\\[.*(?:\\$\\(|`|\\$\\{[^}]*@[A-Za-z])", re.S)',
        'SUBSCRIPT_SUBST_RE = re.compile(r"\\[.*(?:\\$\\(|`)", re.S)',
    ),
    (
        'r12 F2: subscript rule does not cross a newline',
        'SUBSCRIPT_SUBST_RE = re.compile(r"\\[.*(?:\\$\\(|`|\\$\\{[^}]*@[A-Za-z])", re.S)',
        'SUBSCRIPT_SUBST_RE = re.compile(r"\\[.*(?:\\$\\(|`|\\$\\{[^}]*@[A-Za-z])")',
    ),
    (
        'r12 F3: arithmetic expansion operands not checked',
        'self.need(self.arith_ok(body)',
        '(lambda *_a: None)(self.arith_ok(body)',
    ),
    (
        'r12 F3: indirect expansion name not checked',
        'self.need(self.name_ok(name), "`${!name}`"',
        '(lambda *_a: None)(self.name_ok(name), "`${!name}`"',
    ),
    (
        'r12 F3: read subscript not checked',
        'self.need(self.arith_ok(expr), f"the subscript',
        '(lambda *_a: None)(self.arith_ok(expr), f"the subscript',
    ),
    (
        'r12 F3: associative exemption applies to every array',
        'if name not in self.assoc:',
        'if True:',
    ),
    (
        'r12 F3: associative declaration not recorded',
        'self.assoc.add(nm)',
        'pass',
    ),
    (
        'r12 F3: substring offset not checked',
        'self.need(self.arith_ok(off)',
        '(lambda *_a: None)(self.arith_ok(off)',
    ),
    (
        'r12 F3: printf -v allowed',
        'if w == "printf" and k + 1 < len(texts) and texts[k + 1].startswith("-v"):',
        'if False:',
    ),
    (
        'r12 F3: test -v operand not checked',
        'if w == "-v" and k + 1 < len(texts):',
        'if False:',
    ),
    (
        'r12 F3: [[ -eq ]] operands not checked',
        'elif word == "[[" and w in ARITH_COMPARE and 1 < k < len(texts) - 1:',
        'elif False:',
    ),
    (
        'r12 F3: [[ -eq ]] left operand not checked',
        'self.need(self.arith_ok(texts[k - 1])',
        '(lambda *_a: None)(self.arith_ok(texts[k - 1])',
    ),
    (
        'r12 F3: [[ -eq ]] right operand not checked',
        'self.need(self.arith_ok(texts[k + 1]), f"`[[ {w} ]]`"',
        '(lambda *_a: None)(self.arith_ok(texts[k + 1]), f"`[[ {w} ]]`"',
    ),
    (
        'r12 F3: declare -i name not checked',
        'self.name_ok(nm) and self.arith_ok(val)',
        'self.arith_ok(val)',
    ),
    (
        'r12 F3: declare -i value not checked',
        'self.name_ok(nm) and self.arith_ok(val)',
        'self.name_ok(nm)',
    ),
    (
        'r12 F3: declare -n value not checked',
        'self.need(self.name_text_ok(val), f"`{word} -n`"',
        '(lambda *_a: None)(self.name_text_ok(val), f"`{word} -n`"',
    ),
    (
        'r12 F3: declare of an expanded name allowed',
        'if not eq and is_exp(a):',
        'if False:',
    ),
    (
        'r12 F3: array declaration not non-literal',
        'if "A" in flags or "a" in flags:',
        'if False:',
    ),
    (
        'r12 F3: nameref not non-literal',
        'if "n" in flags:\n                        self.nonlit.add(nm)',
        'if "n" in flags:\n                        pass',
    ),
    (
        'r12 F3: nameref target not non-literal',
        'self.nonlit.add(tgt.group(1))',
        'pass',
    ),
    (
        'r12 F3: array literal not non-literal',
        'self.nonlit.add(an.group(1))',
        'pass',
    ),
    (
        'r12 F3: non-literal names ignored',
        'if name in self.nonlit or (name in self.for_vars',
        'if (name in self.for_vars',
    ),
    (
        'r12 F3: loop variable always literal',
        '(name in self.for_vars and name in self.for_bad)',
        'False',
    ),
    (
        'r12 F3: positional parameter literal',
        ' or (name.isdigit() and name != "0"):',
        ':',
    ),
    (
        'r12 F3: arithmetic-result assignment not required',
        'if val != "$(())":',
        'if False:',
    ),
    (
        'r12 F3: expanded or backtick value allowed',
        'elif "$" in val or "`" in val or not self.arith_ok(val, seen):',
        'elif not self.arith_ok(val, seen):',
    ),
    (
        'r12 F3: assigned value tokens not checked',
        'elif "$" in val or "`" in val or not self.arith_ok(val, seen):',
        'elif "$" in val or "`" in val:',
    ),
    (
        'r12 F3: indirect name not recorded',
        'self.brace_names.append(name)',
        'pass',
    ),
    (
        'r12 F3: subscript of an indirection not recorded',
        'self.brace_subs.append((name, rest[1:rest.rfind("]")] if "]" in rest else rest[1:]))',
        'pass',
    ),
    (
        'r12 F3: subscript not recorded',
        'self.brace_subs.append((name, expr))',
        'pass',
    ),
    (
        'r12 F3: offset not recorded',
        'self.brace_offsets.extend(b[pos + 1:].split(":"))',
        'pass',
    ),
    (
        'r12 F3: name listing refused',
        'if rest in ("*", "@", "[@]", "[*]"):',
        'if False:',
    ),
    (
        'r12 F3: (( )) allowed',
        'if lv.cmd_pos and s[self.i:self.i + 1] == "(" and self.arithmetic(self.i + 1):',
        'if False:',
    ),
    (
        'r12 F3: ANSI-C not examined',
        'if bare and nxt == "\'":',
        'if False:',
    ),
    (
        'r12 F3: ANSI-C without a backslash refused',
        'if end >= 0 and "\\\\" in s[i + 2:end]:',
        'if end >= 0:',
    ),
    (
        'r12 F3: loop list words not examined',
        'if not (lit and FOR_PLAIN_WORD_RE.fullmatch(str(text))):',
        'if False:',
    ),
    (
        'r12 F3: quoted loop list words plain',
        'if not (lit and FOR_PLAIN_WORD_RE.fullmatch(str(text))):',
        'if not FOR_PLAIN_WORD_RE.fullmatch(str(text)):',
    ),
    (
        'r12 F3: loop list accepts any word',
        'FOR_PLAIN_WORD_RE = re.compile(r"[0-9]+|\\{[0-9]+\\.\\.[0-9]+(?:\\.\\.[0-9]+)?\\}")',
        'FOR_PLAIN_WORD_RE = re.compile(r".+")',
    ),
    (
        'r12 F3: brace range form dropped',
        'FOR_PLAIN_WORD_RE = re.compile(r"[0-9]+|\\{[0-9]+\\.\\.[0-9]+(?:\\.\\.[0-9]+)?\\}")',
        'FOR_PLAIN_WORD_RE = re.compile(r"[0-9]+")',
    ),
    (
        'r12 F3: bare for reads positional parameters as plain',
        'if lv.expect == "for_in" and lv.for_name:',
        'if False:',
    ),
    (
        'r12 F3: C-style header accepts any text',
        'FOR_ARITH_HEADER_RE.fullmatch(body.replace(";", " ")) is None',
        'False',
    ),
    (
        'r12 F3: C-style header character set widened',
        'FOR_ARITH_HEADER_RE = re.compile(r"[A-Za-z0-9_ \\t+\\-*/%<>=!&|^~,()]*")',
        'FOR_ARITH_HEADER_RE = re.compile(r".*")',
    ),
    (
        'r12 F3: C-style other names plain',
        'if m.group(0) != name:',
        'if False:',
    ),
    (
        'r12 F3: C-style loop not recorded as a loop variable',
        '        self.for_vars.append(name)\n        self.i = j',
        '        self.i = j',
    ),
    (
        'r12 F3: refusal swallowed',
        'self.f3_error = err',
        'pass',
    ),
    (
        'r12 F3: refusal reported beside an env problem',
        'elif scan.f3_error is not None:  # Round 12',
        'if scan.f3_error is not None:  # Round 12',
    ),
    (
        'r12 F3: refusal dropped when no older rule fired',
        'elif scan.f3_error is not None:  # Round 12',
        'elif False:  # Round 12',
    ),
    (
        'r12 F3: matrix variant refusal dropped',
        'f"text the scanner cannot read ({vscan.f3_error})" if vscan.f3_error is not None else ""',
        '""',
    ),
)

FAIL_RE = re.compile(r"self-test FAIL:[^'\n]*'([^']*)'")


def run_guard(path, root, tmpdir):
    env = dict(os.environ)
    env["TMPDIR"] = tmpdir
    res = subprocess.run(
        [sys.executable, "-I", str(path), "--self-test", str(root)],
        capture_output=True, text=True, env=env,
    )
    return res.returncode, res.stdout, res.stderr


def classify(rc, err, equivalent):
    """Return (state, note) for one mutant run."""
    if rc == 0:
        return ("EQUIVALENT" if equivalent else "SURVIVES"), "-"
    m = FAIL_RE.search(err)
    if m:
        return "RED", m.group(1)
    m = re.search(r"self-test FAIL: ([^\n]{1,80})", err)
    if m:  # a named check that is not a table case (for example a helper of the guard)
        return "RED", m.group(1)
    if "Traceback (most recent call last)" in err:  # the mutant made the guard crash: detected, killed by a crash
        return "RED", "crash: " + err.strip().splitlines()[-1][:100]
    return "OTHER-DEFECT", "failed without a named case: " + err.strip().splitlines()[-1][:100] if err.strip() else "failed without output"


OBSERVE_NONE, OBSERVE_ACCEPTED = 0, 3  # the two exit codes of `--observe`; anything else is a failed run


def observe(path, tmpdir):
    """Round 10/11: run the OBSERVATIONS against the guard at ``path`` in its own interpreter. Returns ("none", []) when it
    refuses all of them, ("accepted", names) when it accepts some, and ("failed", [message]) when the run exited with
    neither expected code (code r10 F4: a run that broke is not evidence about the mutant)."""
    res = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--observe", str(path), str(Path(tmpdir) / "obs")],
                         capture_output=True, text=True, env=dict(os.environ, TMPDIR=str(tmpdir)))
    names = [ln for ln in res.stdout.splitlines() if ln]
    if res.returncode == OBSERVE_NONE and not names:
        return "none", []
    if res.returncode == OBSERVE_ACCEPTED and names:
        return "accepted", names
    last = (res.stderr.strip().splitlines() or ["no output"])[-1][:100]
    return "failed", [f"observation run exited {res.returncode}: {last}"]


def work_row(mutated, label, root, tmpdir, equivalent, stem="mutant"):
    """(state, note) of one mutant (bytes). The row is RED on a self-test kill or on an accepted observation, and an
    OTHER-DEFECT when the observation run itself failed."""
    path = Path(tmpdir) / f"{stem}.py"
    path.write_bytes(mutated)
    try:
        rc, _out, err = run_guard(path, root, tmpdir)
        state, note = classify(rc, err, equivalent)
        if rc == 0:  # self-test stayed green: try to tell the mutant from the guard by an observation
            kind, seen = observe(path, tmpdir)
            if kind == "accepted":
                state, note = "RED", "observation: " + seen[0]
            elif kind == "failed":
                state, note = "OTHER-DEFECT", seen[0]
    finally:
        try:
            path.unlink()
        except OSError:
            pass
    return state, note


def control_row(root, tmpdir):
    """Row 0: the unmutated guard passes `--self-test` and accepts no observation (code r10 F4: the control observes too)."""
    rc, _o, err = run_guard(GUARD, root, tmpdir)
    if rc != 0:
        return "RED", (err.strip().splitlines() or ["self-test failed"])[-1][:200]
    kind, seen = observe(GUARD, tmpdir)
    if kind == "none":
        return "GREEN", "-"
    return ("RED" if kind == "accepted" else "OTHER-DEFECT"), seen[0]


def work(item):
    k, label, mutated, root, tmpdir, equivalent = item
    if mutated is None:
        return k, "OTHER-DEFECT", label
    state, note = work_row(mutated, label, root, tmpdir, equivalent, f"mutant_{k}")
    return k, state, f"{label} | {note}"


def build_items(root, tmpdir, limit, select="", lines=""):
    import check_release_features as G

    src = GUARD.read_bytes()
    text = src.decode("utf-8")
    cut = text.index(G.CONDITION_MARKER + "\n")
    head, tail = text[:cut], text[cut:]
    items = []
    k = 1
    for line, start, end in G._refusal_sites(src):
        mutated = src[:start] + b"(lambda *_a, **_k: None)" + src[end:]
        items.append((k, f"refusal call at line {line}", mutated, root, tmpdir, False))
        k += 1
    for desc, old, new in G.CONDITION_MUTANTS:
        n = head.count(old)
        mutated = (head.replace(old, new, 1) + tail).encode("utf-8") if n == 1 else None
        label = desc if n == 1 else f"{desc} (anchor found {n} times, not once)"
        items.append((k, label, mutated, root, tmpdir, False))
        k += 1
    for desc, old, new in EXTRA_MUTANTS:
        n = head.count(old)
        mutated = (head.replace(old, new, 1) + tail).encode("utf-8") if n == 1 else None
        label = desc if n == 1 else f"{desc} (anchor found {n} times, not once)"
        items.append((k, label, mutated, root, tmpdir, False))
        k += 1
    for desc, old, new in EQUIVALENT_MUTANTS:
        n = head.count(old)
        mutated = (head.replace(old, new, 1) + tail).encode("utf-8") if n == 1 else None
        label = desc if n == 1 else f"{desc} (anchor found {n} times, not once)"
        items.append((k, label, mutated, root, tmpdir, True))
        k += 1
    if select or lines:  # Round 12: the impact-selected sweep keeps the rows whose label matches or whose refusal line is in range
        lo, hi = (int(x) for x in lines.split("-")) if lines else (0, -1)
        keep = []
        for item in items:
            site = re.fullmatch(r"refusal call at line (\d+)", item[1])
            if (select and re.search(select, item[1])) or (site and lo <= int(site.group(1)) <= hi):
                keep.append(item)
        items = keep
    return items[:limit] if limit else items


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--observe"]:  # internal: print the OBSERVATIONS the guard module at argv[1] accepts
        names = accepted_observations(argv[1], argv[2])
        for name in names:
            print(name)
        return OBSERVE_ACCEPTED if names else OBSERVE_NONE
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--root", default=str(HERE.parent.parent))
    ap.add_argument("--out", default="")
    ap.add_argument("--limit", type=int, default=0, help="run only the first N mutants (debug)")
    ap.add_argument("--select", default="", help="impact-selected sweep: only rows whose label matches this regex")
    ap.add_argument("--lines", default="", help="impact-selected sweep: also the refusal calls on guard lines A-B")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    base = root / ".local-runs"
    base.mkdir(parents=True, exist_ok=True)
    started = time.time()
    lines = []
    with tempfile.TemporaryDirectory(prefix="relfeat-par.", dir=str(base)) as tmpdir:
        control, cnote = control_row(root, tmpdir)
        rc = 0 if control == "GREEN" else 1
        err = cnote
        lines.append(f"0 CONTROL-{control} unmutated guard" + ("" if control == "GREEN" else f" | {cnote}"))
        counts = {"RED": 0, "EQUIVALENT": 0, "SURVIVES": 0, "OTHER-DEFECT": 0}
        if rc == 0:
            items = build_items(root, tmpdir, args.limit, args.select, args.lines)
            with multiprocessing.Pool(max(1, args.jobs)) as pool:
                for k, state, note in pool.imap_unordered(work, items):
                    counts[state] += 1
                    lines.append(f"{k} {state} {note}")
        else:
            lines.append(err.strip()[-300:])
    lines[1:] = sorted(lines[1:], key=lambda s: int(s.split(" ", 1)[0]) if s.split(" ", 1)[0].isdigit() else 0)
    total = sum(counts.values())
    summary = (f"RED {counts['RED']} / EQUIVALENT {counts['EQUIVALENT']} / SURVIVES {counts['SURVIVES']} / "
               f"OTHER-DEFECTS {counts['OTHER-DEFECT']} (rows run: {total + 1})")
    wall = f"wall time {time.time() - started:.0f} s with {args.jobs} jobs"
    lines += [summary, wall]
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    ok = rc == 0 and counts["SURVIVES"] == 0 and counts["OTHER-DEFECT"] == 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
