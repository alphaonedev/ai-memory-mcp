"""Executed-command ledger of Apache AGE builds (#9951 r2, #9965, #9981).

An AGE build is found by what a file EXECUTES, never by what its text says.
Each file is cut into units by its kind and each unit into commands:

* Dockerfile (a basename that contains "Dockerfile"): every RUN of one build
  stage, in order (shell form joined over backslash continuations with the
  comment lines Docker drops dropped, JSON exec form, heredoc body); WORKDIR
  sets the directory. One stage is one unit.
* YAML (.yml, .yaml, .yml.tpl, .yaml.tpl): every `run:` value (single line or
  block) is a unit; a `content: |` block is a unit when it starts with a
  shell shebang; the items of `runcmd:` / `bootcmd:` (string, block or flow
  list) are one unit.
* Shell (.sh, .bash or a shell shebang): the whole file is one unit and every
  here-document body is a unit of its own.
* Makefile (Makefile, *.mk): the recipe of each rule is one unit.
* Python (.py): every subprocess.run / call / check_call / check_output /
  Popen with a list argv (a `cwd=` constant sets the directory), and every
  shell=True string and os.system string parsed as shell, in source order;
  the module is one unit. A module that does not parse is a finding.

Comments, strings, echo arguments, docstrings and prose never execute and
never count. Commands are normalised: leading VAR=value words and the
wrappers sudo, env, nice, time, exec, command and nohup are dropped; the
script of `bash -c` / `sh -c` and the remote command of ssh are parsed as
shell; cd and pushd set the directory.

A command is an AGE build when its argv0 is make, gmake or $(MAKE) and
either its directory (the -C value, else the current directory) names age
as a word, or an earlier command of the unit names the AGE source (the SSOT
repo URL, apache/age, a 7+ hex prefix of AGE_SOURCE_COMMIT or an
AGE_SOURCE_ variable). The build is patched when an earlier command of the
same unit runs the applier: argv0 python or python3 with an argument that
ends in apply_age_patch.py, and neither --verify nor --print-pin (those
only check). An unpatched build is `<path>:<line>: age-build-without-patch`.
"""
import ast
import json
import os
import re

APPLIER = "apply_age_patch.py"
CHECK_ONLY_FLAGS = {"--verify", "--print-pin"}
MAKE_NAMES = {"make", "gmake", "$(MAKE)", "${MAKE}", "$MAKE"}
PYTHON_RE = re.compile(r"python3?(?:\.\d+)?")
AGE_DIR_RE = re.compile(r"(?i)(?<![a-z])age(?![a-z])")
HEX_RUN_RE = re.compile(r"(?i)(?<![0-9a-z])[0-9a-f]{7,40}(?![0-9a-z])")
AGE_NAMES = ("apache/age", "AGE_SOURCE_")
MIN_SHA_PREFIX = 7
MAX_DEPTH = 8
SHELL_SHEBANG = re.compile(r"^#!\s*\S*(?:/|\s)(?:env\s+)?(?:ba|da|z|k)?sh\b")
WRAPPERS = {"sudo", "env", "nice", "time", "exec", "command", "nohup"}
WRAPPER_ARG_OPTS = {"sudo": {"-u", "-g", "-C", "-h", "-p", "-U"}, "nice": {"-n"}, "env": {"-u", "-C", "-S"}}
SHELLS = {"bash", "sh", "dash", "zsh", "ksh"}
SSH_ARG_OPTS = {"-i", "-p", "-o", "-l", "-F", "-J", "-b", "-c", "-D", "-E", "-L", "-m", "-O", "-Q", "-R", "-S", "-W", "-w"}
RESERVED = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "case", "esac", "!", "{", "}", "function"}
SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")
FINDING = "age-build-without-patch"
UNPARSEABLE_PY = "ledger-unparseable-python"


class Command:
    """One executed command: its argv, the line of argv0, the line of each
    word (for a nested `sh -c` script) and a fixed directory (Python cwd=)."""
    __slots__ = ("argv", "line", "word_lines", "cwd")

    def __init__(self, argv, line, word_lines=None, cwd=None):
        self.argv, self.line, self.cwd = argv, line, cwd
        self.word_lines = word_lines or [line] * len(argv)


# --- shell -------------------------------------------------------------------
def _balanced(text, i, open_ch, close_ch):
    """Index just past the close that balances text[i] == open_ch (quotes skipped)."""
    depth, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            i = n if j < 0 else j + 1
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def shell_commands(text, line0=1, depth=0):
    """Commands (argv, line of argv0) of a shell text, in execution order;
    a here-document body is parsed as shell too (it is commonly fed to a
    shell); command substitutions run before the command that holds them."""
    cmds = []
    if depth > MAX_DEPTH:
        return cmds
    words, word, word_line, has_word = [], [], line0, False
    skip_next, heredocs = False, []
    line, i, n = line0, 0, len(text)

    def end_word():
        nonlocal word, has_word, skip_next
        if has_word:
            if skip_next:
                skip_next = False
            else:
                words.append(("".join(word), word_line))
        word, has_word = [], False

    def end_cmd():
        nonlocal words
        end_word()
        if words:
            cmds.append(Command([w for w, _ in words], words[0][1], [ln for _, ln in words]))
        words = []

    def start(cur_line):
        nonlocal has_word, word_line
        if not has_word:
            has_word, word_line = True, cur_line

    while i < n:
        c = text[i]
        if c == "\n":
            end_cmd()
            line += 1
            i += 1
            for delim, strip_tabs in heredocs:
                body, body_line = [], line
                while i < n:
                    j = text.find("\n", i)
                    j = n if j < 0 else j
                    raw = text[i:j]
                    i = j + 1
                    line += 1
                    if (raw.lstrip("\t") if strip_tabs else raw) == delim:
                        break
                    body.append(raw)
                cmds.extend(shell_commands("\n".join(body), body_line, depth + 1))
            heredocs = []
            continue
        if c in " \t\r":
            end_word()
            i += 1
            continue
        if c == "#" and not has_word:
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "\\":
            if i + 1 < n and text[i + 1] == "\n":
                line += 1
                i += 2
                continue
            start(line)
            word.append(text[i + 1:i + 2])
            i += 2
            continue
        if c == "'":
            start(line)
            j = text.find("'", i + 1)
            j = n if j < 0 else j
            word.append(text[i + 1:j])
            line += text.count("\n", i, j)
            i = j + 1
            continue
        if c == '"':
            start(line)
            i += 1
            while i < n and text[i] != '"':
                d = text[i]
                if d == "\\" and i + 1 < n and text[i + 1] in '"\\$`\n':
                    if text[i + 1] == "\n":
                        line += 1
                    else:
                        word.append(text[i + 1])
                    i += 2
                    continue
                if d == "$" and text.startswith("$(", i) and not text.startswith("$((", i):
                    j = _balanced(text, i + 1, "(", ")")
                    cmds.extend(shell_commands(text[i + 2:j - 1], line, depth + 1))
                    word.append(text[i:j])
                    line += text.count("\n", i, j)
                    i = j
                    continue
                if d == "`":
                    j = text.find("`", i + 1)
                    j = n if j < 0 else j
                    cmds.extend(shell_commands(text[i + 1:j], line, depth + 1))
                    word.append(text[i:j + 1])
                    line += text.count("\n", i, j)
                    i = j + 1
                    continue
                if d == "\n":
                    line += 1
                word.append(d)
                i += 1
            i += 1
            continue
        if c == "$" and text.startswith("$(", i):
            start(line)
            j = _balanced(text, i + 1, "(", ")")
            if not text.startswith("$((", i):
                cmds.extend(shell_commands(text[i + 2:j - 1], line, depth + 1))
            word.append(text[i:j])
            line += text.count("\n", i, j)
            i = j
            continue
        if c == "$" and text.startswith("${", i):
            start(line)
            j = _balanced(text, i + 1, "{", "}")
            word.append(text[i:j])
            i = j
            continue
        if c == "`":
            start(line)
            j = text.find("`", i + 1)
            j = n if j < 0 else j
            cmds.extend(shell_commands(text[i + 1:j], line, depth + 1))
            word.append(text[i:j + 1])
            line += text.count("\n", i, j)
            i = j + 1
            continue
        if c in ";&|()":
            end_cmd()
            i += 1
            continue
        if c in "<>":
            if has_word and "".join(word).isdigit():
                word, has_word = [], False
            end_word()
            if text.startswith("<<<", i):
                i += 3
                skip_next = True
                continue
            if text.startswith("<<", i):
                i += 2
                strip_tabs = text.startswith("-", i)
                i += 1 if strip_tabs else 0
                while i < n and text[i] in " \t":
                    i += 1
                m = re.match(r"""(['"]?)([^\s'";&|<>()]+)\1""", text[i:])
                if m:
                    heredocs.append((m.group(2), strip_tabs))
                    i += m.end()
                continue
            while i < n and text[i] in "<>&":
                i += 1
            if text.startswith("&", i - 1) and i < n and text[i].isdigit():
                i += 1  # 2>&1
                continue
            skip_next = True
            continue
        start(line)
        word.append(c)
        i += 1
    end_cmd()
    return cmds


def _basename(word):
    return word.rsplit("/", 1)[-1]


def normalise(cmd, depth=0):
    """The commands one parsed command executes: wrappers and assignments
    dropped, `sh -c` and ssh remote commands parsed as shell."""
    argv, lines = list(cmd.argv), list(cmd.word_lines)
    i = 0

    def skip_opts(name):
        nonlocal i
        while i < len(argv) and argv[i].startswith("-") and argv[i] != "--":
            i += 2 if argv[i] in WRAPPER_ARG_OPTS.get(name, ()) else 1
        if i < len(argv) and argv[i] == "--":
            i += 1

    while i < len(argv):
        w = argv[i]
        if w in RESERVED or ASSIGN_RE.match(w):
            i += 1
            continue
        base = _basename(w)
        if base in WRAPPERS:
            i += 1
            skip_opts(base)
            continue
        break
    argv, lines = argv[i:], lines[i:]
    if not argv:
        return []
    base = _basename(argv[0])
    if depth < MAX_DEPTH and base in SHELLS and "-c" in argv[1:]:
        k = argv.index("-c", 1)
        if k + 1 < len(argv):
            out = []
            for sub in shell_commands(argv[k + 1], lines[k + 1], depth + 1):
                sub.cwd = cmd.cwd
                out.extend(normalise(sub, depth + 1))
            return out
    if depth < MAX_DEPTH and base == "ssh":
        k = 1
        while k < len(argv) and argv[k].startswith("-"):
            k += 2 if argv[k] in SSH_ARG_OPTS else 1
        if k + 1 < len(argv):
            out = []
            for sub in shell_commands(" ".join(argv[k + 1:]), lines[k + 1], depth + 1):
                out.extend(normalise(sub, depth + 1))
            return out
    return [Command(argv, lines[0], lines, cmd.cwd)]


# --- the decision --------------------------------------------------------------
def names_age_source(argv, ssot):
    repo = ssot.get("AGE_SOURCE_REPO") or "\0"
    commit = (ssot.get("AGE_SOURCE_COMMIT") or "").lower()
    for w in argv:
        if repo in w or any(name in w for name in AGE_NAMES):
            return True
        for m in HEX_RUN_RE.finditer(w):
            tok = m.group(0).lower()
            if commit and len(tok) >= MIN_SHA_PREFIX and commit.startswith(tok):
                return True
    return False


def is_applier(argv):
    if _basename(argv[0]) == APPLIER or (PYTHON_RE.fullmatch(_basename(argv[0])) and any(
            w.endswith(APPLIER) for w in argv[1:])):
        return not any(w in CHECK_ONLY_FLAGS or w.split("=", 1)[0] in CHECK_ONLY_FLAGS for w in argv[1:])
    return False


def make_dir(argv, cwd):
    for k, w in enumerate(argv[1:], 1):
        if w == "-C" and k + 1 < len(argv):
            return argv[k + 1]
        if w.startswith("-C") and len(w) > 2:
            return w[2:]
        if w.startswith("--directory="):
            return w.split("=", 1)[1]
    return cwd


def evaluate(unit, ssot, cwd=""):
    """[(line, patched)] of every AGE build of one unit (a list of Commands)."""
    builds, named, patched = [], False, False
    for raw in unit:
        for cmd in normalise(raw):
            argv = cmd.argv
            if cmd.cwd is not None:
                cwd = cmd.cwd
            base = _basename(argv[0])
            if base in ("cd", "pushd"):
                target = argv[1] if len(argv) > 1 else ""
                cwd = target if target.startswith("/") or not cwd else cwd.rstrip("/") + "/" + target
            elif is_applier(argv):
                patched = True
            elif argv[0] in MAKE_NAMES or base in MAKE_NAMES:
                if named or AGE_DIR_RE.search(make_dir(argv, cwd) or ""):
                    builds.append((cmd.line, patched))
            named = named or names_age_source(argv, ssot)
    return builds


# --- units per file kind -----------------------------------------------------------
def dockerfile_units(text):
    units, cur, lines = [], [], text.split("\n")
    k = 0
    while k < len(lines):
        start = k
        raw = lines[k]
        m = re.match(r"(?i)^\s*(FROM|RUN|WORKDIR)\b\s*(.*)$", raw)
        k += 1
        if not m:
            continue
        instr, rest = m.group(1).upper(), m.group(2)
        body = [rest]
        while body[-1].rstrip().endswith("\\") and k < len(lines):
            nxt = lines[k]
            body.append("\\" if nxt.lstrip().startswith("#") else nxt)
            k += 1
        if instr == "FROM":
            if cur:
                units.append(cur)
            cur = []
            continue
        if instr == "WORKDIR":
            cur.append(Command(["cd", rest.strip()], start + 1))
            continue
        joined = "\n".join(body)
        head = joined.lstrip()
        if head.startswith("["):
            try:
                argv = json.loads(head)
                if isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv):
                    cur.append(Command(argv, start + 1))
                    continue
            except ValueError:
                pass
        hd = re.match(r"<<-?\s*(['\"]?)(\w+)\1", head)
        if hd:
            hbody, hline = [], k + 1
            while k < len(lines) and lines[k].strip() != hd.group(2):
                hbody.append(lines[k])
                k += 1
            k += 1
            cur.extend(shell_commands("\n".join(hbody), hline))
            continue
        cur.extend(shell_commands(joined, start + 1))
    if cur:
        units.append(cur)
    return units


def _block(lines, k, key_col, seq_at_col=False):
    """Lines of the YAML node that starts after line k: every line more
    indented than key_col (and, for a sequence value, the `- ` items at
    key_col itself, which YAML allows for a mapping's sequence)."""
    body, first = [], k + 1
    j = k + 1
    while j < len(lines):
        ln = lines[j]
        col = len(ln) - len(ln.lstrip())
        if ln.strip() and col <= key_col and not (seq_at_col and col == key_col and ln.lstrip().startswith("- ")):
            break
        body.append(ln)
        j += 1
    return body, first, j


def _flow_list(text):
    items, cur, quote, i = [], [], None, 0
    text = text.strip()
    if not (text.startswith("[") and text.endswith("]")):
        return None
    text = text[1:-1]
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < len(text):
                cur.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            else:
                cur.append(c)
        elif c in "'\"":
            quote = c
        elif c == ",":
            items.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    items.append("".join(cur).strip())
    return [x for x in items if x]


def _scalar(value):
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return re.sub(r"\s+#.*$", "", v)


def yaml_units(text):
    units, lines = [], text.split("\n")
    k = 0
    while k < len(lines):
        ln = lines[k]
        m = re.match(r"^(\s*)(-\s+)?(run|content|runcmd|bootcmd)\s*:\s*(.*)$", ln)
        if not m:
            k += 1
            continue
        key_col = len(m.group(1)) + len(m.group(2) or "")
        key, value = m.group(3), m.group(4).strip()
        if key in ("runcmd", "bootcmd"):
            body, first, k = _block(lines, k, key_col, seq_at_col=True)
            unit, item_col = [], None
            j = 0
            while j < len(body):
                im = re.match(r"^(\s*)-\s+(.*)$", body[j])
                if not im or (item_col is not None and len(im.group(1)) != item_col):
                    j += 1
                    continue
                item_col = len(im.group(1))
                item, line_no = im.group(2), first + j + 1
                if re.match(r"^[|>][-+0-9]*\s*$", item):
                    sub, sfirst, end = _block(body, j, item_col)
                    unit.extend(shell_commands("\n".join(sub), first + sfirst + 1))
                    j = end
                    continue
                flow = _flow_list(item)
                if flow is not None:
                    unit.append(Command(flow, line_no))
                else:
                    unit.extend(shell_commands(_scalar(item), line_no))
                j += 1
            units.append(unit)
            continue
        if re.match(r"^[|>][-+0-9]*\s*(?:#.*)?$", value):
            body, first, k = _block(lines, k, key_col)
            script = "\n".join(body)
            if key == "content" and not SHELL_SHEBANG.match(script.lstrip()):
                continue
            units.append(shell_commands(script, first + 1))
            continue
        k += 1
        if key == "run" and value:
            units.append(shell_commands(_scalar(value), k))
    return units


def makefile_units(text):
    units, cur, lines = [], [], text.split("\n")
    for k, ln in enumerate(lines, 1):
        if ln.startswith("\t"):
            body = ln[1:].lstrip("@-+ ")
            body = body.replace("$(MAKE)", "make").replace("${MAKE}", "make")
            cur.extend(shell_commands(body, k))
        elif ln.strip() and not ln.startswith("#"):
            if cur:
                units.append(cur)
            cur = []
    if cur:
        units.append(cur)
    return units


def _const_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "<expr>" for v in node.values)
    return "<expr>"


def python_units(text):
    tree = ast.parse(text)
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
        owner = f.value.id if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else ""
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        first = node.args[0]
        if owner == "os" and name == "system":
            calls.append((node.lineno, node.col_offset, shell_commands(_const_str(first), node.lineno)))
            continue
        if name not in SUBPROCESS_FUNCS:
            continue
        shell = isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True
        cwd = _const_str(kw["cwd"]) if "cwd" in kw else None
        if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
            argv = [_const_str(e) for e in first.elts]
            if shell:
                cmds = shell_commands(argv[0], node.lineno)
            else:
                cmds = [Command(argv, node.lineno)]
        elif shell or isinstance(first, (ast.Constant, ast.JoinedStr)):
            cmds = shell_commands(_const_str(first), node.lineno)
        else:
            continue
        if cwd is not None:
            for c in cmds:
                c.cwd = cwd
        calls.append((node.lineno, node.col_offset, cmds))
    calls.sort(key=lambda t: (t[0], t[1]))
    unit = [c for _, _, cmds in calls for c in cmds]
    return [unit]


def file_kind(rel, text):
    base = os.path.basename(rel)
    if "Dockerfile" in base:
        return "dockerfile"
    if re.search(r"\.ya?ml(?:\.tpl)?$", base):
        return "yaml"
    if base == "Makefile" or base.endswith(".mk"):
        return "makefile"
    if base.endswith(".py"):
        return "python"
    if base.endswith((".sh", ".bash")) or SHELL_SHEBANG.match(text):
        return "shell"
    return None


def units_of(rel, text):
    kind = file_kind(rel, text)
    if kind == "dockerfile":
        return dockerfile_units(text)
    if kind == "yaml":
        return yaml_units(text)
    if kind == "makefile":
        return makefile_units(text)
    if kind == "python":
        return python_units(text)
    if kind == "shell":
        return [shell_commands(text)]
    return []


def builds(rel, text, ssot):
    """[(line, patched)] of every AGE build the file executes. Raises
    SyntaxError for a Python module that does not parse."""
    out = []
    for unit in units_of(rel, text):
        out.extend(evaluate(unit, ssot))
    return sorted(set(out))


def findings(rel, text, ssot):
    try:
        found = builds(rel, text, ssot)
    except (SyntaxError, ValueError, RecursionError):
        return [f"{rel}: {UNPARSEABLE_PY}"]
    return [f"{rel}:{line}: {FINDING}" for line, patched in found if not patched]
