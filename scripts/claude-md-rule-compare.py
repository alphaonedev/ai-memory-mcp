#!/usr/bin/env python3
"""claude-md-rule-compare.py - issue #4507 (PR #4508 review R3-F3): make a CLAUDE.md rule change loud.

Run by .github/workflows/claude-md-rule-compare.yml from the BASE branch (pull_request_target). The pull
request head is DATA: its CLAUDE.md and the two docs/reference files are read out of git objects with
`git ls-tree` and `git cat-file` into a scratch directory. Nothing from the head is executed, imported or
checked out, and a symlink blob (mode 120000) at any of the three paths is refused.

The BASE guard (scripts/check-claude-md-size.py of the base checkout) and the BASE manifest
(scripts/qc-allowlists/claude-md-rule-sections.sha256) then judge the head copies:

  * every rule section whose raw text no longer hashes to the BASE manifest (changed, added, removed) is
    written to the step summary with the section name and a unified diff, headed "RULE TEXT CHANGED";
  * if the only differences are ASCII digit runs of the generated census (a number before its unit words)
    inside a section whose heading starts with `## Prime directive` (the real heading carries a date), the
    heading is "COUNT CHANGED" instead;
  * any OTHER error the base guard reports about the head copies (a lowered floor, a deleted pinned
    heading, a broken index) is "BASE GUARD REFUSES THE HEAD" and counts as a rule change;
  * a rule change fails the job unless a commit in base..head carries a trailer line
    `Rule-Change-Approved-By: <who>`; a count-only change passes but is still printed.

This is TAMPERING EVIDENCE, not authority. The trailer is data an agent can also write, and the head also
carries its own manifest, so the comparison deliberately uses the base one. What enforces is the two
independent reviews and the sole merger. Fail closed: a missing, unreadable or symlinked base guard, base
manifest or base CLAUDE.md is a failure. The comparison runs only in isolated mode (`python3 -I`); the self-test
runs a non-isolated copy beside planted files named like every module this script imports, under several interpreter
flag sets, and fails if one runs (#5163). The base guard is compiled from its source bytes; the self-test plants a
weakened cached .pyc beside it and fails if it is used (#5163). Bootstrap: pull_request_target
runs only once this workflow is on the base branch, so the PR that introduces it is judged by review.

Python 3.9 standard library only.

Usage (the comparison refuses to run without -I):
  python3 -I scripts/claude-md-rule-compare.py --base-root DIR --repo DIR --base-sha SHA --head-sha SHA
      --scratch DIR [--summary FILE]
  python3 -I scripts/claude-md-rule-compare.py --self-test
"""
import sys

if __name__ == "__main__" and not sys.flags.isolated:
    # R6 (#5163): checked before any other import. The self-test plants a file named like each imported module
    # beside a non-isolated copy and fails if one runs.
    print("## CLAUDE.md rule-change comparison\n\nRESULT: FAIL (closed) - run the comparison as "
          "`python3 -I scripts/claude-md-rule-compare.py` (isolated mode)")
    sys.exit(1)

import argparse  # noqa: E402 - after the isolated-mode refusal on purpose (#5163)
import ast
import contextlib
import difflib
import importlib.machinery
import importlib.util
import io
import os
import py_compile
import re
import shutil
import stat
import subprocess
import tokenize
import unicodedata
from pathlib import Path
from typing import NamedTuple

GUARD_REL = "scripts/check-claude-md-size.py"
MANIFEST_REL = "scripts/qc-allowlists/claude-md-rule-sections.sha256"
DATA_PATHS = ("CLAUDE.md", "docs/reference/ARCHITECTURE_REFERENCE.md", "docs/reference/CODE_STYLE.md")
# #6714: the leading `\S` is load-bearing. git trims only ASCII blanks, so a value led by a non-ASCII space (no-break,
# ideographic, em space) reaches this pattern with it; refusing such a value is the fail-closed direction.
TRAILER = re.compile(r"^Rule-Change-Approved-By: (\S.*)$", re.MULTILINE)
SHA = re.compile(r"^[0-9a-f]{40}$")
# #6572: an approval value must name somebody. These Unicode categories (control, format, unassigned, private use,
# surrogate, separators, combining marks) and the fillers below render as nothing, so a value made only of them
# is the same as an empty value and does not count.
INVISIBLE_CATEGORIES = frozenset(("Cc", "Cf", "Cn", "Co", "Cs", "Zl", "Zp", "Zs", "Mn", "Me"))
INVISIBLE_FILLERS = frozenset("\u115f\u1160\u3164\uffa0\u2800")
# R4 (#4507): a digit is rule text (a vote size, a file threshold, a release branch). Only a digit run that is a
# public-surface census count INSIDE a section whose heading STARTS WITH CENSUS_SECTION (the real heading carries a
# date, so the match is a prefix; #5375) may change without the trailer; the same words in any other section are rule
# text. Fail closed, the precedent of root issue #4869.
CENSUS_SECTION = "## Prime directive"
CENSUS_DIGITS = re.compile(
    r"\b\d+(?=\s+(?:MCP tools|production HTTP route registrations|unique URL paths|CLI subcommands|"
    r"in the default build)\b)", re.ASCII)  # R5 (#5165): ASCII digits only; any other digit is rule text
# R4 (#4507): the code and configuration that judge a rule change. A change to any of them is reported and needs
# the trailer, so a guard weakened in one PR cannot silently judge the next one. The manifest is not listed: the
# section comparison above already judges it against the base.
TRUSTED_PATHS = ("scripts/check-claude-md-size.py", "scripts/claude-md-rule-compare.py",
                 ".github/workflows/claude-md-guard.yml", ".github/workflows/claude-md-rule-compare.yml",
                 ".github/CODEOWNERS")
DIFF_LINE_CAP = 200
MAX_BLOB_BYTES = 2 * 1024 * 1024  # far above any legitimate file; refuses a memory-exhaustion blob
# Messages of the base guard that the section comparison already reports in its own words.
DRIFT_MARKERS = ("changed: sha256", "is not pinned in", "is missing from CLAUDE.md")


def git(repo: Path, *args: str) -> bytes:
    """Run git in `repo` and return stdout bytes; a non-zero exit raises RuntimeError (fail closed)."""
    # #6712: local replace objects (refs/replace, `git replace --graft`) change the messages and parents base..head reads;
    # every git call here ignores them, so the history the comparison judges is the history that was fetched.
    # #6798: a commit-graph file (in the repository or an alternate object store) supplies parent edges without a
    # checksum check and GIT_NO_REPLACE_OBJECTS does not turn it off, so the graph is disabled per call as well.
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    command = ["git", "-C", str(repo), "-c", "core.commitGraph=false", *args]
    result = subprocess.run(command, capture_output=True, check=False, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout


def regular_file(path: Path, label: str) -> None:
    """Raise unless `path` is a regular, non-symlink file (every level below its checkout is not checked: the
    base checkout is the trusted workflow checkout)."""
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        raise RuntimeError(f"cannot stat {label}: {exc}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise RuntimeError(f"{label} is a symlink or not a regular file")


def load_source_module(name: str, path: Path):
    """R5 (#5163): execute `path` compiled from its source bytes with compile(); no cached bytecode file is
    read. The self-test plants a weakened unchecked-hash .pyc beside the guard and fails if it is used."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    code = compile(path.read_bytes(), str(path), "exec", dont_inherit=True)
    exec(code, module.__dict__)  # noqa: S102 - trusted base code, compiled from source on purpose
    return module


def load_base_guard(base_root: Path):
    """Import the BASE guard module (trusted code of the base commit), compiled from its source."""
    guard = base_root / GUARD_REL
    regular_file(guard, f"base guard {GUARD_REL}")
    regular_file(base_root / MANIFEST_REL, f"base manifest {MANIFEST_REL}")
    regular_file(base_root / "CLAUDE.md", "base CLAUDE.md")
    module = load_source_module("base_claude_md_guard", guard)
    for name in ("rule_section_hashes", "load_manifest", "check", "read_utf8", "fence_scan"):
        if not hasattr(module, name):
            raise RuntimeError(f"the base guard has no {name}; it cannot judge this pull request")
    return module


def extract_head(repo: Path, head_sha: str, dest: Path) -> None:
    """Copy the three data files of `head_sha` into `dest` as plain files. A symlink or non-blob is refused."""
    for rel in DATA_PATHS:
        listing = git(repo, "ls-tree", "-z", head_sha, "--", rel)
        entries = [entry for entry in listing.split(b"\0") if entry]
        if len(entries) != 1:
            raise RuntimeError(f"{rel} is absent from the head commit")
        meta, _tab, name = entries[0].partition(b"\t")
        mode, kind, blob = meta.decode("ascii").split(" ")
        if name.decode("utf-8") != rel or kind != "blob" or mode not in ("100644", "100755"):
            raise RuntimeError(f"{rel} is not a regular file blob in the head (mode {mode}, type {kind})")
        if int(git(repo, "cat-file", "-s", blob).decode("ascii").strip()) > MAX_BLOB_BYTES:
            raise RuntimeError(f"{rel} in the head is larger than {MAX_BLOB_BYTES} bytes")
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git(repo, "cat-file", "blob", blob))


def section_texts(guard, text: str) -> dict:
    """Return {key: raw section text} using the same split the guard hashes."""
    bodies = {guard.PREAMBLE_KEY: []}
    current = guard.PREAMBLE_KEY
    for line, in_code in guard.fence_scan(text):
        if not in_code and line.startswith("## "):
            current = line.rstrip()
            bodies.setdefault(current, [])
            continue
        bodies[current].append(line)
    return {key: "\n".join(lines) for key, lines in bodies.items()}


def fenced(body: str, info: str = "diff") -> list:
    """R4 (#4507): a code fence one backtick longer than the longest backtick run in `body`, so head text can
    never close the block early and render as Markdown in the job summary."""
    longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + info, body, fence]


def span(text: str) -> str:
    """R5 (#5166): head-controlled text outside a fence (a heading, a guard message, a trailer value) as one
    inline code span, longer than any backtick run inside it, on one line, so it never renders as Markdown."""
    flat = " ".join(text.splitlines())
    ticks = "`" * (max((len(run) for run in re.findall(r"`+", flat)), default=0) + 1)
    return f"{ticks} {flat} {ticks}"


def trusted_changes(repo: Path, base_sha: str, head_sha: str) -> list:
    """The TRUSTED_PATHS the head changes relative to its merge base with the base (fail closed on git error)."""
    merge_base = git(repo, "merge-base", base_sha, head_sha).decode("ascii").strip()
    out = git(repo, "diff", "--name-only", "-z", "--no-renames", merge_base, head_sha, "--", *TRUSTED_PATHS)
    return sorted(name.decode("utf-8", "replace") for name in out.split(b"\0") if name)


def unified(old: str, new: str, key: str) -> str:
    diff = list(difflib.unified_diff(old.split("\n"), new.split("\n"), "base", "head", lineterm="", n=2))
    if len(diff) > DIFF_LINE_CAP:
        diff = diff[:DIFF_LINE_CAP] + [f"... diff truncated at {DIFF_LINE_CAP} lines"]
    return "\n".join(diff)


def config_free_env() -> dict:
    """The environment of the trailer parser (#6396): built from scratch, so nothing the host exports
    (GIT_CONFIG_COUNT/KEY_n/VALUE_n, GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, HOME, XDG_CONFIG_HOME) reaches it; the
    system config is switched off (git reads it from a compile-time path otherwise) and the global one is the null
    device. GIT_DIR is the null device, so no repository is discovered whatever the working directory is
    (GIT_CEILING_DIRECTORIES stops an upward walk but does not exclude the working directory itself, #6433)."""
    return {"PATH": os.environ.get("PATH", os.defpath), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "HOME": os.devnull, "XDG_CONFIG_HOME": os.devnull, "GIT_CEILING_DIRECTORIES": os.sep,
            "GIT_DIR": os.devnull}


def trailer_block(message: bytes) -> str:
    """The trailer block git finds in one commit message, parsed WITHOUT any git configuration (#6396).

    `git interpret-trailers --parse` decides what is a trailer with git's own rules, but it also reads
    `trailer.<token>.key` and `trailer.separators` from the system, global and repository configuration; a
    configured token aliases another line to the approval key or turns a mostly-prose final paragraph into a trailer
    block. So the parser runs with GIT_DIR at the null device (#6433: no repository is discovered, so the repository
    config is never found, whatever the working directory is; the filesystem root is only a second line of defence),
    no system config, no global config and no HOME or XDG directory; its defaults (separator `:`) are then the only
    rules. A parser failure raises RuntimeError (fail closed)."""
    try:
        result = subprocess.run(["git", "interpret-trailers", "--parse", "--no-divider"], input=message,
                                capture_output=True, check=False, cwd=os.sep, env=config_free_env())
    except OSError as exc:
        raise RuntimeError(f"git interpret-trailers could not run: {exc}") from exc
    if result.returncode != 0:
        raise RuntimeError("git interpret-trailers failed: " + result.stderr.decode("utf-8", "replace").strip())
    return result.stdout.decode("utf-8", "replace")


def names_someone(value: str) -> bool:
    """#6572: True when `value` has at least one character that renders (not invisible, not a filler)."""
    return any(unicodedata.category(char) not in INVISIBLE_CATEGORIES and char not in INVISIBLE_FILLERS
               for char in value)


def approvals(repo: Path, base_sha: str, head_sha: str) -> list:
    """The `Rule-Change-Approved-By` trailer values in base..head (commit messages are data). #6179: only the
    git trailer block (the final paragraph, git interpret-trailers semantics) is read; a body line that starts
    with the key is prose, not an approval. #6396: each raw message is parsed by `trailer_block`, which loads no
    git configuration, so neither the host nor the repository can widen what counts as a trailer. #6431: the log
    read pins `--no-show-signature` and `--encoding=UTF-8`, so a host `log.showSignature` cannot inject verifier text
    and a host `i18n.logOutputEncoding` cannot turn a real approval into unreadable bytes. #6572: a value made only
    of invisible characters or fillers names nobody and does not count."""
    out = git(repo, "log", "-z", "--no-show-signature", "--encoding=UTF-8", "--format=%B", f"{base_sha}..{head_sha}")
    found = []
    for message in out.split(b"\0"):
        if message.strip():
            values = [match.group(1).strip() for match in TRAILER.finditer(trailer_block(message))]
            found += [value for value in values if names_someone(value)]
    return found


def compare(base_root: Path, repo: Path, base_sha: str, head_sha: str, scratch: Path, index_pins=None):
    """Return (report_text, failed). Raises RuntimeError for a fail-closed precondition."""
    for sha in (base_sha, head_sha):
        if not SHA.fullmatch(sha):
            raise RuntimeError(f"{sha!r} is not a 40-hex commit id")
    # #6573: a shallow boundary at the base hides that an old commit is an ancestor of it, so base..head would count
    # that commit's earlier approval for this change. Anything but a plain `false` (a git too old to know the
    # option echoes it back) is refused.
    if git(repo, "rev-parse", "--is-shallow-repository").decode().strip() != "false":
        raise RuntimeError("the repository is shallow (or git cannot say); the comparison needs full history (#6573)")
    # #6712: a legacy graft file (old git still honours it, new git ignores it) rewrites parents the same way a replace
    # object does and cannot be switched off per call, so a repository that has one, or a GIT_GRAFT_FILE override, is refused.
    graft_path = git(repo, "rev-parse", "--git-path", "info/grafts").decode().strip()
    if "GIT_GRAFT_FILE" in os.environ or os.path.lexists(repo / graft_path):
        raise RuntimeError("the repository has a graft file (info/grafts or GIT_GRAFT_FILE); the comparison needs the "
                           "real history (#6712)")
    guard = load_base_guard(base_root)
    head_root = scratch / "head"
    if head_root.exists():
        shutil.rmtree(head_root)
    head_root.mkdir(parents=True)
    extract_head(repo, head_sha, head_root)
    manifest_dest = head_root / MANIFEST_REL
    manifest_dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(base_root / MANIFEST_REL, manifest_dest)

    manifest_errors, pinned = guard.load_manifest(base_root)
    if manifest_errors:
        raise RuntimeError("the base manifest is unusable: " + "; ".join(manifest_errors))
    head_text = guard.read_utf8(head_root / "CLAUDE.md")
    base_text = guard.read_utf8(base_root / "CLAUDE.md")
    head_hashes, duplicates = guard.rule_section_hashes(head_text)
    head_bodies = section_texts(guard, head_text)
    base_bodies = section_texts(guard, base_text)

    lines = ["## CLAUDE.md rule-change comparison (base manifest vs pull request head)", ""]
    rule_changed = False
    count_changed = False
    for key in sorted(set(pinned) | set(head_hashes)):
        if key in pinned and head_hashes.get(key) == pinned[key]:
            continue
        old = base_bodies.get(key)
        new = head_bodies.get(key)
        # #5404: split on the census digit runs and compare the text BETWEEN them; no stand-in character is
        # substituted, so no byte the head holds (U+0000 included) can imitate a number.
        if old is not None and new is not None and key.startswith(CENSUS_SECTION) and (
                CENSUS_DIGITS.split(old) == CENSUS_DIGITS.split(new)):
            count_changed = True
            lines += [f"### COUNT CHANGED: {span(key)}", "", "Only census counts differ.", ""] + fenced(
                unified(old, new, key)) + [""]
        else:
            rule_changed = True
            state = "removed" if new is None else ("added" if old is None else "changed")
            lines += [f"### RULE TEXT CHANGED ({state}): {span(key)}", ""] + fenced(
                unified(old or "", new or "", key)) + [""]
    for key in duplicates:
        rule_changed = True
        lines += [f"### RULE TEXT CHANGED (duplicated heading): {span(key)}", ""]
    residual = [error for error in guard.check(head_root, index_pins) if not any(marker in error for marker in DRIFT_MARKERS)]
    for error in residual:
        rule_changed = True
        lines.append(f"- BASE GUARD REFUSES THE HEAD: {span(error)}")
    if residual:
        lines.append("")
    for rel in trusted_changes(repo, base_sha, head_sha):
        rule_changed = True
        lines.append(f"- GUARD CHANGED: {rel} (the code that judges rule changes; needs the trailer)")
    approved = approvals(repo, base_sha, head_sha)
    failed = False
    if rule_changed and not approved:
        failed = True
        lines.append("RESULT: FAIL - the rule text changed and no commit in the range carries a "
                     "`Rule-Change-Approved-By: <who>` trailer.")
    elif rule_changed:
        lines.append("RESULT: PASS - rule text changed; approval trailer(s): "
                     + "; ".join(span(value) for value in approved)
                     + ". This is tamper-evidence: the trailer is data, and review plus the sole merger enforce.")
    elif count_changed:
        lines.append("RESULT: PASS - only counts changed (printed above for review).")
    else:
        lines.append("RESULT: PASS - no rule section differs from the base manifest.")
    return "\n".join(lines) + "\n", failed


def run(args) -> int:
    if not sys.flags.isolated:
        # R5 (#5163): second line of defence for a caller that imports this module; the refusal that
        # stops a sibling module is the one above the imports.
        print("## CLAUDE.md rule-change comparison\n\nRESULT: FAIL (closed) - run the comparison as "
              "`python3 -I scripts/claude-md-rule-compare.py` (isolated mode)")
        return 1
    scratch = Path(args.scratch)
    try:
        scratch.mkdir(parents=True, exist_ok=True)
        report, failed = compare(Path(args.base_root), Path(args.repo), args.base_sha, args.head_sha, scratch)
    except (RuntimeError, OSError, UnicodeDecodeError, ValueError, SyntaxError) as exc:
        report, failed = f"## CLAUDE.md rule-change comparison\n\nRESULT: FAIL (closed) - {exc}\n", True
    print(report)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(report)
    return 1 if failed else 0


# --------------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------------
IDENT = ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false")


def make_repo(guard, root: Path):
    """A git repo whose first commit is a valid tree (CLAUDE.md, references, manifest). Returns the base sha."""
    root.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    guard.build_fixture(root)
    path = root / "CLAUDE.md"
    heading = guard.CLAUDE_MD_REQUIRED_HEADINGS[2]
    census = next(h for h in guard.CLAUDE_MD_REQUIRED_HEADINGS if h.startswith(CENSUS_SECTION))
    text = path.read_text(encoding="utf-8").replace(
        heading + "\n", heading + "\nThe tool limit is 103 tools.\nThe vote needs 5 MCP tools.\n", 1)
    path.write_text(text.replace(
        census + "\n", census + "\nThe surface has 103 MCP tools and 99 CLI subcommands (97 in the default build). A vote needs 5 agents.\n",
        1), encoding="utf-8")
    guard.update_manifest_quiet(root)
    for rel in TRUSTED_PATHS:
        stub = root / rel
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text("# stub\n", encoding="utf-8")
    return commit_all(root, "base")


def commit_all(root: Path, message: str) -> str:
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), *IDENT, "commit", "-q", "--allow-empty", "-m", message], check=True)
    return git(root, "rev-parse", "HEAD").decode().strip()


CHILD_ENV_KEEP = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT")


def child_env(extra=None) -> dict:
    """#5508: the environment of every Python child the self-test starts. Built explicitly: only the names in
    CHILD_ENV_KEEP are copied from this process (a child needs a PATH and a locale; SYSTEMROOT is for Windows), plus
    `extra`. Nothing else is inherited, so PYTHONPATH, PYTHONHOME, PYTHONSAFEPATH, PYTHONSTARTUP, PYTHONINSPECT and the
    like set by an operator cannot change what a child measures."""
    env = {key: os.environ[key] for key in CHILD_ENV_KEEP if key in os.environ}
    env.update(extra or {})
    return env


REFUSAL_ISOLATION_SETS = ([], ["-E"], ["-s"], ["-E", "-s"], ["-E", "-s", "-S", "-B", "-O"], ["-S", "-E"])


def refusal_flag_sets() -> list:
    """#5507: the interpreter flag sets the non-isolated refusal is run under: every -X frozen_modules option (none,
    off, on) in front of every isolation set of REFUSAL_ISOLATION_SETS."""
    return [xopt + isolation for xopt in ([], ["-X", "frozen_modules=off"], ["-X", "frozen_modules=on"])
            for isolation in REFUSAL_ISOLATION_SETS]


def non_isolated_child(script: Path, flags: list, scratch: Path):
    """#5380: run `script` with the interpreter flags `flags` (never -I) and the comparison arguments. Returns None
    without starting anything when `script` is inside the real scripts/ directory: there a merged sibling named
    like a standard module would run inside the trusted job, so the child must start from a scratch copy."""
    if Path(script).resolve().parent == Path(__file__).resolve().parent:
        return None
    return subprocess.run([sys.executable, *flags, str(script), "--base-root", ".", "--repo", ".",
                           "--base-sha", "0" * 40, "--head-sha", "0" * 40, "--scratch", str(scratch)],
                          capture_output=True, text=True, check=False, env=child_env(), stdin=subprocess.DEVNULL)


class Plant(NamedTuple):
    """#5473: what plant_probe measured. `ok` is False when the child did not report, the planted file ran and was not
    expected to (or the reverse), or the flags the child reports differ from the flags plant_probe passed it."""
    shadowable: bool
    preloaded: bool
    planted_ran: bool
    ok: bool
    no_site: int
    ignore_env: int
    safe_path: int
    frozen_xopt: str


def plant_probe(name: str, probe: Path, xopts: list, env=None, isolate=("-S", "-E"), exit_code: int = 0) -> Plant:
    """#5441: plant `name`.py beside a child that imports `name`, run with the isolation flags `isolate` (default
    -S -E) plus the interpreter options `xopts`; `env` (None: child_env(), never the inherited environment) is the child's environment. Before importing,
    the CHILD prints its own verdict (through _frozen_importlib): whether `name` is already loaded, and whether it is
    loaded, built-in or frozen, together with the flags it was started with (#5473: sys.flags.no_site,
    sys.flags.ignore_environment, sys.flags.safe_path where the interpreter has it, and the frozen_modules -X
    option). Nothing is assumed about the interpreter: the callers compare these reports with what they require."""
    probe.mkdir(parents=True, exist_ok=True)
    (probe / f"{name}.py").write_text(f"print('PLANTED')\nraise SystemExit({exit_code})\n", encoding="utf-8")
    (probe / "probe.py").write_text(
        "import sys, _frozen_importlib as fi\n"
        f"name = {name!r}\n"
        "pre = name in sys.modules\n"
        "print('VERDICT', int(pre), int(pre or name in sys.builtin_module_names "
        "or fi.FrozenImporter.find_spec(name) is not None), sys.flags.no_site, sys.flags.ignore_environment, "
        "int(getattr(sys.flags, 'safe_path', 0)), sys._xoptions.get('frozen_modules') or '-')\n"
        "__import__(name)\n"
        "print('REAL')\n", encoding="utf-8")
    result = subprocess.run([sys.executable, *xopts, *isolate, str(probe / "probe.py")],
                            capture_output=True, text=True, check=False, cwd=str(probe),
                            env=child_env() if env is None else env, stdin=subprocess.DEVNULL)
    return parse_plant(result.stdout, xopts, isolate, result.returncode)


VERDICT_LINE = re.compile(r"VERDICT ([01]) ([01]) ([01]) ([01]) ([01]) (-|on|off)")


def parse_plant(stdout: str, xopts: list, isolate, returncode: int = 0) -> Plant:
    """#5473/#5509: turn the output of a probe child into a Plant. Pure (no process), so the self-test feeds it
    synthetic output. Exactly one line whose text starts with VERDICT (after stripping blanks) must exist, and it must
    match VERDICT_LINE exactly (five fields in {0,1}, then -, on or off; a preloaded module is also built-in or
    frozen). The child must have exited 0. `ok` needs, as WHOLE lines: PLANTED exactly once and no REAL when the
    module is not loaded, built-in or frozen; REAL exactly once and no PLANTED when it is; and the reported flags to
    equal the requested ones."""
    lines = stdout.splitlines()
    verdict = [VERDICT_LINE.fullmatch(line) for line in lines if line.strip().startswith("VERDICT")]
    if returncode != 0 or len(verdict) != 1 or verdict[0] is None:
        return Plant(False, False, False, False, -1, -1, -1, "?")
    preloaded, inert, no_site, ignore_env, safe_path, frozen_xopt = verdict[0].groups()
    if preloaded == "1" and inert != "1":
        return Plant(False, False, False, False, -1, -1, -1, "?")
    shadowable = inert == "0"
    want_frozen = next((xopts[i + 1].split("=", 1)[1] for i in range(len(xopts) - 1)
                        if xopts[i] == "-X" and xopts[i + 1].startswith("frozen_modules=")), "-")
    flags_ok = (int(no_site), int(ignore_env), frozen_xopt) == (int("-S" in isolate), int("-E" in isolate), want_frozen)
    planted, real = lines.count("PLANTED"), lines.count("REAL")
    outcome_ok = (planted, real) == ((1, 0) if shadowable else (0, 1))
    return Plant(shadowable, preloaded == "1", planted > 0, outcome_ok and flags_ok, int(no_site), int(ignore_env),
                 int(safe_path), frozen_xopt)


def safe_path_probe_bad(plant: Plant) -> bool:
    """#5511: True when a probe child started with -E and PYTHONSAFEPATH=1 in its environment either did not behave as
    its own verdict says or reports a non-zero safe_path flag, that is, it honoured the environment variable."""
    return (not plant.ok) or plant.safe_path != 0


def safe_path_measurement_gap(has_flag: bool, honours: bool) -> bool:
    """#5511: True when the interpreter has sys.flags.safe_path but a bare child did not report it from
    PYTHONSAFEPATH, which means the measurement of PYTHONSAFEPATH support is itself broken."""
    return has_flag and not honours


def plant_coverage_gap(probed: list, names: list, rounds: int) -> bool:
    """#5443: True when `probed` is not exactly `names` once per round."""
    return probed != names * rounds


# #5472: the top-level modules this script imports (except sys), pinned as a literal so the self-test has a source of
# truth that does not come from imported_modules() itself. Adding or removing an import without updating this tuple
# makes the self-test red.
EXPECTED_IMPORTS = ("argparse", "ast", "contextlib", "difflib", "importlib", "io", "os", "pathlib", "py_compile", "re",
                    "shutil", "stat", "subprocess", "tokenize", "typing", "unicodedata")


def import_pin_gap(found: list, pinned) -> tuple:
    """#5472: (missing, extra): the pinned names `found` lacks, and the names in `found` that are not pinned."""
    return (sorted(set(pinned) - set(found)), sorted(set(found) - set(pinned)))


def imported_modules(path: Path) -> list:
    """#5379: the top-level names of every module `path` imports (parsed with ast, never executed), except `sys`.
    The self-test plants one file per name beside its non-isolated child. What a planted file does on a given
    interpreter is not stated here: plant_probe has the child report whether each name is loaded, built-in or
    frozen, and the self-test requires the planted file to run exactly when the child says it is not (#5441).
    EXPECTED_IMPORTS pins the set (#5472). Dynamic imports (importlib.import_module, __import__) are not found by
    this ast scan (#5405). They cannot run before the refusal: refusal_prefix_gap (#5510) requires the code above it to
    be the docstring and `import sys`; the self-test applies it to this file."""
    names = set()
    for node in ast.walk(ast.parse(path.read_bytes())):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    names.discard("sys")
    return sorted(names)


CONTROL_BYTES = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)")


def refusal_prefix_gap(source: bytes) -> str:
    """#5510/#5560: "" when `source` (the file BYTES, never a str) is plain strict utf-8 and the only statements that
    execute above the isolation refusal are the docstring and `import sys`, and the refusal is exactly
    `if __name__ == "__main__" and not sys.flags.isolated:` whose body is calls to print and sys.exit with constant
    arguments; otherwise why not. Parsed with ast from the bytes, never executed, so the check reads the file the way
    the interpreter does. It is closed-world and fails closed: it refuses a non-bytes argument; any coding cookie or
    BOM other than plain utf-8 spelled utf-8 or utf8 (tokenize.detect_encoding follows the PEP 263 rule the
    interpreter uses, so a cookie in any spelling on line 1 or 2 is covered); bytes that are not strict utf-8; any
    control byte other than tab, LF and CRLF line ends (NUL, form feed, a lone CR and the rest) anywhere in the file;
    and a line ending in a line-continuation backslash above the refusal. Module level statements are the only code
    that runs when the file is started, so a dynamic import, eval, exec, a branch, a class body or a decorator above
    the refusal cannot hide: any statement outside this whitelist is refused."""
    if not isinstance(source, (bytes, bytearray)):
        return "the source is not bytes"
    source = bytes(source)
    try:
        encoding = tokenize.detect_encoding(iter(source.splitlines(keepends=True)).__next__)[0]
    except (SyntaxError, StopIteration, LookupError) as exc:
        return f"the source encoding cannot be determined: {exc}"
    if encoding not in ("utf-8", "utf8"):
        return f"the source declares the encoding {encoding}, not plain utf-8 (a BOM or a coding cookie)"
    try:
        source.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        return f"the source is not strict utf-8: {exc}"
    if CONTROL_BYTES.search(source):
        return "the source has a control byte other than tab, LF and CRLF line ends"
    try:
        body = ast.parse(source).body
    except (SyntaxError, ValueError) as exc:
        return f"the source does not parse: {exc}"
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    if not body or not isinstance(body[0], ast.Import) or [(a.name, a.asname) for a in body[0].names] != [("sys", None)]:
        return "the first statement after the docstring is not `import sys`"
    if len(body) < 2 or not isinstance(body[1], ast.If) or body[1].orelse:
        return "the statement after `import sys` is not the refusal if"
    refusal = body[1]
    if any(line.rstrip(b"\r").endswith(b"\\") for line in source.split(b"\n")[:refusal.lineno - 1]):
        return "a line above the refusal ends with a line-continuation backslash"
    want = ast.dump(ast.parse('__name__ == "__main__" and not sys.flags.isolated', mode="eval").body)
    if ast.dump(refusal.test) != want:
        return "the refusal test is not `__name__ == \"__main__\" and not sys.flags.isolated`"
    for stmt in refusal.body:
        call = stmt.value if isinstance(stmt, ast.Expr) else None
        name = ast.unparse(call.func) if isinstance(call, ast.Call) else ""
        if name not in ("print", "sys.exit") or call.keywords or not all(isinstance(a, ast.Constant) for a in call.args):
            return "the refusal body is not print and sys.exit calls with constant arguments"
    return ""


def selftest_dir() -> Path:
    """#5384: the scratch directory of this process's self-test, under the repo's .local-runs (never /tmp)."""
    return Path(__file__).resolve().parent.parent / ".local-runs" / f"rule-compare-selftest-{os.getpid()}"


def guarded_run(cases) -> int:
    """#6574: run the self-test case function; an exception that no per-cell guard caught is a named FAIL and exit 1
    (the run is over at that point, so the remaining cells cannot run), never a bare traceback."""
    try:
        return cases()
    except Exception as exc:  # noqa: BLE001 - #6574: the last line of defence of the harness itself
        print(f"FAIL: self-test - aborted in an unguarded cell: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def self_test() -> int:
    try:
        return guarded_run(_self_test_cases)
    finally:
        shutil.rmtree(selftest_dir(), ignore_errors=True)  # a case that raises must not leave scratch behind


def _self_test_cases() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    guard_path = repo_root / GUARD_REL
    try:
        guard = load_source_module("sibling_guard", guard_path)
    except (RuntimeError, OSError, SyntaxError, ValueError) as exc:
        print(f"FAIL: self-test - cannot load the sibling guard: {exc}", file=sys.stderr)
        return 1
    refusal = guard.scratch_base_error(repo_root)
    if refusal:
        print(refusal, file=sys.stderr)
        return 1
    base_dir = selftest_dir()
    shutil.rmtree(base_dir, ignore_errors=True)
    base_dir.mkdir(parents=True)
    failures = []

    counter = [0]

    def guarded(name, fn):
        """#6574: run one inline cell group; any exception is that group's named FAIL and the run continues."""
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - #6574: an exception in an unwrapped cell is a named FAIL, never an abort
            failures.append(name)
            print(f"FAIL: self-test - {name}: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)

    def case(name, mutate, want_fail, needle, trailer=None, base_mutate=None, message=None):
        counter[0] += 1
        work = base_dir / f"c{counter[0]}"
        base_sha = make_repo(guard, work / "repo")
        base_root = work / "baseroot"
        shutil.copytree(work / "repo", base_root, ignore=shutil.ignore_patterns(".git"))
        shutil.copyfile(guard_path, base_root / GUARD_REL)
        if base_mutate:
            base_mutate(base_root)
        mutate(work / "repo")
        if message is None:
            message = "head change" + (f"\n\nRule-Change-Approved-By: {trailer}" if trailer else "")
        head_sha = commit_all(work / "repo", message)
        try:
            report, failed = compare(base_root, work / "repo", base_sha, head_sha, work / "scratch", guard.fixture_index_pins())
        except RuntimeError as exc:
            report, failed = f"RESULT: FAIL (closed) - {exc}", True
        except Exception as exc:  # noqa: BLE001 - #6435: any other exception is this cell's FAIL, never an abort
            failures.append(name)
            print(f"FAIL: self-test - {name}: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
            return
        if failed != want_fail or needle not in report:
            failures.append(name)
            print(f"FAIL: self-test - {name}: failed={failed} (wanted {want_fail}), needle {needle!r}\n{report}",
                  file=sys.stderr)
        else:
            print(f"PASS: self-test - {name}")

    heading = guard.CLAUDE_MD_REQUIRED_HEADINGS[2]

    def edit(old, new):
        def apply(root):
            target = root / "CLAUDE.md"
            target.write_text(target.read_text(encoding="utf-8").replace(old, new, 1), encoding="utf-8")
        return apply

    def reseal(root):
        guard.update_manifest_quiet(root)

    def reword(root):
        edit("tool limit is 103 tools", "tool limit is NOT 103 tools")(root)
        reseal(root)

    case("reworded section without a trailer fails with the diff", reword, True, "RULE TEXT CHANGED")
    case("the diff names the section and shows the change", reword, True, "+The tool limit is NOT 103 tools.")
    case("reworded section with the trailer passes", reword, False, "approval trailer(s): ` Justin `", trailer="Justin")
    case("a trailer value with a backtick is one code span (#5378)", reword, False,
         "approval trailer(s): `` Jus`tin ``", trailer="Jus`tin")
    case("a trailer quoted mid-line does not count", reword, True, "RESULT: FAIL",
         message="head change Rule-Change-Approved-By: Justin")
    case("an empty trailer value does not count", reword, True, "RESULT: FAIL",
         message="head change\n\nRule-Change-Approved-By: ")
    for label, invisible_value in (("a zero width space", "\u200b"), ("a Hangul filler", "\u3164"),
                                   ("a right-to-left override", "\u202e"), ("a braille blank", "\u2800"),
                                   ("several invisible characters", "\u2060\ufeff\u00ad\u200d")):
        case(f"an approval value made only of {label} does not count (#6572)", reword, True,
             "no commit in the range carries", message=f"head change\n\nRule-Change-Approved-By: {invisible_value}")
    case("an approval value with a visible name and an invisible character still counts (#6572)", reword, False,
         "approval trailer(s):", message="head change\n\nRule-Change-Approved-By: J\u00f6rg\u200b")
    # #6743: git trims only ASCII blanks from a trailer value, so a value led by a form feed, a vertical tab, a no-break
    # space or an ideographic space reaches the comparison with that character in front of the name. TRAILER requires
    # a non-space first character, so such a value is refused (fail closed); a pattern that lets it through counts it.
    for label, lead in (("a form feed", "\x0c"), ("a vertical tab", "\x0b"), ("a no-break space", "\u00a0"),
                        ("an ideographic space", "\u3000")):
        case(f"an approval value led by {label} does not count (#6743)", reword, True, "no commit in the range carries",
             message=f"head change\n\nRule-Change-Approved-By: {lead}Justin")
    # #6714: the same refusal for further Unicode spaces, and for a value that is only such a space then a name.
    for label, lead in (("an em space", "\u2003"), ("an ogham space mark", "\u1680"), ("a thin space", "\u2009")):
        case(f"an approval value led by {label} does not count (#6714)", reword, True, "no commit in the range carries",
             message=f"head change\n\nRule-Change-Approved-By: {lead}Justin")
    case("an empty trailer value followed by another trailer does not count (#6576)", reword, True, "RESULT: FAIL",
         message="head change\n\nRule-Change-Approved-By:\nCo-Authored-By: Placeholder <noreply@example.invalid>")
    case("a body line starting with the trailer key above a separate trailer block does not count (#6179)", reword,
         True, "RESULT: FAIL",
         message="head change\n\nThe guard documents the\nRule-Change-Approved-By: <who>. Fails closed on a missing"
                 " guard.\n\nCo-Authored-By: Placeholder <noreply@example.invalid>")
    case("a body line starting with the trailer key in a non-final paragraph does not count (#6179)", reword, True,
         "RESULT: FAIL", message="head change\n\nRule-Change-Approved-By: Justin\n\nprose closes the body")
    case("a trailer inside the final trailer block beside other trailers passes (#6179)", reword, False,
         "approval trailer(s): ` Justin `",
         message="head change\n\nbody prose\n\nRule-Change-Approved-By: Justin\n"
                 "Co-Authored-By: Placeholder <noreply@example.invalid>")

    def widened_config(key, value):
        """A repository-local git config on the head fixture repo (#6396): the approval read must ignore it."""
        def apply(root):
            reword(root)
            subprocess.run(["git", "-C", str(root), "config", key, value], check=True)
        return apply

    case("a repo trailer.separators config does not widen the trailer block (#6396, #6403)", widened_config(
        "trailer.separators", ":="), True, "RESULT: FAIL",
         message="head change\n\na=b\nRule-Change-Approved-By: Justin")
    case("a repo trailer.<token>.key alias does not make another trailer an approval (#6396)", widened_config(
        "trailer.approve.key", "Rule-Change-Approved-By"), True, "RESULT: FAIL",
         message="head change\n\napprove: Justin")
    case("a repo trailer.<token>.key token does not turn a prose paragraph into a trailer block (#6396)", widened_config(
        "trailer.sign.key", "Sign"), True, "RESULT: FAIL",
         message="head change\n\nprose one\nprose two\nprose three\nSign: x\nRule-Change-Approved-By: Justin")
    case("the approval key inside another trailer's value does not count (#6403)", reword, True, "RESULT: FAIL",
         message="head change\n\nNote: Rule-Change-Approved-By: Justin")
    case("a lower-case approval key does not count (#6403)", reword, True, "RESULT: FAIL",
         message="head change\n\nrule-change-approved-by: Justin")
    case("a folded approval value counts as one trailer (#6403)", reword, False, "approval trailer(s): ` Justin `",
         message="head change\n\nRule-Change-Approved-By:\n  Justin")
    case("a patch divider line after the trailer does not hide prose from the trailer read (#6396)", reword, True,
         "RESULT: FAIL", message="head change\n\nRule-Change-Approved-By: Justin\n---\nprose after the line")

    def host_environment(name, entries, message, approved=False, where="trailer parser"):
        """Export git config through the HOST environment around one comparison (#6396): it must not reach the
        trailer parser (#6396) or the log read (#6431, `approved`: a real approval must still be counted)."""
        saved = {key: os.environ.get(key) for key in entries}
        os.environ.update(entries)
        try:
            if approved:
                case(f"{name} does not hide an approval from the {where} (#6431)", reword, False,
                     "approval trailer(s): ` Justin `", message=message)
            else:
                case(f"{name} does not reach the trailer parser (#6396)", reword, True, "RESULT: FAIL", message=message)
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    host_config = base_dir / "host.gitconfig"
    host_config.write_text("[trailer \"approve\"]\n\tkey = Rule-Change-Approved-By\n", encoding="utf-8")
    host_environment("a host GIT_CONFIG_COUNT trailer alias", {
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "trailer.approve.key", "GIT_CONFIG_VALUE_0": "Rule-Change-Approved-By"},
        "head change\n\napprove: Justin")
    host_environment("a host GIT_CONFIG_GLOBAL trailer alias", {"GIT_CONFIG_GLOBAL": str(host_config)},
                     "head change\n\napprove: Justin")
    # #6431: the log read honours host config too; an output encoding other than UTF-8 turns a real approval into
    # unreadable bytes (a lockout), and a signature verifier line is injected in front of a signed message.
    approved_message = "head change\n\nRule-Change-Approved-By: Justin"
    host_environment("a host i18n.logOutputEncoding=UTF-16", {
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "i18n.logOutputEncoding", "GIT_CONFIG_VALUE_0": "UTF-16"},
        approved_message, approved=True, where="log read")
    host_environment("a host log.showSignature=true", {
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "log.showSignature", "GIT_CONFIG_VALUE_0": "true"},
        approved_message, approved=True, where="log read")
    env_pins = config_free_env()
    if (env_pins.get("GIT_CONFIG_NOSYSTEM") != "1" or env_pins.get("GIT_CONFIG_GLOBAL") != os.devnull
            or env_pins.get("HOME") != os.devnull or env_pins.get("GIT_CEILING_DIRECTORIES") != os.sep
            or env_pins.get("GIT_DIR") != os.devnull):
        print(f"FAIL: self-test - the trailer parser environment is not config-free: {env_pins!r}", file=sys.stderr)
        failures.append("config-free env")
    else:
        print("PASS: self-test - the trailer parser environment disables system and global git config (#6396)")

    saved_git_dir = os.environ.get("GIT_DIR")
    os.environ["GIT_DIR"] = str(base_dir / "alias-repo" / ".git")
    try:
        exported_pin = config_free_env().get("GIT_DIR")
    finally:
        if saved_git_dir is None:
            os.environ.pop("GIT_DIR", None)
        else:
            os.environ["GIT_DIR"] = saved_git_dir
    if exported_pin != os.devnull:
        print(f"FAIL: self-test - a host GIT_DIR export reaches the trailer parser environment (#6433): {exported_pin!r}",
              file=sys.stderr)
        failures.append("host GIT_DIR")
    else:
        print("PASS: self-test - a host GIT_DIR export does not reach the trailer parser environment (#6433)")

    def parser_failure(label, git_body):
        """A `git` earlier on PATH that exits non-zero (or is absent): the trailer read must raise, never return []."""
        fake = base_dir / f"fakegit-{label}"
        fake.mkdir()
        if git_body is not None:
            (fake / "git").write_text(f"#!{sys.executable}\n{git_body}", encoding="utf-8")
            (fake / "git").chmod(0o755)
        saved_path = os.environ.get("PATH")
        os.environ["PATH"] = str(fake)
        try:
            trailer_block(b"subject\n\nRule-Change-Approved-By: Justin\n")
            raised = False
        except RuntimeError:
            raised = True
        except Exception as exc:  # noqa: BLE001 - #6435: a different exception is this cell's FAIL, never an abort
            raised = False
            print(f"FAIL: self-test - a trailer parser that {label}: expected RuntimeError, got {type(exc).__name__}"
                  f": {exc} (#6435)", file=sys.stderr)
            failures.append(f"parser {label}")
            return
        finally:
            if saved_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = saved_path
        if raised:
            print(f"PASS: self-test - a trailer parser that {label} fails closed (#6396)")
        else:
            print(f"FAIL: self-test - a trailer parser that {label} did not fail closed (#6396)", file=sys.stderr)
            failures.append(f"parser {label}")

    # #6433: the parser must not discover a repository from ANY working directory. GIT_CEILING_DIRECTORIES stops an
    # upward walk but does not exclude the working directory itself, so a parser started inside a repository (a
    # repository at the filesystem root, or a dropped cwd) would read that repository's trailer config.
    def alias_repo_cell():
        alias_repo = base_dir / "alias-repo"
        subprocess.run(["git", "init", "-q", str(alias_repo)], check=True)
        subprocess.run(["git", "-C", str(alias_repo), "config", "trailer.approve.key", "Rule-Change-Approved-By"], check=True)
        inside = subprocess.run(["git", "interpret-trailers", "--parse", "--no-divider"], input=b"s\n\napprove: Justin\n",
                                capture_output=True, check=False, cwd=str(alias_repo), env=config_free_env())
        if b"Rule-Change-Approved-By" in inside.stdout:
            print("FAIL: self-test - the trailer parser environment still finds a repository from its working directory"
                  " (#6433)", file=sys.stderr)
            failures.append("parser environment repository")
        else:
            print("PASS: self-test - the trailer parser environment does not find a repository from its working directory"
                  " (#6433)")

    guarded("the trailer parser environment does not find a repository from its working directory (#6433) fixture", alias_repo_cell)

    def recorded_parser_call(parse=trailer_block):
        """Run `parse` (trailer_block) with a recording `git` first on PATH: the working directory and GIT_DIR it was
        given."""
        fake = base_dir / "fakegit-record"
        fake.mkdir(exist_ok=True)
        record = base_dir / "fakegit-record.txt"
        (fake / "git").write_text(f"#!{sys.executable}\nimport os\n"
                                  f"open({str(record)!r}, 'w').write(os.getcwd() + '\\n' + os.environ.get('GIT_DIR', '<unset>'))\n",
                                  encoding="utf-8")
        (fake / "git").chmod(0o755)
        saved_path = os.environ.get("PATH")
        os.environ["PATH"] = str(fake)
        try:
            parse(b"subject\n")
            return record.read_text(encoding="utf-8").split("\n")
        finally:
            if saved_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = saved_path

    def parser_call_result(parse=trailer_block):
        try:
            return recorded_parser_call(parse)
        except Exception as exc:  # noqa: BLE001 - #6574: any exception is this cell's result (a FAIL), never an abort
            return repr(exc), None

    seen_cwd, seen_git_dir = parser_call_result()
    if seen_cwd != os.path.realpath(os.sep) or seen_git_dir != os.devnull:
        print(f"FAIL: self-test - the trailer parser runs from the filesystem root with GIT_DIR at the null device"
              f" (#6433): cwd={seen_cwd!r} GIT_DIR={seen_git_dir!r}", file=sys.stderr)
        failures.append("parser cwd and GIT_DIR")
    else:
        print("PASS: self-test - the trailer parser runs from the filesystem root with GIT_DIR at the null device (#6433)")

    def pin(label, check):
        """A cell for the harness itself: `check()` returns "" when the pinned behaviour holds, else the problem."""
        def run_check():
            problem = check()
            if problem:
                failures.append(label)
                print(f"FAIL: self-test - {label}: {problem}", file=sys.stderr)
            else:
                print(f"PASS: self-test - {label}")
        guarded(label, run_check)

    def raising_parse(_message):
        raise TypeError("injected by the #6574 pin")

    def raising_cases():
        raise TypeError("injected by the #6574 pin")

    def check_parser_site():
        got = parser_call_result(raising_parse)
        if got[1] is not None or "TypeError" not in got[0]:
            return f"a TypeError in the parser call was not reported as this cell's result: {got!r}"
        return ""

    def check_guarded():
        before = len(failures)
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            guarded("injected cell", raising_cases)
        named = failures[before:] == ["injected cell"] and "FAIL: self-test - injected cell: unexpected TypeError" in captured.getvalue()
        del failures[before:]
        return "" if named else f"an exception in a guarded group was not reported by name: {captured.getvalue()!r}"

    def check_backstop():
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            code = guarded_run(raising_cases)
        if code != 1 or "FAIL: self-test - aborted in an unguarded cell: TypeError" not in captured.getvalue():
            return f"the top-level backstop returned {code!r} with {captured.getvalue()!r}"
        return ""

    pin("an exception in the parser-call cell is that cell's named result, not an abort (#6574)", check_parser_site)
    pin("an exception in a guarded cell group is reported by name and the run continues (#6574)", check_guarded)
    pin("an exception outside every cell guard is a named FAIL with exit 1 at the top level (#6574)", check_backstop)

    parser_failure("exits non-zero", "import sys\nsys.stderr.write('boom')\nsys.exit(3)\n")
    parser_failure("is missing", None)

    def filler(root):
        edit("section body x", "section body y")(root)
        reseal(root)

    case("same-size filler swap is a rule change", filler, True, "RULE TEXT CHANGED")

    census_heading = next(h for h in guard.CLAUDE_MD_REQUIRED_HEADINGS if h.startswith(CENSUS_SECTION))

    def census_edit(old, new):
        def apply(root):
            edit(old, new)(root)
            reseal(root)
        return apply

    case("a census-count change prints COUNT CHANGED and passes", census_edit("103 MCP tools", "104 MCP tools"),
         False, "COUNT CHANGED")
    case("every census phrase may change together (R4)", census_edit(
        "103 MCP tools and 99 CLI subcommands (97 in the default build)",
        "110 MCP tools and 101 CLI subcommands (98 in the default build)"), False, "COUNT CHANGED")
    case("a digit change in prose outside the census is a rule change (R4)",
         census_edit("tool limit is 103 tools", "tool limit is 1 tools"), True, "RULE TEXT CHANGED")
    case("a vote size next to census words outside the prime directive is a rule change (R4)",
         census_edit("The vote needs 5 MCP tools.", "The vote needs 1 MCP tools."), True, "RULE TEXT CHANGED")
    case("a prose digit in the census section is a rule change (R4)",
         census_edit("A vote needs 5 agents.", "A vote needs 1 agents."), True, "RULE TEXT CHANGED")
    case("a census digit plus a prose digit together is a rule change (R4)", census_edit(
        "The surface has 103 MCP tools and 99 CLI subcommands (97 in the default build). A vote needs 5 agents.",
        "The surface has 104 MCP tools and 99 CLI subcommands (97 in the default build). A vote needs 1 agents."),
        True, "RULE TEXT CHANGED")
    case("a census unit word changed with the same digits is a rule change (R4)",
         census_edit("103 MCP tools and", "103 MCP toolz and"), True, "RULE TEXT CHANGED")
    case("a census digit changed without its unit word is a rule change (R4)",
         census_edit("(97 in the default build)", "(97 in the default build) 12"), True, "RULE TEXT CHANGED")
    case("a census count in non-ASCII digits is a rule change (R5, #5165)",
         census_edit("103 MCP tools", "\u0661\u0660\u0664 MCP tools"), True, "RULE TEXT CHANGED")

    def link_heading(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## [ok](https://e.invalid/x)\n\nbody\n",
                          encoding="utf-8")

    case("a head heading is a code span in the summary (R5, #5166)", link_heading, True,
         "RULE TEXT CHANGED (added): ` ## [ok](https://e.invalid/x) `")

    def trusted_write(rel, data=b"# weakened\n"):
        def apply(root):
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return apply

    guard_edit = trusted_write(GUARD_REL)
    case("a change to the guard code is reported and needs the trailer (R4)", guard_edit, True, "GUARD CHANGED")
    case("a guard change with the trailer passes (R4)", guard_edit, False, "approval trailer(s)", trailer="Justin")
    # R5 (#5164): the trusted set is pinned to a literal, and the per-path cases loop over that literal, so
    # dropping an entry from TRUSTED_PATHS fails here instead of silently dropping its own case.
    pinned_trusted = ("scripts/check-claude-md-size.py", "scripts/claude-md-rule-compare.py",
                      ".github/workflows/claude-md-guard.yml", ".github/workflows/claude-md-rule-compare.yml",
                      ".github/CODEOWNERS")
    if TRUSTED_PATHS != pinned_trusted:
        failures.append("TRUSTED_PATHS pin")
        print(f"FAIL: self-test - TRUSTED_PATHS {TRUSTED_PATHS} differs from the pinned set (R5, #5164)",
              file=sys.stderr)
    else:
        print("PASS: self-test - TRUSTED_PATHS equals the pinned set (R5, #5164)")
    for rel in pinned_trusted:
        case(f"a change to {rel} is reported and needs the trailer (R4)", trusted_write(rel), True,
             f"GUARD CHANGED: {rel}")

    def weakened_pyc(root):
        # #5163: an unchecked-hash .pyc of a guard that reports every section as pinned; the source is untouched.
        source = (root / GUARD_REL).read_text(encoding="utf-8") + (
            "\n_real_hashes = rule_section_hashes\n\n\n"
            "def rule_section_hashes(text):\n"
            "    hashes, dups = _real_hashes(text)\n"
            "    pins = load_manifest(Path(__file__).resolve().parent.parent)[1]\n"
            "    return {k: pins.get(k, v) for k, v in hashes.items()}, dups\n")
        weak = root / "weak-guard-source.py"
        weak.write_text(source, encoding="utf-8")
        cfile = Path(importlib.util.cache_from_source(str(root / GUARD_REL)))
        cfile.parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(str(weak), cfile=str(cfile), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        weak.unlink()

    case("a cached .pyc beside the base guard is never loaded (R5, #5163)", reword, True, "RULE TEXT CHANGED",
         base_mutate=weakened_pyc)

    def isolated_refusal():
        # #5163/#5313/#5474: the comparison must refuse to run without -I. The non-isolated child is started from a
        # COPY of the script in an empty scratch directory (never from the real scripts/ directory, #5380), with a file
        # planted beside the copy for every imported name; none may run before the refusal, under each flag set below.
        iso = base_dir / "iso"
        iso.mkdir(parents=True, exist_ok=True)
        copy = iso / "claude-md-rule-compare.py"
        shutil.copyfile(Path(__file__).resolve(), copy)
        for name in sorted(set(EXPECTED_IMPORTS) | set(imported_modules(Path(__file__).resolve()))):
            (iso / f"{name}.py").write_text("print('PLANTED')\nraise SystemExit(0)\n", encoding="utf-8")
        # #5507: the set covers every frozen_modules option, alone and with every isolation set.
        flag_sets = refusal_flag_sets()
        for xopt in ([], ["-X", "frozen_modules=off"], ["-X", "frozen_modules=on"]):
            for isolation in ([], ["-E"], ["-s"], ["-E", "-s"], ["-E", "-s", "-S", "-B", "-O"], ["-S", "-E"]):
                if xopt + isolation not in flag_sets:
                    return False
        # #5283/#5373/#5474/#5507: the refusal is pinned for every flag set in refusal_flag_sets(): each of no -X option,
        # -X frozen_modules=off and -X frozen_modules=on, alone and crossed with each isolation set in
        # REFUSAL_ISOLATION_SETS (partial isolation -E, -s, both, plus -S -B -O, and -S -E). -P is not pinned here.
        for flags in flag_sets:
            result = non_isolated_child(copy, flags, iso / "s")
            if result is None or not (result.returncode == 1 and "isolated mode" in result.stdout
                                      and "PLANTED" not in result.stdout + result.stderr):
                return False
        # #5380: the helper refuses to start a child from the real scripts/ directory; pin that refusal.
        return non_isolated_child(Path(__file__).resolve(), [], iso / "s") is None

    if isolated_refusal():
        print("PASS: self-test - a comparison run without -I fails closed (R5, #5163)")
    else:
        failures.append("non-isolated run")
        print("FAIL: self-test - a comparison run without -I did not fail closed (R5, #5163)", file=sys.stderr)

    def importlib_plant():
        # #5424/#5441/#5442/#5443/#5473: importlib is in the plant set, the imported set equals the pin, and for EVERY
        # pinned name a planted file runs exactly when the child finds the module neither preloaded, built-in nor
        # frozen, under default interpreter options and under -X frozen_modules=off, with the child's own flag report
        # equal to what is required. Returns "" or why.
        found = imported_modules(Path(__file__).resolve())
        missing, extra = import_pin_gap(found, EXPECTED_IMPORTS)
        if missing or extra:
            return f"imported_modules() and EXPECTED_IMPORTS disagree: missing {missing}, extra {extra} (#5472)"
        if not import_pin_gap(found[1:], EXPECTED_IMPORTS)[0] or not import_pin_gap(found + ["zz_unpinned"],
                                                                                     EXPECTED_IMPORTS)[1] \
                or any(import_pin_gap(list(EXPECTED_IMPORTS), EXPECTED_IMPORTS)):
            return "the import pin check does not tell a narrowed or widened list from the pin (#5472)"
        # #5473: parse_plant on synthetic child output: ok needs a matching planted/shadowable pair AND matching flags.
        synth = [("VERDICT 0 0 1 1 0 -\nPLANTED\n", [], True), ("VERDICT 0 0 0 1 0 -\nPLANTED\n", [], False),
                 ("VERDICT 0 0 1 0 0 -\nPLANTED\n", [], False), ("VERDICT 0 0 1 1 0 off\nPLANTED\n", [], False),
                 ("VERDICT 0 0 1 1 0 off\nPLANTED\n", ["-X", "frozen_modules=off"], True),
                 ("VERDICT 0 0 1 1 0 -\nPLANTED\n", ["-X", "frozen_modules=off"], False),
                 ("VERDICT 0 1 1 1 0 -\nREAL\n", [], True), ("VERDICT 0 1 1 1 0 -\nPLANTED\n", [], False),
                 ("VERDICT 0 0 1 1 0 -\nREAL\n", [], False), ("PLANTED\n", [], False),
                 ("VERDICT 0 0 1 1 0 -\nVERDICT 0 0 1 1 0 -\nPLANTED\n", [], False),
                 ("VERDICT 0 0 1 1 x -\nPLANTED\n", [], False),
                 # #5509: the loose cases measured at 8328fbb65, each now refused
                 ("VERDICT 0 7 1 1 0 -\nPLANTED\n", [], False), ("VERDICT 0 1 1 1 0 -\nTraceback\nImportError\n", [], False),
                 ("VERDICT 0 0 1 1 0 -\nxPLANTEDx\n", [], False),
                 ("VERDICT 0 0 1 1 0 -\n VERDICT 0 0 1 1 0 -\nPLANTED\n", [], False),
                 ("VERDICT 0 1 1 1 0 -\nREAL\nREAL\n", [], False), ("VERDICT 0 0 1 1 0 -\nPLANTED\nREAL\n", [], False),
                 ("VERDICT 1 0 1 1 0 -\nREAL\n", [], False), ("VERDICT 0 1 1 1 0 - \nREAL\n", [], False),
                 ("VERDICT 0 1 1 1 0 bad\nREAL\n", [], False),
                 ("VERDICT 7 0 1 1 0 -\nPLANTED\n", [], False), ("VERDICT 1 0 1 1 0 -\nPLANTED\n", [], False), ("VERDICT 0 1 1 1 0 -\nREAL\n", [], True)]
        for out, xo, want in synth:
            if parse_plant(out, xo, ("-S", "-E")).ok != want:
                return f"parse_plant gave the wrong ok for {out!r} with options {xo} (#5473)"
        # #5561: every numeric field of the VERDICT row is 0 or 1. A 2 in field 2, 3, 4 or 5 must give the all-failed
        # Plant, compared as a whole: fields 3 to 5 are not all part of `ok`, so comparing ok alone cannot see them.
        failed_plant = Plant(False, False, False, False, -1, -1, -1, "?")
        for row in ("VERDICT 0 2 1 1 0 -\nREAL\n", "VERDICT 0 0 2 1 0 -\nPLANTED\n", "VERDICT 0 0 1 2 0 -\nPLANTED\n",
                    "VERDICT 0 0 1 1 2 -\nPLANTED\n", "VERDICT 0 1 2 1 0 -\nREAL\n", "VERDICT 0 1 1 2 0 -\nREAL\n",
                    "VERDICT 0 1 1 1 2 -\nREAL\n", "VERDICT 2 1 1 1 0 -\nREAL\n", "VERDICT 0 1 1 1 10 -\nREAL\n"):
            if parse_plant(row, [], ("-S", "-E")) != failed_plant:
                return f"parse_plant accepted a VERDICT field outside 0 and 1: {row!r} (#5561)"
        # #5509: a child that exited non-zero is never ok, even when its output reads as a pass.
        if parse_plant("VERDICT 0 1 1 1 0 -\nREAL\n", [], ("-S", "-E"), 1).ok \
                or parse_plant("VERDICT 0 0 1 1 0 -\nPLANTED\n", [], ("-S", "-E"), 1).ok:
            return "parse_plant accepted a probe child that exited non-zero (#5509)"
        if not parse_plant("VERDICT 0 0 1 1 0 -\nPLANTED\n", [], ("-S", "-E")).planted_ran:
            return "parse_plant did not read the planted marker (#5473)"
        # #5510: nothing may execute above the refusal except `import sys`. The real source must pass; each synthetic
        # source (mutant M05b and siblings: a dynamic import, an eval, an import in a branch, a class body, a decorator,
        # a second imported name, a call inside the refusal, a weakened refusal test) must be refused.
        raw = Path(__file__).read_bytes()
        source = raw.decode("utf-8")

        def gap(text: str) -> str:
            return refusal_prefix_gap(text.encode("utf-8"))

        if refusal_prefix_gap(raw):
            return f"the source has code above the isolation refusal: {refusal_prefix_gap(raw)} (#5510)"
        marker = "if __name__ == \"__main__\" and not sys.flags.isolated:"
        before = {"__import__('colorsys')\n", "import json\n", "if False:\n    import json\n", "x = eval('1')\n",
                  "class C:\n    import json\n", "@(lambda f: f)\ndef g():\n    pass\n", "exec('pass')\n",
                  "import importlib\nimportlib.import_module('colorsys')\n", "x = 1\n", "from os import path\n"}
        for inserted in sorted(before):
            if not gap(source.replace(marker, inserted + marker, 1)):
                return f"code above the isolation refusal was not refused: {inserted!r} (#5510)"
        for old, new in (("import sys\n\nif __name__", "import sys, json\n\nif __name__"),
                         ("import sys\n\nif __name__", "import sys as s\nimport sys\n\nif __name__"),
                         ("sys.exit(1)", "sys.exit(__import__('colorsys'))"), ("    print(\"## CLAUDE.md rule-change", "    __import__('colorsys')\n    print(\"## CLAUDE.md rule-change"),
                         ("not sys.flags.isolated:", "not sys.flags.isolated or True:"),
                         ("import sys\n\nif __name__", "import sys as s\n\nif __name__"), ("sys.exit(1)", "sys.exit(1, **{})"),
                         ("    sys.exit(1)\n", "    sys.exit(1)\nelse:\n    x = 1\n"), ("not sys.flags.isolated:", "not sys.flags.isolated or __import__('colorsys'):"),
                         (marker, "if True:"), ("import sys\n\nif __name__", "import sys\n\nx = 1\nif __name__")):
            if old not in source or not gap(source.replace(old, new, 1)):
                return f"a changed refusal or import line was not refused: {new!r} (#5510)"
        if not gap("") or not gap("import sys\n"):
            return "a source without the refusal was not refused (#5510)"
        # #5560: the check works on the BYTES and is closed-world about encoding and control bytes. Each source below
        # was accepted by the text based check of f95e295a0 (the utf-7 spellings even ran hidden code) or only
        # refused by accident; each must be refused with a stated reason.
        refusal = 'import sys\nif __name__ == "__main__" and not sys.flags.isolated:\n    print("refused")\n    sys.exit(1)\n'
        hidden = 'import sys\n#+AAo-print("hidden")\nif __name__ == "__main__" and not sys.flags.isolated:\n    print("refused")\n    sys.exit(1)\n'
        plain = ('"""doc"""\n' + refusal).encode("utf-8")
        if refusal_prefix_gap(plain) or refusal_prefix_gap(b"#!/usr/bin/env python3\n# coding: utf-8\n" + plain) \
                or refusal_prefix_gap(b"# -*- coding: utf8 -*-\n" + plain) or refusal_prefix_gap(b'"""doc"""\r\n' + refusal.encode().replace(b"\n", b"\r\n")):
            return "a plain utf-8 source (shebang, utf-8 cookie, CRLF) was refused (#5560)"
        encodings = {
            "utf-7 cookie on line 1": b"# coding: utf-7\n" + b'"""doc"""\n' + hidden.encode(),
            "utf-7 cookie on line 2 under a shebang": b"#!/usr/bin/env python3\n# coding: utf-7\n" + b'"""doc"""\n' + hidden.encode(),
            "utf-16 with BOM": ('"""doc"""\n' + refusal).encode("utf-16"),
            "utf-8 BOM and a latin-1 cookie": b"\xef\xbb\xbf# coding: latin-1\n" + plain,
            "utf-8 BOM alone": b"\xef\xbb\xbf" + plain,
            "vim style utf-7 cookie": b"# vim: set fileencoding=utf-7 :\n" + b'"""doc"""\n' + hidden.encode(),
            "emacs style utf-7 cookie": b"# -*- coding: utf-7 -*-\n" + b'"""doc"""\n' + hidden.encode(),
            "latin-1 cookie with a latin-1 byte": b"# coding: latin-1\n" + '"""d\xe9"""\n'.encode("latin-1") + refusal.encode(),
            "unknown cookie": b"# coding: no-such-codec\n" + plain,
            "bytes that are not utf-8": b'"""d\xff"""\n' + refusal.encode(),
            "CR-only line ends": ('"""doc"""\rimport sys\r# note\rimport json\r' + refusal.split("import sys\n", 1)[1]).replace("\n", "\r").encode(),
            "a lone CR inside a comment": b'"""doc"""\nimport sys\n# note\rimport json\n' + refusal.split("import sys\n", 1)[1].encode(),
            "form feed": b'"""doc"""\nimport sys\n\x0c\n' + refusal.split("import sys\n", 1)[1].encode(),
            "NUL": b'"""doc"""\nimport sys\n#\x00\n' + refusal.split("import sys\n", 1)[1].encode(),
            "vertical tab": b'"""doc"""\nimport sys\n\x0b\n' + refusal.split("import sys\n", 1)[1].encode(),
            "DEL": b'"""doc"""\nimport sys\n#\x7f\n' + refusal.split("import sys\n", 1)[1].encode(),
            "line continuation backslash": b'"""doc"""\nimport sys\n\\\n' + refusal.split("import sys\n", 1)[1].encode(),
            "backslash in the docstring slot": b'"""doc \\\nmore"""\n' + refusal.encode(),
            "a str instead of bytes": '"""doc"""\n' + refusal,
        }
        # The structure check also sees most of these, because ast.parse of the bytes honours the cookie. Each gate is
        # therefore also pinned on a source that is structurally valid, so no gate is carried by another one.
        benign = {
            "a benign utf-7 cookie": b"# coding: utf-7\n" + plain,
            "a benign utf-7 cookie on line 2 under a shebang": b"#!/usr/bin/env python3\n# coding: utf-7\n" + plain,
            "a benign vim style cookie": b"# vim: set fileencoding=utf-7 :\n" + plain,
            "a benign emacs style cookie": b"# -*- coding: utf-7 -*-\n" + plain,
            "a benign latin-1 cookie": b"# coding: latin-1\n" + plain,
            "a benign latin-1 cookie on line 2": b"#!/usr/bin/env python3\n# coding: iso-8859-1\n" + plain,
            "all CR line ends": ('"""doc"""\n' + refusal).replace("\n", "\r").encode("utf-8"),
            "an invalid utf-8 byte after line 2": b'"""doc"""\n# note\n# \xff\n' + refusal.encode(),
            "a CRLF line continuation backslash": b'"""doc"""\r\nimport sys\r\n\\\r\n' + refusal.split("import sys\n", 1)[1].replace("\n", "\r\n").encode(),
        }
        for byte in [*range(0, 9), 11, 12, *range(14, 32), 127]:
            benign[f"control byte {byte:#04x} in a comment"] = b'"""doc"""\nimport sys\n#' + bytes([byte]) + b"\n" + refusal.split("import sys\n", 1)[1].encode()
        for label, data in {**encodings, **benign}.items():
            if not refusal_prefix_gap(data):
                return f"a source with {label} was not refused (#5560)"
        # imported_modules reads the bytes the way the interpreter does: a utf-7 comment that hides an import is seen.
        hidden_import = base_dir / "hidden-import.py"
        hidden_import.write_bytes(b"# coding: utf-7\n#+AAo-import colorsys\nimport sys\n")
        if "colorsys" not in imported_modules(hidden_import):
            return "imported_modules did not see an import hidden behind a coding cookie (#5560)"
        # #5562: only a real docstring (a str constant) is stripped from the front. Any other first statement must be
        # refused, however harmless it looks, so it cannot be mistaken for the docstring.
        tail = refusal
        for label, first in (("a call", "__import__('colorsys')\n"), ("a number", "1\n"), ("a bytes literal", "b'doc'\n"),
                             ("an f-string", "f'{__import__(\"colorsys\")}'\n"), ("a name", "x\n"),
                             ("a docstring-like call", "str('doc')\n"), ("an ellipsis", "...\n"), ("None", "None\n")):
            if not gap(first + tail):
                return f"{label} in the docstring slot was not refused (#5562)"
        if gap('"""doc"""\n' + tail) or gap(tail):
            return "a plain docstring or no docstring was refused (#5562)"
        # #5563: the refusal body may call only print and sys.exit. Each other callable, with constant arguments and
        # followed by the valid print and sys.exit, must be refused, so the whitelist cannot grow unseen.
        head = 'import sys\nif __name__ == "__main__" and not sys.flags.isolated:\n'
        for callee in ("exec", "eval", "compile", "getattr", "setattr", "open", "globals", "vars", "input", "breakpoint",
                       "type", "os._exit", "sys.exit.__call__", "print.__call__"):
            if not gap(f'{head}    {callee}("import colorsys")\n    print("refused")\n    sys.exit(1)\n'):
                return f"a refusal body that calls {callee} was not refused (#5563)"
        if gap(f'{head}    print("refused")\n    sys.exit(1)\n') or gap(f'{head}    print("a", "b")\n    sys.exit(2)\n'):
            return "a refusal body of print and sys.exit calls was refused (#5563)"
        names = list(EXPECTED_IMPORTS)  # the probe set is the pin, never the output of imported_modules (#5472)
        if "importlib" not in names:
            return "importlib is not in the plant set"
        probed = []
        for xopts in ([], ["-X", "frozen_modules=off"]):
            live = []
            for name in names:
                plant = plant_probe(name, base_dir / "implant", xopts)
                # #5473: the flags the CHILD reports must be the ones this check relies on (-S -E, no safe path, and
                # the frozen_modules option asked for), whatever the interpreter or its site start-up does.
                if (plant.no_site, plant.ignore_env, plant.safe_path) != (1, 1, 0) \
                        or plant.frozen_xopt != ("off" if xopts else "-"):
                    return (f"the probe child reported no_site/ignore_environment/safe_path/frozen_modules "
                            f"{(plant.no_site, plant.ignore_env, plant.safe_path, plant.frozen_xopt)} for {name} "
                            f"(xopts {xopts}), not (1, 1, 0, {'off' if xopts else '-'}) (#5473)")
                if name == "importlib" and plant.preloaded:
                    return "importlib was already loaded under -S -E, so the probe is not independent of site (#5442)"
                if not plant.ok:
                    return f"the planted {name}.py behaved differently from the child's own verdict (xopts {xopts})"
                probed.append(name)
                if plant.planted_ran:
                    live.append(name)
            print(f"INFO: self-test - planted file ran (measured) for {live} with options {xopts}")
        # #5509: the child's exit code reaches parse_plant: a planted file that ran and exited 3 is never ok.
        # #5565: run on a module name no interpreter provides, so the planted file always runs and the pin cannot be
        # skipped on an interpreter where every probed name is inert. exit_code 0 is the positive control.
        fake = "zz_rule_compare_5565_absent"
        control_ok = plant_probe(fake, base_dir / "implant-fake", [])
        exit_three = plant_probe(fake, base_dir / "implant-fake-exit", [], exit_code=3)
        if not (control_ok.ok and control_ok.shadowable):  # ok already requires PLANTED exactly once
            return "the planted file of an absent module did not run cleanly (#5565)"
        if exit_three.ok:
            return "a probe child that exited non-zero was accepted (#5509, #5565)"
        if plant_coverage_gap(probed, names, 2):
            return "not every imported name was probed"
        if plant_coverage_gap(names + names, names, 2) or not plant_coverage_gap(names[:1], names, 1) \
                or not plant_coverage_gap(names + names, names, 1):
            return "the coverage check does not tell a narrowed probe from a full one"
        # #5441: measured, not assumed: the child must report encodings as already loaded and the planted file must
        # stay inert; this fails on an interpreter where that is not the case, which would leave the preloaded
        # branch of the probe unexercised.
        enc = plant_probe("encodings", base_dir / "implant", [])
        if not (enc.preloaded and not enc.planted_ran and enc.ok):
            return "a preloaded module's planted file ran, or the child did not report it preloaded"
        # #5441/#5475: with PYTHONSAFEPATH=1 in the environment the child, started with -E, must report safe_path 0
        # and the planted file must behave as the child's verdict says.
        # #5511: the two conditions below are pure functions, pinned on synthetic input so that deleting or weakening one is red.
        good, wrong_flag = parse_plant("VERDICT 0 1 1 1 0 -\nREAL\n", [], ("-S", "-E")), \
            parse_plant("VERDICT 0 1 1 1 1 -\nREAL\n", [], ("-S", "-E"))
        if safe_path_probe_bad(good) or not safe_path_probe_bad(wrong_flag) \
                or not safe_path_probe_bad(parse_plant("", [], ("-S", "-E"))) \
                or safe_path_measurement_gap(False, False) or safe_path_measurement_gap(True, True) \
                or safe_path_measurement_gap(False, True) or not safe_path_measurement_gap(True, False):
            return "the PYTHONSAFEPATH probe conditions are not pinned (#5511)"
        safe = plant_probe("importlib", base_dir / "implant", [], child_env({"PYTHONSAFEPATH": "1"}))
        if safe_path_probe_bad(safe):
            return "the probe child honours PYTHONSAFEPATH, so its result depends on the environment"
        # Negative control (#5475): whether this interpreter honours PYTHONSAFEPATH is MEASURED by a bare child,
        # not read from sys.version_info. When it does, a child started without -E must report safe_path 1 and the
        # probe must say ok False (the planted file is inert while the verdict says shadowable); this shows the
        # check above can fail and that ok is not always True. When it does not, the control is skipped and said so.
        honours = subprocess.run([sys.executable, "-S", "-c", "import sys; print(int(getattr(sys.flags, 'safe_path', 0)))"],
                                 capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL,
                                 env=child_env({"PYTHONSAFEPATH": "1"})).stdout.strip() == "1"
        if safe_path_measurement_gap(hasattr(sys.flags, "safe_path"), honours):
            return "this interpreter has sys.flags.safe_path but a bare child did not report it from PYTHONSAFEPATH (#5475)"
        if honours:
            control = plant_probe("importlib", base_dir / "implant", [], child_env({"PYTHONSAFEPATH": "1"}), ("-S",))
            if control.safe_path != 1 or control.ok:
                return "the probe cannot tell an inert planted file from a live one"
        print(f"INFO: self-test - this interpreter honours PYTHONSAFEPATH: {honours} (measured; the control runs only then)")
        # #5473: the flag report can say 0. A child started without -S must report no_site 0 (and -E still 1), and a
        # child started without -E must report ignore_environment 0; an always-1 report is red.
        no_s = plant_probe("importlib", base_dir / "implant", [], isolate=("-E",))
        no_e = plant_probe("importlib", base_dir / "implant", [], isolate=("-S",))
        if (no_s.no_site, no_s.ignore_env, no_e.no_site, no_e.ignore_env) != (0, 1, 1, 0) or not (no_s.ok and no_e.ok):
            return "the probe child's flag report does not follow the flags it was started with (#5473)"
        print(f"INFO: self-test - importlib already loaded without -S: {no_s.preloaded} (measured, not assumed)")
        return ""

    plant_failure = importlib_plant()
    if not plant_failure:
        print("PASS: self-test - the plant set equals the pinned imports and every planted file ran as the child reported (#5424)")
    else:
        failures.append("importlib plant")
        print(f"FAIL: self-test - the importlib plant check failed: {plant_failure} (#5424, #5441)", file=sys.stderr)

    def importer_refusal():
        # #5377: a caller that imports the module skips the module-top refusal (it is gated on __name__ ==
        # "__main__"), so run() is its only refusal. Load the file as a module in a child without -I and call run().
        imp = base_dir / "imp"
        imp.mkdir(parents=True, exist_ok=True)
        code = ("import argparse, importlib.util, sys\n"
                "spec = importlib.util.spec_from_file_location('rc_importer', sys.argv[1])\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(module)\n"
                "sys.exit(module.run(argparse.Namespace(base_root='.', repo='.', base_sha='0' * 40, "
                "head_sha='0' * 40, scratch=sys.argv[2], summary=None)))\n")
        result = subprocess.run([sys.executable, "-c", code, str(Path(__file__).resolve()), str(imp / "s")],
                                capture_output=True, text=True, check=False, cwd=str(imp), env=child_env(),
                                stdin=subprocess.DEVNULL)
        return result.returncode == 1 and "isolated mode" in result.stdout

    if importer_refusal():
        print("PASS: self-test - run() refuses a non-isolated caller that imports the module (#5377)")
    else:
        failures.append("importer refusal")
        print("FAIL: self-test - run() did not refuse a non-isolated caller that imports the module (#5377)",
              file=sys.stderr)

    def hostile_parent_env():
        # #5508: the self-test children get a controlled environment (child_env), so a parent that exports the variables
        # below must not change any result. Rerun the three child-spawning checks with those variables set in THIS
        # process; each must still pass. PYTHONINSPECT, PYTHONUSERBASE and PYTHONUTF8 are in the set too (#5564):
        # every child has stdin=DEVNULL, so a child that honoured PYTHONINSPECT would read EOF and exit, not hang; the
        # pin below therefore does not rely on a hang, it checks that child_env passes no PYTHON* name and that a bare
        # child reports sys.flags.inspect 0 and the default user base.
        hostile_dir = base_dir / "hostile"
        hostile_dir.mkdir(parents=True, exist_ok=True)
        for name in EXPECTED_IMPORTS:
            (hostile_dir / f"{name}.py").write_text("print('PLANTED')\nraise SystemExit(0)\n", encoding="utf-8")
        startup = hostile_dir / "startup.py"
        startup.write_text("print('PLANTED')\n", encoding="utf-8")
        hostile = {"PYTHONPATH": str(hostile_dir), "PYTHONHOME": str(hostile_dir / "no-home"), "PYTHONSAFEPATH": "1",
                   "PYTHONSTARTUP": str(startup), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONWARNINGS": "error",
                   "PYTHONINSPECT": "1", "PYTHONUSERBASE": str(hostile_dir / "userbase"), "PYTHONUTF8": "1"}
        saved = {key: os.environ.get(key) for key in hostile}
        os.environ.update(hostile)
        try:
            refusal_ok = isolated_refusal()
            plant_why = importlib_plant()
            importer_ok = importer_refusal()
            leaked = sorted(key for key in child_env() if key.startswith("PYTHON"))
            bare = subprocess.run([sys.executable, "-c", "import site, sys; print(sys.flags.inspect, site.getuserbase())"],
                                  capture_output=True, text=True, check=False, env=child_env(), stdin=subprocess.DEVNULL)
            env_ok = not leaked and bare.returncode == 0 and bare.stdout.startswith("0 ") \
                and str(hostile_dir) not in bare.stdout
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        return refusal_ok and not plant_why and importer_ok and env_ok

    if hostile_parent_env():
        print("PASS: self-test - the probe, refusal and importer checks are green under a hostile parent environment (#5508)")
    else:
        failures.append("hostile parent environment")
        print("FAIL: self-test - the probe, refusal and importer checks depend on the parent environment (#5508)",
              file=sys.stderr)

    def crash_cleanup():
        # #5384: a self-test whose case raises still removes its scratch directory. The child loads this file as
        # a module (so the module-top refusal does not apply), makes its first case raise, and prints its pid;
        # the top-level backstop turns the raise into exit 1 (#6574) and the scratch directory must still go.
        code = ("import importlib.util, os, sys\n"
                "spec = importlib.util.spec_from_file_location('rc_crash', sys.argv[1])\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(module)\n"
                "def boom(*args, **kwargs):\n"
                "    raise RuntimeError('boom')\n"
                "module.make_repo = boom\n"
                "print(os.getpid(), flush=True)\n"
                "code = module.self_test()\n"
                "print('crashed' if code == 1 else 'unexpected')\n")
        result = subprocess.run([sys.executable, "-I", "-c", code, str(Path(__file__).resolve())],
                                capture_output=True, text=True, check=False, env=child_env(), stdin=subprocess.DEVNULL)
        lines = result.stdout.split()
        if len(lines) != 2 or lines[1] != "crashed" or not lines[0].isdigit():
            return False
        left = repo_root / ".local-runs" / f"rule-compare-selftest-{lines[0]}"
        survived = left.exists()
        shutil.rmtree(left, ignore_errors=True)
        return not survived

    if crash_cleanup():
        print("PASS: self-test - a self-test whose case raises removes its scratch directory (#5384)")
    else:
        failures.append("crash cleanup")
        print("FAIL: self-test - a self-test whose case raises left its scratch directory behind (#5384)",
              file=sys.stderr)

    def rename_guard(root):
        subprocess.run(["git", "-C", str(root), "mv", GUARD_REL, GUARD_REL + ".old"], check=True)

    case("a renamed trusted file is reported (R4)", rename_guard, True, f"GUARD CHANGED: {GUARD_REL}")

    def delete_compare_workflow(root):
        (root / ".github/workflows/claude-md-rule-compare.yml").unlink()

    case("a deleted trusted workflow is reported (R4)", delete_compare_workflow, True,
         "GUARD CHANGED: .github/workflows/claude-md-rule-compare.yml")
    case("a workflow trigger block removed is reported (R4)", trusted_write(
        ".github/workflows/claude-md-guard.yml", b"name: stub\n"), True,
        "GUARD CHANGED: .github/workflows/claude-md-guard.yml")
    case("a trusted workflow that is not UTF-8 is reported, not a crash (R4)", trusted_write(
        ".github/workflows/claude-md-guard.yml", b"\xff\xfe\x00"), True,
        "GUARD CHANGED: .github/workflows/claude-md-guard.yml")

    def chmod_guard(root):
        (root / GUARD_REL).chmod(0o755)

    case("a mode change of a trusted file is reported (R4)", chmod_guard, True, f"GUARD CHANGED: {GUARD_REL}")

    def symlink_guard(root):
        target = root / GUARD_REL
        target.unlink()
        target.symlink_to("claude-md-rule-compare.py")

    case("a trusted file replaced by a symlink is reported (R4)", symlink_guard, True, f"GUARD CHANGED: {GUARD_REL}")
    case("a change to an untrusted file is not a guard change (R4)", trusted_write("README.md", b"hi\n"), False,
         "no rule section differs")

    def fence_check(root):
        edit("tool limit is 103 tools", "tool limit is 103 tools\n```\n[link](https://e.invalid)")(root)
        reseal(root)

    case("head backticks cannot close the summary fence (R4)", fence_check, True, "````diff")

    def long_fence(root):
        edit("tool limit is 103 tools", "tool limit is 103 tools\n``````\n[link](https://e.invalid)")(root)
        reseal(root)

    case("a long head backtick run gets a longer fence (R4)", long_fence, True, "```````diff")

    def reseal_only(root):
        manifest = root / MANIFEST_REL
        manifest.write_text(manifest.read_text(encoding="utf-8") + "# resealed, text unchanged\n", encoding="utf-8")

    case("a manifest edit with unchanged text passes", reseal_only, False, "no rule section differs")

    def hash_forge(root):
        edit("tool limit is 103 tools", "tool limit is NOT 103 tools")(root)  # head manifest left stale: base used

    case("a head that edits text but not its manifest is still a rule change", hash_forge, True,
         "RULE TEXT CHANGED")

    def remove_section(root):
        target = root / "CLAUDE.md"
        text = target.read_text(encoding="utf-8")
        start = text.index(heading)
        end = text.index("\n## ", start) + 1
        target.write_text(text[:start] + text[end:], encoding="utf-8")
        reseal(root)

    case("a removed section fails", remove_section, True, "RULE TEXT CHANGED (removed)")

    def add_section(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## New rule\nNever do X.\n", encoding="utf-8")
        reseal(root)

    case("an added section fails", add_section, True, "RULE TEXT CHANGED (added)")

    def weaken_floor(root):
        (root / "docs/reference/CODE_STYLE.md").write_text("# gone\n", encoding="utf-8")

    case("a head the base guard refuses (reference emptied) fails", weaken_floor, True, "BASE GUARD REFUSES THE HEAD")
    case("a head the base guard refuses passes only with the trailer", weaken_floor, False, "approval trailer(s)",
         trailer="Justin")

    def missing_manifest(root):
        pass

    def drop_base_manifest(root):
        (root / MANIFEST_REL).unlink()

    case("a missing base manifest fails closed", missing_manifest, True, "cannot stat base manifest",
         base_mutate=drop_base_manifest)

    def symlink_blob(root):
        target = root / "docs/reference/CODE_STYLE.md"
        target.unlink()
        target.symlink_to("ARCHITECTURE_REFERENCE.md")

    case("a symlink blob in the head fails closed", symlink_blob, True, "is not a regular file blob")

    def claude_symlink(root):
        target = root / "CLAUDE.md"
        target.unlink()
        target.symlink_to("docs/reference/CODE_STYLE.md")

    case("a symlinked CLAUDE.md in the head fails closed", claude_symlink, True, "is not a regular file blob")

    def huge(root):
        with open(root / "docs/reference/CODE_STYLE.md", "a", encoding="utf-8") as handle:
            handle.write("x" * (MAX_BLOB_BYTES + 1))

    case("an oversize head blob fails closed", huge, True, "larger than")

    def invisible(root):
        edit("tool limit is 103 tools", "tool limit is 103\u202e tools")(root)
        reseal(root)

    case("an invisible-character edit is a rule change", invisible, True, "RULE TEXT CHANGED")

    def drop_guard(root):
        (root / GUARD_REL).unlink()

    case("a missing base guard fails closed", missing_manifest, True, "cannot stat base guard", base_mutate=drop_guard)

    def fresh_pair(name):
        work = base_dir / name
        base_sha = make_repo(guard, work / "repo")
        base_root = work / "baseroot"
        shutil.copytree(work / "repo", base_root, ignore=shutil.ignore_patterns(".git"))
        shutil.copyfile(guard_path, base_root / GUARD_REL)
        return work, base_sha, base_root

    def refused(label, base_root, repo, base_sha, head_sha, scratch, needle):
        try:
            compare(base_root, repo, base_sha, head_sha, scratch, guard.fixture_index_pins())
        except RuntimeError as exc:
            if needle in str(exc):
                print(f"PASS: self-test - {label}")
                return
            print(f"FAIL: self-test - {label}: refused with {exc} (wanted {needle!r})", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - #6435: any other exception is this cell's FAIL, never an abort
            print(f"FAIL: self-test - {label}: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
        else:
            print(f"FAIL: self-test - {label}: not refused", file=sys.stderr)
        failures.append(label)

    work, base_sha, base_root = fresh_pair("sym")
    refused("R4 a symbolic ref instead of a commit id fails closed", base_root, work / "repo", "HEAD", base_sha,
            work / "scratch", "40-hex")
    refused("R5 an abbreviated commit id fails closed", base_root, work / "repo", base_sha, base_sha[:12],
            work / "scratch", "40-hex")
    refused("R5 an upper-case commit id fails closed", base_root, work / "repo", base_sha, base_sha.upper(),
            work / "scratch", "40-hex")
    refused("R5 a commit id with a trailing newline fails closed", base_root, work / "repo", base_sha,
            base_sha + "\n", work / "scratch", "40-hex")

    for label, body, want in (
            ("no backticks keep the plain three-backtick fence", "plain text", "```diff"),
            ("a three-backtick run gets a four-backtick fence", "a\n```\nb", "````diff"),
            ("a five-backtick run gets a six-backtick fence", "a\n`````\nb", "``````diff"),
            ("a tilde run does not lengthen the backtick fence", "~~~~~~~~\nb", "```diff")):
        got = fenced(body)
        closes = got[2]
        if got[0] != want or closes != want[:-len("diff")] or got[1] != body:
            print(f"FAIL: self-test - R5 fenced(): {label}: {got!r}", file=sys.stderr)
            failures.append(label)
        else:
            print(f"PASS: self-test - R5 fenced(): {label}")

    # #5179: the trusted-path diff starts at the merge base, so a trusted change that landed on the base after
    # the head forked is not charged to the head (every other fixture is linear).
    def merge_base_cell():
        work, fork_sha, base_root = fresh_pair("mergebase")
        repo = work / "repo"
        (repo / GUARD_REL).write_text("# the base moved on\n", encoding="utf-8")
        moved_sha = commit_all(repo, "base moves on")
        subprocess.run(["git", "-C", str(repo), "checkout", "-q", fork_sha], check=True)
        (repo / "docs").mkdir(parents=True, exist_ok=True)
        (repo / "docs" / "untrusted-note.md").write_text("x\n", encoding="utf-8")
        head_sha = commit_all(repo, "head change")
        try:
            report, failed = compare(base_root, repo, moved_sha, head_sha, work / "scratch", guard.fixture_index_pins())
        except RuntimeError as exc:
            report, failed = f"RESULT: FAIL (closed) - {exc}", True
        if failed or "GUARD CHANGED" in report:
            print(f"FAIL: self-test - R6 a base-side trusted change after the fork is charged to the head\n{report}",
                  file=sys.stderr)
            failures.append("merge base")
        else:
            print("PASS: self-test - R6 a base-side trusted change after the fork is not charged to the head (#5179)")

    guarded("a base-side trusted change after the fork is not charged to the head (#5179) fixture", merge_base_cell)

    # #6403: the approval range is base..head. A base-side commit after the fork that carries the trailer must not
    # approve a head that carries none (a symmetric base...head range would count it).
    def approval_range_cell():
        work, fork_sha, base_root = fresh_pair("approvalrange")
        repo = work / "repo"
        moved_sha = commit_all(repo, "base moves on\n\nRule-Change-Approved-By: Justin")
        subprocess.run(["git", "-C", str(repo), "checkout", "-q", fork_sha], check=True)
        reword(repo)
        head_sha = commit_all(repo, "head change")
        try:
            report, failed = compare(base_root, repo, moved_sha, head_sha, work / "scratch", guard.fixture_index_pins())
        except RuntimeError as exc:
            report, failed = f"RESULT: FAIL (closed) - {exc}", True
        if not failed or "approval trailer(s)" in report:
            print(f"FAIL: self-test - a base-side commit after the fork approves the head\n{report}", file=sys.stderr)
            failures.append("approval range")
        else:
            print("PASS: self-test - a base-side commit after the fork carrying the trailer does not approve the head (#6403)")

    guarded("a base-side commit after the fork carrying the trailer does not approve the head (#6403) fixture", approval_range_cell)

    def range_cell(name, work, base_root, repo, base_sha, head_sha, want_fail, needle):
        """One base..head comparison on a fixture repo: the verdict and the report text must match."""
        try:
            report, failed = compare(base_root, repo, base_sha, head_sha, work / "scratch", guard.fixture_index_pins())
        except RuntimeError as exc:
            report, failed = f"RESULT: FAIL (closed) - {exc}", True
        except Exception as exc:  # noqa: BLE001 - #6435: any other exception is this cell's FAIL, never an abort
            failures.append(name)
            print(f"FAIL: self-test - {name}: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
            return
        if failed != want_fail or needle not in report:
            failures.append(name)
            print(f"FAIL: self-test - {name}: failed={failed} (wanted {want_fail}), needle {needle!r}\n{report}",
                  file=sys.stderr)
        else:
            print(f"PASS: self-test - {name}")

    def cli_cell(name, work, base_root, repo, base_sha, head_sha, want_rc, needles):
        """#6741: run the comparison as the CI job does (`python3 -I <script>`, a child process) and check the exit
        code, the only thing the job reads, together with the words the report must carry."""
        result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--base-root", str(base_root),
                                 "--repo", str(repo), "--base-sha", base_sha, "--head-sha", head_sha,
                                 "--scratch", str(work / "cli-scratch")],
                                capture_output=True, text=True, check=False, env=child_env(), stdin=subprocess.DEVNULL)
        missing = [needle for needle in needles if needle not in result.stdout]
        if result.returncode != want_rc or missing:
            failures.append(name)
            print(f"FAIL: self-test - {name}: exit {result.returncode} (wanted {want_rc}), missing {missing!r}\n"
                  f"{result.stdout}{result.stderr}", file=sys.stderr)
        else:
            print(f"PASS: self-test - {name}")

    # #6434: every commit message is read on its own (git log -z). A subject line that is the approval key is never a
    # trailer; read as one blob, the older commit's subject would become the last paragraph of the combined output
    # and count as an approval for the newer commit that follows it.
    work, fork_sha, base_root = fresh_pair("subjectkey")
    repo = work / "repo"
    reword(repo)
    commit_all(repo, "Rule-Change-Approved-By: Justin")
    (repo / "docs").mkdir(parents=True, exist_ok=True)
    (repo / "docs" / "follow-up.md").write_text("x\n", encoding="utf-8")
    head_sha = commit_all(repo, "plain follow-up")
    range_cell("an older commit whose subject is the approval key does not approve the newer head (#6434)", work,
               base_root, repo, fork_sha, head_sha, True, "no commit in the range carries")

    work, fork_sha, base_root = fresh_pair("subjectkeynewest")
    repo = work / "repo"
    reword(repo)
    commit_all(repo, "plain first commit")
    head_sha = commit_all(repo, "Rule-Change-Approved-By: Justin")
    range_cell("a newest commit whose subject is the approval key does not approve the head (#6434)", work, base_root,
               repo, fork_sha, head_sha, True, "no commit in the range carries")

    # #6432: an approval counts wherever it sits in base..head: on a merged side-branch commit, on the merge commit
    # itself, on an older commit and on the newest one. A log read that skips merges (--no-merges), follows only the
    # first parent (--first-parent) or reads one message locks out a real approval.
    def approved_range(name, build, want_fail=False, needle="approval trailer(s): ` Justin `"):
        def cell():
            work, fork_sha, base_root = fresh_pair(name)
            repo = work / "repo"
            head_sha = build(repo, fork_sha)
            range_cell(f"an approval {ANYWHERE[name]} counts (#6432)", work, base_root, repo, fork_sha, head_sha,
                       want_fail, needle)
        guarded(f"an approval {ANYWHERE[name]} counts (#6432) fixture", cell)

    def merged(side_message, merge_message):
        def build(repo, fork_sha):
            subprocess.run(["git", "-C", str(repo), "checkout", "-q", "-b", "side"], check=True)
            reword(repo)
            commit_all(repo, side_message)
            subprocess.run(["git", "-C", str(repo), "checkout", "-q", fork_sha], check=True)
            (repo / "docs").mkdir(parents=True, exist_ok=True)
            (repo / "docs" / "main-work.md").write_text("x\n", encoding="utf-8")
            commit_all(repo, "main work")
            subprocess.run(["git", "-C", str(repo), *IDENT, "merge", "-q", "--no-ff", "-m", merge_message, "side"],
                           check=True)
            return git(repo, "rev-parse", "HEAD").decode().strip()
        return build

    def stacked(older_message, newer_message):
        def build(repo, fork_sha):
            reword(repo)
            commit_all(repo, older_message)
            (repo / "docs").mkdir(parents=True, exist_ok=True)
            (repo / "docs" / "follow-up.md").write_text("x\n", encoding="utf-8")
            return commit_all(repo, newer_message)
        return build

    ANYWHERE = {"onsidebranch": "on a merged side-branch commit", "onmerge": "only on the merge commit",
                "onolder": "on an older commit followed by a plain one", "onnewest": "on the newest commit after a plain one"}
    approval = "\n\nRule-Change-Approved-By: Justin"
    approved_range("onsidebranch", merged("side work" + approval, "Merge side"))
    approved_range("onmerge", merged("side work", "Merge side" + approval))
    approved_range("onolder", stacked("older work" + approval, "plain follow-up"))
    approved_range("onnewest", stacked("plain first", "newest work" + approval))

    # #6575: on a SIGNED commit a host log.showSignature puts the verifier's text in front of the message; a verifier
    # text with a blank line and a trailer-shaped block must never count as an approval. The commit object is built by
    # hand with a gpgsig header and `gpg.program` is a stand-in verifier, so the cell needs no key material and the
    # `--no-show-signature` pin of the log read is load-bearing here (the unsigned fixtures above print no verifier).
    def showsig_cell():
        work, fork_sha, base_root = fresh_pair("showsigverifier")
        repo = work / "repo"
        reword(repo)
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        tree = git(repo, "write-tree").decode().strip()
        signed = (f"tree {tree}\nparent {fork_sha}\nauthor t <t@example.invalid> 1700000000 +0000\n"
                  "committer t <t@example.invalid> 1700000000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n x\n"
                  " -----END PGP SIGNATURE-----\n\nhead change\n")
        head_sha = subprocess.run(["git", "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"],
                                  input=signed.encode(), capture_output=True, check=True).stdout.decode().strip()
        verifier = base_dir / "fake-verifier"
        verifier.write_text(f"#!{sys.executable}\nimport sys\nsys.stdin.read()\n"
                            "sys.stderr.write('v\\n\\nRule-Change-Approved-By: forged\\nSigned-off-by: v\\n')\nsys.exit(1)\n",
                            encoding="utf-8")
        verifier.chmod(0o755)
        sig_env = {"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "log.showSignature", "GIT_CONFIG_VALUE_0": "true",
                   "GIT_CONFIG_KEY_1": "gpg.program", "GIT_CONFIG_VALUE_1": str(verifier)}
        saved_sig = {key: os.environ.get(key) for key in sig_env}
        os.environ.update(sig_env)
        try:
            range_cell("a host signature verifier's text on a signed commit is never an approval (#6575)", work, base_root,
                       repo, fork_sha, head_sha, True, "no commit in the range carries")
        finally:
            for key, value in saved_sig.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    guarded("a host signature verifier's text on a signed commit is never an approval (#6575) fixture", showsig_cell)

    # #6609: a non-ASCII approver identity is reported byte-exact (the log read is pinned to UTF-8 output); a
    # single-byte decode of the log would print the approver as `J\ufffdrg` while the decision stays unchanged.
    def nonascii_cell():
        work, fork_sha, base_root = fresh_pair("nonasciiapprover")
        repo = work / "repo"
        reword(repo)
        head_sha = commit_all(repo, "head change\n\nRule-Change-Approved-By: J\u00f6rg")
        range_cell("a non-ASCII approver identity is reported intact (#6609)", work, base_root, repo, fork_sha, head_sha,
                   False, "approval trailer(s): ` J\u00f6rg `")

    guarded("a non-ASCII approver identity is reported intact (#6609) fixture", nonascii_cell)

    # #6573: in a clone whose base was fetched with --depth 1 the shallow boundary hides that an old commit is an
    # ancestor of the base, so an earlier, real approval reaches base..head through a merge parent. The comparison
    # must refuse a shallow repository; the same fixture in a full clone must still ignore the old approval.
    def shallow_cell():
        work, fork_sha, base_root = fresh_pair("shallow")
        repo = work / "repo"
        (repo / "docs").mkdir(parents=True, exist_ok=True)
        (repo / "docs" / "old.md").write_text("x\n", encoding="utf-8")
        old_sha = commit_all(repo, "old rule change\n\nRule-Change-Approved-By: old-real-approval")
        (repo / "docs" / "base.md").write_text("x\n", encoding="utf-8")
        shallow_base = commit_all(repo, "base moves on")
        reword(repo)
        side_sha = commit_all(repo, "pull request work")
        merge_sha = git(repo, *IDENT, "commit-tree", f"{side_sha}^{{tree}}", "-p", side_sha, "-p", old_sha,
                        "-m", "merge the old commit").decode().strip()
        git(repo, "update-ref", "refs/pull/1/head", merge_sha)
        git(repo, "reset", "-q", "--hard", shallow_base)
        clones = {}
        for kind, depth in (("full", []), ("shallow", ["--depth", "1"])):
            clone = work / f"{kind}-clone"
            subprocess.run(["git", "clone", "-q", *depth, f"file://{repo}", str(clone)], check=True, capture_output=True)
            git(clone, "fetch", "-q", "origin", "+refs/pull/1/head:refs/remotes/pull/head")
            clones[kind] = clone
        flags = {kind: git(clone, "rev-parse", "--is-shallow-repository").decode().strip() for kind, clone in clones.items()}
        if flags != {"full": "false", "shallow": "true"}:
            print(f"FAIL: self-test - the #6573 fixture is not a full clone and a shallow clone: {flags!r}", file=sys.stderr)
            failures.append("shallow fixture")
        range_cell("a full clone ignores an old approval reached through a merge parent (#6573)", work, base_root,
                   clones["full"], shallow_base, merge_sha, True, "no commit in the range carries")
        range_cell("a shallow repository is refused instead of counting an old approval (#6573)", work, base_root,
                   clones["shallow"], shallow_base, merge_sha, True, "the repository is shallow")
        cli_cell("the program exits 1 with RESULT: FAIL (closed) on a shallow repository (#6741)", work, base_root,
                 clones["shallow"], shallow_base, merge_sha, 1,
                 ("RESULT: FAIL (closed) - the repository is shallow",))

    guarded("a shallow repository is refused instead of counting an old approval (#6573) fixture", shallow_cell)

    # #6741: the exit code of the program is what the CI job reads. An unapproved rule change must exit 1 and say
    # FAIL, an approved one must exit 0 and say PASS, and a fail-closed refusal must exit 1; a run() whose exit map
    # returned 0 for a failed comparison would print FAIL and still pass the job.
    def cli_exit_cell():
        work, fork_sha, base_root = fresh_pair("cliexitfail")
        repo = work / "repo"
        reword(repo)
        head_sha = commit_all(repo, "head change")
        cli_cell("the program exits 1 and reports FAIL for an unapproved rule change (#6741)", work, base_root, repo,
                 fork_sha, head_sha, 1, ("RESULT: FAIL - the rule text changed",))
        work, fork_sha, base_root = fresh_pair("cliexitpass")
        repo = work / "repo"
        reword(repo)
        head_sha = commit_all(repo, "head change\n\nRule-Change-Approved-By: Justin")
        cli_cell("the program exits 0 and reports PASS for an approved rule change (#6741)", work, base_root, repo,
                 fork_sha, head_sha, 0, ("RESULT: PASS - rule text changed; approval trailer(s): ` Justin `",))

    guarded("the program exit code for an unapproved and an approved rule change (#6741) fixture", cli_exit_cell)

    # #6712: history substitution through local repository state. A replace object that swaps the head commit for one
    # carrying an approval, and one that grafts an approved commit in as a parent, must not make an unapproved range
    # pass (the git calls pin GIT_NO_REPLACE_OBJECTS=1); a graft file or GIT_GRAFT_FILE is refused outright.
    def replace_cell():
        work, fork_sha, base_root = fresh_pair("replaceswap")
        repo = work / "repo"
        reword(repo)
        head_sha = commit_all(repo, "head change")
        approved = git(repo, *IDENT, "commit-tree", f"{head_sha}^{{tree}}", "-p", fork_sha, "-m",
                       "head change\n\nRule-Change-Approved-By: Justin").decode().strip()
        git(repo, "replace", head_sha, approved)
        range_cell("a replace object that swaps the head for an approved commit does not approve it (#6712)", work,
                   base_root, repo, fork_sha, head_sha, True, "no commit in the range carries")
        work, fork_sha, base_root = fresh_pair("replacegraft")
        repo = work / "repo"
        old_sha = git(repo, *IDENT, "commit-tree", f"{fork_sha}^{{tree}}", "-p", fork_sha, "-m",
                      "old change\n\nRule-Change-Approved-By: Justin").decode().strip()
        reword(repo)
        head_sha = commit_all(repo, "head change")
        git(repo, "replace", "--graft", head_sha, fork_sha, old_sha)
        range_cell("a grafted approved parent does not approve the head (#6712)", work, base_root, repo, fork_sha,
                   head_sha, True, "no commit in the range carries")
        work, fork_sha, base_root = fresh_pair("graftfile")
        repo = work / "repo"
        reword(repo)
        head_sha = commit_all(repo, "head change\n\nRule-Change-Approved-By: Justin")
        grafts = repo / ".git" / "info" / "grafts"
        grafts.parent.mkdir(parents=True, exist_ok=True)
        grafts.write_text(f"{head_sha} {fork_sha}\n", encoding="utf-8")
        range_cell("a repository with a graft file is refused (#6712)", work, base_root, repo, fork_sha, head_sha, True,
                   "has a graft file")
        grafts.unlink()
        saved_graft = os.environ.get("GIT_GRAFT_FILE")
        os.environ["GIT_GRAFT_FILE"] = str(grafts)
        try:
            range_cell("a GIT_GRAFT_FILE override is refused (#6712)", work, base_root, repo, fork_sha, head_sha, True,
                       "has a graft file")
        finally:
            if saved_graft is None:
                os.environ.pop("GIT_GRAFT_FILE", None)
            else:
                os.environ["GIT_GRAFT_FILE"] = saved_graft

    guarded("replace objects and grafts cannot approve a range (#6712) fixture", replace_cell)

    # #6798: a commit-graph file (in the repository, or served from an alternate object store) is a third way to change
    # the parents the base..head walk sees: git takes parent edges from it without checking its checksum. A graph whose
    # entry for an in-range commit names an approved side commit must not approve the range (git() pins
    # core.commitGraph=false). The graph is written by git, then one parent entry is rewritten in place.
    def rewrite_graph_parent(graph, child, new_parent):
        """Point parent 1 of `child` at `new_parent` inside the commit-graph file `graph` (both are in that graph)."""
        graph.chmod(0o644)
        data = bytearray(graph.read_bytes())
        chunks = {}
        for i in range(data[6] + 1):
            chunks[bytes(data[8 + 12 * i:12 + 12 * i])] = int.from_bytes(data[12 + 12 * i:20 + 12 * i], "big")
        count = int.from_bytes(data[chunks[b"OIDF"] + 255 * 4:chunks[b"OIDF"] + 256 * 4], "big")
        oids = [bytes(data[chunks[b"OIDL"] + 20 * i:chunks[b"OIDL"] + 20 * (i + 1)]).hex() for i in range(count)]
        entry = chunks[b"CDAT"] + 36 * oids.index(child) + 20
        data[entry:entry + 4] = oids.index(new_parent).to_bytes(4, "big")
        graph.write_bytes(bytes(data))

    def lying_graph_fixture(name):
        """An unapproved two-commit change plus an approved side commit; returns the repo and its commits."""
        work, fork_sha, base_root = fresh_pair(name)
        repo = work / "repo"
        approved = git(repo, *IDENT, "commit-tree", f"{fork_sha}^{{tree}}", "-p", fork_sha, "-m",
                       "other change\n\nRule-Change-Approved-By: Justin").decode().strip()
        git(repo, "update-ref", "refs/heads/approved-side", approved)
        reword(repo)
        mid_sha = commit_all(repo, "mid change")
        head_sha = commit_all(repo, "head change")
        return work, repo, base_root, fork_sha, approved, mid_sha, head_sha

    def graph_write(where):
        subprocess.run(["git", "-C", str(where), "-c", "core.commitGraph=true", "commit-graph", "write", "--reachable"],
                       check=True, capture_output=True)

    def graph_cell():
        work, repo, base_root, fork_sha, approved, mid_sha, head_sha = lying_graph_fixture("graphrepo")
        graph_write(repo)
        rewrite_graph_parent(repo / ".git" / "objects" / "info" / "commit-graph", mid_sha, approved)
        range_cell("a commit-graph parent entry naming an approved commit does not approve the range (#6798)", work,
                   base_root, repo, fork_sha, head_sha, True, "no commit in the range carries")
        work, repo, base_root, fork_sha, approved, mid_sha, head_sha = lying_graph_fixture("graphalt")
        alt = work / "alt.git"
        subprocess.run(["git", "clone", "-q", "--bare", "--no-local", str(repo), str(alt)], check=True,
                       capture_output=True)
        graph_write(alt)
        rewrite_graph_parent(alt / "objects" / "info" / "commit-graph", mid_sha, approved)
        (repo / ".git" / "objects" / "info" / "alternates").write_text(str(alt / "objects") + "\n", encoding="utf-8")
        range_cell("a commit-graph served by an alternate object store does not approve the range (#6798)", work,
                   base_root, repo, fork_sha, head_sha, True, "no commit in the range carries")

    guarded("a rewritten commit-graph cannot approve a range (#6798) fixture", graph_cell)

    # #6742: the shallow refusal is "anything but a plain `false`". A git too old to know --is-shallow-repository
    # echoes the option name back; that answer must be refused, not read as "not shallow". The stand-in git sits first
    # on PATH and answers only that query, every other call goes to the real git (reviewer mutant X5, `== "true"`).
    def old_git(label, answer):
        real_git = shutil.which("git")
        if real_git is None:
            raise RuntimeError("git is not on PATH")
        fake_dir = base_dir / f"fake-git-{label}"
        fake_dir.mkdir()
        (fake_dir / "git").write_text(
            f"#!{sys.executable}\nimport os, sys\nif sys.argv[-1] == '--is-shallow-repository':\n"
            f"    sys.stdout.write({answer!r})\n    sys.exit(0)\nos.execv({real_git!r}, [{real_git!r}] + sys.argv[1:])\n",
            encoding="utf-8")
        (fake_dir / "git").chmod(0o755)
        return fake_dir

    def shallow_answer_cell(label, answer, wording):
        def cell():
            fake_dir = old_git(label, answer)
            saved_path = os.environ["PATH"]
            os.environ["PATH"] = f"{fake_dir}{os.pathsep}{saved_path}"
            try:
                case(f"a git that answers {wording} to --is-shallow-repository is refused (#6742)", reword, True,
                     "the repository is shallow", trailer="Justin")
            finally:
                os.environ["PATH"] = saved_path
        guarded(f"a git that answers {wording} to --is-shallow-repository (#6742) fixture", cell)

    shallow_answer_cell("echo", "--is-shallow-repository\n", "the option name")
    # #6713: the same refusal for an empty answer and for a capitalised one; only the exact word `false` is accepted.
    shallow_answer_cell("empty", "", "nothing")
    shallow_answer_cell("capital", "False\n", "False")

    # #6744: the fixtures of the #6575, #6609 and #6573 cells run inside guarded(), so a fault while building one
    # (a git that refuses `clone --depth`, a full disk) is that cell's named FAIL and the cells after it still run.
    # Read from this file's own syntax tree: no `fresh_pair` call for those fixtures may sit directly in the body of
    # _self_test_cases, and the function that holds each one must be handed to guarded().
    ROUND4_FIXTURES = ("showsigverifier", "nonasciiapprover", "shallow")

    def fixtures_guarded_cell():
        tree = ast.parse(Path(__file__).resolve().read_text(encoding="utf-8"))
        outer = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                     and node.name == "_self_test_cases")
        handed = {arg.id for node in ast.walk(outer) if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Name) and node.func.id == "guarded"
                  for arg in node.args[1:] if isinstance(arg, ast.Name)}
        found = {}

        def visit(node, holder):
            for child in ast.iter_child_nodes(node):
                inner = child.name if isinstance(child, ast.FunctionDef) else holder
                if (isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == "fresh_pair"
                        and child.args and isinstance(child.args[0], ast.Constant)):
                    found[child.args[0].value] = holder
                visit(child, inner)

        visit(outer, None)
        return {name: found.get(name) for name in ROUND4_FIXTURES}, handed

    holders, handed = fixtures_guarded_cell()
    loose = [name for name, holder in holders.items() if holder is None or holder not in handed]
    if loose:
        failures.append("round-4 fixtures outside guarded")
        print(f"FAIL: self-test - the fixtures {loose!r} are built outside guarded() (#6744)", file=sys.stderr)
    else:
        print("PASS: self-test - the #6575, #6609 and #6573 fixtures are built inside guarded() (#6744)")

    # #6818: the #6744 pin reads this file's syntax tree, so a fault there (a missing file, a changed layout) used to
    # abort the whole run at this point and hide every later cell. The pin must therefore never be called directly in
    # the body of _self_test_cases: it runs only inside guarded(), where a fault is its named FAIL.
    def pin_call_guarded_cell():
        tree = ast.parse(Path(__file__).resolve().read_text(encoding="utf-8"))
        outer = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                     and node.name == "_self_test_cases")
        direct = []

        def visit(node):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.Lambda)):
                    continue
                if (isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                        and child.func.id == "fixtures_guarded_cell"):
                    direct.append(child.lineno)
                visit(child)

        visit(outer)
        if direct:
            failures.append("the #6744 pin is called outside guarded")
            print(f"FAIL: self-test - the #6744 pin is called directly at line(s) {direct!r} of _self_test_cases, "
                  "outside guarded() (#6818)", file=sys.stderr)
        else:
            print("PASS: self-test - the #6744 pin runs only inside guarded() (#6818)")

    guarded("the #6744 pin is never called outside guarded() (#6818) fixture", pin_call_guarded_cell)

    # #5180: the COUNT CHANGED branch uses the same dynamic fence as the rule branch; no other census diff carries
    # a backtick run, so a static fence there was never caught.
    work, _, _ = fresh_pair("countfence")
    repo = work / "repo"
    claude = repo / "CLAUDE.md"
    census_line = "The surface has 103 MCP tools"
    claude.write_text(claude.read_text(encoding="utf-8").replace(
        census_line, "````\n````\n" + census_line, 1), encoding="utf-8")
    guard.update_manifest_quiet(repo)
    fence_base = commit_all(repo, "base with a backtick run next to the census")
    base_root = work / "baseroot2"
    shutil.copytree(repo, base_root, ignore=shutil.ignore_patterns(".git"))
    shutil.copyfile(guard_path, base_root / GUARD_REL)
    claude.write_text(claude.read_text(encoding="utf-8").replace(census_line, "The surface has 104 MCP tools", 1),
                      encoding="utf-8")
    guard.update_manifest_quiet(repo)
    head_sha = commit_all(repo, "head change")
    try:
        report, failed = compare(base_root, repo, fence_base, head_sha, work / "scratch", guard.fixture_index_pins())
    except RuntimeError as exc:
        report, failed = f"RESULT: FAIL (closed) - {exc}", True
    if failed or "COUNT CHANGED" not in report or not re.search(r"\n`````diff\n.*?\n`````\n", report, re.S):
        print(f"FAIL: self-test - R6 the COUNT CHANGED fence is not longer than a backtick run\n{report}",
              file=sys.stderr)
        failures.append("count fence")
    else:
        print("PASS: self-test - R6 the COUNT CHANGED fence is longer than a backtick run in the census section "
              "(#5180)")

    # #5282: every head-controlled string printed outside a fence goes through span(), including text that holds a
    # backtick run; the cases below carry backticks in head headings and in the guard message that quotes them.
    for raw, want in (("a", "` a `"), ("a ``` b", "```` a ``` b ````"), ("a\nb", "` a b `"),
                      ("`", "`` ` ``"), ("a`b", "`` a`b ``"),
                      ("a\rb", "` a b `"), ("a\u2028b", "` a b `")):  # #5381: CR and U+2028 break lines too
        if span(raw) == want:
            print(f"PASS: self-test - span({raw!r}) is one code span (#5282)")
        else:
            failures.append(f"span {raw!r}")
            print(f"FAIL: self-test - span({raw!r}) = {span(raw)!r}, wanted {want!r} (#5282)", file=sys.stderr)

    def tick_heading(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## added `x` heading\n\nbody\n", encoding="utf-8")

    case("a head heading with a backtick is one code span (#5282)", tick_heading, True,
         "RULE TEXT CHANGED (added): `` ## added `x` heading ``")

    def duplicated_tick_heading(root):
        target = root / "CLAUDE.md"
        target.write_text(target.read_text(encoding="utf-8") + "\n## dup `y`\n\nbody\n\n## dup `y`\n\nbody\n",
                          encoding="utf-8")

    case("a duplicated head heading with a backtick is one code span (#5282)", duplicated_tick_heading, True,
         "RULE TEXT CHANGED (duplicated heading): `` ## dup `y` ``")
    case("a base-guard refusal quoting a head heading with a backtick is one code span (#5282)",
         duplicated_tick_heading, True, "- BASE GUARD REFUSES THE HEAD: `` FAIL: CLAUDE.md has the heading '## dup `y`' more than once")

    work, _, _ = fresh_pair("countkey")
    repo = work / "repo"
    claude = repo / "CLAUDE.md"
    claude.write_text(claude.read_text(encoding="utf-8")
                      + "\n## Prime directive census `z` addendum\n\nThe addendum has 103 MCP tools\n", encoding="utf-8")
    guard.update_manifest_quiet(repo)
    key_base = commit_all(repo, "base with a census section whose heading holds a backtick")
    base_root = work / "baseroot3"
    shutil.copytree(repo, base_root, ignore=shutil.ignore_patterns(".git"))
    shutil.copyfile(guard_path, base_root / GUARD_REL)
    claude.write_text(claude.read_text(encoding="utf-8").replace("addendum has 103 MCP tools", "addendum has 104 MCP tools", 1),
                      encoding="utf-8")
    guard.update_manifest_quiet(repo)
    head_sha = commit_all(repo, "head change")
    try:
        report, failed = compare(base_root, repo, key_base, head_sha, work / "scratch", guard.fixture_index_pins())
    except RuntimeError as exc:
        report, failed = f"RESULT: FAIL (closed) - {exc}", True
    needle = "### COUNT CHANGED: `` ## Prime directive census `z` addendum ``"
    if failed or needle not in report:
        print(f"FAIL: self-test - the COUNT CHANGED heading is not one code span (#5282)\n{report}", file=sys.stderr)
        failures.append("count key span")
    else:
        print("PASS: self-test - the COUNT CHANGED heading with a backtick is one code span (#5282)")

    # #5376: a head census line that holds a literal "#" where the base had a number is a rule change, not a count.
    def hash_for_count(root):
        edit("The surface has 103 MCP tools", "The surface has # MCP tools")(root)
        reseal(root)

    case("a census number replaced by a literal # is a rule change, not COUNT CHANGED (#5376)", hash_for_count,
         True, "RULE TEXT CHANGED")

    # #5404: a head census line that holds U+0000 where the base had a number is a rule change, not a count.
    def hash_for_nul(root):
        edit("The surface has 103 MCP tools", "The surface has \x00 MCP tools")(root)
        reseal(root)

    case("a census number replaced by U+0000 is a rule change, not COUNT CHANGED (#5404)", hash_for_nul,
         True, "RULE TEXT CHANGED")

    # #5425: the CENSUS_DIGITS split comparison is pinned against every weakening of its pattern. Each case is a
    # head (or base and head) change that must be a rule change; the comment names the mutant it kills.
    def census_case(name, old, new, base_old=None, base_new=None, want_fail=True):
        base_edit = None
        if base_old is not None:
            def base_edit(root):
                edit(base_old, base_new)(root)
                reseal(root)
        case(name, census_edit(old, new), want_fail, "RULE TEXT CHANGED" if want_fail else "COUNT CHANGED",
             base_mutate=base_edit)

    # M4 (join the pieces): a census number deleted while its spaces stay.
    census_case("a census number deleted with its spaces kept is a rule change (#5425)",
                "has 103 MCP tools", "has  MCP tools")
    # M5 (drop the first piece): text before the first census number edited.
    census_case("text before the first census number edited is a rule change (#5425)",
                "The surface has 103 MCP", "The surface lacks 103 MCP")
    # M8 (drop the word boundary): a base number glued to a letter changes with the letter kept.
    census_case("a census number glued to a letter v103 to v104 is a rule change (#5425)",
                "has 103 MCP tools", "has v104 MCP tools", "has 103 MCP tools", "has v103 MCP tools")
    # M9 (lookahead whitespace optional): a base number glued to the census words.
    census_case("a census number glued to the census words 103MCP to 104MCP is a rule change (#5425)",
                "has 103 MCP tools", "has 104MCP tools", "has 103 MCP tools", "has 103MCP tools")
    # M12 (any non-space run instead of digits): a number replaced by a word.
    census_case("a census number replaced by a word is a rule change (#5425)",
                "has 103 MCP tools", "has many MCP tools")
    # M10 (digit class widened with NUL and #): the byte follows a digit, where the word boundary does not block it.
    census_case("a census number followed by a literal # is a rule change (#5425)",
                "has 103 MCP tools", "has 10# MCP tools")
    census_case("a census number followed by U+0000 is a rule change (#5425)",
                "has 103 MCP tools", "has 10\x00 MCP tools")

    # Further mutants of the same lines (round 10): a pattern or comparison weakened in a way no case above caught.
    # N2 (one whitespace, not a run): a census number followed by two spaces is still a census number.
    census_case("a census count change across a double space is still COUNT CHANGED (#5426)",
                "has 103 MCP tools", "has 104  MCP tools", "has 103 MCP tools", "has 103  MCP tools", want_fail=False)
    # N8 (digit run capped at three): a four-digit count is a census number too.
    census_case("a four-digit census count change is still COUNT CHANGED (#5426)",
                "has 103 MCP tools", "has 1040 MCP tools", "has 103 MCP tools", "has 1030 MCP tools",
                want_fail=False)
    # N3 (a census phrase dropped from the alternation): the route and URL-path phrases are census counts.
    census_case("route and URL-path census counts change as COUNT CHANGED (#5426)",
                "has 103 MCP tools", "has 104 MCP tools, 104 production HTTP route registrations, 90 unique URL paths",
                "has 103 MCP tools", "has 103 MCP tools, 103 production HTTP route registrations, 89 unique URL paths",
                want_fail=False)
    # N6 (case-insensitive census words): a lower-case words run is not a census phrase.
    census_case("a count before lower-case census words is a rule change (#5426)",
                "has 103 MCP tools", "has 104 mcp tools", "has 103 MCP tools", "has 103 mcp tools")
    # N7 (no word boundary after the census words): a census word glued to more letters is not a census phrase.
    census_case("a count before census words with a glued suffix is a rule change (#5426)",
                "has 103 MCP tools", "has 104 MCP toolsX", "has 103 MCP tools", "has 103 MCP toolsX")
    # N11 (compare the pieces sorted): the text between the numbers moved to another place is a rule change.
    census_case("census text between the numbers reordered is a rule change (#5426)",
                "103 MCP tools and 99 CLI subcommands (97 in the default build)",
                "103 CLI subcommands (99 MCP tools and 97 in the default build)")
    # N12/N13 (strip or collapse the pieces): whitespace between a number and its words is rule text.
    census_case("extra whitespace between a census number and its words is a rule change (#5426)",
                "has 103 MCP tools", "has 103   MCP tools")
    # N14 (case-fold the pieces): a case change in the text between the numbers is a rule change.
    census_case("a case change in census prose is a rule change (#5426)",
                "A vote needs 5 agents.", "a vote needs 5 agents.")

    # #5375: the docstring says what the code does: the census exemption is a heading PREFIX match.
    doc_words = " ".join((__doc__ or "").split())
    if f"inside a section whose heading starts with `{CENSUS_SECTION}`" in doc_words:
        print("PASS: self-test - the docstring states the COUNT CHANGED section rule as a heading prefix (#5375)")
    else:
        failures.append("docstring prefix")
        print("FAIL: self-test - the docstring does not state that COUNT CHANGED applies to a heading prefix "
              "(#5375)", file=sys.stderr)

    # #5383: the changelog states the guarantee the code gives: a program-level refusal under -I, not "never runs".
    changelog = repo_root / "changelog.d" / "4507.fixed.md"
    if not changelog.is_file():
        print("PASS: self-test - changelog.d/4507.fixed.md is consumed; the #5383 wording pin does not apply")
    elif "when the script is run as a program" in changelog.read_text(encoding="utf-8"):
        print("PASS: self-test - the changelog scopes the sibling-module refusal to a program run (#5383)")
    else:
        failures.append("changelog wording")
        print("FAIL: self-test - changelog.d/4507.fixed.md does not scope the sibling-module refusal to a program "
              "run (#5383)", file=sys.stderr)

    def base_claude_symlink(root):
        target = root / "CLAUDE.md"
        target.rename(root / "CLAUDE.real.md")
        target.symlink_to("CLAUDE.real.md")

    case("R4 a symlinked base CLAUDE.md fails closed", missing_manifest, True, "not a regular file",
         base_mutate=base_claude_symlink)

    def base_guard_symlink(root):
        target = root / GUARD_REL
        target.unlink()
        target.symlink_to("/dev/null")

    case("R5 a symlinked base guard fails closed", missing_manifest, True, "not a regular file",
         base_mutate=base_guard_symlink)

    def base_manifest_symlink(root):
        target = root / MANIFEST_REL
        target.rename(root / "manifest.real")
        target.symlink_to("../../manifest.real")

    case("R5 a symlinked base manifest fails closed", missing_manifest, True, "not a regular file",
         base_mutate=base_manifest_symlink)

    def base_manifest_garbage(root):
        with open(root / MANIFEST_REL, "a", encoding="utf-8") as handle:
            handle.write("not a manifest line\n")

    case("R4 a malformed base manifest fails closed even with the trailer", reword, True, "unusable",
         trailer="Justin", base_mutate=base_manifest_garbage)
    case("R5 a malformed base manifest fails closed without the trailer", reword, True, "unusable",
         base_mutate=base_manifest_garbage)

    shutil.rmtree(base_dir, ignore_errors=True)
    if failures:
        print(f"FAIL: self-test - {len(failures)} case(s) failed", file=sys.stderr)
        return 1
    print("PASS: self-test #4507 R3-F3 - rule changes are reported, need the trailer, counts only print, "
          "and every fail-closed path refuses")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--base-root")
    parser.add_argument("--repo")
    parser.add_argument("--base-sha")
    parser.add_argument("--head-sha")
    parser.add_argument("--scratch")
    parser.add_argument("--summary")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not all((args.base_root, args.repo, args.base_sha, args.head_sha, args.scratch)):
        parser.error("--base-root, --repo, --base-sha, --head-sha and --scratch are required")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
