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
  * if the only differences are ASCII digit runs of the generated census inside the Prime directive
    section (a number before its unit words), the heading is "COUNT CHANGED" instead;
  * any OTHER error the base guard reports about the head copies (a lowered floor, a deleted pinned
    heading, a broken index) is "BASE GUARD REFUSES THE HEAD" and counts as a rule change;
  * a rule change fails the job unless a commit in base..head carries a trailer line
    `Rule-Change-Approved-By: <who>`; a count-only change passes but is still printed.

This is TAMPERING EVIDENCE, not authority. The trailer is data an agent can also write, and the head also
carries its own manifest, so the comparison deliberately uses the base one. What enforces is the two
independent reviews and the sole merger. Fail closed: a missing, unreadable or symlinked base guard, base
manifest or base CLAUDE.md is a failure. The comparison runs only in isolated mode (`python3 -I`): the script
directory is then not on the import path, so no file beside the script can stand in for a standard module, and
the base guard is compiled from its source, never from a cached .pyc (#5163). Bootstrap: pull_request_target
runs only once this workflow is on the base branch, so the PR that introduces it is judged by review.

Python 3.9 standard library only.

Usage (the comparison refuses to run without -I):
  python3 -I scripts/claude-md-rule-compare.py --base-root DIR --repo DIR --base-sha SHA --head-sha SHA
      --scratch DIR [--summary FILE]
  python3 -I scripts/claude-md-rule-compare.py --self-test
"""
import sys

if __name__ == "__main__" and not sys.flags.isolated:
    # R6 (#5163): checked before any other import. Without -I the script directory heads sys.path, so a
    # file there named like a standard module (argparse, difflib, ...) would run at its import, before any
    # check inside main() or run() could refuse. sys is built in and cannot be shadowed.
    print("## CLAUDE.md rule-change comparison\n\nRESULT: FAIL (closed) - run the comparison as "
          "`python3 -I scripts/claude-md-rule-compare.py` (isolated mode)")
    sys.exit(1)

import argparse  # noqa: E402 - after the isolated-mode refusal on purpose (#5163)
import difflib
import importlib.util
import os
import py_compile
import re
import shutil
import stat
import subprocess
from pathlib import Path

GUARD_REL = "scripts/check-claude-md-size.py"
MANIFEST_REL = "scripts/qc-allowlists/claude-md-rule-sections.sha256"
DATA_PATHS = ("CLAUDE.md", "docs/reference/ARCHITECTURE_REFERENCE.md", "docs/reference/CODE_STYLE.md")
TRAILER = re.compile(r"^Rule-Change-Approved-By: (\S.*)$", re.MULTILINE)
SHA = re.compile(r"^[0-9a-f]{40}$")
# R4 (#4507): a digit is rule text (a vote size, a file threshold, a release branch). Only a digit run that is a
# public-surface census count INSIDE the prime-directive section (the generated inventory line) may change without
# the trailer; the same words in any other section are rule text. Fail closed, the precedent of root issue #4869.
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
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
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
    """R5 (#5163): execute `path` compiled from its source bytes. A cached bytecode file beside it (an
    unchecked-hash .pyc is loaded without comparing it to the source) is never consulted."""
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


def approvals(repo: Path, base_sha: str, head_sha: str) -> list:
    """The `Rule-Change-Approved-By` trailer values in base..head (commit messages are data)."""
    out = git(repo, "log", "--format=%B%x00", f"{base_sha}..{head_sha}").decode("utf-8", "replace")
    found = []
    for message in out.split("\0"):
        found += [match.group(1).strip() for match in TRAILER.finditer(message)]
    return found


def compare(base_root: Path, repo: Path, base_sha: str, head_sha: str, scratch: Path, index_pins=None):
    """Return (report_text, failed). Raises RuntimeError for a fail-closed precondition."""
    for sha in (base_sha, head_sha):
        if not SHA.fullmatch(sha):
            raise RuntimeError(f"{sha!r} is not a 40-hex commit id")
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
        if old is not None and new is not None and key.startswith(CENSUS_SECTION) and (
                CENSUS_DIGITS.sub("#", old) == CENSUS_DIGITS.sub("#", new)):
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


def self_test() -> int:
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
    base_dir = repo_root / ".local-runs" / f"rule-compare-selftest-{os.getpid()}"
    shutil.rmtree(base_dir, ignore_errors=True)
    base_dir.mkdir(parents=True)
    failures = []

    counter = [0]

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
    case("a trailer quoted mid-line does not count", reword, True, "RESULT: FAIL",
         message="head change Rule-Change-Approved-By: Justin")
    case("an empty trailer value does not count", reword, True, "RESULT: FAIL",
         message="head change\n\nRule-Change-Approved-By: ")

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
        # #5163/#5313: without -I the script directory heads sys.path, so the comparison must refuse to run, and
        # the non-isolated child is started from a COPY of the script in an empty scratch directory (never from
        # the real scripts/ directory, where a merged sibling named like a standard module would run inside the
        # trusted job). Standard-module files are planted beside the copy; none may run.
        iso = base_dir / "iso"
        iso.mkdir(parents=True, exist_ok=True)
        copy = iso / "claude-md-rule-compare.py"
        shutil.copyfile(Path(__file__).resolve(), copy)
        for name in ("argparse", "difflib", "py_compile", "re", "shutil", "stat", "subprocess"):
            (iso / f"{name}.py").write_text("print('PLANTED')\nraise SystemExit(0)\n", encoding="utf-8")
        # #5283: the refusal must hold for every partial isolation, not only for a bare interpreter: -E (ignore
        # PYTHON* variables) and -s (no user site) each leave the script directory on sys.path.
        for flags in ([], ["-E"], ["-s"]):
            result = subprocess.run([sys.executable, *flags, str(copy), "--base-root", ".", "--repo", ".",
                                     "--base-sha", "0" * 40, "--head-sha", "0" * 40, "--scratch", str(iso / "s")],
                                    capture_output=True, text=True, check=False)
            if not (result.returncode == 1 and "isolated mode" in result.stdout
                    and "PLANTED" not in result.stdout + result.stderr):
                return False
        return True

    if isolated_refusal():
        print("PASS: self-test - a comparison run without -I fails closed (R5, #5163)")
    else:
        failures.append("non-isolated run")
        print("FAIL: self-test - a comparison run without -I did not fail closed (R5, #5163)", file=sys.stderr)

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
    if failed or "COUNT CHANGED" not in report or "`````diff" not in report:
        print(f"FAIL: self-test - R6 the COUNT CHANGED fence is not longer than a backtick run\n{report}",
              file=sys.stderr)
        failures.append("count fence")
    else:
        print("PASS: self-test - R6 the COUNT CHANGED fence is longer than a backtick run in the census section "
              "(#5180)")

    # #5282: every head-controlled string printed outside a fence goes through span(), including text that holds a
    # backtick run; the cases below carry backticks in head headings and in the guard message that quotes them.
    for raw, want in (("a", "` a `"), ("a ``` b", "```` a ``` b ````"), ("a\nb", "` a b `"),
                      ("`", "`` ` ``"), ("a`b", "`` a`b ``")):
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
