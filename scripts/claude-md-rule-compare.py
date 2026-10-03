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
  * if the only differences inside a section are digit runs, the heading is "COUNT CHANGED" instead;
  * any OTHER error the base guard reports about the head copies (a lowered floor, a deleted pinned
    heading, a broken index) is "BASE GUARD REFUSES THE HEAD" and counts as a rule change;
  * a rule change fails the job unless a commit in base..head carries a trailer line
    `Rule-Change-Approved-By: <who>`; a count-only change passes but is still printed.

This is TAMPERING EVIDENCE, not authority. The trailer is data an agent can also write, and the head also
carries its own manifest, so the comparison deliberately uses the base one. What enforces is the two
independent reviews and the sole merger. Fail closed: a missing, unreadable or symlinked base guard, base
manifest or base CLAUDE.md is a failure. Bootstrap: pull_request_target runs only once this workflow is on the
base branch, so the PR that introduces it is judged by review.

Python 3.9 standard library only.

Usage:
  claude-md-rule-compare.py --base-root DIR --repo DIR --base-sha SHA --head-sha SHA [--summary FILE]
  claude-md-rule-compare.py --self-test
"""
import argparse
import difflib
import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

GUARD_REL = "scripts/check-claude-md-size.py"
MANIFEST_REL = "scripts/qc-allowlists/claude-md-rule-sections.sha256"
DATA_PATHS = ("CLAUDE.md", "docs/reference/ARCHITECTURE_REFERENCE.md", "docs/reference/CODE_STYLE.md")
TRAILER = re.compile(r"^Rule-Change-Approved-By: (\S.*)$", re.MULTILINE)
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGITS = re.compile(r"\d+")
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


def load_base_guard(base_root: Path):
    """Import the BASE guard module (trusted code of the base commit)."""
    guard = base_root / GUARD_REL
    regular_file(guard, f"base guard {GUARD_REL}")
    regular_file(base_root / MANIFEST_REL, f"base manifest {MANIFEST_REL}")
    regular_file(base_root / "CLAUDE.md", "base CLAUDE.md")
    spec = importlib.util.spec_from_file_location("base_claude_md_guard", guard)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the base guard")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
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
        if not SHA.match(sha):
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
        if old is not None and new is not None and DIGITS.sub("#", old) == DIGITS.sub("#", new):
            count_changed = True
            lines += [f"### COUNT CHANGED: {key}", "", "Only digit runs differ.", "", "```diff",
                      unified(old, new, key), "```", ""]
        else:
            rule_changed = True
            state = "removed" if new is None else ("added" if old is None else "changed")
            lines += [f"### RULE TEXT CHANGED ({state}): {key}", "", "```diff",
                      unified(old or "", new or "", key), "```", ""]
    for key in duplicates:
        rule_changed = True
        lines += [f"### RULE TEXT CHANGED (duplicated heading): {key}", ""]
    residual = [error for error in guard.check(head_root, index_pins) if not any(marker in error for marker in DRIFT_MARKERS)]
    for error in residual:
        rule_changed = True
        lines.append(f"- BASE GUARD REFUSES THE HEAD: {error}")
    if residual:
        lines.append("")
    approved = approvals(repo, base_sha, head_sha)
    failed = False
    if rule_changed and not approved:
        failed = True
        lines.append("RESULT: FAIL - the rule text changed and no commit in the range carries a "
                     "`Rule-Change-Approved-By: <who>` trailer.")
    elif rule_changed:
        lines.append("RESULT: PASS - rule text changed; approval trailer(s): " + "; ".join(approved)
                     + ". This is tamper-evidence: the trailer is data, and review plus the sole merger enforce.")
    elif count_changed:
        lines.append("RESULT: PASS - only counts changed (printed above for review).")
    else:
        lines.append("RESULT: PASS - no rule section differs from the base manifest.")
    return "\n".join(lines) + "\n", failed


def run(args) -> int:
    scratch = Path(args.scratch)
    try:
        scratch.mkdir(parents=True, exist_ok=True)
        report, failed = compare(Path(args.base_root), Path(args.repo), args.base_sha, args.head_sha, scratch)
    except (RuntimeError, OSError, UnicodeDecodeError, ValueError) as exc:
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
    path.write_text(path.read_text(encoding="utf-8").replace(
        heading + "\n", heading + "\nThe tool limit is 103 tools.\n", 1), encoding="utf-8")
    guard.update_manifest_quiet(root)
    return commit_all(root, "base")


def commit_all(root: Path, message: str) -> str:
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), *IDENT, "commit", "-q", "--allow-empty", "-m", message], check=True)
    return git(root, "rev-parse", "HEAD").decode().strip()


def self_test() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    guard_path = repo_root / GUARD_REL
    spec = importlib.util.spec_from_file_location("sibling_guard", guard_path)
    if spec is None or spec.loader is None:
        print("FAIL: self-test - cannot load the sibling guard", file=sys.stderr)
        return 1
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
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
    case("reworded section with the trailer passes", reword, False, "approval trailer(s): Justin", trailer="Justin")
    case("a trailer quoted mid-line does not count", reword, True, "RESULT: FAIL",
         message="head change Rule-Change-Approved-By: Justin")
    case("an empty trailer value does not count", reword, True, "RESULT: FAIL",
         message="head change\n\nRule-Change-Approved-By: ")

    def filler(root):
        edit("section body x", "section body y")(root)
        reseal(root)

    case("same-size filler swap is a rule change", filler, True, "RULE TEXT CHANGED")

    def count(root):
        edit("103 tools", "104 tools")(root)
        reseal(root)

    case("a digit-only change prints COUNT CHANGED and passes", count, False, "COUNT CHANGED")

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
