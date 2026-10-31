"""Derive the repository paths a Rust test or source file can open (#8240 cargo_skip).

Library used by the cargo_skip guard test (scripts/ci/tests/test_impact_cargo_skip_*.py)
and runnable as a report:

    python3 -I scripts/ci/impact/read_set.py --repo <tree> [--within <glob> ...]

The scan is deliberately over-inclusive (fail closed). Every string literal of
every tracked .rs file is a possible path (include_str!, include_bytes!,
fs::read*, read_to_string, Path/PathBuf literals, Command arguments, format!
templates), chained join/new/from/push calls are concatenated into one path,
and every path-like token of a script that a literal names is followed to a
fixpoint (a test that runs scripts/x.py reads whatever x.py reads). A literal
refers to a tracked file when it, or a trailing run of its path components,
equals that path or names a directory holding it, or when it is a bare file
name. A bare directory name counts only inside a join chain or a format
fragment, where it is a path component rather than prose.
"""
import argparse
import collections
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

sys.path.append(str(Path(__file__).resolve().parents[1]))

from impact import common  # noqa: E402

GIT_TIMEOUT_S = 120
MAX_LITERAL_LEN = 300
MAX_FILE_BYTES = 2_000_000
RUST_SUFFIX = ".rs"
SCRIPT_SUFFIXES = (".py", ".sh", ".bash")
STRING = r'"((?:[^"\\\n]|\\.)*)"'
RUST_LITERAL = re.compile(STRING)
# A script token must look like a path: a separator or a file extension.
SCRIPT_TOKEN = re.compile(r"[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+)*")
TRIM_TAIL = re.compile(r"[#?:\s].*$")
PLACEHOLDER = re.compile(r"\{[^}]*\}|%[sd]")
CHAIN = re.compile(r'(?:(?:Path|PathBuf)::(?:new|from)|\.join|\.push)\(\s*' + STRING + r'\s*\)'
                   r'(?:\s*\.(?:join|push)\(\s*' + STRING + r'\s*\))*')
GLOB_STEM = re.compile(r"([A-Za-z0-9_.@+/-]+)/[*?\[]")
# A Rust file runs scripts only when it can spawn a process.
EXEC_MARK = re.compile(r"Command\b|process::")
PY_IMPORT = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
TESTS_DIR = "scripts/ci/tests/"
# Every step script of a workflow or composite action is a read (security F2,
# #8328): the cargo legs run them, so a skippable path they name is a hole.
WORKFLOW_ROOTS = (".github/workflows/", ".github/actions/")
WORKFLOW_SUFFIXES = (".yml", ".yaml")
UNITTEST_MODULE = re.compile(r"-m\s+unittest(?:\s+-[A-Za-z]+)*\s+([A-Za-z0-9_]+)")
ROOT_MARK = re.compile(
    r"CARGO_MANIFEST_DIR|repo_root|project_root|workspace_root")
LEADING_DOTS = ("./", "../")
# Prefix on a candidate that is a chain or a format fragment: a bare directory
# name is then a path component and counts as a directory reference.
DIR_MARK = "\0dir:"
NAME_MARK = "."


def tracked_files(repo: Path) -> List[str]:
    """Return the tracked paths of `repo` (NUL-separated git ls-files)."""
    res = subprocess.run(["git", "ls-files", "-z"], cwd=str(repo),
                         capture_output=True, timeout=GIT_TIMEOUT_S)
    if res.returncode != 0:
        raise RuntimeError("git ls-files failed")
    return [p.decode("utf-8", "surrogateescape")
            for p in res.stdout.split(common.NUL.encode()) if p]


def normalise(text: str) -> str:
    """Strip a trailing anchor or argument, leading ./ and ../ runs and slashes."""
    value = TRIM_TAIL.sub("", text.strip())
    changed = True
    while changed:
        changed = False
        for lead in LEADING_DOTS:
            if value.startswith(lead):
                value = value[len(lead):]
                changed = True
    return value.strip("/")


def candidates_of(text: str, is_rust: bool,
                  top_dirs: Optional[Set[str]] = None) -> Set[str]:
    """Return the path candidates of one source text (see the module doc).

    A Rust literal that is exactly a tracked top-level directory name (a const
    array of walk roots, a `.join(root)` argument) is a directory read.
    """
    top_dirs = top_dirs or set()
    out: Set[str] = set()

    def add(item: str, bare_dir: bool) -> None:
        if 0 < len(item) <= MAX_LITERAL_LEN:
            norm = normalise(item)
            if norm:
                out.add((DIR_MARK if bare_dir else "") + norm)

    if is_rust:
        # A top-level name inside a multi-part chain is only the first component
        # of a longer path (.join("docs").join("integrations")), not a root walk.
        chained = [(m.start(), m.end()) for m in CHAIN.finditer(text)
                   if len(RUST_LITERAL.findall(m.group(0))) > 1]
        for match in RUST_LITERAL.finditer(text):
            item = match.group(1)
            in_chain = any(lo <= match.start() < hi for lo, hi in chained)
            fragments = [f for f in PLACEHOLDER.split(item) if f]
            templated = len(fragments) != 1 or fragments[0] != item
            for fragment in fragments:
                words = fragment.split()
                if len(words) > 1 or fragment != fragment.strip():
                    # Prose or a command line: only path-shaped words count.
                    for word in words:
                        if "/" in word or NAME_MARK in word:
                            add(word, False)
                else:
                    add(fragment, templated or (fragment in top_dirs and not in_chain))
        for match in CHAIN.finditer(text):
            parts = [normalise(p) for p in RUST_LITERAL.findall(match.group(0))]
            add("/".join(p for p in parts if p), True)
    else:
        for token in SCRIPT_TOKEN.findall(text):
            if "/" in token or NAME_MARK in token:
                add(token, False)
        for stem in GLOB_STEM.findall(text):
            add(stem, True)
        for module in PY_IMPORT.findall(text):
            add(module + ".py", False)
        for module in UNITTEST_MODULE.findall(text):
            add(module + ".py", False)
    return out


class PathIndex:
    """Lookup structures over the tracked paths."""

    def __init__(self, paths: Iterable[str]) -> None:
        self.paths = set(paths)
        self.by_name: Dict[str, Set[str]] = collections.defaultdict(set)
        self.by_dir: Dict[str, Set[str]] = collections.defaultdict(set)
        for path in self.paths:
            self.by_name[path.rsplit("/", 1)[-1]].add(path)
            parts = path.split("/")
            for i in range(1, len(parts)):
                self.by_dir["/".join(parts[:i])].add(path)

    def resolve(self, candidate: str) -> Set[str]:
        """Return every tracked path `candidate` may name."""
        bare_dir = candidate.startswith(DIR_MARK)
        literal = candidate[len(DIR_MARK):] if bare_dir else candidate
        found: Set[str] = set()
        parts = literal.split("/")
        for start in range(len(parts)):
            tail = "/".join(parts[start:])
            if bare_dir and len(parts) > 1 and start == len(parts) - 1:
                # The last component of a longer chain is a scratch name.
                continue
            if tail in self.paths:
                found.add(tail)
            if tail in self.by_dir and (bare_dir or "/" in tail):
                found |= self.by_dir[tail]
        if len(parts) == 1 and NAME_MARK in literal:
            found |= self.by_name.get(literal, set())
        return found


def read_text(repo: Path, rel: str) -> str:
    """Read a tracked file as text; empty when unreadable or oversized."""
    try:
        path = repo / rel
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(errors="replace")
    except OSError:
        return ""


def guarded_map(section: dict) -> Dict[str, List[str]]:
    """Return {rust source: guarded roots} from the cargo_skip walk_guards."""
    return {g["rust"]: list(g["roots"]) for g in section["walk_guards"]}


def is_workflow(path: str) -> bool:
    """Return True for a workflow or composite-action YAML file."""
    return path.endswith(WORKFLOW_SUFFIXES) and path.startswith(WORKFLOW_ROOTS)


def under_any(path: str, roots: Iterable[str]) -> bool:
    """Return True when `path` is a root or lies under one."""
    return any(path == root or path.startswith(root.rstrip("/") + "/")
               for root in roots)


def referenced_paths(repo: Path, paths: Optional[List[str]] = None,
                     guarded: Optional[Dict[str, List[str]]] = None) -> Dict[str, str]:
    """Return {referenced path: first referrer} reachable from the Rust files.

    `guarded` maps a Rust source to the walk roots whose scan a Python guard
    mirrors on every PR (rules.json cargo_skip.walk_guards): hits under those
    roots are not reported for that source.
    """
    paths = paths if paths is not None else tracked_files(repo)
    guarded = guarded or {}
    index = PathIndex(paths)
    top_dirs = {p.split("/")[0] for p in paths if "/" in p}
    referenced: Dict[str, str] = {}
    scanned: Set[str] = set()
    queue = [p for p in paths if p.endswith(RUST_SUFFIX) or is_workflow(p)]
    while queue:
        source = queue.pop()
        if source in scanned:
            continue
        scanned.add(source)
        text = read_text(repo, source)
        is_rust = source.endswith(RUST_SUFFIX)
        # A top-level directory name in a join chain is a repository path only
        # in a file that anchors at the repository root; elsewhere it is a
        # scratch-directory component.
        rooted = (not is_rust) or bool(ROOT_MARK.search(text))
        # A script is followed only when something that can run it names it: a
        # Rust file that spawns processes, or another followed script.
        runs_scripts = not is_rust or bool(EXEC_MARK.search(text))
        for candidate in candidates_of(text, is_rust, top_dirs):
            if (not rooted and candidate.startswith(DIR_MARK)
                    and "/" not in candidate[len(DIR_MARK):]):
                continue
            for hit in index.resolve(candidate):
                if source in guarded and under_any(hit, guarded[source]):
                    continue
                # A followed script contributes only scripts and its exact
                # scripts/ci/tests modules: its prose and glob mentions of docs
                # are read by the docs gates (their own CI jobs), not by cargo.
                if not is_rust and not (hit.endswith(SCRIPT_SUFFIXES)
                                        or hit.startswith(TESTS_DIR)):
                    continue
                if not is_rust and not (
                        hit == candidate or hit.endswith("/" + candidate)):
                    continue  # a script names files exactly; a directory is not read whole
                referenced.setdefault(hit, source)
                if (runs_scripts and hit.endswith(SCRIPT_SUFFIXES)
                        and not hit.startswith(TESTS_DIR)
                        and hit not in scanned):
                    queue.append(hit)
    return referenced


def main(argv: Optional[List[str]] = None) -> int:
    """Print the referenced paths that match any --within glob."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=".")
    parser.add_argument("--within", action="append", default=[])
    args = parser.parse_args(argv)
    refs = referenced_paths(Path(args.repo))
    for path in sorted(refs):
        if not args.within or any(common.match_glob(g, path) for g in args.within):
            print("%s\t%s" % (path, refs[path]))
    return common.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
