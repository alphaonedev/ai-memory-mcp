"""Build or refresh the impact index (SQLite, WAL) for a repository (#8240).

Usage:
    python3 -I scripts/ci/impact/build_index.py --repo . --db <file> \
        [--junit <file>] [--codegraph <dir>] [--metadata-file <json>]

Tables: crates, crate_deps, test_targets (from `cargo metadata`), path_rules
and settings (from rules.json), history (from a JUnit file when given) and
file_symbols / symbol_edges (read-only import of a codegraph index when it
has the expected schema). Running it twice on the same inputs yields the same
rows; history is kept across runs.
"""
import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# >>> sibling-load 9399 (canonical text; scripts/ci/sibling_load.py; test_sibling_load_9399 pins every copy)
class SiblingLoadError(ImportError):
    """A refused sibling load; ``reason`` is one of the fixed words the refusal line prints."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _sibling_path(filename):
    import os
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), filename)


def _load_sibling(filename, module_name):
    import os
    import stat
    import sys
    import types
    here = os.path.dirname(os.path.realpath(__file__))
    try:
        here_st = os.stat(here)
    except OSError:
        raise SiblingLoadError("unreadable") from None
    here_id = (here_st.st_dev, here_st.st_ino)
    path = os.path.realpath(os.path.join(here, filename))
    if os.path.commonpath([here, path]) != here:
        raise SiblingLoadError("symlink leaves the script folder")
    loaded = sys.modules.get(module_name)
    if loaded is not None:
        if os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
            return loaded
        raise SiblingLoadError("module name taken")
    # The script folder opened must have the device and inode the stat above recorded, so a swap of that folder or of
    # any folder above it (for a symlink or by a rename) is refused; each component below it is opened relative to the
    # descriptor before it and never through a symlink; the type check, the read and the compile use one descriptor.
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    parts = os.path.relpath(path, here).split(os.sep)
    fds = []
    try:
        try:
            fds.append(os.open(here, dir_flags))
            opened = os.fstat(fds[0])
            if (opened.st_dev, opened.st_ino) != here_id:
                raise SiblingLoadError("unreadable")
            for part in parts[:-1]:
                fds.append(os.open(part, dir_flags, dir_fd=fds[-1]))
            fds.append(os.open(parts[-1], os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0), dir_fd=fds[-1]))
        except FileNotFoundError:
            raise SiblingLoadError("absent") from None
        except OSError:
            raise SiblingLoadError("unreadable") from None
        try:
            if not stat.S_ISREG(os.fstat(fds[-1]).st_mode):
                raise SiblingLoadError("not a regular file")
            with os.fdopen(fds[-1], "rb", closefd=False) as handle:
                source = handle.read()
        except OSError:
            raise SiblingLoadError("unreadable") from None
    finally:
        for fd in fds:
            os.close(fd)
    if not source:
        raise SiblingLoadError("empty")
    module = types.ModuleType(module_name)
    module.__file__ = path
    saved_path = list(sys.path)
    sys.modules[module_name] = module
    try:
        exec(compile(source, path, "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    finally:
        sys.path[:] = saved_path
    return module


def _sibling_refusal(prog, filename, exc):
    import sys
    why = exc.reason if isinstance(exc, SiblingLoadError) else type(exc).__name__
    if not why.replace(" ", "_").isidentifier():
        why = "BaseException"
    # The path comes from the checkout, so a control character in a folder name must not start a second output line
    # (a runner reads workflow commands at a line start): every non-printable character is written as its escape.
    shown = "".join(ch if ch.isprintable() else ascii(ch)[1:-1] for ch in _sibling_path(filename))
    print("%s: refused: sibling module %s at %s cannot be loaded (%s)" % (prog, filename, shown, why),
          file=sys.stderr, flush=True)
# <<< sibling-load 9399


SIBLING_PROG = "build_index"
SIBLING_EXIT_LOAD_REFUSED = 3

try:
    common = _load_sibling("common.py", "impact.common")
except (Exception, SystemExit) as exc:  # any failed load ends here with one fixed line (#9399)
    _sibling_refusal(SIBLING_PROG, "common.py", exc)
    sys.exit(SIBLING_EXIT_LOAD_REFUSED)

INCLUDE_SCAN_TOPS = ("src", "tests", "benches")
INCLUDE_RE = re.compile(r"include_(?:str|bytes)!\s*\(")
LITERAL_RE = re.compile(r'^"([^"\\]*)"$')
MANIFEST_CONCAT_RE = re.compile(
    r'^concat!\(\s*env!\(\s*"CARGO_MANIFEST_DIR"\s*\)\s*,\s*"([^"\\]*)"\s*,?\s*\)$')
CARGO_TIMEOUT_S = 300
RESOLVE_TIMEOUT_S = 60
MAX_JUNIT_BYTES = 64 * 1024 * 1024
CODEGRAPH_DB_NAME = "codegraph.db"
CODEGRAPH_NODE_COLUMNS = {"id", "kind", "name", "file_path"}
CODEGRAPH_EDGE_COLUMNS = {"source", "target", "kind"}
FAILURE_TAGS = ("failure", "error")
FLAKY_TAGS = ("flakyFailure", "flakyError", "rerunFailure", "rerunError")


def run_cargo_metadata(repo: Path, extra: List[str], timeout_s: int) -> dict:
    """Run `cargo metadata --format-version 1` and return the parsed JSON."""
    cmd = ["cargo", "metadata", "--format-version", "1"] + extra
    res = subprocess.run(cmd, cwd=str(repo), capture_output=True, text=True,
                         timeout=timeout_s)
    if res.returncode != 0:
        raise RuntimeError("cargo metadata failed: %s" % res.stderr.strip()[-400:])
    return json.loads(res.stdout)


def relative_to_repo(path: str, repo: Path) -> str:
    """Return `path` relative to the repo root with forward slashes."""
    real_repo = os.path.realpath(str(repo))
    real = os.path.realpath(path)
    rel = os.path.relpath(real, real_repo)
    return Path(rel).as_posix()


def target_kind(kinds: List[str]) -> Optional[str]:
    """Map a cargo target kind list to one of common.TARGET_KINDS (or None)."""
    for kind in ("test", "bench", "bin"):
        if kind in kinds:
            return kind
    if any(k in common.LIB_KINDS for k in kinds):
        return "lib"
    return None


def resolve_edges(metadata: dict, members: Set[str]) -> Set[Tuple[str, str]]:
    """Member-to-member edges taken from a `resolve` section, when present."""
    resolve = metadata.get("resolve")
    if not resolve:
        return set()
    names = {p["id"]: p["name"] for p in metadata["packages"]}
    edges: Set[Tuple[str, str]] = set()
    for node in resolve.get("nodes", []):
        src = names.get(node["id"])
        for dep in node.get("deps", []):
            dst = names.get(dep["pkg"])
            if src in members and dst in members and src != dst:
                edges.add((src, dst))
    return edges


def load_metadata(repo: Path, metadata_file: Optional[Path]) -> dict:
    """Return cargo metadata: from a file, else from cargo (no-deps + resolve)."""
    if metadata_file is not None:
        return json.loads(Path(metadata_file).read_text())
    metadata = run_cargo_metadata(repo, ["--no-deps"], CARGO_TIMEOUT_S)
    try:
        full = run_cargo_metadata(repo, ["--offline"], RESOLVE_TIMEOUT_S)
        metadata["resolve"] = full.get("resolve")
        metadata["packages_resolved"] = full.get("packages", [])
    except (RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        common.log("impact: resolve section skipped (%s)" % str(exc)[:160])
    return metadata


def write_crates(con: sqlite3.Connection, metadata: dict, repo: Path) -> None:
    """Replace crates, crate_deps and test_targets from metadata."""
    for table in ("crates", "crate_deps", "test_targets"):
        con.execute("delete from %s" % table)
    packages = metadata["packages"]
    members = {p["name"] for p in packages}
    edges: Set[Tuple[str, str]] = set()
    for pkg in packages:
        manifest = relative_to_repo(pkg["manifest_path"], repo)
        src_root = Path(manifest).parent.as_posix()
        con.execute("insert into crates values (?,?,?)", (pkg["name"], manifest, src_root))
        for dep in pkg.get("dependencies", []):
            if dep.get("path") and dep["name"] in members and dep["name"] != pkg["name"]:
                edges.add((pkg["name"], dep["name"]))
        for target in pkg.get("targets", []):
            kind = target_kind(target.get("kind", []))
            if kind is None:
                continue
            con.execute("insert or replace into test_targets values (?,?,?,?)",
                        (target["name"], kind, pkg["name"],
                         relative_to_repo(target["src_path"], repo)))
    edges |= resolve_edges(metadata, members)
    con.executemany("insert into crate_deps values (?,?)", sorted(edges))


def write_rules(con: sqlite3.Connection, rules: dict) -> None:
    """Replace path_rules and settings from rules.json."""
    con.execute("delete from path_rules")
    con.execute("delete from settings")
    for rule in rules["rules"]:
        for job in rule["jobs"]:
            con.execute("insert into path_rules values (?,?,?)",
                        (rule["priority"], rule["glob"], job))
    for key in common.SETTING_KEYS:
        con.execute("insert into settings values (?,?)", (key, json.dumps(rules[key])))


def strip_comment_lines(text: str) -> str:
    """Drop whole-line `//` comments (doc comments included) from Rust text."""
    return "\n".join(ln for ln in text.split("\n") if not ln.lstrip().startswith("//"))


def in_string_literal(text: str, index: int) -> bool:
    """True when `index` sits inside a string literal on its own line."""
    line_start = text.rfind("\n", 0, index) + 1
    return len(re.findall(r'(?<!\\)"', text[line_start:index])) % 2 == 1


def balanced_argument(text: str, start: int) -> str:
    """Return the macro argument text from `start` to its matching `)` (stripped)."""
    depth = 1
    pos = start
    while pos < len(text) and depth:
        char = text[pos]
        depth += (char == "(") - (char == ")")
        pos += 1
    return " ".join(text[start:pos - 1].split()) if depth == 0 else text[start:start + 80]


def scan_includes(repo: Path) -> Tuple[Set[str], List[str]]:
    """Return (resolved include targets, unresolved include descriptions).

    Every `include_str!(...)` and `include_bytes!(...)` under src/, tests/ and
    benches/ names a file the compiler reads, so a change to it is a Rust
    change (S3). Targets resolve relative to the including file. A non-literal
    argument, a target that is not a file, or one outside the repository is
    unresolved, which makes the selector treat markdown changes as ALL.
    """
    root = Path(repo).resolve()
    files: Set[str] = set()
    unresolved: List[str] = []
    for top in INCLUDE_SCAN_TOPS:
        for source in sorted((root / top).rglob("*.rs")):
            text = strip_comment_lines(source.read_text(errors="replace"))
            for match in INCLUDE_RE.finditer(text):
                if in_string_literal(text, match.start()):
                    continue
                arg = balanced_argument(text, match.end())
                where = source.relative_to(root).as_posix()
                literal = LITERAL_RE.match(arg)
                manifest = MANIFEST_CONCAT_RE.match(arg)
                if manifest is not None:
                    # CARGO_MANIFEST_DIR of the root package is the repository root.
                    target = (root / manifest.group(1).lstrip("/")).resolve()
                elif literal is not None:
                    target = (source.parent / literal.group(1)).resolve()
                else:
                    unresolved.append("%s: %s" % (where, arg[:80]))
                    continue
                try:
                    rel = target.relative_to(root).as_posix()
                except ValueError:
                    unresolved.append("%s: outside repo %s" % (where, literal.group(1)))
                    continue
                if target.is_file():
                    files.add(rel)
                else:
                    unresolved.append("%s: missing %s" % (where, rel))
    return files, unresolved


def write_includes(con: sqlite3.Connection, repo: Path) -> None:
    """Record the include scan in the settings table."""
    files, unresolved = scan_includes(repo)
    con.execute("insert into settings values (?,?)",
                (common.INCLUDE_FILES_KEY, json.dumps(sorted(files))))
    con.execute("insert into settings values (?,?)",
                (common.INCLUDE_UNRESOLVED_KEY, json.dumps(unresolved)))


def testcase_status(case: ET.Element) -> Tuple[bool, int]:
    """Return (failed, flaky_count) for one JUnit testcase element."""
    failed = any(case.find(tag) is not None for tag in FAILURE_TAGS)
    flaky = sum(len(case.findall(tag)) for tag in FLAKY_TAGS)
    return failed, flaky


def ingest_junit(con: sqlite3.Connection, junit: Path) -> int:
    """Fold a cargo nextest / cargo test JUnit file into the history table."""
    if junit.stat().st_size > MAX_JUNIT_BYTES:
        raise ValueError("junit file larger than %d bytes" % MAX_JUNIT_BYTES)
    root = ET.parse(str(junit)).getroot()
    stats: Dict[str, Dict[str, float]] = {}
    for suite in root.iter("testsuite"):
        target = suite.get("name", "").split("::")[-1]
        if not target:
            continue
        entry = stats.setdefault(target, {"time": 0.0, "failed": 0, "flaky": 0})
        for case in suite.iter("testcase"):
            failed, flaky = testcase_status(case)
            entry["time"] += float(case.get("time", "0") or 0)
            entry["failed"] += 1 if failed else 0
            entry["flaky"] += flaky
    now = int(time.time())
    for target, entry in stats.items():
        previous = con.execute("select flaky_count from history where target=?",
                               (target,)).fetchone()
        flaky_total = int(entry["flaky"]) + (previous[0] if previous else 0)
        con.execute("insert or replace into history values (?,?,?,?,?)",
                    (target, entry["time"], "failed" if entry["failed"] else "passed",
                     flaky_total, now))
    return len(stats)


def import_codegraph(con: sqlite3.Connection, codegraph: Path) -> str:
    """Import files and file-level edges from a codegraph index, read-only."""
    db_path = codegraph if codegraph.is_file() else codegraph / CODEGRAPH_DB_NAME
    if not db_path.is_file():
        common.log("impact: codegraph db not found at %s; skipped" % db_path)
        return "skipped: not found"
    src = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        nodes = {r[1] for r in src.execute("pragma table_info(nodes)")}
        edges = {r[1] for r in src.execute("pragma table_info(edges)")}
        if not (CODEGRAPH_NODE_COLUMNS <= nodes and CODEGRAPH_EDGE_COLUMNS <= edges):
            common.log("impact: codegraph schema differs; skipped (nodes=%s edges=%s)"
                       % (sorted(nodes), sorted(edges)))
            return "skipped: schema differs"
        con.execute("delete from file_symbols")
        con.execute("delete from symbol_edges")
        con.executemany(
            "insert into file_symbols values (?,?,?,?)",
            src.execute("select file_path, id, name, kind from nodes"))
        con.executemany(
            "insert into symbol_edges values (?,?,?)",
            src.execute(
                "select distinct s.file_path, d.file_path, e.kind from edges e "
                "join nodes s on s.id = e.source join nodes d on d.id = e.target "
                "where s.file_path != d.file_path"))
    finally:
        src.close()
    return "imported"


def build_index(repo: Path, db: Path, metadata: Optional[dict] = None,
                rules_path: Optional[Path] = None, junit: Optional[Path] = None,
                codegraph: Optional[Path] = None,
                metadata_file: Optional[Path] = None) -> dict:
    """Create or refresh the index at `db` and return a summary dict."""
    repo = Path(repo)
    db = Path(db)
    db.parent.mkdir(parents=True, exist_ok=True)
    rules = common.load_rules(rules_path)
    if metadata is None:
        metadata = load_metadata(repo, metadata_file)
    con = common.open_db(db)
    summary = {"codegraph": "not requested", "junit_targets": 0}
    try:
        con.execute("delete from schema_version")
        con.execute("insert into schema_version values (?)", (common.SCHEMA_VERSION,))
        write_crates(con, metadata, repo)
        write_rules(con, rules)
        write_includes(con, repo)
        if junit is not None:
            summary["junit_targets"] = ingest_junit(con, Path(junit))
        if codegraph is not None:
            summary["codegraph"] = import_codegraph(con, Path(codegraph))
        con.commit()
        summary["crates"] = con.execute("select count(*) from crates").fetchone()[0]
        summary["targets"] = con.execute("select count(*) from test_targets").fetchone()[0]
    finally:
        con.close()
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--db", required=True, help="impact db file to create or refresh")
    parser.add_argument("--junit", help="cargo nextest / cargo test JUnit file")
    parser.add_argument("--codegraph", help="a .codegraph directory (read-only import)")
    parser.add_argument("--metadata-file", help="cargo metadata JSON instead of running cargo")
    parser.add_argument("--rules", help="alternative rules.json")
    args = parser.parse_args(argv)
    try:
        summary = build_index(
            Path(args.repo), Path(args.db),
            rules_path=Path(args.rules) if args.rules else None,
            junit=Path(args.junit) if args.junit else None,
            codegraph=Path(args.codegraph) if args.codegraph else None,
            metadata_file=Path(args.metadata_file) if args.metadata_file else None)
    except (RuntimeError, ValueError, OSError, sqlite3.Error, ET.ParseError,
            subprocess.TimeoutExpired) as exc:
        common.log("impact: build_index failed: %s" % exc)
        return common.EXIT_FAIL
    print("impact index: %s" % json.dumps(summary, sort_keys=True))
    return common.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
