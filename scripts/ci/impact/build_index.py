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
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from impact import common  # noqa: E402

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
