"""Shared constants and helpers for the impact-selection scripts (#8240)."""
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Dict, List, Optional, Pattern

IMPACT_DIR = Path(__file__).resolve().parent
RULES_PATH = IMPACT_DIR / "rules.json"
SCHEMA_VERSION = 1
ALL_KEY = "ALL"
EVENT_PULL_REQUEST = "pull_request"
EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
RUST_KEY = "rust"
CELLS_KEY = "cells"
FAIL_CLOSED_INDEX = "index-unavailable"
FAIL_CLOSED_DIFF = "diff-unavailable"
FAIL_CLOSED_EMPTY = "empty-diff-fail-closed"
REASON_UNCLASSIFIED = "unclassified"
REASON_KEY = "*"
TARGET_KINDS = ("test", "bench", "bin", "lib")
LIB_KINDS = ("lib", "rlib", "cdylib", "dylib", "staticlib", "proc-macro")
SETTING_KEYS = ("known_jobs", "always_on", "force_all_base_prefixes",
                "force_all_base_names", "cell_crates", "cell_globs")

SCHEMA_SQL = """
create table if not exists schema_version (version integer not null);
create table if not exists settings (key text primary key, value text not null);
create table if not exists crates (
    name text primary key, manifest_path text not null, src_root text not null);
create table if not exists crate_deps (
    crate text not null, dep text not null, primary key (crate, dep));
create table if not exists test_targets (
    name text not null, kind text not null, crate text not null,
    path text not null, primary key (name, kind, crate));
create table if not exists path_rules (
    priority integer not null, glob text not null, job_key text not null);
create table if not exists history (
    target text primary key, duration_s real, last_result text,
    flaky_count integer not null default 0, updated_at integer not null);
create table if not exists file_symbols (
    file_path text not null, symbol_id text not null, name text, kind text);
create table if not exists symbol_edges (
    src_file text not null, dst_file text not null, kind text);
"""


def log(message: str) -> None:
    """Write one diagnostic line to stderr (never to a GitHub output file)."""
    print(message, file=sys.stderr)


def glob_to_regex(glob: str) -> Pattern:
    """Translate a path glob to a full-match regex.

    `**/` matches zero or more directories, `**` matches anything, `*`
    matches within one path segment and `?` matches one non-slash character.
    """
    out: List[str] = []
    i = 0
    while i < len(glob):
        ch = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def match_glob(glob: str, path: str) -> bool:
    """Return True when `path` matches `glob`."""
    return glob_to_regex(glob).match(path) is not None


def load_rules(path: Optional[Path] = None) -> dict:
    """Load and sanity-check rules.json."""
    rules = json.loads(Path(path or RULES_PATH).read_text())
    known = set(rules["known_jobs"])
    priorities = [r["priority"] for r in rules["rules"]]
    if len(priorities) != len(set(priorities)):
        raise ValueError("duplicate rule priority in rules.json")
    for rule in rules["rules"]:
        bad = set(rule["jobs"]) - known - {ALL_KEY}
        if bad:
            raise ValueError("rule %s names unknown job keys %s"
                             % (rule["glob"], sorted(bad)))
    return rules


def open_db(path: Path) -> sqlite3.Connection:
    """Open (creating when absent) the impact db in WAL mode with the schema."""
    con = sqlite3.connect(str(path))
    con.execute("pragma journal_mode=wal")
    con.executescript(SCHEMA_SQL)
    return con


def open_existing_db(path: Path) -> sqlite3.Connection:
    """Open an existing impact db; raise FileNotFoundError when it is absent."""
    if not Path(path).is_file():
        raise FileNotFoundError("impact db not found: %s" % path)
    con = sqlite3.connect(str(path))
    version = con.execute("select version from schema_version").fetchone()
    if not version or version[0] != SCHEMA_VERSION:
        con.close()
        raise ValueError("impact db schema version mismatch")
    return con


def load_settings(con: sqlite3.Connection) -> Dict[str, object]:
    """Return the settings table decoded from JSON."""
    return {k: json.loads(v) for k, v in con.execute("select key, value from settings")}
