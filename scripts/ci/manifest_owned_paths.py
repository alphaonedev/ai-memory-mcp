#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Map changed paths to the qual_* pin test that owns them (#8050).

A tests/fixtures/**/*.json manifest inventories repo paths (for example SDK
sources fingerprinted by sha256). Its owning tests/qual_*.rs test references
the manifest through include_str!/include_bytes!. A diff that touches an
inventoried path must run that test; this gate names it.

decision: inventory every manifest string over a path-shape filter because r1
and r2 each found paths the filter let through (52e10527).

Every string value found anywhere in a manifest is inventoried, normalised (a
leading ./ or / and a trailing / are stripped, // collapses), whether or not the
path exists today. A changed path matches an inventoried string when it equals
it or starts with it plus "/" (so a folder entry covers its children, with or
without a trailing slash and even after the folder is deleted). Matching is
exact string equality or folder prefix, so an over-inventoried string such as a
sha256 or a word cannot match a real diff path. A manifest file is inventoried
by its own owning test. Manifests are enumerated with os.walk and a raising
onerror, so an unreadable fixtures folder is a gate defect, never "ok".
Exit 0: no inventoried path changed; 1: matches (run the named tests);
2: gate defect (unparseable manifest, manifest without owner, bad root, any
internal error), printed as one line `gate defect: <reason>`.
"""

import argparse
import json
import os
from pathlib import Path
import posixpath
import re
import sys

EXIT_OK = 0  # no changed path is inventoried
EXIT_MATCH = 1  # a changed path is inventoried; run the owning test
EXIT_DEFECT = 2  # gate defect: fail closed
INCLUDE_RE = re.compile(r'include_(?:str|bytes)!\(\s*"fixtures/([^"]+)"\s*\)')
FIXTURES_DIR = "tests/fixtures"  # include_str!("fixtures/<key>") is relative to tests/
GLOB_CHARS = "*?["


def norm(path):
    """Normalise a repo-relative path ('./a//b/' -> 'a/b', '/a' -> 'a')."""
    return posixpath.normpath(path.strip().replace("\\", "/")).lstrip("/")


def walk_strings(node):
    """Yield every string value in a parsed JSON document."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for item in node:
            yield from walk_strings(item)
    elif isinstance(node, dict):
        for item in node.values():
            yield from walk_strings(item)


def add_entry(inventory, rel, owner):
    """Record that `rel` is owned by (manifest, test stem)."""
    owners = inventory.setdefault(rel, [])
    if owner not in owners:
        owners.append(owner)


def raise_walk_error(err):
    """os.walk onerror hook: an unreadable folder is a gate defect."""
    raise err


def glob_regex(pattern):
    """Translate a repo-relative glob ('**/' spans folders; '*' and '?' stay in one segment)."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile("^" + out + "$")


def find_files(root, pattern):
    """Return sorted files under root matching the glob; read errors raise (fail closed)."""
    fixed = []
    for part in pattern.split("/")[:-1]:
        if any(ch in part for ch in GLOB_CHARS):
            break
        fixed.append(part)
    base = root.joinpath(*fixed)
    if not base.is_dir():
        return []
    regex = glob_regex(pattern)
    found = []
    for folder, _dirs, names in os.walk(str(base), onerror=raise_walk_error):
        for name in names:
            path = Path(folder) / name
            if regex.match(path.relative_to(root).as_posix()):
                found.append(path)
    return sorted(found)


def load_inventory(root, manifests_glob, tests_glob):
    """Return {path: [(manifest, test stem)]}; raise ValueError on defects."""
    owners = {}
    for test in find_files(root, tests_glob):
        for name in INCLUDE_RE.findall(test.read_text(encoding="utf-8", errors="replace")):
            owners.setdefault(name, []).append(test.stem)
    fixtures = root / FIXTURES_DIR
    inventory = {}
    for manifest in find_files(root, manifests_glob):
        try:
            key = manifest.relative_to(fixtures).as_posix()
        except ValueError:
            key = manifest.name
        try:
            doc = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError) as err:
            raise ValueError("unparseable manifest %s: %s" % (key, err))
        if key not in owners:
            raise ValueError("manifest %s has no owning qual test" % key)
        for stem in owners[key]:
            add_entry(inventory, manifest.relative_to(root).as_posix(), (key, stem))
        for value in walk_strings(doc):
            rel = norm(value)
            if rel and rel != "." and not rel.startswith(".."):
                for stem in owners[key]:
                    add_entry(inventory, rel, (key, stem))
    return inventory


def read_diff(path):
    """Read the changed-path list (file or stdin) as UTF-8, dropping a BOM."""
    data = Path(path).read_bytes() if path else sys.stdin.buffer.read()
    return data.decode("utf-8-sig")


def owners_of(inventory, path):
    """Return the owners of every inventoried string equal to `path` or a folder prefix of it."""
    found = []
    for rel, entry in inventory.items():
        if path == rel or path.startswith(rel + "/"):
            found.extend(o for o in entry if o not in found)
    return found


def run(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--diff-file", help="file with one changed path per line (default: stdin)")
    ap.add_argument("--manifests-glob", default="tests/fixtures/**/*.json")
    ap.add_argument("--tests-glob", default="tests/qual_*.rs")
    args = ap.parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        raise ValueError("root not found: %s" % root)
    inventory = load_inventory(root, args.manifests_glob, args.tests_glob)
    hits = 0
    for line in read_diff(args.diff_file).splitlines():
        path = norm(line) if line.strip() else ""
        for manifest, stem in owners_of(inventory, path) if path else []:
            print("%s  %s  run: cargo test --test %s" % (path, manifest, stem))
            hits += 1
    if hits:
        return EXIT_MATCH
    print("ok")
    return EXIT_OK


def main(argv=None):
    """Run the gate; every internal error is a one-line gate defect (exit 2)."""
    try:
        return run(argv)
    except Exception as err:  # fail closed: any failure is a gate defect, never a pass
        reason = " ".join(str(err).split()) or type(err).__name__
        print("gate defect: %s" % reason, file=sys.stderr)
        return EXIT_DEFECT


if __name__ == "__main__":
    sys.exit(main())
