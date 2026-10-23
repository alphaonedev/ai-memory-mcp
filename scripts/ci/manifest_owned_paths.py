#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Map changed paths to the qual_* pin test that owns them (#8050).

A tests/fixtures/**/*.json manifest inventories repo paths (for example SDK
sources fingerprinted by sha256). Its owning tests/qual_*.rs test references
the manifest through include_str!/include_bytes!. A diff that touches an
inventoried path must run that test; this gate names it. Every path-shaped
string in a manifest counts as inventoried whether or not the file exists
today (a deleted or renamed pinned file must still name its test), a directory
string covers everything beneath it, and the manifest file itself is
inventoried by its own owning test. Strings that are not path-shaped are
ignored (see PATH_SHAPED_RE), so a new manifest key cannot bypass the gate.
Exit 0: no inventoried path changed; 1: matches (run the named tests);
2: gate defect (unparseable manifest, manifest without owner, bad root, any
internal error), printed as one line `gate defect: <reason>`.
"""

import argparse
import json
from pathlib import Path
import posixpath
import re
import sys

EXIT_OK = 0  # no changed path is inventoried
EXIT_MATCH = 1  # a changed path is inventoried; run the owning test
EXIT_DEFECT = 2  # gate defect: fail closed
INCLUDE_RE = re.compile(r'include_(?:str|bytes)!\(\s*"fixtures/([^"]+)"\s*\)')
FIXTURES_DIR = "tests/fixtures"  # include_str!("fixtures/<key>") is relative to tests/
SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
EXTENSION_RE = re.compile(r"\.[A-Za-z][A-Za-z0-9]{0,7}$")
PATH_SHAPED_RULE = "no URL scheme, not absolute, contains '/' or ends in a file extension"
"""Name of the path-shaped heuristic applied by is_path_shaped.

A manifest string is treated as a repo path when it has no URL scheme, is not
absolute, has no NUL, and either contains a '/' or ends in a file extension (a
dot then a letter). Bare words and hex digests are not paths. The rule errs
towards inventorying: an extra entry costs one extra test run, a missing entry
lets a pinned file change unguarded.
"""


def norm(path):
    """Normalise a repo-relative path ('./a//b' -> 'a/b')."""
    return posixpath.normpath(path.strip().replace("\\", "/")).lstrip("/")


def is_path_shaped(value):
    """Return True when a manifest string looks like a repo-relative path (fail closed)."""
    text = value.strip().replace("\\", "/")
    if not text or "\x00" in text or text.startswith("/") or SCHEME_RE.match(text):
        return False
    return "/" in text or EXTENSION_RE.search(text) is not None


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


def add_entry(inventory, rel, is_dir, owner):
    """Record that `rel` (a directory when is_dir) is owned by (manifest, test)."""
    entry = inventory.setdefault(rel, {"dir": False, "owners": []})
    entry["dir"] = entry["dir"] or is_dir
    if owner not in entry["owners"]:
        entry["owners"].append(owner)


def load_inventory(root, manifests_glob, tests_glob):
    """Return {path: {"dir": bool, "owners": [(manifest, test stem)]}}; ValueError on defects."""
    owners = {}
    for test in sorted(root.glob(tests_glob)):
        for name in INCLUDE_RE.findall(test.read_text(encoding="utf-8", errors="replace")):
            owners.setdefault(name, []).append(test.stem)
    fixtures = root / FIXTURES_DIR
    inventory = {}
    for manifest in sorted(root.glob(manifests_glob)):
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
            add_entry(inventory, manifest.relative_to(root).as_posix(), False, (key, stem))
        for value in walk_strings(doc):
            rel = norm(value) if is_path_shaped(value) else ""
            if rel and rel != "." and not rel.startswith(".."):
                is_dir = value.strip().endswith(("/", "\\")) or (root / rel).is_dir()
                for stem in owners[key]:
                    add_entry(inventory, rel, is_dir, (key, stem))
    return inventory


def read_diff(path):
    """Read the changed-path list (file or stdin) as UTF-8, dropping a BOM."""
    data = Path(path).read_bytes() if path else sys.stdin.buffer.read()
    return data.decode("utf-8-sig")


def owners_of(inventory, path):
    """Return the owners whose entry equals `path` or, for a directory, contains it."""
    found = []
    for rel, entry in inventory.items():
        if path == rel or (entry["dir"] and path.startswith(rel + "/")):
            found.extend(o for o in entry["owners"] if o not in found)
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
