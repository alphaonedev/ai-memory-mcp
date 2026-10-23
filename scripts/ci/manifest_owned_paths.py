#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Map changed paths to the qual_* pin test that owns them (#8050).

A tests/fixtures/*.json manifest inventories repo paths (for example SDK
sources fingerprinted by sha256). Its owning tests/qual_*.rs test references
the manifest through include_str!/include_bytes!. A diff that touches an
inventoried path must run that test; this gate names it. Every string value in
a manifest that resolves to an existing file under --root counts as inventoried,
so a new manifest key cannot bypass the gate.
Exit 0: no inventoried path changed; 1: matches (run the named tests);
2: gate defect (unparseable manifest, manifest without owner, bad root).
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


def norm(path):
    """Normalise a repo-relative path ('./a//b' -> 'a/b')."""
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


def load_inventory(root, manifests_glob, tests_glob):
    """Return {repo path: [(manifest name, owning test stem)]}; raise ValueError on defects."""
    owners = {}
    for test in sorted(root.glob(tests_glob)):
        for name in INCLUDE_RE.findall(test.read_text(encoding="utf-8", errors="replace")):
            owners.setdefault(name, []).append(test.stem)
    inventory = {}
    for manifest in sorted(root.glob(manifests_glob)):
        try:
            doc = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError) as err:
            raise ValueError("unparseable manifest %s: %s" % (manifest.name, err))
        if manifest.name not in owners:
            raise ValueError("manifest %s has no owning qual test" % manifest.name)
        for value in walk_strings(doc):
            rel = norm(value)
            if rel and not rel.startswith("..") and (root / rel).is_file():
                for stem in owners[manifest.name]:
                    inventory.setdefault(rel, []).append((manifest.name, stem))
    return inventory


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--diff-file", help="file with one changed path per line (default: stdin)")
    ap.add_argument("--manifests-glob", default="tests/fixtures/*.json")
    ap.add_argument("--tests-glob", default="tests/qual_*.rs")
    args = ap.parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        print("manifest_owned_paths: root not found: %s" % root, file=sys.stderr)
        return EXIT_DEFECT
    try:
        inventory = load_inventory(root, args.manifests_glob, args.tests_glob)
    except ValueError as err:
        print("manifest_owned_paths: gate defect: %s" % err, file=sys.stderr)
        return EXIT_DEFECT
    text = Path(args.diff_file).read_text(encoding="utf-8") if args.diff_file else sys.stdin.read()
    hits = 0
    for line in text.splitlines():
        path = norm(line) if line.strip() else ""
        for manifest, stem in inventory.get(path, []):
            print("%s  %s  run: cargo test --test %s" % (path, manifest, stem))
            hits += 1
    if hits:
        return EXIT_MATCH
    print("ok")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
