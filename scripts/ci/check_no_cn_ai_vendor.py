#!/usr/bin/env python3
"""Documentation vendor-name gate: fail when a tracked file names a barred provider.

Scans every tracked text file (git ls-files, or a directory walk when the root
is not a git checkout) for the barred provider and model names in
VENDOR_TERMS_ROT13. The names are stored ROT13-encoded so that this tree
itself stays at zero hits; decode() restores them at run time.

One exception is data, not code: scripts/ci/cn_ai_vendor_allow.json lists the
Flash model in agent cluster, hive and swarm testing (path prefixes plus a line
context regex) and the Rust files whose non-comment lines carry functional
provider tables (comment lines in those files are still scanned).

Exit codes: 0 no hits, 1 hits found, 2 usage or I/O error.
Standard library only.
"""

import argparse
import codecs
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ALLOW_FILE = Path(__file__).with_name("cn_ai_vendor_allow.json")

EXIT_OK = 0
EXIT_HITS = 1
EXIT_USAGE = 2

# Plain word terms (ROT13). Matched case-insensitively, not inside a longer
# run of letters; a digit or separator on either side still matches
# (name3, name-max, NAME_API_KEY).
VENDOR_TERMS_ROT13 = (
    "qrrcfrrx", "djra", "xvzv", "zvavznk", "muvch",
    "pungtyz", "onvpuhna", "qbhonb", "reavr", "uhalhna", "fgrcsha",
    "vagreayz", "qfu", "qnfufpbcr",
)
# The one family with an allowlisted testing exception (ROT13).
FLASH_FAMILY_ROT13 = "tyz"
# Patterns that need more than a bare word (ROT13 fragments).
SUFFIXED_ROT13 = "zbbafubg"
SUFFIXED_PATTERN = r"(?:\s+ai\b|_api|-v\d|\.cn)"
ZERO_ONE_AI_ROT13 = "01.nv"
YI_LARGE_ROT13 = "lv-ynetr"

LEAD = r"(?<![A-Za-z0-9])"
TRAIL = r"(?![A-Za-z])"
BINARY_SNIFF_BYTES = 8192
SKIP_DIRS = frozenset((".git", "target", "node_modules", ".local-runs"))
COMMENT_PREFIXES = ("//", "/*", "*")
RUST_SUFFIX = ".rs"


def decode(text):
    """ROT13-decode one stored term."""
    return codecs.decode(text, "rot13")


def build_patterns():
    """Return a list of (label, compiled regex) for every barred name.

    The label is also the lowercase literal used as a cheap substring prefilter.
    """
    patterns = []
    for stored in VENDOR_TERMS_ROT13:
        term = decode(stored)
        patterns.append((term, re.compile(LEAD + re.escape(term) + TRAIL, re.I)))
    family = decode(FLASH_FAMILY_ROT13)
    patterns.append((family, re.compile(LEAD + re.escape(family) + TRAIL, re.I)))
    moon = decode(SUFFIXED_ROT13)
    patterns.append((moon, re.compile(LEAD + moon + SUFFIXED_PATTERN, re.I)))
    zero = decode(ZERO_ONE_AI_ROT13)
    patterns.append((zero, re.compile(r"(?<![\w.])" + re.escape(zero) + TRAIL, re.I)))
    yi = decode(YI_LARGE_ROT13)
    patterns.append((yi, re.compile(LEAD + re.escape(yi) + TRAIL, re.I)))
    return patterns


def load_allow(path):
    """Load the allowlist JSON; a missing file is a usage error."""
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def list_files(root):
    """Tracked files via git, else a directory walk. Returns relative posix paths."""
    try:
        done = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True, check=True,
        )
        names = [n for n in done.stdout.decode("utf-8", "replace").split("\0") if n]
        if names:
            return sorted(n for n in names if (root / n).is_file())
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    found = []
    stack = [root]
    while stack:
        here = stack.pop()
        for entry in here.iterdir():
            if entry.is_dir():
                if entry.name not in SKIP_DIRS:
                    stack.append(entry)
            elif entry.is_file():
                found.append(entry.relative_to(root).as_posix())
    return sorted(found)


def is_comment_line(line):
    """True for a Rust line comment or block comment line."""
    return line.lstrip().startswith(COMMENT_PREFIXES)


def flash_allowed(rel, line, allow):
    """The Flash-in-testing exception: allowlisted path prefix and line context."""
    spec = allow.get("flash_testing", {})
    if not any(rel.startswith(p) for p in spec.get("path_prefixes", [])):
        return False
    context = spec.get("line_context_regex")
    # A path prefix scopes the exception; the context regex must also hold on
    # lines of files that are not wholly testing assets.
    if rel.startswith("sdk/python/swarm/") or rel.startswith("infra/do-hive/"):
        return True
    return bool(context and re.search(context, line, re.I))


def scan_text(rel, text, patterns, allow):
    """Yield (line_number, label) for every disallowed hit in one file."""
    family = decode(FLASH_FAMILY_ROT13)
    code_paths = {s["path"] for s in allow.get("functional_code_sites", [])}
    rust_code_ok = rel in code_paths and rel.endswith(RUST_SUFFIX)
    low = text.lower()
    live = [(label, rx) for label, rx in patterns if label.lower() in low]
    if not live:
        return
    for number, line in enumerate(text.split("\n"), 1):
        for label, rx in live:
            if not rx.search(line):
                continue
            if label == family and flash_allowed(rel, line, allow):
                continue
            if rust_code_ok and not is_comment_line(line):
                continue
            yield number, label


def scan_root(root, allow):
    """Return a list of (path, line, label) hits under root."""
    patterns = build_patterns()
    hits = []
    for rel in list_files(root):
        data = (root / rel).read_bytes()
        if b"\0" in data[:BINARY_SNIFF_BYTES]:
            continue
        text = data.decode("utf-8", "replace")
        for number, label in scan_text(rel, text, patterns, allow):
            hits.append((rel, number, label))
    return hits


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--allow-file", type=Path, default=DEFAULT_ALLOW_FILE)
    parser.add_argument("--count-only", action="store_true", help="print only the hit count")
    args = parser.parse_args(argv)
    try:
        allow = load_allow(args.allow_file)
        hits = scan_root(args.root.resolve(), allow)
    except (OSError, ValueError) as err:
        print(f"check_no_cn_ai_vendor: {err}", file=sys.stderr)
        return EXIT_USAGE
    if not args.count_only:
        for rel, number, label in hits:
            print(f"{rel}:{number}: barred name `{label}`")
    print(f"hits: {len(hits)}")
    return EXIT_HITS if hits else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
