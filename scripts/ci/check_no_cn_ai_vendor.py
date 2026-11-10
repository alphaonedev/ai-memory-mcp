#!/usr/bin/env python3
"""Documentation vendor-name gate: fail when a tracked file names a barred provider.

Scans every tracked text file (git ls-files, or a directory walk when the root
is not a git checkout) for the barred provider and model names in
VENDOR_TERMS_ROT13. The names are stored ROT13-encoded so that this tree
itself stays at zero hits; decode() restores them at run time.

One exception is data, not code: scripts/ci/cn_ai_vendor_allow.json lists the
path prefixes of agent cluster, hive and swarm test material, where a
Flash-qualified model token (family, optional version, then the Flash
qualifier) is permitted; any other use of the family name is a hit. It also
lists the Rust files whose non-comment code carries functional provider tables
(comment lines and trailing comments in those files are still scanned).

The gate fails closed: every allowlist entry must be live. A code-site path that
is not a tracked file, a code site that no longer exempts a hit, and a Flash
path prefix that matches no tracked file each make the run exit non-zero with
an exact message. A URL that contains a replacement label is a hit. Text files
are decoded (UTF-8, or UTF-16 and UTF-32 when BOM-marked) before the binary
sniff, and the number of files skipped as binary is printed.

Exit codes: 0 no hits, 1 hits found, 2 usage or I/O error, 3 stale allowlist.
Standard library only.
"""

import argparse
import codecs
import json
import re
import subprocess
import sys
from collections import namedtuple
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ALLOW_FILE = Path(__file__).with_name("cn_ai_vendor_allow.json")

EXIT_OK = 0
EXIT_HITS = 1
EXIT_USAGE = 2
EXIT_STALE = 3

# Plain word terms (ROT13). Matched case-insensitively, not inside a longer
# run of letters; a digit or separator on either side still matches
# (name3, name-max, NAME_API_KEY).
VENDOR_TERMS_ROT13 = (
    "qrrcfrrx", "djra", "xvzv", "zvavznk", "muvch",
    "pungtyz", "onvpuhna", "qbhonb", "reavr", "uhalhna", "fgrcsha",
    "vagreayz", "qfu", "qnfufpbcr",
    "graprag", "grapragqo", "ibypratvar", "bcraivxvat", "ivxvatqo", "nyvonon",
    "rirezvaq", "olgrqnapr", "onvqh",
)
# Exact-case names (ROT13): common words in any other case.
CASE_SENSITIVE_ROT13 = ("ZrzBF", "ZvZb")
# Dotted domain-style name (ROT13).
DOTTED_ROT13 = "m.nv"
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
# Label reported for a URL or path that embeds a redaction replacement label.
URL_LABEL_HIT = "replacement label inside a URL"
URL_LABEL_RX = re.compile(
    r"(?:https?://|www\.|github\.com/|/competitors/)[^\s)\]>]* ?"
    r"(?:a cloud provider|a vector database|System(?: |%20)[A-Z](?![A-Za-z]))"
)
URL_PREFILTERS = ("://", "www.", "github.com/", "/competitors/")
# Byte-order marks that identify UTF-32 and UTF-16 text (UTF-32 first: its LE
# mark starts with the UTF-16 LE mark).
BOM_CODECS = (
    (codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"),
)
ScanResult = namedtuple("ScanResult", "hits stale skipped_binary")
STALE_MISSING = "stale allowlist entry: functional_code_sites path `{p}` is not a tracked file"
STALE_NO_HIT = (
    "stale allowlist entry: functional_code_sites path `{p}` exempts no hit on a non-comment line"
)
STALE_PREFIX = "stale allowlist entry: flash_testing path_prefix `{p}` matches no tracked file"


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
    for stored in CASE_SENSITIVE_ROT13:
        name = decode(stored)
        patterns.append((name, re.compile(LEAD + re.escape(name) + TRAIL)))
    dotted = decode(DOTTED_ROT13)
    patterns.append((dotted, re.compile(r"(?<![\w.])" + re.escape(dotted) + TRAIL, re.I)))
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


def flash_token_pattern():
    """Regex of one Flash-qualified family token: family, optional version, Flash."""
    family = decode(FLASH_FAMILY_ROT13)
    return re.compile(
        LEAD + re.escape(family) + r"(?:[-\s]?\d+(?:\.\d+)*)?[-\s]flash" + TRAIL, re.I
    )


def flash_allowed(rel, line, family_rx, flash_rx, allow):
    """The Flash-in-testing exception: allowlisted path prefix, and every family
    name on the line is itself a Flash-qualified token."""
    spec = allow.get("flash_testing", {})
    if not any(rel.startswith(p) for p in spec.get("path_prefixes", [])):
        return False
    return all(flash_rx.match(line, m.start()) for m in family_rx.finditer(line))


def rust_trailing_comment(line):
    """Text of a trailing // or /* comment that starts outside a string or char literal."""
    in_string = False
    i = 0
    size = len(line)
    while i < size:
        char = line[i]
        if in_string:
            if char == "\\":
                i += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "'":
            if i + 2 < size and line[i + 1] != "\\" and line[i + 2] == "'":
                i += 3
                continue
            if i + 3 < size and line[i + 1] == "\\" and line[i + 3] == "'":
                i += 4
                continue
        elif line.startswith(("//", "/*"), i):
            return line[i + 2:]
        i += 1
    return ""


def url_label_hit(line):
    """True when a URL or competitor path on the line embeds a replacement label."""
    if not any(token in line for token in URL_PREFILTERS):
        return False
    return bool(URL_LABEL_RX.search(line))


def scan_text(rel, text, patterns, allow, used=None):
    """Yield (line_number, label) for every disallowed hit in one file.

    `used`, when given, is a set that receives rel when a functional code site
    exempted at least one hit on a non-comment line.
    """
    family = decode(FLASH_FAMILY_ROT13)
    family_rx = re.compile(LEAD + re.escape(family) + TRAIL, re.I)
    flash_rx = flash_token_pattern()
    code_paths = {s["path"] for s in allow.get("functional_code_sites", [])}
    rust_code_ok = rel in code_paths and rel.endswith(RUST_SUFFIX)
    low = text.lower()
    live = [(label, rx) for label, rx in patterns if label.lower() in low]
    for number, line in enumerate(text.split("\n"), 1):
        if url_label_hit(line):
            yield number, URL_LABEL_HIT
        code_line = rust_code_ok and not is_comment_line(line)
        trailing = rust_trailing_comment(line) if code_line else ""
        for label, rx in live:
            if not rx.search(line):
                continue
            if label == family and flash_allowed(rel, line, family_rx, flash_rx, allow):
                continue
            if code_line:
                if trailing and rx.search(trailing):
                    yield number, label
                elif used is not None:
                    used.add(rel)
                continue
            yield number, label


def decode_text(data):
    """Return decoded text, or None for binary data (a NUL early with no UTF-16/32 mark)."""
    for mark, codec in BOM_CODECS:
        if data.startswith(mark):
            return data.decode(codec, "replace")
    if b"\0" in data[:BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8", "replace")


def stale_entries(allow, files, used):
    """Messages for every allowlist entry that exempts nothing."""
    tracked = set(files)
    stale = []
    for site in allow.get("functional_code_sites", []):
        path = site["path"]
        if path not in tracked:
            stale.append(STALE_MISSING.format(p=path))
        elif path not in used:
            stale.append(STALE_NO_HIT.format(p=path))
    for prefix in allow.get("flash_testing", {}).get("path_prefixes", []):
        if not any(name.startswith(prefix) for name in tracked):
            stale.append(STALE_PREFIX.format(p=prefix))
    return stale


def run_scan(root, allow):
    """Scan the tree; return ScanResult(hits, stale, skipped_binary)."""
    patterns = build_patterns()
    hits = []
    used = set()
    skipped = 0
    files = list_files(root)
    for rel in files:
        text = decode_text((root / rel).read_bytes())
        if text is None:
            skipped += 1
            continue
        for number, label in scan_text(rel, text, patterns, allow, used):
            hits.append((rel, number, label))
    return ScanResult(hits, stale_entries(allow, files, used), skipped)


def scan_root(root, allow):
    """Return a list of (path, line, label) hits under root."""
    return run_scan(root, allow).hits


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--allow-file", type=Path, default=DEFAULT_ALLOW_FILE)
    parser.add_argument("--count-only", action="store_true", help="print only the hit count")
    args = parser.parse_args(argv)
    try:
        allow = load_allow(args.allow_file)
        result = run_scan(args.root.resolve(), allow)
    except (OSError, ValueError) as err:
        print(f"check_no_cn_ai_vendor: {err}", file=sys.stderr)
        return EXIT_USAGE
    hits = result.hits
    if not args.count_only:
        for rel, number, label in hits:
            print(f"{rel}:{number}: barred name `{label}`")
    for message in result.stale:
        print(message, file=sys.stderr)
    print(f"skipped binary: {result.skipped_binary}")
    print(f"hits: {len(hits)}")
    if hits:
        return EXIT_HITS
    return EXIT_STALE if result.stale else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
