#!/usr/bin/env python3
"""Source invariant for #6569: no integration-test crate loads a file twice.

`clippy::duplicate_mod` (promoted by `-D clippy::all`) fails the required
"Postgres feature gate" job when one test crate loads the same file through two
`#[path]` declarations. The shape that tripped it: a test file that declares
`mod common;` AND `#[path = "common/X.rs"] mod X;`, while a file under
`tests/common/` also `#[path]`-loads its sibling `X.rs`.

Rules checked here (stdlib only):
  1. A file under tests/common/ never uses `#[path]`; siblings are declared once
     in tests/common/mod.rs.
  2. A top-level tests/*.rs that declares `mod common;` never uses a `#[path]`
     that points inside tests/common/.

Run: python3 -m unittest scripts/ci/tests/test_no_duplicate_mod_6569.py
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TESTS = REPO / 'tests'
PATH_ATTR = re.compile(r'^\s*#\[path\s*=\s*"([^"]+)"\s*\]', re.M)
MOD_COMMON = re.compile(r'^\s*mod\s+common\s*;', re.M)
MOD_DECL = re.compile(r'^\s*(?:pub\s+)?mod\s+([A-Za-z0-9_]+)\s*;', re.M)


def common_loaded_files():
    """Files a crate with `mod common;` already loads: mod.rs children and any
    file a tests/common file pulls in through `#[path]`."""
    out = set()
    common = TESTS / 'common'
    for m in MOD_DECL.finditer((common / 'mod.rs').read_text(encoding='utf-8')):
        out.add((common / (m.group(1) + '.rs')).resolve())
    for f in common.rglob('*.rs'):
        for m in PATH_ATTR.finditer(f.read_text(encoding='utf-8')):
            out.add((f.parent / m.group(1)).resolve())
    return out


class NoDuplicateMod(unittest.TestCase):
    def test_common_files_do_not_path_load_siblings(self):
        bad = []
        for f in sorted((TESTS / 'common').rglob('*.rs')):
            for m in PATH_ATTR.finditer(f.read_text(encoding='utf-8')):
                bad.append(f'{f.relative_to(REPO)}: #[path = "{m.group(1)}"]')
        self.assertEqual(bad, [], 'tests/common files must not #[path]-load siblings; '
                                  'declare them once in tests/common/mod.rs (#6569)')

    def test_users_of_common_do_not_path_load_into_common(self):
        bad = []
        loaded = common_loaded_files()
        for f in sorted(TESTS.glob('*.rs')):
            text = f.read_text(encoding='utf-8')
            if not MOD_COMMON.search(text):
                continue
            for m in PATH_ATTR.finditer(text):
                target = (f.parent / m.group(1)).resolve()
                if target in loaded:
                    bad.append(f'{f.relative_to(REPO)}: #[path = "{m.group(1)}"]')
        self.assertEqual(bad, [], 'a crate that has `mod common;` must reach common files '
                                  'through it, not a second #[path] load (#6569)')


if __name__ == '__main__':
    unittest.main()
