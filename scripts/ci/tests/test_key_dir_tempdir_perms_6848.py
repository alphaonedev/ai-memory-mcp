#!/usr/bin/env python3
"""Key-directory tempdirs in integration tests must ask for mode 0700 (#6848).

``keypair::save`` refuses a key directory that is group- or world-writable (#3198 posture).
``tempfile`` creates directories with ``0o777 & !umask`` unless ``Builder::permissions`` is
given, so a test that hands a bare ``tempfile::tempdir()`` to ``keypair::save`` passes only
under umask 022 (CI) and fails under umask 002 (many Linux accounts, f2): the test relied on
the ambient umask instead of asking for the mode.

The scan: in ``tests/**/*.rs``, a tempdir binding (``tempfile::tempdir()``,
``TempDir::new()``, ``Builder::new()...tempdir()``) that is passed -- directly via
``.path()`` or through a ``let d = x.path();`` alias, in the same fn -- as the key directory
of ``keypair::save`` must carry ``.permissions(..)`` in its initializer, or be chmod-ed
(``set_permissions`` / ``from_mode``) between the binding and the save.

Run: python3 -m unittest discover -s scripts/ci/tests
"""
import re
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

BIND = re.compile(
    r"let\s+(?:mut\s+)?(\w+)\s*=\s*(tempfile::(?:tempdir\s*\(\s*\)|TempDir::new\s*\(\s*\)"
    r"|Builder::new\(\)[^;]*?\.tempdir\s*\(\s*\))[^;]*);",
    re.S,
)
SAVE = re.compile(r"keypair::save\s*\(\s*&?[\w.]+\s*,\s*&?(\w+)(\.path\(\))?")
ALIAS = re.compile(r"let\s+(\w+)\s*=\s*&?(\w+)\.path\(\)\s*(?:\.to_path_buf\(\))?\s*;")
FN_BOUNDARY = re.compile(r"\n\s*(?:pub\s+)?(?:async\s+)?fn\s")


def violations(root):
    """[(path, binding line, name)] key-dir tempdirs created without an explicit mode."""
    out = []
    for path in sorted(Path(root).rglob("*.rs")):
        s = path.read_text(encoding="utf-8", errors="replace")
        for m in SAVE.finditer(s):
            pre = s[: m.start()]
            tgt = m.group(1)
            aliases = [a for a in ALIAS.finditer(pre) if a.group(1) == tgt]
            if aliases:
                tgt = aliases[-1].group(2)
            elif not m.group(2):
                continue
            binds = [b for b in BIND.finditer(pre) if b.group(1) == tgt]
            if not binds:
                continue
            b = binds[-1]
            if FN_BOUNDARY.search(s[b.end() : m.start()]):
                continue
            if "permissions(" in b.group(0):
                continue
            if re.search(r"set_permissions|from_mode", s[b.end() : m.start()]):
                continue
            out.append((path.as_posix(), s.count("\n", 0, b.start()) + 1, tgt))
    return sorted(set(out))


class KeyDirTempdirPerms6848(unittest.TestCase):
    def test_no_umask_dependent_key_dir_tempdir_6848(self):
        bad = [(Path(p).relative_to(REPO).as_posix(), ln, n) for p, ln, n in violations(REPO / "tests")]
        self.assertEqual(
            bad,
            [],
            "key-dir tempdirs created with the ambient umask (add .permissions(0o700), #6848): %r" % bad,
        )

    def test_scan_flags_planted_shapes_6848(self):
        planted = {
            "a.rs": 'fn t() {\n let d = tempfile::tempdir().expect("d");\n keypair::save(&k, d.path()).unwrap();\n}\n',
            "b.rs": 'fn t() {\n let d = tempfile::TempDir::new().unwrap();\n let p = d.path();\n keypair::save(&k, p).unwrap();\n}\n',
            "c.rs": 'fn t() {\n let d = tempfile::Builder::new().prefix("k-").tempdir().unwrap();\n keypair::save(&k, d.path()).unwrap();\n}\n',
        }
        ok = {
            "ok1.rs": 'fn t() {\n let d = tempfile::Builder::new().permissions(P).tempdir().unwrap();\n keypair::save(&k, d.path()).unwrap();\n}\n',
            "ok2.rs": 'fn t() {\n let d = tempfile::tempdir().unwrap();\n std::fs::set_permissions(d.path(), P).unwrap();\n keypair::save(&k, d.path()).unwrap();\n}\n',
        }
        base = REPO / ".local-runs"
        base.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(base)) as td:
            root = Path(td)
            for name, text in {**planted, **ok}.items():
                (root / name).write_text(text, encoding="utf-8")
            got = {Path(p).name for p, _l, _n in violations(root)}
        self.assertEqual(got, set(planted))


if __name__ == "__main__":
    unittest.main()
