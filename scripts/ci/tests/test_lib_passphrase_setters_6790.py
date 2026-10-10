#!/usr/bin/env python3
"""No in-process DB-passphrase / at-rest setter in the shared lib test binary (#6790).

``db::open`` (``storage::connection::refuse_at_rest_requested_without_sqlcipher``) reads the
passphrase channel -- the ``AI_MEMORY_DB_PASSPHRASE`` variable AND the ``cfg(test)``
process-private passphrase slot that ``--db-passphrase-file`` seeds -- on every open. Hundreds
of lib tests open a database and never take the env lock, so a lib test that WRITES that
channel in the shared process makes a concurrent, unrelated open fail with the sqlcipher
refusal (``macos-fed,sqlite`` shard, run 38015742119). Serialising the writers against each
other (#3539) cannot close the window for readers that do not take the lock.

The rule this cell pins: a ``src/**`` test fn that sets or seeds the channel must run in an
ISOLATED CHILD process (``run_env_isolated_child_or_spawn``), where no other test can observe
it. The ``storage::connection`` env setter additionally lives in their own integration
binary (``tests/db_passphrase_refusal_6790.rs``), the #2146 / ``config_precedence.rs``
precedent.

Run: python3 -m unittest discover -s scripts/ci/tests
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GATE = REPO / "scripts" / "check-env-mutation-lock.py"

CHILD_FN = "run_env_isolated_child_or_spawn"
# Seeds or sets the channel: slot seeders, the guard that resets it, env writers of the variable db::open reads. Matched on the sanitised body (comments and strings blanked).
SEED_RE = re.compile(r"\b(?:set_db_passphrase|DbPassphraseGuard\s*::\s*enter)\s*[(<]")
CAPTURE_RE = re.compile(r"\bcapture\s*\(\s*[\w:]*\bENV_DB_PASSPHRASE\s*\)")
SET_CALL_RE = re.compile(r"\.\s*set\s*\(")
# Literal-name env writers, matched on the raw body.
RAW_SETVAR_RE = re.compile(r"set_var\s*\(\s*\"AI_MEMORY_DB_PASSPHRASE\"")
RAW_FILE_FLAG_RE = re.compile(r"\"--db-passphrase-file\"")
APPLY_RE = re.compile(r"\bapply_startup_env\s*\(")
SETVAR_CONST_RE = re.compile(r"\bset_var\s*\(\s*[\w:]*\bENV_DB_PASSPHRASE\b")

MOVED_SETTERS = ("passphrase_set_on_non_sqlcipher_refuses_open_s1",)
INTEGRATION = REPO / "tests" / "db_passphrase_refusal_6790.rs"


def load_gate():
    spec = importlib.util.spec_from_file_location("env_mutation_lock_gate", GATE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # @dataclass resolves its module through sys.modules
    spec.loader.exec_module(mod)
    return mod


def violations(src_root, gate):
    """[(rel, line, fn)] test fns that set/seed the passphrase channel without a child process."""
    found = []
    for path in sorted(Path(src_root).rglob("*.rs")):
        rel = path.relative_to(REPO).as_posix() if str(path).startswith(str(REPO)) else path.name
        src = path.read_text(encoding="utf-8", errors="replace")
        info = gate.parse_file(rel, src, False)
        for fn in info.fns:
            if not fn.test or fn.end < 0:
                continue
            san = info.san[fn.start:fn.end]
            raw = info.src[fn.start:fn.end]
            seeds = (
                bool(SEED_RE.search(san))
                or (bool(CAPTURE_RE.search(san)) and bool(SET_CALL_RE.search(san)))
                or bool(RAW_SETVAR_RE.search(raw))
                or bool(SETVAR_CONST_RE.search(san))
                or (bool(RAW_FILE_FLAG_RE.search(raw)) and bool(APPLY_RE.search(san)))
            )
            if seeds and not re.search(r"\b%s\s*\(" % CHILD_FN, san):
                found.append((rel, gate.line_of(src, fn.start), fn.name))
    return found


class LibPassphraseSetters6790(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate = load_gate()

    def test_no_unisolated_passphrase_setter_in_lib_tests_6790(self):
        bad = violations(REPO / "src", self.gate)
        self.assertEqual(
            bad,
            [],
            "lib test fns that set or seed the DB-passphrase channel in the shared test process "
            "(wrap the body in run_env_isolated_child_or_spawn or move it to tests/): %r" % bad,
        )

    def test_connection_env_setter_lives_in_own_binary_6790(self):
        conn = (REPO / "src" / "storage" / "connection.rs").read_text(encoding="utf-8")
        for name in MOVED_SETTERS:
            self.assertNotRegex(
                conn, r"\bfn\s+%s\b" % name,
                "%s must live in tests/db_passphrase_refusal_6790.rs (own process), not the lib binary" % name,
            )
        self.assertTrue(INTEGRATION.is_file(), "missing %s" % INTEGRATION)
        body = INTEGRATION.read_text(encoding="utf-8")
        for name in MOVED_SETTERS:
            self.assertRegex(body, r"\bfn\s+%s\b" % name)

    def test_guard_detects_planted_setters_6790(self):
        """Mutation cell: the scan must flag each planted shape and pass the isolated one."""
        import tempfile
        planted = {
            "slot.rs": "#[cfg(test)]\nmod t {\n#[test]\nfn seeds() { let _p = DbPassphraseGuard::enter(&iso); }\n}\n",
            "envguard.rs": "#[cfg(test)]\nmod t {\n#[test]\nfn sets() {\n"
                           "let g = EnvGuard::capture(ENV_DB_PASSPHRASE);\ng.set(\"x\");\n}\n}\n",
            "setvar.rs": "#[cfg(test)]\nmod t {\n#[test]\nfn sets() {\n"
                         "unsafe { std::env::set_var(\"AI_MEMORY_DB_PASSPHRASE\", \"x\") };\n}\n}\n",
            "applyfile.rs": "#[cfg(test)]\nmod t {\n#[test]\nfn boots() {\n"
                            "let a = [\"--db-passphrase-file\", \"p\"];\napply_startup_env(&cli, &cfg);\n}\n}\n",
        }
        isolated = (
            "#[cfg(test)]\nmod t {\n#[test]\nfn ok() {\n"
            "if crate::config::run_env_isolated_child_or_spawn(\"t::ok\") { return; }\n"
            "let _p = DbPassphraseGuard::enter(&iso);\n}\n}\n"
        )
        base = REPO / ".local-runs"
        base.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(base)) as td:
            root = Path(td)
            for name, text in planted.items():
                (root / name).write_text(text, encoding="utf-8")
            (root / "isolated.rs").write_text(isolated, encoding="utf-8")
            got = {Path(r).name for r, _l, _f in violations(root, self.gate)}
        self.assertEqual(got, set(planted), "planted shapes flagged: %r" % sorted(got))


if __name__ == "__main__":
    unittest.main()
