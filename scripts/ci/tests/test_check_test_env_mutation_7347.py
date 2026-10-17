#!/usr/bin/env python3
"""Unit tests for scripts/check-test-env-mutation.py (#7347).

Run: python3 -m unittest scripts/ci/tests/test_check_test_env_mutation_7347.py

Each rule is proven twice: a clean fixture passes and a mutant that breaks exactly that rule
fails. Fixtures are built in a scratch dir under .local-runs/ (never /tmp).
"""
import importlib.util
import shutil
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GATE = REPO / "scripts" / "check-test-env-mutation.py"
SPEC = importlib.util.spec_from_file_location("check_test_env_mutation", GATE)
gate = importlib.util.module_from_spec(SPEC)
sys.modules["check_test_env_mutation"] = gate
SPEC.loader.exec_module(gate)

SCRATCH = REPO / ".local-runs" / "env-mutation-gate-7347"

WRITER = """
use tokio::sync::Mutex;
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

#[tokio::test]
async fn writer() {
    let _lock = ENV_LOCK.lock().await;
    unsafe { std::env::set_var("A", "1") };
}
"""
LOCKED_READER = """
#[test]
fn reader() {
    let _lock = ENV_LOCK.blocking_lock();
    let _ = std::env::var("A");
}
"""
UNLOCKED_READER = """
#[test]
fn reader() {
    let _ = std::env::var("A");
}
"""


class Fixture(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        (SCRATCH / "tests").mkdir(parents=True)
        self.addCleanup(shutil.rmtree, SCRATCH, True)

    def put(self, name, text):
        (SCRATCH / "tests" / name).write_text(text)

    def scan(self):
        return gate.scan_tree(SCRATCH)


class ScanRules(Fixture):
    def test_locked_reader_passes(self):
        self.put("a.rs", WRITER + LOCKED_READER)
        self.assertEqual(self.scan(), {})

    def test_unlocked_reader_is_flagged(self):
        # The #7347 shape: locked writer, unlocked reader in the same file.
        self.put("a.rs", WRITER + UNLOCKED_READER)
        self.assertEqual(self.scan(), {"tests/a.rs": 1})

    def test_file_without_env_mutation_is_ignored(self):
        self.put("a.rs", UNLOCKED_READER)
        self.assertEqual(self.scan(), {})

    def test_process_isolated_marker_exempts_file(self):
        marker = "// env-mutation-gate: process-isolated -- one test per process\n"
        self.put("a.rs", marker + WRITER + UNLOCKED_READER)
        self.assertEqual(self.scan(), {})

    def test_marker_inside_string_does_not_exempt(self):
        # Only a real comment line counts.
        text = WRITER + UNLOCKED_READER + 'const S: &str = "x";\n'
        self.put("a.rs", text)
        self.assertEqual(self.scan(), {"tests/a.rs": 1})

    def test_serial_attribute_counts_as_lock(self):
        reader = "#[test]\n#[serial]\nfn reader() { let _ = std::env::var(\"A\"); }\n"
        self.put("a.rs", WRITER + reader)
        self.assertEqual(self.scan(), {})

    def test_lock_word_inside_comment_or_string_is_not_a_lock(self):
        reader = (
            "#[test]\nfn reader() {\n    // take ENV_LOCK here\n"
            "    let _s = \"ENV_LOCK\";\n    let _ = std::env::var(\"A\");\n}\n"
        )
        self.put("a.rs", WRITER + reader)
        self.assertEqual(self.scan(), {"tests/a.rs": 1})

    def test_block_clock_flush_are_not_lock_words(self):
        reader = (
            "#[test]\nfn reader() {\n    let _ = block_on(x());\n    let _c = clock();\n"
            "    flush_blocking();\n    let _ = std::env::var(\"A\");\n}\n"
        )
        self.put("a.rs", WRITER + reader)
        self.assertEqual(self.scan(), {"tests/a.rs": 1})

    def test_idiom_spellings_count_as_locks(self):
        for call in ("let _g = env_lock();", "let _g = test_env_lock();", "let _g = FED_ENV_LOCK.lock();",
                     "let _g = EnvLockGuard::new();"):
            with self.subTest(call=call):
                reader = "#[test]\nfn reader() { %s let _ = std::env::var(\"A\"); }\n" % call
                self.put("a.rs", WRITER + reader)
                self.assertEqual(self.scan(), {})

    def test_braces_in_strings_and_chars_do_not_break_body_matching(self):
        reader = (
            "#[test]\nfn first() {\n    let _s = \"}{\"; let _c = '}'; let _g = ENV_LOCK.blocking_lock();\n}\n"
            "#[test]\nfn second() {\n    let _ = std::env::var(\"A\");\n}\n"
        )
        self.put("a.rs", WRITER + reader)
        self.assertEqual(self.scan(), {"tests/a.rs": 1})

    def test_non_test_helper_fn_is_not_counted(self):
        helper = "fn helper() { let _ = std::env::var(\"A\"); }\n"
        self.put("a.rs", WRITER + helper)
        self.assertEqual(self.scan(), {})

    def test_remove_var_alone_triggers_the_rule(self):
        text = "#[test]\nfn w() { unsafe { std::env::remove_var(\"A\") }; }\n"
        self.put("a.rs", text)
        self.assertEqual(self.scan(), {"tests/a.rs": 1})


class Ratchet(Fixture):
    def test_new_violation_fails(self):
        self.assertEqual(len(gate.compare({"tests/a.rs": 1}, {})), 1)

    def test_raised_count_fails(self):
        problems = gate.compare({"tests/a.rs": 3}, {"tests/a.rs": 2})
        self.assertTrue(problems and problems[0].startswith("RAISED"))

    def test_stale_entry_fails(self):
        problems = gate.compare({}, {"tests/a.rs": 2})
        self.assertTrue(problems and problems[0].startswith("STALE"))

    def test_equal_counts_pass(self):
        self.assertEqual(gate.compare({"tests/a.rs": 2}, {"tests/a.rs": 2}), [])

    def test_main_round_trip(self):
        self.put("a.rs", WRITER + UNLOCKED_READER)
        root = str(SCRATCH)
        self.assertEqual(gate.main(["--root", root]), 1)
        self.assertEqual(gate.main(["--root", root, "--update-baseline"]), 0)
        self.assertEqual(gate.main(["--root", root]), 0)
        self.put("a.rs", WRITER + LOCKED_READER)
        self.assertEqual(gate.main(["--root", root]), 1)  # stale baseline line


class RealTree(unittest.TestCase):
    def test_repo_matches_its_baseline(self):
        found = gate.scan_tree(REPO)
        baseline = gate.read_baseline(REPO / gate.BASELINE_REL)
        self.assertEqual(gate.compare(found, baseline), [])

    def test_2529_file_is_clean(self):
        # #7347: the sync reader in this file now holds ENV_LOCK.
        self.assertNotIn("tests/federation_pending_resurrection_2529.rs", gate.scan_tree(REPO))

    def test_base_shape_of_2529_is_flagged(self):
        text = (REPO / "tests" / "federation_pending_resurrection_2529.rs").read_text()
        unlocked = text.replace("    let _lock = ENV_LOCK.blocking_lock();\n", "")
        self.assertNotEqual(text, unlocked)
        scratch = REPO / ".local-runs" / "env-mutation-gate-7347-real"
        shutil.rmtree(scratch, ignore_errors=True)
        (scratch / "tests").mkdir(parents=True)
        self.addCleanup(shutil.rmtree, scratch, True)
        (scratch / "tests" / "x.rs").write_text(unlocked)
        self.assertEqual(gate.scan_tree(scratch), {"tests/x.rs": 1})


if __name__ == "__main__":
    unittest.main()
