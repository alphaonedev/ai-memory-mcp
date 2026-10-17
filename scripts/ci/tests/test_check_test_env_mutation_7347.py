#!/usr/bin/env python3
"""Unit tests for scripts/check-test-env-mutation.py (#7347).

Run: python3 -m unittest scripts/ci/tests/test_check_test_env_mutation_7347.py

Each rule is proven twice: a clean fixture passes and a mutant that breaks exactly that rule
fails. Fixtures are built in a scratch dir under .local-runs/ (never a tmp dir).
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
    let _c = db::open(":memory:");
}
"""
UNLOCKED_READER = """
#[test]
fn reader() {
    let _c = db::open(":memory:");
}
"""


def reader(prefix, body="let _c = db::open(\":memory:\");"):
    return "#[test]\nfn reader() {\n    %s\n    %s\n}\n" % (prefix, body)


class Fixture(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        (SCRATCH / "tests").mkdir(parents=True)
        self.addCleanup(shutil.rmtree, SCRATCH, True)

    def put(self, name, text):
        (SCRATCH / "tests" / name).write_text(text)

    def scan(self):
        return gate.scan_tree(SCRATCH)

    def flagged(self, text):
        self.put("a.rs", text)
        return self.scan()


class ScanRules(Fixture):
    def test_locked_reader_passes(self):
        self.assertEqual(self.flagged(WRITER + LOCKED_READER), set())

    def test_unlocked_reader_is_flagged(self):
        # The #7347 shape: locked writer, unlocked SQLite opener in the same file.
        self.assertEqual(self.flagged(WRITER + UNLOCKED_READER), {"tests/a.rs::reader"})

    def test_file_without_env_mutation_is_ignored(self):
        self.assertEqual(self.flagged(UNLOCKED_READER + UNLOCKED_READER.replace("reader", "other")), set())

    def test_process_isolated_marker_exempts_file(self):
        marker = "// env-mutation-gate: process-isolated -- one test per process\n"
        self.assertEqual(self.flagged(marker + WRITER + UNLOCKED_READER), set())

    def test_serial_attribute_counts_as_lock(self):
        text = WRITER + "#[test]\n#[serial]\nfn reader() { let _c = db::open(\":memory:\"); }\n"
        self.assertEqual(self.flagged(text), set())

    def test_lock_word_inside_comment_or_string_is_not_a_lock(self):
        text = WRITER + reader("// take ENV_LOCK here\n    let _s = \"ENV_LOCK\";")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_idiom_spellings_count_as_locks(self):
        helper = ("fn env_lock() -> std::sync::MutexGuard<'static, ()> { ENV_LOCK2.lock().unwrap() }\n"
                  "fn w() { let _g = ENV_LOCK2.lock().unwrap(); unsafe { std::env::set_var(\"A\", \"1\") }; }\n"
                  "#[test]\nfn w_test() { w(); }\n")
        for call in ("let _g = env_lock();", "let _g = ENV_LOCK2.lock().unwrap();",
                     "let _g = ENV_LOCK2.lock().unwrap_or_else(|e| e.into_inner());"):
            with self.subTest(call=call):
                self.assertEqual(self.flagged(helper + reader(call)), set())

    def test_braces_in_strings_and_chars_do_not_break_body_matching(self):
        text = WRITER + (
            "#[test]\nfn first() {\n    let _s = \"}{\"; let _c = '}'; let _g = ENV_LOCK.blocking_lock();\n"
            "    let _d = db::open(\":memory:\");\n}\n"
            "#[test]\nfn second() {\n    let _d = db::open(\":memory:\");\n}\n")
        self.assertEqual(self.flagged(text), {"tests/a.rs::second"})

    def test_non_test_helper_fn_is_not_counted(self):
        text = WRITER + "fn helper() { let _c = db::open(\":memory:\"); }\n"
        self.assertEqual(self.flagged(text), set())

    def test_remove_var_alone_triggers_the_rule(self):
        text = ("#[test]\nfn w() { unsafe { std::env::remove_var(\"A\") }; }\n"
                "#[test]\nfn w2() { unsafe { std::env::remove_var(\"B\") }; }\n")
        self.assertEqual(self.flagged(text), {"tests/a.rs::w", "tests/a.rs::w2"})


class LockPrecision(Fixture):
    """#7349 review MEDIUM 2: a fn counts as locked only with THE writers' lock, held for the body."""

    def test_unrelated_conn_lock_does_not_count(self):
        text = WRITER + reader("let g = conn.lock().unwrap();")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_unrelated_db_lock_await_does_not_count(self):
        text = WRITER + "#[tokio::test]\nasync fn reader() {\n    let g = db.lock().await;\n    let _c = db::open(\":memory:\");\n}\n"
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_rwlock_type_name_does_not_count(self):
        text = WRITER + reader("let _t: Option<RwLock<u8>> = None;")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_let_underscore_drops_the_guard_at_once(self):
        text = WRITER + reader("let _ = ENV_LOCK.blocking_lock();")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_bare_statement_lock_is_not_held(self):
        text = WRITER + reader("ENV_LOCK.blocking_lock();")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_lock_taken_after_the_first_open_does_not_count(self):
        text = WRITER + reader("let _c = db::open(\":memory:\");", "let _g = ENV_LOCK.blocking_lock();")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_lock_in_inner_block_does_not_live_for_the_body(self):
        text = WRITER + reader("{ let _g = ENV_LOCK.blocking_lock(); }")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_lock_in_a_never_called_closure_does_not_count(self):
        text = WRITER + reader("let _f = || { let _g = ENV_LOCK.blocking_lock(); };")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_a_different_env_lock_static_does_not_count(self):
        text = WRITER + reader("let _g = OTHER_LOCK.blocking_lock();")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_cfg_attr_test_is_a_test(self):
        text = WRITER + "#[cfg_attr(feature = \"x\", test)]\nfn reader() { let _c = db::open(\":memory:\"); }\n"
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_cfg_attr_predicate_test_is_not_a_test_attribute(self):
        text = WRITER + "#[cfg_attr(test, allow(dead_code))]\nfn helper() { let _c = db::open(\":memory:\"); }\n"
        self.assertEqual(self.flagged(text), set())

    def test_lock_held_by_the_caller_of_a_writer_fn_is_the_writers_lock(self):
        # 2529 shape: the writer fn holds no lock itself; each locked test calls it.
        text = ("static ENV_LOCK: Mutex<()> = Mutex::const_new(());\n"
                "fn set_opt_out() { unsafe { std::env::set_var(\"A\", \"0\") }; }\n"
                "#[tokio::test]\nasync fn w() { let _l = ENV_LOCK.lock().await; set_opt_out(); }\n"
                "#[test]\nfn good() { let _l = ENV_LOCK.blocking_lock(); let _c = db::open(\":memory:\"); }\n"
                "#[test]\nfn bad() { let _c = db::open(\":memory:\"); }\n")
        self.assertEqual(self.flagged(text), {"tests/a.rs::bad"})

    def test_lock_in_a_called_helper_counts_one_level(self):
        helper = "fn take() -> MutexGuard<'static, ()> { ENV_LOCK.blocking_lock() }\n"
        self.assertEqual(self.flagged(WRITER + helper + reader("let _g = take();")), set())

    def test_helper_guard_dropped_at_once_does_not_count(self):
        helper = "fn take() -> MutexGuard<'static, ()> { ENV_LOCK.blocking_lock() }\n"
        self.assertEqual(self.flagged(WRITER + helper + reader("let _ = take();")),
                         {"tests/a.rs::reader"})

    def test_helper_holding_the_lock_while_it_works_counts(self):
        helper = ("fn with_env_lock(f: impl FnOnce()) { let _g = ENV_LOCK.blocking_lock(); f(); }\n")
        self.assertEqual(self.flagged(WRITER + helper + reader("with_env_lock(|| ());")), set())

    def test_local_guard_type_constructor_counts(self):
        text = ("static ENV_LOCK: Mutex<()> = Mutex::const_new(());\n"
                "struct AgentIdEnv { _l: MutexGuard<'static, ()> }\n"
                "impl AgentIdEnv {\n"
                "    fn set(v: &str) -> Self { let l = ENV_LOCK.blocking_lock(); unsafe { std::env::set_var(\"A\", v) }; Self { _l: l } }\n"
                "}\n"
                "#[test]\nfn good() { let _e = AgentIdEnv::set(\"x\"); let _c = db::open(\":memory:\"); }\n"
                "#[test]\nfn bad() { let _c = db::open(\":memory:\"); }\n")
        self.assertEqual(self.flagged(text), {"tests/a.rs::bad"})

    def test_nested_module_fn_is_qualified(self):
        text = WRITER + "mod inner {\n" + UNLOCKED_READER + "}\n"
        self.assertEqual(self.flagged(text), {"tests/a.rs::inner::reader"})


class Coverage(Fixture):
    """#7349 review MEDIUM 3: files that mutate env only through tests/common helpers are scanned."""

    def test_env_var_guard_only_file_is_scanned(self):
        text = ("#[test]\nfn guarded() { let _g = EnvVarGuard::set(\"A\", \"1\".into()); let _c = db::open(\":memory:\"); }\n"
                "#[test]\nfn bare() { let _c = db::open(\":memory:\"); }\n")
        self.assertEqual(self.flagged(text), {"tests/a.rs::bare"})

    def test_env_var_guard_dropped_at_once_does_not_count(self):
        text = ("#[test]\nfn guarded() { let _ = EnvVarGuard::set(\"A\", \"1\".into()); let _c = db::open(\":memory:\"); }\n"
                "#[test]\nfn other() { let _g = EnvVarGuard::remove(\"A\"); }\n")
        self.assertEqual(self.flagged(text), {"tests/a.rs::guarded"})

    def test_multi_env_var_guard_counts_as_writer_and_lock(self):
        text = ("#[test]\nfn guarded() { let _g = MultiEnvVarGuard::apply(&[(\"A\", None)]); let _c = db::open(\":memory:\"); }\n"
                "#[test]\nfn bare() { let _c = db::open(\":memory:\"); }\n")
        self.assertEqual(self.flagged(text), {"tests/a.rs::bare"})

    def test_once_setter_called_first_counts(self):
        text = ("#[test]\nfn first() { ensure_no_config_env(); let _c = db::open(\":memory:\"); }\n"
                "#[test]\nfn late() { let _c = db::open(\":memory:\"); ensure_no_config_env(); }\n")
        self.assertEqual(self.flagged(text), {"tests/a.rs::late"})

    def test_permissive_attestation_setter_is_a_writer(self):
        text = ("#[test]\nfn a() { permissive_attestation_for_tests(); let _c = db::open(\":memory:\"); }\n"
                "#[test]\nfn b() { let _c = db::open(\":memory:\"); }\n")
        self.assertEqual(self.flagged(text), {"tests/a.rs::b"})

    def test_install_test_operator_key_guard_counts(self):
        text = ("#[test]\nfn a() { let (_k, _g) = install_test_operator_key(); let _c = db::open(\":memory:\"); }\n"
                "#[test]\nfn b() { let _c = db::open(\":memory:\"); }\n")
        self.assertEqual(self.flagged(text), {"tests/a.rs::b"})

    def test_bare_imported_set_var_is_a_writer(self):
        text = ("use std::env::set_var;\n"
                "#[test]\nfn a() { unsafe { set_var(\"A\", \"1\") }; }\n"
                "#[test]\nfn b() { let _c = db::open(\":memory:\"); }\n")
        self.assertEqual(self.flagged(text), {"tests/a.rs::a", "tests/a.rs::b"})


class FalsePositives(Fixture):
    """#7349 review MEDIUM 4: nothing to race in one test, or in a fn that reaches no reader."""

    def test_single_test_binary_is_exempt(self):
        self.assertEqual(self.flagged("#[test]\nfn only() { unsafe { std::env::set_var(\"A\", \"1\") }; let _c = db::open(\":memory:\"); }\n"), set())

    def test_pure_fn_is_exempt(self):
        text = WRITER + "#[test]\nfn pure() { assert_eq!(1 + 1, 2); validate(\"x\"); }\n"
        self.assertEqual(self.flagged(text), set())

    def test_fn_calling_a_local_helper_that_opens_the_db_is_not_pure(self):
        text = WRITER + "fn helper() { let _c = db::open(\":memory:\"); }\n#[test]\nfn viahelper() { helper(); }\n"
        self.assertEqual(self.flagged(text), {"tests/a.rs::viahelper"})

    def test_fn_inside_a_macro_rules_body_is_a_template_not_a_test(self):
        text = WRITER + ("macro_rules! gen {\n    () => {\n        #[test]\n"
                         "        fn templ() { let _c = db::open(\":memory:\"); }\n    };\n}\n")
        self.assertEqual(self.flagged(text), set())

    def test_lock_two_helpers_down_is_followed(self):
        helpers = ("fn inner(f: impl FnOnce()) { let _g = ENV_LOCK.blocking_lock(); f(); }\n"
                   "fn outer(f: impl FnOnce()) { inner(f); }\n")
        self.assertEqual(self.flagged(WRITER + helpers + reader("outer(|| ());")), set())

    def test_guard_bound_inside_a_helper_is_released_when_it_returns(self):
        helpers = ("fn inner() -> MutexGuard<'static, ()> { ENV_LOCK.blocking_lock() }\n"
                   "fn outer() { let _g = inner(); }\n")
        self.assertEqual(self.flagged(WRITER + helpers + reader("outer();")), {"tests/a.rs::reader"})

    def test_local_fn_named_like_an_opener_is_judged_by_its_body(self):
        text = WRITER + "fn fresh_db() -> u8 { 1 }\n#[test]\nfn only_path() { let _p = fresh_db(); }\n"
        self.assertEqual(self.flagged(text), set())

    def test_fn_calling_a_local_pure_helper_stays_pure(self):
        text = WRITER + "fn helper() -> u8 { 1 }\n#[test]\nfn viahelper() { helper(); }\n"
        self.assertEqual(self.flagged(text), set())

    def test_env_var_read_without_db_is_still_a_reader_via_vars(self):
        text = WRITER + "#[test]\nfn vars() { let _n = std::env::vars().count(); }\n"
        self.assertEqual(self.flagged(text), {"tests/a.rs::vars"})


class Ratchet(Fixture):
    def test_new_violation_fails(self):
        problems = gate.compare({"tests/a.rs::x"}, set())
        self.assertTrue(problems and problems[0].startswith("NEW"))

    def test_swap_new_unlocked_fn_fails_even_when_another_was_fixed(self):
        # Baseline allowed `old`; the change locks `old` and adds an unlocked `brand_new`.
        problems = gate.compare({"tests/a.rs::brand_new"}, {"tests/a.rs::old"})
        self.assertEqual([p.split()[0] for p in problems], ["NEW", "STALE"])

    def test_stale_entry_fails(self):
        problems = gate.compare(set(), {"tests/a.rs::x"})
        self.assertTrue(problems and problems[0].startswith("STALE"))

    def test_equal_sets_pass(self):
        self.assertEqual(gate.compare({"tests/a.rs::x"}, {"tests/a.rs::x"}), [])

    def test_old_count_format_is_rejected(self):
        path = SCRATCH / "base.txt"
        SCRATCH.mkdir(parents=True, exist_ok=True)
        path.write_text("3 tests/a.rs\n")
        with self.assertRaises(SystemExit):
            gate.read_baseline(path)

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
        found = gate.scan_tree(REPO)
        self.assertFalse([k for k in found if "federation_pending_resurrection_2529" in k])

    def test_base_shape_of_2529_is_flagged(self):
        text = (REPO / "tests" / "federation_pending_resurrection_2529.rs").read_text()
        unlocked = text.replace("    let _lock = ENV_LOCK.blocking_lock();\n", "")
        self.assertNotEqual(text, unlocked)
        scratch = REPO / ".local-runs" / "env-mutation-gate-7347-real"
        shutil.rmtree(scratch, ignore_errors=True)
        (scratch / "tests").mkdir(parents=True)
        self.addCleanup(shutil.rmtree, scratch, True)
        (scratch / "tests" / "x.rs").write_text(unlocked)
        self.assertEqual(gate.scan_tree(scratch), {"tests/x.rs::upsert_sql_does_not_clobber_decided_status_2529"})


if __name__ == "__main__":
    unittest.main()
