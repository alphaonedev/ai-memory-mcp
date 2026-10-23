#!/usr/bin/env python3
"""Unit tests for scripts/check-test-env-mutation.py (#7347).

Run: python3 -m unittest scripts/ci/tests/test_check_test_env_mutation_7347.py

Each rule is proven twice: a clean fixture passes and a mutant that breaks exactly that rule
fails. Fixtures are built in a scratch dir under .local-runs/ (never a tmp dir).
"""
import ast
import importlib.util
import re
import shutil
import sys
import types
import unittest
import unittest.mock
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
        # #7386: only when every writer is #[serial] too.
        text = (WRITER.replace("#[tokio::test]", "#[tokio::test]\n#[serial]")
                + "#[test]\n#[serial]\nfn reader() { let _c = db::open(\":memory:\"); }\n")
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
        self.assertEqual(self.flagged(WRITER + helper + reader("with_env_lock(|| {", "let _c = db::open(\":memory:\"); });")), set())

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
        self.assertEqual(self.flagged(WRITER + helpers + reader("outer(|| {", "let _c = db::open(\":memory:\"); });")), set())

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


OPEN = 'let _c = db::open(":memory:");'

SERIAL_4357 = """
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
struct EnvGuard(&'static str);
impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        unsafe { std::env::set_var(key, value) };
        Self(key)
    }
}
impl Drop for EnvGuard {
    fn drop(&mut self) { unsafe { std::env::remove_var(self.0) }; }
}
fn enforce_mode() -> EnvGuard { EnvGuard::set("AI_MEMORY_MODE", "enforce") }
async fn exercise() {
    let _mode = enforce_mode();
    let _c = db::open(":memory:");
}
#[tokio::test]
async fn first() {
    let _serial = SERIAL.lock().await;
    exercise().await;
}
#[tokio::test]
async fn second() {
    let _serial = SERIAL.lock().await;
    let _c = db::open(":memory:");
}
"""


def test_fn(name, body, attrs="#[test]"):
    return "%s\nfn %s() {\n    %s\n}\n" % (attrs, name, body)


class FalsePositivesR3(Fixture):
    """#7349 r2 code M1 / security M1: shapes the r2 gate flagged although the lock is held."""

    def test_a_lock_held_two_callers_up_is_the_writers_lock_4357_shape(self):
        self.assertEqual(self.flagged(SERIAL_4357), set())

    def test_a_lock_held_two_callers_up_still_flags_an_unlocked_test(self):
        self.assertEqual(self.flagged(SERIAL_4357 + test_fn("bare", OPEN)), {"tests/a.rs::bare"})

    def test_b_lock_taken_inside_a_loop_is_not_the_canonical_shape(self):
        # r6: the gate models no scopes below the top-level block; a loop-body lock fails closed.
        body = "for _ in 0..2 {\n        let _g = ENV_LOCK.blocking_lock();\n        %s\n    }" % OPEN
        self.assertEqual(self.flagged(WRITER + test_fn("reader", body)), {"tests/a.rs::reader"})

    def test_b_lock_taken_inside_a_block_on_closure_is_not_the_canonical_shape(self):
        body = "rt.block_on(async {\n        let _g = ENV_LOCK.lock().await;\n        %s\n    });" % OPEN
        self.assertEqual(self.flagged(WRITER + test_fn("reader", body)), {"tests/a.rs::reader"})

    def test_b_lock_hoisted_above_the_loop_is_credited(self):
        body = "let _g = ENV_LOCK.blocking_lock();\n    for _ in 0..2 {\n        %s\n    }" % OPEN
        self.assertEqual(self.flagged(WRITER + test_fn("reader", body)), set())

    def test_b_once_helper_called_in_a_closure_is_followed(self):
        text = (test_fn("a", "rt.block_on(async {\n        common::permissive_attestation_for_tests();\n"
                             "        %s\n    });" % OPEN)
                + test_fn("b", "std::thread::spawn(|| {\n        common::permissive_attestation_for_tests();\n"
                               "        %s\n    });" % OPEN))
        self.assertEqual(self.flagged(text), set())

    def test_b_lock_helper_called_inside_a_loop_is_not_credited(self):
        helper = "fn take() -> MutexGuard<'static, ()> { ENV_LOCK.blocking_lock() }\n"
        body = "for _ in 0..2 {\n        let _g = take();\n        %s\n    }" % OPEN
        self.assertEqual(self.flagged(WRITER + helper + test_fn("reader", body)), {"tests/a.rs::reader"})

    def test_c_file_lock_held_by_every_test_with_common_guard_writes(self):
        text = ("static TEST_LOCK: Mutex<()> = Mutex::new(());\n"
                + test_fn("w", "let _t = TEST_LOCK.lock().unwrap();\n    "
                          "let _g = EnvVarGuard::set(\"A\", \"1\".into());\n    " + OPEN)
                + test_fn("r", "let _t = TEST_LOCK.lock().unwrap();\n    " + OPEN))
        self.assertEqual(self.flagged(text), set())

    def test_d_use_item_is_not_a_reader(self):
        text = WRITER + reader("use ai_memory::storage::SqliteStore;\n    let _g = ENV_LOCK.blocking_lock();")
        self.assertEqual(self.flagged(text), set())

    def test_e_env_read_of_a_variable_no_sibling_writes_is_not_a_reader(self):
        text = WRITER + test_fn("r", "let _u = std::env::var(\"AI_MEMORY_TEST_POSTGRES_URL\");")
        self.assertEqual(self.flagged(text), set())

    def test_e_env_read_of_a_written_variable_is_still_a_reader(self):
        text = WRITER + test_fn("r", "let _u = std::env::var(\"A\");")
        self.assertEqual(self.flagged(text), {"tests/a.rs::r"})

    def test_e_env_read_through_a_const_name_is_resolved(self):
        text = ("const KEY: &str = \"A\";\nconst OTHER: &str = \"B\";\n" + WRITER
                + test_fn("r", "let _u = std::env::var(KEY);")
                + test_fn("s", "let _u = std::env::var(OTHER);")
                + test_fn("t", "let _u = std::env::var(unknown_name());"))
        self.assertEqual(self.flagged(text), {"tests/a.rs::r", "tests/a.rs::t"})

    def test_f_ignored_test_is_exempt(self):
        text = (WRITER + test_fn("r", OPEN, "#[test]\n#[ignore = \"needs pg\"]")
                + test_fn("bare", OPEN))
        self.assertEqual(self.flagged(text), {"tests/a.rs::bare"})

    def test_f_ignored_writer_does_not_bind_the_non_ignored_tests(self):
        text = (test_fn("w", "unsafe { std::env::set_var(\"A\", \"1\") };", "#[test]\n#[ignore]")
                + test_fn("r1", OPEN) + test_fn("r2", OPEN))
        self.assertEqual(self.flagged(text), set())

    def test_f_every_ci_ignored_run_is_single_threaded(self):
        # The #[ignore] exemption holds because CI runs ignored tests one at a time:
        # postgres-ignored.yml:118, coverage.yml:583 and cert-postgres-age.yml:382 pass
        # `--test-threads=1`; token-budget.yml:146 runs one `--exact` test.
        runs = gate.ignored_test_runs(REPO / ".github" / "workflows")
        names = {path for path, _, _ in runs}
        self.assertTrue({"postgres-ignored.yml", "coverage.yml", "cert-postgres-age.yml"} <= names, names)
        bad = [(path, line) for path, line, cmd in runs
               if "--test-threads=1" not in cmd and "--exact" not in cmd]
        self.assertEqual(bad, [])

    def test_f_a_parallel_ignored_run_is_detected(self):
        wf = SCRATCH / "wf"
        wf.mkdir()
        (wf / "x.yml").write_text("jobs:\n  a:\n    steps:\n      - run: |\n          cargo test \\\n"
                                  "            -- --ignored\n")
        self.assertEqual([(p, c.split()[-1]) for p, _, c in gate.ignored_test_runs(wf)],
                         [("x.yml", "--ignored")])


class FalseNegativesR3(Fixture):
    """#7349 r2 code M2 / security M2: shapes the r2 gate passed although they race the writers."""

    def test_g_once_setter_is_not_the_lock_when_other_writers_use_env_lock(self):
        text = WRITER + reader("common::ensure_no_config_env();")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_g_once_setter_two_callers_up_is_not_the_lock_either(self):
        text = (WRITER + "fn setup() { common::ensure_no_config_env(); }\nfn outer() { setup(); }\n"
                + reader("outer();"))
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_g_two_distinct_once_setters_each_need_their_own_call(self):
        text = (test_fn("a", "common::ensure_no_config_env();\n    "
                        "common::permissive_attestation_for_tests();\n    " + OPEN)
                + test_fn("b", "common::ensure_no_config_env();\n    " + OPEN))
        self.assertEqual(self.flagged(text), {"tests/a.rs::b"})

    def test_h_guard_dropped_before_the_open_is_not_held(self):
        text = WRITER + reader("let g = ENV_LOCK.blocking_lock();\n    drop(g);")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_h_guard_dropped_after_the_open_is_flagged_by_design(self):
        # #7628: the gate does not model drops; a guard the test mentions again is not credited.
        text = WRITER + reader("let g = ENV_LOCK.blocking_lock();", OPEN + "\n    drop(g);")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_i_a_side_lock_the_writer_takes_outside_its_write_is_not_the_writers_lock(self):
        text = ("static ENV_LOCK: Mutex<()> = Mutex::new(());\nstatic STATE: Mutex<u8> = Mutex::new(0);\n"
                + test_fn("w", "{ let _s = STATE.lock().unwrap(); }\n    let _g = ENV_LOCK.lock().unwrap();\n"
                          "    unsafe { std::env::set_var(\"A\", \"1\") };\n    let _t = STATE.lock().unwrap();")
                + reader("let _s = STATE.lock().unwrap();"))
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_i_a_lock_held_by_only_some_writers_is_not_enough(self):
        text = ("static ENV_LOCK: Mutex<()> = Mutex::new(());\nstatic STATE: Mutex<u8> = Mutex::new(0);\n"
                + test_fn("w1", "let _s = STATE.lock().unwrap();\n    let _g = ENV_LOCK.lock().unwrap();\n"
                          "    unsafe { std::env::set_var(\"A\", \"1\") };")
                + test_fn("w2", "let _g = ENV_LOCK.lock().unwrap();\n    unsafe { std::env::set_var(\"A\", \"2\") };")
                + reader("let _s = STATE.lock().unwrap();"))
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_j_reader_reached_through_a_same_file_method_call(self):
        text = (WRITER + "struct Harness;\nimpl Harness {\n    fn start(&self) { %s }\n}\n" % OPEN
                + test_fn("reader", "let h = Harness;\n    h.start();"))
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_k_common_helper_that_opens_sqlite_is_a_db_open(self):
        (SCRATCH / "tests" / "common").mkdir()
        (SCRATCH / "tests" / "common" / "mod.rs").write_text(
            "pub fn spawn_test_daemon() -> u8 { let _c = ai_memory::db::open(\":memory:\"); 1 }\n"
            "pub fn pure_helper() -> u8 { 1 }\n")
        text = ("mod common;\n" + WRITER
                + test_fn("reader", "let _d = common::spawn_test_daemon();")
                + test_fn("pure", "let _d = common::pure_helper();"))
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_lock_helper_released_on_return_does_not_cover_a_later_open(self):
        helper = "fn with_env_lock(f: impl FnOnce()) { let _g = ENV_LOCK.blocking_lock(); f(); }\n"
        self.assertEqual(self.flagged(WRITER + helper + reader("with_env_lock(|| ());")),
                         {"tests/a.rs::reader"})


class Issue7361(Fixture):
    """#7361: postgres readers and a guard helper that wraps another guard helper."""

    def test_postgres_url_sqlx_and_pgpool_are_readers(self):
        for body in ("let _u = common::postgres_url();", "let _p = sqlx::postgres::PgPoolOptions::new();",
                     "let _p: Option<PgPool> = None;", "let _s = PostgresStore::connect(&url).await;"):
            with self.subTest(body=body):
                self.assertEqual(self.flagged(WRITER + reader("", body)), {"tests/a.rs::reader"})

    def test_guard_helper_wrapping_a_guard_helper_counts(self):
        helpers = ("fn take() -> MutexGuard<'static, ()> { ENV_LOCK.blocking_lock() }\n"
                   "fn take_outer() -> MutexGuard<'static, ()> { take() }\n")
        self.assertEqual(self.flagged(WRITER + helpers + reader("let _g = take_outer();")), set())


class PrecisionR3(Fixture):
    """#7349 r3 hand-check: shapes that are not a race."""

    def test_a_query_on_an_open_connection_or_pool_is_not_a_reader(self):
        body = 'let _q = sqlx::query("SELECT 1");\n    let _p = rusqlite::params![1];'
        self.assertEqual(self.flagged(WRITER + reader("", body)), set())

    def test_sole_unlocked_writer_with_no_sibling_reader_races_nothing(self):
        text = (test_fn("writer", 'unsafe { std::env::remove_var("A") };\n    let _v = std::env::var("A");')
                + test_fn("pure", "let _x = 1;"))
        self.assertEqual(self.flagged(text), set())

    def test_unlocked_writer_still_flags_a_sibling_reader(self):
        text = (test_fn("writer", 'unsafe { std::env::remove_var("A") };')
                + test_fn("opener", OPEN))
        self.assertEqual(self.flagged(text), {"tests/a.rs::opener", "tests/a.rs::writer"})


    def test_a_once_fn_that_opens_after_its_own_call_once_is_safe(self):
        helper = ("fn build() {\n    static O: std::sync::Once = std::sync::Once::new();\n"
                  '    O.call_once(|| unsafe { std::env::set_var("A", "0") });\n    ' + OPEN + "\n}\n")
        self.assertEqual(self.flagged(helper + test_fn("a", "build();") + test_fn("b", "build();")), set())


    def test_a_src_const_var_name_is_resolved(self):
        (SCRATCH / "src").mkdir()
        (SCRATCH / "src" / "k.rs").write_text('pub const KNOB_ENV: &str = "AI_KNOB";\n')
        text = (WRITER.replace('std::env::set_var("A", "1")', "std::env::set_var(ai_memory::k::KNOB_ENV, \"1\")")
                + reader("", 'let _u = std::env::var("AI_MEMORY_TEST_POSTGRES_URL");'))
        self.assertEqual(self.flagged(text), set())
        self.assertEqual(self.flagged(text.replace("AI_MEMORY_TEST_POSTGRES_URL", "AI_KNOB")),
                         {"tests/a.rs::reader"})


HOLDER = "struct Holder<T> { _g: T }\n"
MARKER_REASON = "// env-mutation-gate: process-isolated -- one test per process\n"
FILE_3761 = REPO / "tests" / "mcp_driver_text_closed_3761.rs"
PG_LOCK_3761 = "    let _env = ENV_LOCK.lock().await;\n"


class Issue7361R4(Fixture):
    """#7361 last item: the PG leg of the 3761 file is fixed, not baselined."""

    def test_3761_file_has_no_violating_fn(self):
        found = gate.scan_tree(REPO)
        self.assertEqual([k for k in found if k.startswith("tests/mcp_driver_text_closed_3761.rs::")], [])

    def test_3761_postgres_leg_without_the_file_lock_is_flagged(self):
        text = FILE_3761.read_text(encoding="utf-8")
        unlocked = text.replace(PG_LOCK_3761, "")
        self.assertNotEqual(text, unlocked)
        self.assertEqual(self.flagged(unlocked), {"tests/a.rs::pg_driver_faults_render_closed_per_funnel_3761"})


class Issue7383(Fixture):
    """#7383: raw byte / raw C strings, byte chars and C strings are scrubbed as literals."""

    LITERALS = ('br"\\"', 'br#"{"k":"v"}"#', 'br##"a"#"b"##', 'cr"\\"', 'cr#"x"y"#', "b'\"'", "b'\\''",
                'c"\\""', 'b"\\""')

    def test_writer_after_a_byte_or_c_literal_is_seen(self):
        for lit in self.LITERALS:
            with self.subTest(lit=lit):
                text = (test_fn("writer", "let _b = %s;\n    unsafe { std::env::set_var(\"A\", \"1\") };" % lit)
                        + test_fn("opener", OPEN))
                self.assertEqual(self.flagged(text), {"tests/a.rs::opener", "tests/a.rs::writer"})

    def test_reader_after_a_byte_or_c_literal_is_seen(self):
        for lit in self.LITERALS:
            with self.subTest(lit=lit):
                self.assertEqual(self.flagged(WRITER + reader("let _b = %s;" % lit)), {"tests/a.rs::reader"})

    def test_scrub_blanks_the_whole_literal(self):
        for lit in self.LITERALS:
            with self.subTest(lit=lit):
                self.assertEqual(gate.scrub("x(%s);" % lit).strip(), "x(%s);" % (" " * len(lit)))


class Issue7384(Fixture):
    """#7384: the process-isolated marker is a real line comment with a reason."""

    def test_marker_with_a_reason_still_exempts_the_file(self):
        self.assertEqual(self.flagged(MARKER_REASON + WRITER + UNLOCKED_READER), set())

    def test_marker_that_is_not_a_real_line_comment_does_not_exempt(self):
        for wrap in ('const _M: &str = r"\n%s";\n', 'const _M: &str = "\n%s";\n', "/*\n%s*/\n",
                     "/* outer /* nested */\n%s*/\n"):
            with self.subTest(wrap=wrap):
                text = wrap % MARKER_REASON + WRITER + UNLOCKED_READER
                self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_marker_without_a_reason_does_not_exempt(self):
        for marker in ("// env-mutation-gate: process-isolated\n", "// env-mutation-gate: process-isolated --\n",
                       "// env-mutation-gate: process-isolated --   \n",
                       "let _x = 1; // env-mutation-gate: process-isolated -- trailing\n"):
            with self.subTest(marker=marker):
                self.assertEqual(self.flagged(marker + WRITER + UNLOCKED_READER), {"tests/a.rs::reader"})


MACRO_SETX = 'macro_rules! setx {\n    () => {\n        unsafe { std::env::set_var("A", "1") }\n    };\n}\n'
MACRO_SETL = ('macro_rules! setl {\n    () => {{\n        let _g = ENV_LOCK.blocking_lock();\n'
              '        unsafe { std::env::set_var("A", "1") }\n    }};\n}\n')
MACRO_FWD = "macro_rules! fwd {\n    () => {\n        setx!()\n    };\n}\n"


class Issue7385(Fixture):
    """#7385: an env write in a same-file macro_rules! body is a write site at each invocation."""

    def test_macro_writer_is_a_write_site(self):
        text = MACRO_SETX + test_fn("writer", "setx!();") + test_fn("opener", OPEN)
        self.assertEqual(self.flagged(text), {"tests/a.rs::opener", "tests/a.rs::writer"})

    def test_macro_writer_beside_a_locked_writer_is_flagged(self):
        text = WRITER + MACRO_SETX + test_fn("w2", "setx!();") + LOCKED_READER
        self.assertEqual(self.flagged(text), {"tests/a.rs::w2"})

    def test_forwarding_macro_is_followed(self):
        text = WRITER + MACRO_SETX + MACRO_FWD + test_fn("w2", "fwd!();") + LOCKED_READER
        self.assertEqual(self.flagged(text), {"tests/a.rs::w2"})

    def test_macro_writer_invoked_under_the_lock_passes(self):
        text = WRITER + MACRO_SETX + test_fn("w2", "let _g = ENV_LOCK.blocking_lock();\n    setx!();") + LOCKED_READER
        self.assertEqual(self.flagged(text), set())

    def test_macro_that_takes_the_lock_around_its_write_passes(self):
        text = WRITER + MACRO_SETL + test_fn("w2", "setl!();") + LOCKED_READER
        self.assertEqual(self.flagged(text), set())


class Issue7386(Fixture):
    """#7386: #[serial] protects only against #[serial] writers with the same key."""

    def test_serial_reader_beside_a_non_serial_writer_is_flagged(self):
        text = WRITER + test_fn("reader", OPEN, "#[test]\n#[serial]")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_serial_reader_beside_serial_writers_passes(self):
        text = (test_fn("writer", 'unsafe { std::env::set_var("A", "1") };', "#[test]\n#[serial]")
                + test_fn("reader", OPEN, "#[test]\n#[serial_test::serial]"))
        self.assertEqual(self.flagged(text), set())

    def test_serial_key_must_match(self):
        writer = test_fn("writer", 'unsafe { std::env::set_var("A", "1") };', "#[test]\n#[serial(env)]")
        self.assertEqual(self.flagged(writer + test_fn("reader", OPEN, "#[test]\n#[serial(other)]")),
                         {"tests/a.rs::reader"})
        self.assertEqual(self.flagged(writer + test_fn("reader", OPEN, "#[test]\n#[serial(env)]")), set())
        self.assertEqual(self.flagged(writer + test_fn("reader", OPEN, "#[test]\n#[serial]")),
                         {"tests/a.rs::reader"})

    def test_non_serial_reader_beside_serial_writers_is_flagged(self):
        text = (test_fn("writer", 'unsafe { std::env::set_var("A", "1") };', "#[test]\n#[serial]")
                + test_fn("reader", OPEN))
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})


class Issue7391(Fixture):
    """#7391: the baseline is read and written as UTF-8 whatever the locale says."""

    def test_non_ascii_baseline_round_trip_under_an_ascii_locale(self):
        name = "reader_été"
        (SCRATCH / "tests" / "a.rs").write_text(WRITER + UNLOCKED_READER.replace("reader", name),
                                                encoding="utf-8")
        real_read, real_write = Path.read_text, Path.write_text

        def ascii_read(self, encoding=None, errors=None):
            return real_read(self, encoding=encoding or "ascii", errors=errors)

        def ascii_write(self, data, encoding=None, errors=None, **kw):
            return real_write(self, data, encoding=encoding or "ascii", errors=errors, **kw)

        root = str(SCRATCH)
        with unittest.mock.patch.object(Path, "read_text", ascii_read), \
                unittest.mock.patch.object(Path, "write_text", ascii_write):
            self.assertEqual(gate.main(["--root", root, "--update-baseline"]), 0)
            self.assertEqual(gate.read_baseline(SCRATCH / gate.BASELINE_REL), {"tests/a.rs::" + name})
            self.assertEqual(gate.main(["--root", root]), 0)


LOCK_HEAD = "use tokio::sync::Mutex;\nstatic ENV_LOCK: Mutex<()> = Mutex::const_new(());\n"
CONSUME = "fn consume<T>(_t: T) {}\n"
GUARD = "let g = ENV_LOCK.blocking_lock();\n    "


def writer_with(between):
    """A locked writer that does `between` with its guard g before it writes."""
    return (LOCK_HEAD + "#[tokio::test]\nasync fn writer() {\n    let g = ENV_LOCK.lock().await;\n    %s\n"
            "    unsafe { std::env::set_var(\"A\", \"1\") };\n}\n" % between)


GUARD_G = "let g = ENV_LOCK.blocking_lock();\n    "
FLAGGED = {"tests/a.rs::reader"}

# helper fns the r5 fixtures call; each is a NON-test fn so it is judged only through its caller
BORROW_HELPER = ("fn peek(g: &MutexGuard<'static, ()>) -> bool { let _r = &g; true }\n"
                 "fn take_by_ref() -> bool { let g = ENV_LOCK.blocking_lock(); peek(&g) }\n")
LOG_HELPER = "fn log_it() { let g = ENV_LOCK.blocking_lock(); let _n = format!(\"{:?}\", g); }\n"
CONSUME_FN = "fn consume<T>(_t: T) {}\n"


class CanonicalShapeR6(Fixture):
    """#7623-#7627: a lock is credited ONLY for `let <name> = <lock>;` in the top-level block, never
    mentioned again. The 12 r5 fail-open shapes and 10 more all come out NOT credited."""

    R5_SHAPES = {
        # #7623 a helper that only borrows its guard is not a guard-returning helper
        "helper_uses_guard_by_ref_returns_bool": (BORROW_HELPER, "let _x = take_by_ref();"),
        "helper_logs_guard_returns_unit": (LOG_HELPER, "let _x = log_it();"),
        # #7624 partial move of a field
        "struct_field_partial_move_then_drop": (HOLDER, "let h = Holder { _g: ENV_LOCK.blocking_lock() };\n"
                                                         "    let k = h._g;\n    drop(k);"),
        "struct_field_drop_h_dot_g": (HOLDER, "let h = Holder { _g: ENV_LOCK.blocking_lock() };\n    drop(h._g);"),
        # #7625 an underscore tuple slot drops the lock at the end of the statement
        "tuple_underscore_slot": ("", "let (_, _x) = (ENV_LOCK.blocking_lock(), 0u8);"),
        # #7626 match / if let / for consume the guard
        "match_guard_binding_arm": ("", GUARD_G + "match Some(g) { Some(_h) => {} None => {} }"),
        "if_let_some_moves_out": ("", GUARD_G + "if let Some(_h) = Some(g) {}"),
        "for_in_vec_consumes": ("", GUARD_G + "for _h in vec![g] {}"),
        # #7627 by-value methods and await
        "option_unwrap_stmt": ("", "let o = Some(ENV_LOCK.blocking_lock());\n    o.unwrap();"),
        "option_map_drop": ("", "let o = Some(ENV_LOCK.blocking_lock());\n    drop(o.map(|x| x));"),
        "vec_into_iter_for_each_drop": ("", "let v = vec![ENV_LOCK.blocking_lock()];\n    v.into_iter().for_each(drop);"),
        "async_move_awaited": ("", GUARD_G + "let f = async move { let _r = &g; };\n    rt.block_on(f);"),
    }

    OWN_SHAPES = {
        "plain_drop": ("", GUARD_G + "drop(g);"),
        "mem_drop_path": ("", GUARD_G + "std::mem::drop(g);"),
        "moved_into_a_fn": (CONSUME_FN, GUARD_G + "consume(g);"),
        "moved_into_a_binding": ("", GUARD_G + "let h = g;"),
        "mentioned_again_by_ref": ("", GUARD_G + "let _r = &g;"),
        "shadowed_binding": ("", GUARD_G + "let g = 5;"),
        "lone_underscore_pattern": ("", "let _ = ENV_LOCK.blocking_lock();"),
        "bare_statement": ("", "ENV_LOCK.blocking_lock();"),
        "lock_in_an_inner_block": ("", "{ let _g = ENV_LOCK.blocking_lock(); }"),
        "lock_in_a_loop_body": ("", "for _ in 0..1 { let _g = ENV_LOCK.blocking_lock(); }"),
        "lock_in_a_closure": ("", "let c = || { let _g = ENV_LOCK.blocking_lock(); };\n    c();"),
        "tuple_pattern_unknown_helper": ("", "let (_a, _b) = (ENV_LOCK.blocking_lock(), 1);"),
        "reassigned": ("", "let mut g = ENV_LOCK.blocking_lock();\n    g = ENV_LOCK.blocking_lock();"),
        # #8001 / #7389 / #7474: the turbofish call form of drop is a mention of the guard like any other
        "turbofish_drop": ("", GUARD_G + "drop::<_>(g);"),
        "turbofish_mem_drop": ("", GUARD_G + "std::mem::drop::<_>(g);"),
        # #7993: a helper whose tail only contains a lock call hands the caller no guard
        "helper_tail_drops_guard": ("fn h() { drop(ENV_LOCK.blocking_lock()) }\n", "let _x = h();"),
        "helper_tail_measures_guard": (
            "fn h() -> usize { std::mem::size_of_val(&ENV_LOCK.blocking_lock()) }\n", "let _x = h();"),
        "helper_tail_unawaited_future": ("fn h() { ENV_LOCK.lock() }\n", "let _x = h();"),
    }

    HELD_BUT_FLAGGED = {
        # #7628: really held in rustc, flagged by design (the gate never models a re-mention)
        "let_underscore_eq_guard": ("", GUARD_G + "let _ = g;"),
        "labelled_loop_break_value": ("", "let g = 'l: loop { break 'l ENV_LOCK.blocking_lock(); };"),
        "mem_forget": ("", GUARD_G + "std::mem::forget(g);"),
        "let_else_some": ("", "let Some(_g) = Some(ENV_LOCK.blocking_lock()) else { return };"),
        # #7390 asked for the opposite ("a fixture with the literal-bound guard before db::open that must
        # not be flagged"). The canonical shape (#7623-#7627) does not model a struct field as a guard, so
        # the shape stays flagged by design; #7390 stays open and PR #7349 no longer closes it (#7998).
        "struct_literal_bound_guard": (HOLDER, "let _h = Holder { _g: ENV_LOCK.blocking_lock() };"),
    }

    def verdict(self, helpers, prefix, body=OPEN):
        return self.flagged(WRITER + (helpers or "") + HOLDER + reader(prefix, body))

    def test_the_canonical_shape_is_credited(self):
        for prefix in ("let _g = ENV_LOCK.blocking_lock();", "let mut g = ENV_LOCK.blocking_lock();",
                       "let _guard = ENV_LOCK.lock().await;", "let g = ENV_LOCK.lock().unwrap();"):
            with self.subTest(prefix=prefix):
                self.assertEqual(self.verdict("", prefix), set())

    def test_the_twelve_r5_fail_open_shapes_are_not_credited(self):
        self.assertEqual(len(self.R5_SHAPES), 12)
        for name, (helpers, prefix) in self.R5_SHAPES.items():
            with self.subTest(shape=name):
                self.assertEqual(self.verdict(helpers, prefix), FLAGGED)

    def test_ten_more_shapes_are_not_credited(self):
        self.assertGreaterEqual(len(self.OWN_SHAPES), 10)
        for name, (helpers, prefix) in self.OWN_SHAPES.items():
            with self.subTest(shape=name):
                self.assertEqual(self.verdict(helpers, prefix), FLAGGED)

    def test_a_lock_taken_after_the_open_is_not_credited(self):
        text = WRITER + reader(OPEN, "let _g = ENV_LOCK.blocking_lock();")
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_the_five_held_but_flagged_shapes_stay_flagged_by_design_7628_7998(self):
        self.assertEqual(len(self.HELD_BUT_FLAGGED), 5)
        for name, (helpers, prefix) in self.HELD_BUT_FLAGGED.items():
            with self.subTest(shape=name):
                self.assertEqual(self.verdict(helpers, prefix), FLAGGED)

    def test_the_guard_chain_is_credited_but_a_wider_chain_is_not(self):
        for call, flagged in (("ENV_LOCK.lock().await", False), ("ENV_LOCK.lock().unwrap()", False),
                              ("ENV_LOCK.lock().expect(\"x\")", False),
                              ("ENV_LOCK.lock().unwrap().clone()", True),
                              ("ENV_LOCK.lock().is_ok()", True)):
            with self.subTest(call=call):
                got = self.verdict("", "let _g = %s;" % call)
                self.assertEqual(got, FLAGGED if flagged else set())

    def test_the_tuple_exception_is_judged_on_the_guard_slot(self):
        writer = test_fn("w", "let (_k, _g) = install_test_operator_key();\n    " + OPEN)

        def scan(prefix):
            return self.flagged(writer + test_fn("reader", prefix + "\n    " + OPEN))

        self.assertEqual(scan("let (_key, _guard) = install_test_operator_key();"), set())
        for prefix in ("let (_key, _) = install_test_operator_key();",
                       "let (_key, g) = install_test_operator_key();\n    drop(g);"):
            with self.subTest(prefix=prefix):
                self.assertEqual(scan(prefix), FLAGGED)

    def test_the_helper_shape_credits_only_a_canonical_caller(self):
        helper = ("struct Env { _lock: MutexGuard<'static, ()> }\n"
                  "impl Env {\n    fn plain() -> Self {\n        let lock = ENV_LOCK.blocking_lock();\n"
                  "        unsafe { std::env::set_var(\"B\", \"1\") };\n        Self { _lock: lock }\n    }\n}\n")
        self.assertEqual(self.flagged(WRITER + helper + reader("let _e = Env::plain();")), set())
        self.assertEqual(self.flagged(WRITER + helper + reader("let _ = Env::plain();")), FLAGGED)
        self.assertEqual(self.flagged(WRITER + helper + reader("Env::plain();")), FLAGGED)

    def test_a_helper_that_mentions_its_lock_twice_is_not_a_guard_helper(self):
        helper = ("struct Env { _lock: MutexGuard<'static, ()> }\n"
                  "impl Env {\n    fn plain() -> Self {\n        let lock = ENV_LOCK.blocking_lock();\n"
                  "        let _r = &lock;\n        Self { _lock: lock }\n    }\n}\n")
        self.assertEqual(self.flagged(WRITER + helper + reader("let _e = Env::plain();")), FLAGGED)

    def test_a_writer_that_does_not_hold_the_canonical_lock_is_unprotected(self):
        for between in ("drop(g);", "let _r = &g;"):
            with self.subTest(between=between):
                text = writer_with(between) + LOCKED_READER
                self.assertIn("tests/a.rs::writer", self.flagged(text))
        self.assertEqual(self.flagged(WRITER + LOCKED_READER), set())

    def test_a_macro_body_lock_in_an_enclosing_block_is_credited(self):
        self.assertEqual(self.flagged(MACRO_SETL + "#[test]\nfn t() { setl!(); }\n"), set())


class ReqwestIpOnly7526(Fixture):
    """#7526: reqwest to an IP-literal peer reads only Rust-side env; a hostname keeps it a reader."""

    CLIENT = "let _c = reqwest::Client::new();\n    let _r = _c.get(%s);"

    def reader_with(self, url, extra=""):
        return WRITER + extra + test_fn("reader", self.CLIENT % url)

    def test_reqwest_to_an_ipv4_literal_is_not_a_reader(self):
        self.assertEqual(self.flagged(self.reader_with('"http://127.0.0.1:8080/x"')), set())

    def test_reqwest_to_an_ipv6_literal_is_not_a_reader(self):
        self.assertEqual(self.flagged(self.reader_with('"http://[::1]:8080/x"')), set())

    def test_reqwest_to_a_bound_local_addr_is_not_a_reader(self):
        text = self.reader_with("&format!(\"http://{}/x\", listener.local_addr().unwrap())")
        self.assertEqual(self.flagged(text), set())

    def test_reqwest_to_a_hostname_is_a_reader(self):
        self.assertEqual(self.flagged(self.reader_with('"http://example.test/x"')), FLAGGED)

    def test_reqwest_to_localhost_is_a_reader(self):
        self.assertEqual(self.flagged(self.reader_with('"http://localhost:8080/x"')), FLAGGED)

    def test_reqwest_without_any_ip_evidence_is_a_reader(self):
        self.assertEqual(self.flagged(self.reader_with("url")), FLAGGED)

    def test_a_placeholder_host_without_local_addr_is_a_reader(self):
        self.assertEqual(self.flagged(self.reader_with('"http://{}/x"')), FLAGGED)

    def reader_calling(self, helper):
        body = self.CLIENT % '"http://127.0.0.1:8080/x"' + "\n    other();"
        return WRITER + helper + test_fn("reader", body)

    def test_one_hostname_url_in_a_called_fn_keeps_the_reader(self):
        text = self.reader_calling('fn other() { let _u = "https://example.test/"; }\n')
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_hostname_url_in_an_unrelated_fn_does_not_matter(self):
        text = self.reader_with('"http://127.0.0.1:8080/x"', 'const U: &str = "https://example.test/";\n')
        self.assertEqual(self.flagged(text), set())

    def test_a_resolver_word_in_a_called_fn_keeps_the_reader(self):
        text = self.reader_calling('fn other() { let _ = c.resolve("x", a); }\n')
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_commented_hostname_does_not_count(self):
        text = self.reader_with('"http://127.0.0.1:8080/x"', "// see https://example.test/ for the docs\n")
        self.assertEqual(self.flagged(text), set())

    def test_ip_only_text_verdicts(self):
        self.assertTrue(gate.ip_only_text('get("http://192.0.2.5:80/a")'))
        self.assertFalse(gate.ip_only_text('get("https://example.com/a")'))
        self.assertFalse(gate.ip_only_text("get(url)"))
        self.assertFalse(gate.ip_only_text(None))


class Issue7997(Fixture):
    """#7997: "A URL literal whose host is a `{..}` placeholder is accepted as IP-only whenever `local_addr(`
    appears ANYWHERE in the text ... any other placeholder, a URL with no literal scheme, or a URL from env
    keeps the reader" / "`local_addr(` alone is not IP evidence"."""

    OTHER_FN_ADDR = "fn bind_peer(l: &L) -> A { l.local_addr().unwrap() }\n"

    def reader_text(self, body, extra=OTHER_FN_ADDR):
        return WRITER + extra + test_fn("reader", "let _c = reqwest::Client::new();\n    " + body)

    READERS = {
        "param_host_with_local_addr_in_another_fn": 'let host = "peer.example";\n    let _r = _c.get(format!("http://{}/x", host));',
        "named_inline_host": 'let host = "peer.example";\n    let _r = _c.get(format!("http://{host}:9/x"));',
        "const_host": 'const H: &str = "peer.example";\n    let _r = _c.get(format!("http://{H}/x"));',
        "scheme_placeholder": 'let _r = _c.get(format!("{}://{}/x", scheme, host));',
        "env_url": 'let _r = _c.get(std::env::var("PEER_URL").unwrap());',
        "named_arg_hostname": 'let _r = _c.get(format!("http://{h}/x", h = "peer.example"));',
        "mixed_host": 'let _r = _c.get(format!("http://{}.example/x", name));',
        "positional_second_arg_is_the_host": 'let _r = _c.get(format!("http://{}/{}", "peer.example", l.local_addr().unwrap()));',
    }

    def test_hostname_placeholders_and_unknown_urls_stay_readers(self):
        for name, body in self.READERS.items():
            with self.subTest(shape=name):
                self.assertEqual(self.flagged(self.reader_text(body)), FLAGGED)

    IP_ONLY = {
        "named_inline_local_addr": 'let addr = l.local_addr().unwrap();\n    let _r = _c.get(format!("http://{addr}/x"));',
        "named_arg_local_addr": 'let _r = _c.get(format!("http://{a}/x", a = l.local_addr().unwrap()));',
        "positional_local_addr": 'let _r = _c.get(format!("http://{}/x", l.local_addr().unwrap()));',
        "let_chain": 'let a = l.local_addr().unwrap();\n    let b = a;\n    let _r = _c.get(format!("http://{b}/x"));',
        "ip_literal_binding": 'let h = "127.0.0.1";\n    let _r = _c.get(format!("http://{h}:9/x"));',
    }

    def test_data_flow_from_local_addr_or_an_ip_literal_is_not_a_reader(self):
        for name, body in self.IP_ONLY.items():
            with self.subTest(shape=name):
                text = self.reader_text(body, "")
                self.assertEqual(self.flagged(text), set())

    def test_a_call_result_is_not_traced_and_fails_closed(self):
        body = 'let addr = bind_peer(&l);\n    let _r = _c.get(format!("http://{addr}/x"));'
        self.assertEqual(self.flagged(self.reader_text(body)), FLAGGED)

    def test_ip_only_text_verdicts(self):
        self.assertFalse(gate.ip_only_text('let h = "x.test"; let u = format!("http://{h}/", h); l.local_addr()'))
        self.assertFalse(gate.ip_only_text("get(l.local_addr().unwrap())"))
        self.assertTrue(gate.ip_only_text('get(format!("http://{}/", l.local_addr().unwrap()))'))


PARAM_KEY = """
use tokio::sync::Mutex;
static LOCK: Mutex<()> = Mutex::const_new(());
const KEY: &str = "AI_MEMORY_X";
fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}
fn set_extra(extra: &[(&str, &str)]) {
    for (k, v) in extra {
        unsafe { std::env::set_var(k, v) };
    }
}
#[test]
fn a() {
    let Some(_u) = pg_url() else { return };
    let _g = LOCK.blocking_lock();
    set_extra(&[(KEY, "1")]);
}
#[test]
fn b() {
    let Some(_u) = pg_url() else { return };
    let _g = LOCK.blocking_lock();
    set_extra(&[]);
}
"""

FIELD_KEY = """
use tokio::sync::Mutex;
static LOCK: Mutex<()> = Mutex::const_new(());
const KEY: &str = "AI_MEMORY_X";
fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}
struct G {
    key: &'static str,
}
impl G {
    fn set(key: &'static str, value: &str) -> Self {
        unsafe { std::env::set_var(key, value) };
        Self { key }
    }
}
impl Drop for G {
    fn drop(&mut self) {
        unsafe { std::env::remove_var(self.key) };
    }
}
#[test]
fn a() {
    let Some(_u) = pg_url() else { return };
    let _l = LOCK.blocking_lock();
    let _g = G::set(KEY, "1");
}
#[test]
fn b() {
    let Some(_u) = pg_url() else { return };
    let _l = LOCK.blocking_lock();
    let _g = G::set("AI_MEMORY_Y", "1");
}
"""

ONCE_AFTER_READER = """
static INIT: std::sync::Once = std::sync::Once::new();
fn install() {
    INIT.call_once(|| unsafe { std::env::set_var("A", "1") });
}
#[test]
fn a() {
    let _u = postgres_url();
    install();
    let _c = db::open(":memory:");
}
#[test]
fn b() {
    let _u = postgres_url();
    install();
}
"""


class Issue7475(Fixture):
    """#7475: the hand-check false positives that are gate defects, and the one that is not."""

    def test_write_key_from_a_parameter_resolves_through_the_callers(self):
        # federation_confine_ns_scope_2711_pg: `for (k, v) in extra { set_var(k, v) }`.
        self.assertEqual(self.flagged(PARAM_KEY), set())

    def test_unresolvable_parameter_key_still_counts_as_any_var(self):
        text = PARAM_KEY.replace('set_extra(&[(KEY, "1")]);', 'let name = "x".to_string();\n    set_extra(&[(&name, "1")]);')
        self.assertEqual(self.flagged(text), {"tests/a.rs::a", "tests/a.rs::b"})

    def test_reader_of_a_resolved_written_var_is_still_a_reader(self):
        text = PARAM_KEY.replace('"AI_MEMORY_TEST_POSTGRES_URL"', '"AI_MEMORY_X"')
        self.assertEqual(self.flagged(text), {"tests/a.rs::a", "tests/a.rs::b"})

    def test_write_key_from_a_field_resolves_through_the_constructor(self):
        # issue_2059_2060_covenant_pg: `CovenantEnvGuard { key }` written in set and in Drop.
        self.assertEqual(self.flagged(FIELD_KEY), set())

    def test_a_method_call_of_another_type_is_not_a_caller_of_an_associated_fn(self):
        # issue_2059_2060_covenant_pg: `HOOK.set(Box::new(..))` names `set` but cannot call the
        # receiver-less `G::set`, so its argument is no key of G.
        text = FIELD_KEY.replace("#[test]\nfn a() {", "fn hook() {\n    let _ = HOOK.set(Box::new(|| ()));\n}\n#[test]\nfn a() {", 1)
        self.assertEqual(self.flagged(text), set())

    def test_a_cli_command_run_opens_the_db_and_is_a_reader(self):
        # valid_from_write_surface_2258: `cli::store::run(&db_path, ..)` reaches db::open (C getenv),
        # so the test stays a reader once `AppConfig::default()` no longer is one.
        for body in ("let _r = ai_memory::cli::store::run(&p, args, false, &cfg, None, &mut out);",
                     "let _r = cli::recall::run_with_curator(&p, args);"):
            with self.subTest(body=body):
                self.assertEqual(self.flagged(WRITER + reader("let cfg = AppConfig::default();", body)),
                                 {"tests/a.rs::reader"})

    def test_field_key_set_from_a_local_still_counts_as_any_var(self):
        text = FIELD_KEY.replace('G::set("AI_MEMORY_Y", "1")', 'G::set(&name, "1")')
        self.assertEqual(self.flagged(text), {"tests/a.rs::a", "tests/a.rs::b"})

    def test_app_config_default_is_not_a_reader(self):
        # config_precedence: `..AppConfig::default()` is a derived Default, no env and no C getenv.
        for body in ("let _c = AppConfig::default();", "let _c = AppConfig { db: None, ..AppConfig::default() };",
                     "let _c = ai_memory::config::AppConfig::default();"):
            with self.subTest(body=body):
                self.assertEqual(self.flagged(WRITER + reader("let _x = 1;", body)), set())

    def test_app_config_load_is_still_a_reader(self):
        for body in ("let _c = AppConfig::load();", "let _c = AppConfig::load_from(&p);"):
            with self.subTest(body=body):
                self.assertEqual(self.flagged(WRITER + reader("let _x = 1;", body)), {"tests/a.rs::reader"})

    def test_once_writer_after_a_reader_still_races_the_other_tests(self):
        # serve_postgres_continuation2: the Once runs in whichever test gets there first, while a
        # sibling test thread is still in its postgres_url() or db::open. This shape is not a gate defect.
        self.assertEqual(self.flagged(ONCE_AFTER_READER), {"tests/a.rs::a", "tests/a.rs::b"})


class Issue7992(Fixture):
    """#7992: a tokio `lock()` / `lock_owned()` is a future; without `.await` no lock is held, so
    `let _g = ENV_LOCK.lock();` must not be credited (in a test, a helper tail or a macro body)."""

    HELPER = ("struct Env { _lock: MutexGuard<'static, ()> }\n"
              "impl Env {\n    fn plain() -> Self {\n        let lock = %s;\n"
              "        unsafe { std::env::set_var(\"B\", \"1\") };\n        Self { _lock: lock }\n    }\n}\n")

    def verdict(self, prefix):
        return self.flagged(WRITER + reader(prefix))

    def test_an_unawaited_tokio_lock_is_not_credited(self):
        for prefix in ("let _g = ENV_LOCK.lock();", "let _g = ENV_LOCK.lock_owned();",
                       "let mut g = ENV_LOCK.lock();"):
            with self.subTest(prefix=prefix):
                self.assertEqual(self.verdict(prefix), FLAGGED)

    def test_the_awaited_and_unwrapped_forms_are_credited(self):
        for prefix in ("let _g = ENV_LOCK.lock().await;", "let _g = ENV_LOCK.lock_owned().await;",
                       "let _g = ENV_LOCK.lock().unwrap();", "let _g = ENV_LOCK.lock().expect(\"x\");",
                       "let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());",
                       "let _g = ENV_LOCK.blocking_lock();"):
            with self.subTest(prefix=prefix):
                self.assertEqual(self.verdict(prefix), set())

    def test_an_unawaited_lock_in_a_guard_helper_is_not_credited(self):
        helper = self.HELPER % "ENV_LOCK.lock()"
        self.assertEqual(self.flagged(WRITER + helper + reader("let _e = Env::plain();")), FLAGGED)
        helper = self.HELPER % "ENV_LOCK.lock().await"
        self.assertEqual(self.flagged(WRITER + helper + reader("let _e = Env::plain();")), set())

    def test_an_unawaited_lock_in_a_macro_body_is_not_credited(self):
        macro = MACRO_SETL.replace("ENV_LOCK.blocking_lock()", "ENV_LOCK.lock()")
        text = WRITER + macro + test_fn("w2", "setl!();") + LOCKED_READER
        # the macro write is unprotected: the other writers and the reader race it
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader", "tests/a.rs::writer", "tests/a.rs::w2"})


class Issue7993(Fixture):
    """#7993: a helper whose tail, `return` or field initialiser merely CONTAINS an unbound lock call is
    not a guard-returning helper (module docstring: "guards returned from fns NOT credited"; the #7623
    class). Only the struct helper shape (helper_ret_guard) hands a lock to its caller."""

    HELPERS = {
        "tail_drops_the_guard": "fn h() { drop(ENV_LOCK.blocking_lock()) }\n",
        "tail_measures_the_guard": "fn h() -> usize { std::mem::size_of_val(&ENV_LOCK.blocking_lock()) }\n",
        "tail_is_an_unawaited_future": "fn h() { ENV_LOCK.lock() }\n",
        "field_init_tail": "fn h() -> Holder<MutexGuard<'static, ()>> { Holder { _g: ENV_LOCK.blocking_lock() } }\n",
    }

    def test_a_helper_that_only_contains_a_lock_call_is_not_credited(self):
        for name, helper in self.HELPERS.items():
            with self.subTest(helper=name):
                text = WRITER + HOLDER + helper + reader("let _x = h();")
                self.assertEqual(self.flagged(text), FLAGGED)

    WHOLE_VALUE = {
        "plain_guard_returning_tail": "fn h() -> MutexGuard<'static, ()> { ENV_LOCK.blocking_lock() }\n",
        "plain_guard_returning_return": "fn h() -> MutexGuard<'static, ()> { return ENV_LOCK.blocking_lock(); }\n",
        "get_or_init_tail": ("fn h() -> MutexGuard<'static, ()> {\n"
                             "    ENV_LOCK.get_or_init(|| Mutex::new(()))\n"
                             "        .lock()\n        .unwrap_or_else(std::sync::PoisonError::into_inner)\n}\n"),
    }

    def test_a_lock_call_that_is_the_whole_returned_value_is_credited(self):
        # #7993 Proposed fix: "add it as a second named helper shape that requires the lock expression
        # (lock call plus GUARD_CHAIN only) to BE the whole tail".
        for name, helper in self.WHOLE_VALUE.items():
            with self.subTest(helper=name):
                self.assertEqual(self.flagged(WRITER + HOLDER + helper + reader("let _x = h();")), set())

    def test_the_struct_helper_shape_is_still_credited(self):
        helper = ("struct Env { _lock: MutexGuard<'static, ()> }\n"
                  "impl Env {\n    fn plain() -> Self {\n        let lock = ENV_LOCK.blocking_lock();\n"
                  "        unsafe { std::env::set_var(\"B\", \"1\") };\n        Self { _lock: lock }\n    }\n}\n")
        self.assertEqual(self.flagged(WRITER + helper + reader("let _e = Env::plain();")), set())


class Issue7994(Fixture):
    """#7994: "A reader inside the closure or async block passed to `std::thread::spawn`, `tokio::spawn` or
    `tokio::task::spawn_blocking` runs on another thread or task that is not bound to the guard's scope ...
    The same holds for a writer: `std::thread::spawn(|| set_var(..))` under the lock is counted as a locked
    write. This fails open." / "a detached site is never covered by a guard of the enclosing fn (fail closed)".
    """

    HOLD = "let _g = ENV_LOCK.blocking_lock();\n    "
    SPAWNS = {
        "thread_spawn": "std::thread::spawn(|| { %s });",
        "thread_spawn_move": "std::thread::spawn(move || { %s });",
        "tokio_spawn_async": "tokio::spawn(async { %s });",
        "tokio_spawn_async_move": "tokio::spawn(async move { %s });",
        "spawn_blocking": "tokio::task::spawn_blocking(move || { %s });",
        "spawn_local": "tokio::task::spawn_local(async { %s });",
        "bare_imported_spawn": "spawn(|| { %s });",
        "thread_builder": "std::thread::Builder::new().spawn(move || { %s }).unwrap();",
        "turbofish": "tokio::spawn::<()>(async { %s });",
    }

    def test_a_reader_in_a_detached_spawn_is_not_covered_by_the_enclosing_lock(self):
        for name, form in self.SPAWNS.items():
            with self.subTest(spawn=name):
                self.assertEqual(self.flagged(WRITER + reader(self.HOLD + form % OPEN, "")), FLAGGED)

    def test_a_helper_called_inside_a_spawn_does_not_inherit_the_lock(self):
        helper = "fn peek() { let _c = db::open(\":memory:\"); }\n"
        spawned = reader(self.HOLD + "std::thread::spawn(|| { peek(); });", "")
        direct = reader(self.HOLD + "peek();", "")
        self.assertEqual(self.flagged(WRITER + helper + spawned), FLAGGED)
        self.assertEqual(self.flagged(WRITER + helper + direct), set())  # control: the same call, not detached

    def test_a_writer_in_a_detached_spawn_is_not_a_locked_write(self):
        writer = ("#[test]\nfn w2() {\n    %sstd::thread::spawn(|| { unsafe { std::env::set_var(\"B\", \"1\") }; });\n}\n"
                  % self.HOLD)
        flagged = self.flagged(WRITER + LOCKED_READER + writer)
        self.assertIn("tests/a.rs::w2", flagged)

    def test_a_lock_taken_inside_the_spawn_is_not_modelled_and_stays_flagged(self):
        # the canonical shape is a top-level statement of the test fn; a guard made inside a closure
        # is not credited to anything (fail closed), so the gate asks for the lock in the test fn itself
        inner = "let _h = ENV_LOCK.blocking_lock(); %s" % OPEN
        self.assertEqual(self.flagged(WRITER + reader("std::thread::spawn(|| { %s });" % inner, "")), FLAGGED)

    def test_the_outer_lock_still_covers_a_reader_outside_the_spawn(self):
        text = WRITER + reader(self.HOLD + "std::thread::spawn(|| {});", OPEN)
        self.assertEqual(self.flagged(text), set())

    def test_a_spawn_method_on_a_process_is_not_a_detach_site(self):
        text = WRITER + reader(self.HOLD + "let _p = std::process::Command::new(\"true\").spawn();", OPEN)
        self.assertEqual(self.flagged(text), set())


class Issue7995(Fixture):
    """#7995: "A call to a Once-gated setter earns the fn a `once:<setter>` credit ... Two shapes earn it
    without the call ever running before the reader: an unbraced uncalled closure:
    `let _c = || permissive_attestation_for_tests();` / a cfg-disabled call:
    `#[cfg(any())] permissive_attestation_for_tests();`" / "credit a Once setter only as a statement-level
    call in the fn's top-level block ... and skip any statement preceded by a `#[cfg(` attribute".
    """

    FIRST = test_fn("a", "permissive_attestation_for_tests();\n    " + OPEN)
    SETUP = "fn setup() { permissive_attestation_for_tests(); }\n"
    NOT_RUN = {
        "unbraced_closure": "let _c = || %s;",
        "cfg_disabled": "#[cfg(any())]\n    %s;",
        "cfg_not_test": "#[cfg(not(test))]\n    %s;",
        "closure_passed_on": "run(|| %s);",
        "short_circuit": "let _ = false && %s.is_ok();",
    }
    RAN = {
        "statement": "%s;",
        "let_wildcard": "let _ = %s;",
        "let_named": "let _r = %s;",
    }

    def _flagged_b(self, shape, call, setup=""):
        text = self.FIRST + setup + test_fn("b", (shape % call) + "\n    " + OPEN)
        return self.flagged(text)

    def test_a_setter_call_that_never_ran_is_not_credited(self):
        for name, shape in self.NOT_RUN.items():
            with self.subTest(shape=name):
                self.assertEqual(self._flagged_b(shape, "permissive_attestation_for_tests()"), {"tests/a.rs::b"})

    def test_a_helper_that_persists_the_setter_is_not_credited_when_never_called(self):
        for name, shape in self.NOT_RUN.items():
            with self.subTest(shape=name):
                self.assertEqual(self._flagged_b(shape, "setup()", self.SETUP), {"tests/a.rs::b"})

    def test_a_setter_call_that_certainly_ran_is_credited(self):
        for name, shape in self.RAN.items():
            with self.subTest(shape=name):
                self.assertEqual(self._flagged_b(shape, "permissive_attestation_for_tests()"), set())
                self.assertEqual(self._flagged_b(shape, "setup()", self.SETUP), set())


class Issue7996(Fixture):
    """#7996: "`DIRECT_MUTATION` ... only matches `set_var(` / `remove_var(` ... Three env-writing forms are
    not seen as writers: an aliased import: `use std::env::set_var as sv;` then `sv("A", "1")` / a turbofish
    fn pointer: `let f = std::env::set_var::<&str, &str>; f("A", "1");` / the libc writers `libc::setenv(` /
    `libc::unsetenv(` / `libc::putenv(`" / "one fixture per form, each must create a write site".
    """

    FORMS = {
        "alias": ("use std::env::set_var as sv;\n", "unsafe { sv(\"A\", \"1\") };"),
        "alias_in_braces": ("use std::env::{remove_var as rv, set_var as sv};\n", "unsafe { rv(\"A\") };"),
        "alias_remove": ("use std::env::remove_var as rv;\n", "unsafe { rv(\"A\") };"),
        "turbofish_call": ("", "unsafe { std::env::set_var::<&str, &str>(\"A\", \"1\") };"),
        "turbofish_pointer": ("", "let f = std::env::set_var::<&str, &str>;\n    unsafe { f(\"A\", \"1\") };"),
        "bare_pointer": ("use std::env::set_var;\n", "let f = set_var;\n    unsafe { f(\"A\", \"1\") };"),
        "libc_setenv": ("", "unsafe { libc::setenv(c\"A\".as_ptr(), c\"1\".as_ptr(), 1) };"),
        "libc_unsetenv": ("", "unsafe { libc::unsetenv(c\"A\".as_ptr()) };"),
        "libc_putenv": ("", "unsafe { libc::putenv(buf.as_mut_ptr()) };"),
        "libc_clearenv": ("", "unsafe { libc::clearenv() };"),
    }

    def text(self, header, body, locked):
        lock = "let _g = ENV_LOCK.blocking_lock();\n    " if locked else ""
        return header + LOCK_HEAD + LOCKED_READER + test_fn("w", lock + body)

    def test_every_form_is_a_write_site_that_must_hold_the_lock(self):
        for name, (header, body) in self.FORMS.items():
            with self.subTest(form=name):
                self.assertIn("tests/a.rs::w", self.flagged(self.text(header, body, False)))

    def test_every_form_is_clean_under_the_lock(self):
        for name, (header, body) in self.FORMS.items():
            with self.subTest(form=name):
                self.assertEqual(self.flagged(self.text(header, body, True)), set())

    def test_a_method_or_longer_name_is_not_a_writer(self):
        body = "let _x = cfg.setenv(1); let _y = my_setenv(2); let _z = unsetenv_all(3);"
        self.assertEqual(self.flagged(self.text("", body, False)), set())


class Issue7999(unittest.TestCase):
    """#7628: "The `let_names` docstring at scripts/check-test-env-mutation.py:612-614 also states that
    `let _ = guard;` drops the guard. That is wrong for a named place: `let _ = g;` does not move g
    (drop probe: held=true). Only `let _ = LOCK.call();` drops a temporary." / "Correct the let_names docstring."
    """

    def test_let_names_docstring_tells_a_place_from_a_temporary(self):
        doc = " ".join(gate.let_names.__doc__.split())
        self.assertIn("place", doc)
        self.assertIn("temporary", doc)
        self.assertIn("`let _ = g;`", doc)
        self.assertNotIn("neither does `let _ = ..`: that drops the value", doc)


class Issue8034(Fixture):
    """#8034: "Only an awaited guard expression counts" -- an `async fn` lock helper called without
    `.await` returns a future and holds nothing, so `let _g = env_lock();` is not a held lock."""

    HELPER = ("use tokio::sync::MutexGuard;\n"
              "async fn env_lock() -> MutexGuard<'static, ()> {\n    ENV_LOCK.lock().await\n}\n")

    def reader_text(self, call):
        return (WRITER + self.HELPER
                + "#[tokio::test]\nasync fn reader() {\n    let _g = %s;\n    let _c = db::open(\":memory:\");\n}\n" % call)

    def test_an_unawaited_async_lock_helper_is_flagged(self):
        self.assertEqual(self.flagged(self.reader_text("env_lock()")), FLAGGED)

    def test_the_awaited_async_lock_helper_is_credited(self):
        self.assertEqual(self.flagged(self.reader_text("env_lock().await")), set())

    def test_an_unawaited_async_helper_with_a_question_mark_is_flagged(self):
        self.assertEqual(self.flagged(self.reader_text("env_lock()?")), FLAGGED)

    def test_a_sync_lock_helper_called_without_await_is_still_credited(self):
        helper = "fn env_lock() -> MutexGuard<'static, ()> {\n    ENV_LOCK.blocking_lock()\n}\n"
        text = (WRITER + "use tokio::sync::MutexGuard;\n" + helper
                + "#[test]\nfn reader() {\n    let _g = env_lock();\n    let _c = db::open(\":memory:\");\n}\n")
        self.assertEqual(self.flagged(text), set())


class Issue8035(Fixture):
    """#8035: "resolve the placeholder by scope: the binding must be the one visible at the use site;
    a same-named parameter, `for` variable or closure parameter shadows the check; undecidable keeps the
    reader (fail closed)". A `let` of another fn, or one that follows the use, is no evidence either."""

    GET = 'let c = reqwest::Client::new();\n    let _r = c.get(format!("http://{}/x", host));'

    SHADOWED = {
        "helper_parameter": ('fn helper(host: &str) {\n    %s\n}\n' % GET
                             + test_fn("reader", 'let host = "127.0.0.1";\n    let _u = host;\n    helper("peer.example");')),
        "for_variable": test_fn("reader", 'let host = "127.0.0.1";\n    let c = reqwest::Client::new();\n'
                                '    for host in ["peer.example"] {\n        let _r = c.get(format!("http://{}/x", host));\n    }'),
        "closure_parameter": test_fn("reader", 'let host = "127.0.0.1";\n    let c = reqwest::Client::new();\n'
                                     '    let f = |host: &str| c.get(format!("http://{}/x", host));\n    f("peer.example");'),
        "pattern_binding": test_fn("reader", 'let host = "127.0.0.1";\n    let c = reqwest::Client::new();\n'
                                   '    if let Some(host) = peer() {\n        let _r = c.get(format!("http://{}/x", host));\n    }'),
        "let_follows_the_use": test_fn("reader", 'let c = reqwest::Client::new();\n'
                                       '    let _r = c.get(format!("http://{}/x", host));\n    let host = "127.0.0.1";'),
        "let_of_another_fn": ('fn helper() {\n    let c = reqwest::Client::new();\n'
                              '    let _r = c.get(format!("http://{}/x", host));\n}\n'
                              + test_fn("reader", 'let host = "127.0.0.1";\n    helper();')),
    }

    def test_a_shadowed_or_foreign_binding_keeps_the_reader(self):
        for name, body in self.SHADOWED.items():
            with self.subTest(shape=name):
                self.assertEqual(self.flagged(WRITER + body), FLAGGED)

    def test_the_plain_let_in_the_same_fn_is_still_ip_only(self):
        body = test_fn("reader", 'let host = "127.0.0.1";\n    ' + self.GET)
        self.assertEqual(self.flagged(WRITER + body), set())

    def test_ip_only_text_resolves_by_scope(self):
        text = 'let host = "127.0.0.1"; get(format!("http://{}/x", host))'
        self.assertTrue(gate.ip_only_text(text))
        self.assertFalse(gate.ip_only_text(text, "fn helper(host: &str) "))


class Issue8036(Fixture):
    """#8036: "ip_expr accepts any expression merely CONTAINING `local_addr(`" -- require the canonical
    shape: assigned from `<x>.local_addr()` optionally followed by `.unwrap()`, `.expect(..)` or `?`."""

    def reader_with(self, host):
        body = 'let c = reqwest::Client::new();\n    let _r = c.get(format!("http://{}/x", %s));' % host
        return WRITER + test_fn("reader", body)

    WRAPPED = {
        "resolver_wrapper": "resolve_name(l.local_addr().unwrap())",
        "method_after_the_addr": "l.local_addr().unwrap().to_string() + peer_suffix()",
        "call_in_a_block": "{ other(); l.local_addr().unwrap() }",
        "not_a_method_call": "local_addr()",
        "string_concat": 'format!("peer.example/{}", l.local_addr().unwrap())',
    }

    def test_a_wrapped_local_addr_keeps_the_reader(self):
        for name, host in self.WRAPPED.items():
            with self.subTest(shape=name):
                self.assertEqual(self.flagged(self.reader_with(host)), FLAGGED)

    CANONICAL = {
        "unwrap": "l.local_addr().unwrap()",
        "expect": 'l.local_addr().expect("bound")',
        "question_mark": "l.local_addr()?",
        "field_receiver": "self.listener.local_addr().unwrap()",
    }

    def test_the_canonical_local_addr_shapes_are_ip_only(self):
        for name, host in self.CANONICAL.items():
            with self.subTest(shape=name):
                self.assertEqual(self.flagged(self.reader_with(host)), set())


class Issue8037(Fixture):
    """#8037: "An alias of an alias writer (`use a1 as b1`) is not a write site" -- the alias set must be
    closed under `as` renames, in any order of the `use` items."""

    def writer_via(self, uses):
        return (WRITER_HEAD + uses
                + '#[tokio::test]\nasync fn writer() {\n    let _lock = ENV_LOCK.lock().await;\n'
                + '    unsafe { b1("A", "1") };\n}\n' + test_fn("reader", 'let _c = db::open(":memory:");'))

    def test_an_alias_of_an_alias_writer_is_a_write_site(self):
        text = self.writer_via("use std::env::set_var as a1;\nuse a1 as b1;\n")
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_the_use_items_may_come_in_any_order(self):
        text = self.writer_via("use a1 as b1;\nuse std::env::set_var as a1;\n")
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_three_step_alias_chain_is_a_write_site(self):
        text = self.writer_via("use std::env::set_var as a0;\nuse a0 as a1;\nuse a1 as b1;\n")
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_use_aliases_is_closed_under_renames(self):
        got = gate.use_aliases("use std::env::set_var as a1; use a1 as b1; use other as c1;")
        self.assertEqual(got, {"a1", "b1"})


WRITER_HEAD = "use tokio::sync::Mutex;\nstatic ENV_LOCK: Mutex<()> = Mutex::const_new(());\n"


class Issue8038(Fixture):
    """#8038: "a same-file fn named as a value (an identifier argument not followed by `(`) is live and is
    judged with an EMPTY caller context (fail closed)" and "a `macro_rules!` body whose expansion contains
    a DETACH call makes the macro's invocation arguments detached spans"."""

    OPEN = 'let _c = db::open(":memory:");'
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"

    def test_a_fn_item_handed_to_spawn_by_name_runs_detached(self):
        text = WRITER + "fn work() { %s }\n" % self.OPEN + self.LOCKED % "std::thread::spawn(work).join().unwrap();"
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_path_to_a_fn_item_handed_to_spawn_runs_detached(self):
        text = (WRITER + "mod jobs { pub fn work() { %s } }\n" % self.OPEN
                + self.LOCKED % "std::thread::spawn(jobs::work).join().unwrap();")
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_the_same_fn_called_directly_under_the_lock_is_covered(self):
        text = WRITER + "fn work() { %s }\n" % self.OPEN + self.LOCKED % "work();"
        self.assertEqual(self.flagged(text), set())

    BG = "macro_rules! bg {\n    ($e:expr) => { std::thread::spawn($e) };\n}\n"

    def test_the_arguments_of_a_spawning_macro_run_detached(self):
        text = WRITER + self.BG + self.LOCKED % "bg!(move || { %s }).join().unwrap();" % self.OPEN
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_fn_item_handed_to_a_spawning_macro_runs_detached(self):
        text = WRITER + self.BG + "fn work() { %s }\n" % self.OPEN + self.LOCKED % "bg!(work).join().unwrap();"
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_macro_that_does_not_spawn_keeps_the_lock(self):
        text = (WRITER + "macro_rules! twice {\n    ($e:expr) => { $e; $e };\n}\n"
                + self.LOCKED % ("twice!(%s);" % self.OPEN))
        self.assertEqual(self.flagged(text), set())


class Issue8033(Fixture):
    """#8033: "when a spawn argument is a bare identifier, resolve it to its `let` closure initialiser in the
    same fn and treat that closure span as detached" -- `let work = move || { .. }; spawn(work);` runs the
    closure outside the guard of the enclosing fn."""

    OPEN = 'let _c = db::open(":memory:");'
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"

    BOUND = {
        "move_closure": "let work = move || { %s };\n    std::thread::spawn(work).join().unwrap();",
        "plain_closure": "let work = || { %s };\n    std::thread::scope(|s| { s.spawn(work); });",
        "async_block": "let work = async move { %s };\n    tokio::spawn(work);",
    }

    def test_a_closure_bound_to_a_variable_and_spawned_runs_detached(self):
        for name in ("move_closure", "plain_closure", "async_block"):
            with self.subTest(shape=name):
                text = WRITER + self.LOCKED % (self.BOUND[name] % self.OPEN)
                self.assertEqual(self.flagged(text), FLAGGED)

    def test_the_bound_closure_called_directly_keeps_the_lock(self):
        text = WRITER + self.LOCKED % ("let work = move || { %s };\n    work();" % self.OPEN)
        self.assertEqual(self.flagged(text), set())

    def test_an_identifier_that_is_no_closure_changes_nothing(self):
        text = WRITER + self.LOCKED % ("let work = make_task();\n    std::thread::spawn(work);\n    %s" % self.OPEN)
        self.assertEqual(self.flagged(text), set())


class Issue8044(Fixture):
    """#8044: a same-file helper fn that spawns its parameter detaches the argument of every call of it."""

    OPEN = 'let _c = db::open(":memory:");'
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"
    BG = "fn bg<F: FnOnce() + Send + 'static>(f: F) { std::thread::spawn(f).join().unwrap(); }\n"

    def test_a_closure_handed_to_a_spawning_helper_runs_detached(self):
        text = WRITER + self.BG + self.LOCKED % ("bg(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_variable_handed_to_a_spawning_helper_runs_detached(self):
        text = WRITER + self.BG + self.LOCKED % ("let work = move || { %s };\n    bg(work);" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_fn_item_handed_to_a_spawning_helper_runs_detached(self):
        text = WRITER + self.BG + "fn work() { %s }\n" % self.OPEN + self.LOCKED % "bg(work);"
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_helper_that_forwards_its_parameter_to_a_spawning_helper_detaches(self):
        text = (WRITER + self.BG + "fn outer<F: FnOnce() + Send + 'static>(g: F) { bg(g); }\n"
                + self.LOCKED % ("outer(move || { %s });" % self.OPEN))
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_method_helper_that_spawns_its_parameter_detaches(self):
        text = (WRITER + "struct P;\nimpl P {\n    fn bg<F: FnOnce() + Send + 'static>(&self, f: F) { std::thread::spawn(f); }\n}\n"
                + self.LOCKED % ("P.bg(move || { %s });" % self.OPEN))
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_helper_that_runs_its_parameter_on_the_same_thread_keeps_the_lock(self):
        text = (WRITER + "fn run<F: FnOnce()>(f: F) { f() }\n"
                + self.LOCKED % ("run(move || { %s });" % self.OPEN))
        self.assertEqual(self.flagged(text), set())

    def test_a_helper_that_spawns_something_else_keeps_the_lock(self):
        text = (WRITER + "fn run<F: FnOnce()>(f: F) { std::thread::spawn(|| {}); f() }\n"
                + self.LOCKED % ("run(move || { %s });" % self.OPEN))
        self.assertEqual(self.flagged(text), set())


class Issue8045(Fixture):
    """#8045: a closure variable rebound before it is spawned is resolved to a fixpoint, bounded by
    MAX_REBIND_HOPS, and a chain past the bound is flagged, never cleared."""

    OPEN = 'let _c = db::open(":memory:");'
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"

    def test_a_rebound_closure_variable_runs_detached(self):
        body = "let f = move || { %s };\n    let g = f;\n    std::thread::spawn(g).join().unwrap();" % self.OPEN
        self.assertEqual(self.flagged(WRITER + self.LOCKED % body), FLAGGED)

    def test_a_twice_rebound_closure_variable_runs_detached(self):
        body = ("let f = move || { %s };\n    let g = f;\n    let h = g;\n"
                "    std::thread::spawn(h).join().unwrap();" % self.OPEN)
        self.assertEqual(self.flagged(WRITER + self.LOCKED % body), FLAGGED)

    def test_a_rebound_fn_item_runs_detached(self):
        text = (WRITER + "fn work() { %s }\n" % self.OPEN
                + self.LOCKED % "let g = work;\n    std::thread::spawn(g).join().unwrap();")
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_chain_past_the_hop_bound_is_flagged_not_cleared(self):
        hops = gate.MAX_REBIND_HOPS + 2
        lets = "".join("let v%d = v%d;\n    " % (i + 1, i) for i in range(hops))
        body = ("let v0 = move || { %s };\n    %sstd::thread::spawn(v%d).join().unwrap();" % (self.OPEN, lets, hops))
        self.assertEqual(self.flagged(WRITER + self.LOCKED % body), FLAGGED)

    def test_a_rebound_closure_variable_is_flagged_by_the_general_rule(self):
        # #8056: `f` appears inside another expression (`let g = f`), so it is no longer canonical: detached.
        body = "let f = move || { %s };\n    let g = f;\n    g();" % self.OPEN
        self.assertEqual(self.flagged(WRITER + self.LOCKED % body), FLAGGED)


class Issue8051(Fixture):
    """#8051: a closure carried into a spawn by any non-canonical expression is detached, never credited."""

    OPEN = 'let _c = db::open(":memory:");'
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"
    F0 = "let f0 = move || { %s };\n    " % OPEN
    SP = "std::thread::spawn(%s).join().unwrap();"

    def check(self, tail, expect=FLAGGED):
        self.assertEqual(self.flagged(WRITER + self.LOCKED % (self.F0 + tail)), expect)

    def test_boxed_closure(self):
        self.check("let g = Box::new(f0);\n    " + self.SP % "g")

    def test_typed_boxed_closure(self):
        self.check("let g: Box<dyn FnOnce() + Send> = Box::new(f0);\n    " + self.SP % "g")

    def test_cloned_closure(self):
        self.check("let g = f0.clone();\n    " + self.SP % "g")

    def test_closure_assigned_through_option(self):
        self.check("let mut g = None;\n    g = Some(f0);\n    " + self.SP % "g.unwrap()")

    def test_closure_in_struct_field(self):
        self.check("let s = S { f: f0 };\n    " + self.SP % "s.f")

    def test_closure_from_loop_pattern(self):
        self.check("for g in vec![f0] {\n        " + self.SP % "g" + "\n    }")

    def test_wrapping_closure(self):
        self.check(self.SP % "move || f0()")

    def test_match_arm_binding(self):
        self.check("let o = Some(f0);\n    match o {\n        Some(g) => { " + self.SP % "g" + " }\n        None => {}\n    }")

    def test_same_thread_call_keeps_the_lock(self):
        self.check("f0();", set())

    def test_canonical_rebind_is_still_flagged(self):
        self.check("let g = f0;\n    " + self.SP % "g")

    def test_boxed_carrier_is_flagged_even_when_only_called(self):
        # #8056: a closure name inside Box::new is not a canonical use, so it is detached (fail closed).
        self.check("let g = Box::new(f0);\n    g();")


class Issue8052(Fixture):
    """#8052: a detaching helper outside the file (tests/common, a use-imported name, a `#[path]` or `mod` file)
    detaches the argument of every call of it; a helper that runs its parameter inline does not."""

    OPEN = 'let _c = db::open(":memory:");'
    BG = "pub fn bg<F: FnOnce() + Send + 'static>(f: F) { std::thread::spawn(f); }\n"
    INLINE = "pub fn bg<F: FnOnce()>(f: F) { f() }\n"
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"

    def put_common(self, text):
        (SCRATCH / "tests" / "common").mkdir(exist_ok=True)
        (SCRATCH / "tests" / "common" / "mod.rs").write_text(text)

    def test_a_qualified_common_helper_detaches(self):
        self.put_common(self.BG)
        text = WRITER + self.LOCKED % ("common::bg(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_use_imported_common_helper_detaches(self):
        self.put_common(self.BG)
        text = "use common::bg;\n" + WRITER + self.LOCKED % ("bg(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_glob_imported_common_helper_detaches(self):
        self.put_common(self.BG)
        text = "use common::*;\n" + WRITER + self.LOCKED % ("bg(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_closure_variable_handed_to_a_common_helper_detaches(self):
        self.put_common(self.BG)
        text = WRITER + self.LOCKED % ("let work = move || { %s };\n    common::bg(work);" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_common_helper_that_forwards_to_another_detaches(self):
        self.put_common(self.BG + "pub fn outer<F: FnOnce() + Send + 'static>(g: F) { bg(g); }\n")
        text = WRITER + self.LOCKED % ("common::outer(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_path_module_helper_detaches(self):
        (SCRATCH / "tests" / "support").mkdir()
        (SCRATCH / "tests" / "support" / "spawn.rs").write_text(self.BG)
        text = '#[path = "support/spawn.rs"]\nmod sp;\n' + WRITER + self.LOCKED % ("sp::bg(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_use_imported_path_module_helper_detaches(self):
        (SCRATCH / "tests" / "support").mkdir()
        (SCRATCH / "tests" / "support" / "spawn.rs").write_text(self.BG)
        text = ('#[path = "support/spawn.rs"]\nmod sp;\nuse sp::bg;\n' + WRITER
                + self.LOCKED % ("bg(move || { %s });" % self.OPEN))
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_common_helper_that_runs_its_parameter_inline_keeps_the_lock(self):
        self.put_common(self.INLINE)
        text = WRITER + self.LOCKED % ("common::bg(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), set())

    def test_a_path_module_helper_that_runs_inline_keeps_the_lock(self):
        (SCRATCH / "tests" / "support").mkdir()
        (SCRATCH / "tests" / "support" / "spawn.rs").write_text(self.INLINE)
        text = '#[path = "support/spawn.rs"]\nmod sp;\n' + WRITER + self.LOCKED % ("sp::bg(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), set())

    def test_an_unresolvable_call_is_flagged(self):
        # #8056 #8059: an identifier the gate cannot resolve at a parameter position is detached.
        text = WRITER + self.LOCKED % ("elsewhere::bg(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)


class Issue8056(Fixture):
    """#8056: a closure literal written directly inside a carrier expression runs detached; only an
    immediate call or a plain `let name = <closure>;` that is only ever called is on the same thread."""

    OPEN = 'let _c = db::open(":memory:");'
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"

    def check(self, body, expect=FLAGGED):
        self.assertEqual(self.flagged(WRITER + self.LOCKED % body), expect)

    def test_box_new_literal_handed_to_spawn(self):
        self.check("let f0 = Box::new(move || { %s });\n    std::thread::spawn(f0).join().unwrap();" % self.OPEN)

    def test_some_literal_unwrapped_into_spawn(self):
        self.check("let g = Some(move || { %s });\n    std::thread::spawn(g.unwrap()).join().unwrap();" % self.OPEN)

    def test_struct_field_literal(self):
        self.check("let s = S { f: move || { %s } };\n    std::thread::spawn(s.f).join().unwrap();" % self.OPEN)

    def test_vec_macro_literal_in_a_for_loop(self):
        self.check("for g in vec![move || { %s }] {\n        std::thread::spawn(g).join().unwrap();\n    }" % self.OPEN)

    def test_control_immediately_invoked_literal_keeps_the_lock(self):
        self.check("(move || { %s })();" % self.OPEN, set())

    def test_control_plain_let_only_called_keeps_the_lock(self):
        self.check("let f = move || { %s };\n    f();" % self.OPEN, set())


class Issue8057(Fixture):
    """#8057: spawn passed as a fn value hands whatever it is mapped over to another thread."""

    OPEN = 'let _c = db::open(":memory:");'
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"

    def check(self, body, head="", expect=FLAGGED):
        self.assertEqual(self.flagged(head + WRITER + self.LOCKED % body), expect)

    def test_thread_spawn_as_a_value(self):
        self.check("let f0 = move || { %s };\n    Some(f0).map(std::thread::spawn).unwrap().join().unwrap();" % self.OPEN)

    def test_bare_spawn_as_a_value(self):
        self.check("let f0 = move || { %s };\n    Some(f0).map(spawn).unwrap().join().unwrap();" % self.OPEN,
                   "use std::thread::spawn;\n")

    def test_tokio_spawn_as_a_value(self):
        self.check("let f0 = move || { %s };\n    Some(f0).map(tokio::spawn);" % self.OPEN)

    def test_control_map_with_a_plain_closure_keeps_the_lock(self):
        self.check("let n = Some(1).map(|x| x + 1);\n    %s\n    drop(n);" % self.OPEN, expect=set())


class Issue8058(Fixture):
    """#8058: a carrier re-assigned after the spawn inside a loop must not credit the later binding."""

    OPEN = 'let _c = db::open(":memory:");'
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"

    def check(self, body, expect=FLAGGED):
        self.assertEqual(self.flagged(WRITER + self.LOCKED % body), expect)

    def test_reassigned_carrier_in_a_loop(self):
        self.check("let f0 = move || {};\n    let f1 = move || { %s };\n    let mut g = f0;\n    loop {\n"
                   "        std::thread::spawn(g).join().unwrap();\n        g = f1;\n        break;\n    }" % self.OPEN)

    def test_control_closure_only_called_in_a_loop_keeps_the_lock(self):
        self.check("let f0 = move || { %s };\n    for _ in 0..2 {\n        f0();\n    }" % self.OPEN, set())


class Issue8059(Fixture):
    """#8059: `use common::bg as detach;` resolves to the helper it names."""

    OPEN = 'let _c = db::open(":memory:");'
    BG = "pub fn bg<F: FnOnce() + Send + 'static>(f: F) { std::thread::spawn(f); }\n"
    INLINE = "pub fn bg<F: FnOnce()>(f: F) { f() }\n"
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"

    def put_common(self, text):
        (SCRATCH / "tests" / "common").mkdir(exist_ok=True)
        (SCRATCH / "tests" / "common" / "mod.rs").write_text(text)

    def test_aliased_detaching_helper(self):
        self.put_common(self.BG)
        text = "use common::bg as detach;\n" + WRITER + self.LOCKED % ("detach(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_control_aliased_inline_helper_keeps_the_lock(self):
        self.put_common(self.INLINE)
        text = "use common::bg as detach;\n" + WRITER + self.LOCKED % ("detach(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), set())


class Issue8060(Fixture):
    """#8060: nested `common::spawn::bg` paths and a common helper that calls a detacher in another common file."""

    OPEN = 'let _c = db::open(":memory:");'
    BG = "pub fn bg<F: FnOnce() + Send + 'static>(f: F) { std::thread::spawn(f); }\n"
    INLINE = "pub fn bg<F: FnOnce()>(f: F) { f() }\n"
    OUTER = "pub fn outer<F: FnOnce() + Send + 'static>(f: F) { super::spawn::bg(f) }\n"
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"

    def put_cf(self, name, text):
        (SCRATCH / "tests" / "common").mkdir(exist_ok=True)
        (SCRATCH / "tests" / "common" / name).write_text(text)

    def test_nested_common_submodule_path(self):
        self.put_cf("spawn.rs", self.BG)
        text = WRITER + self.LOCKED % ("common::spawn::bg(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_helper_calling_a_detacher_in_another_common_file(self):
        self.put_cf("spawn.rs", self.BG)
        self.put_cf("outer.rs", self.OUTER)
        text = WRITER + self.LOCKED % ("common::outer::outer(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_control_nested_inline_helper_keeps_the_lock(self):
        self.put_cf("spawn.rs", self.INLINE)
        text = WRITER + self.LOCKED % ("common::spawn::bg(move || { %s });" % self.OPEN)
        self.assertEqual(self.flagged(text), set())


class Issue8046(Fixture):
    """#8046: a macro whose body invokes a detaching macro detaches the arguments of its own invocations."""

    OPEN = 'let _c = db::open(":memory:");'
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"
    INNER = "macro_rules! inner {\n    ($e:expr) => { std::thread::spawn($e) };\n}\n"
    OUTER = "macro_rules! outer {\n    ($e:expr) => { inner!($e) };\n}\n"

    def test_a_macro_forwarding_to_a_spawning_macro_detaches(self):
        text = WRITER + self.INNER + self.OUTER + self.LOCKED % ("outer!(move || { %s }).join().unwrap();" % self.OPEN)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_the_forwarding_chain_is_closed_over_two_levels(self):
        top = "macro_rules! top {\n    ($e:expr) => { outer!($e) };\n}\n"
        text = (WRITER + top + self.OUTER + self.INNER
                + self.LOCKED % ("top!(move || { %s }).join().unwrap();" % self.OPEN))
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_a_macro_forwarding_to_a_macro_that_does_not_spawn_keeps_the_lock(self):
        text = (WRITER + "macro_rules! twice {\n    ($e:expr) => { $e; $e };\n}\n"
                + "macro_rules! outer {\n    ($e:expr) => { twice!($e) };\n}\n"
                + self.LOCKED % ("outer!(%s);" % self.OPEN))
        self.assertEqual(self.flagged(text), set())


class Positive(Fixture):
    """Shared helpers of the r13 classes: a locked reader whose body is spliced in, plus tests/common files."""

    OPEN = 'let _c = db::open(":memory:");'
    LOCKED = "#[test]\nfn reader() {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"
    DRAIN = "for g in q {\n        std::thread::spawn(g).join().unwrap();\n    }"

    def check(self, body, expect=FLAGGED, head=""):
        self.assertEqual(self.flagged(WRITER + head + self.LOCKED % body), expect)

    def put_cf(self, name, text):
        (SCRATCH / "tests" / "common").mkdir(exist_ok=True)
        (SCRATCH / "tests" / "common" / name).write_text(text)


class Issue8065(Positive):
    """#8065: a callee credits a closure argument only when it provably calls it inline; one that stores or
    returns the parameter (stash, id) hands the closure on, so it is detached."""

    STASH = ("fn stash(q: &mut Vec<Box<dyn FnOnce() + Send>>, f: impl FnOnce() + Send + 'static) {\n"
             "    q.push(Box::new(f));\n}\n")
    ID = "fn id<F>(f: F) -> F { f }\n"
    RUN = "fn run<F: FnOnce()>(f: F) { f() }\n"

    def test_stash_then_drain_and_spawn(self):
        self.check("let mut q = Vec::new();\n    stash(&mut q, move || { %s });\n    %s" % (self.OPEN, self.DRAIN),
                   head=self.STASH)

    def test_id_pushed_then_drained(self):
        self.check("let mut q = Vec::new();\n    q.push(Box::new(id(move || { %s })));\n    %s" % (self.OPEN, self.DRAIN),
                   head=self.ID)

    def test_id_sent_over_a_channel_then_spawned(self):
        self.check("let (tx, rx) = std::sync::mpsc::channel();\n    tx.send(id(move || { %s })).unwrap();\n"
                   "    std::thread::spawn(rx.recv().unwrap()).join().unwrap();" % self.OPEN, head=self.ID)

    def test_a_tests_common_helper_that_returns_its_parameter_is_detached(self):
        self.put_cf("mod.rs", "pub fn hold<F: FnOnce() + Send>(f: F) -> F { f }\n")
        self.check("let g = common::hold(move || { %s });\n    std::thread::spawn(g).join().unwrap();" % self.OPEN)

    def test_control_helper_that_only_calls_its_parameter(self):
        self.check("run(move || { %s });" % self.OPEN, set(), head=self.RUN)

    def test_control_helper_chain_that_only_calls_its_parameter(self):
        head = self.RUN + "fn outer<F: FnOnce()>(f: F) { run(f) }\n"
        self.check("outer(move || { %s });" % self.OPEN, set(), head=head)

    def test_control_helper_that_rebinds_and_calls(self):
        head = "fn run<F: FnOnce()>(f: F) { let g = f; g() }\n"
        self.check("run(move || { %s });" % self.OPEN, set(), head=head)

    def test_control_plain_let_only_called(self):
        self.check("let f = move || { %s };\n    f();" % self.OPEN, set())

    def test_control_immediately_invoked(self):
        self.check("(move || { %s })();" % self.OPEN, set())


class Issue8066(Positive):
    """#8066: the value a same-thread closure returns is itself a closure value: credited only when called in
    place (`mk()()`) or bound by a plain `let v = mk();` that is only called; an async block only when awaited."""

    def test_pushed_box_of_mk_then_drained(self):
        self.check("let mk = || move || { %s };\n    let mut q = Vec::new();\n    q.push(Box::new(mk()));\n    %s"
                   % (self.OPEN, self.DRAIN))

    def test_mk_sent_over_a_channel(self):
        self.check("let mk = || move || { %s };\n    let (tx, rx) = std::sync::mpsc::channel();\n"
                   "    tx.send(mk()).unwrap();\n    std::thread::spawn(rx.recv().unwrap()).join().unwrap();" % self.OPEN)

    def test_async_mk_pushed_then_spawned(self):
        self.check("let mk = || async move { %s };\n    let mut q = Vec::new();\n    q.push(Box::new(mk()));\n"
                   "    for g in q {\n        tokio::spawn(g);\n    }" % self.OPEN)

    def test_option_map_closure_value_pushed(self):
        self.check("let mut q = Vec::new();\n    q.push(Some(1).map(|_| move || { %s }).unwrap());\n    %s"
                   % (self.OPEN, self.DRAIN))

    def test_mk_value_bound_and_then_stored(self):
        self.check("let mk = || move || { %s };\n    let v = mk();\n    let mut q = Vec::new();\n    q.push(v);\n    %s"
                   % (self.OPEN, self.DRAIN))

    def test_control_mk_invoked_in_place(self):
        self.check("let mk = || move || { %s };\n    mk()();" % self.OPEN, set())

    def test_control_mk_value_bound_and_only_called(self):
        self.check("let mk = || move || { %s };\n    let v = mk();\n    v();" % self.OPEN, set())


class Issue8067(Positive):
    """#8067: a borrowed closure literal (`&|| ..`, `&mut || ..`) is a closure literal and is classified like any other."""

    def test_shared_borrow_sent_over_a_channel(self):
        self.check("let (tx, rx) = std::sync::mpsc::channel();\n    tx.send(&|| { %s }).unwrap();\n"
                   "    std::thread::spawn(rx.recv().unwrap()).join().unwrap();" % self.OPEN)

    def test_mutable_borrow_pushed_then_drained(self):
        self.check("let mut q = Vec::new();\n    q.push(&mut || { %s });\n    %s" % (self.OPEN, self.DRAIN))

    def test_borrowed_literal_is_seen_as_a_closure(self):
        self.assertEqual(len(gate.closure_literals("q.push(&|| { x });\n q.push(&mut || { y });")), 2)

    def test_control_plain_let_only_called(self):
        self.check("let f = || { %s };\n    f();" % self.OPEN, set())

    def test_control_bit_and_is_not_a_closure(self):
        self.assertEqual(gate.closure_literals("let m = a & b | c;"), [])


class Issue8068(Positive):
    """#8068: an inline runner is matched by its FULL resolved path, never by the last segment of an unresolved
    crate path."""

    def test_unresolved_crate_path_ending_in_an_inline_name(self):
        self.check("ai_memory::pool::map(|| { %s });" % self.OPEN)

    def test_unresolved_free_function_with_an_inline_name(self):
        self.check("pool::for_each(move || { %s });" % self.OPEN)

    def test_control_std_qualified_inline_runner(self):
        self.check("let n = std::iter::once(1).map(|_| { %s 1 }).count();" % self.OPEN, set())

    def test_control_catch_unwind_with_its_wrapper(self):
        self.check("let _r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { %s }));" % self.OPEN, set())

    def test_control_imported_catch_unwind(self):
        head = "use std::panic::{catch_unwind, AssertUnwindSafe};\n"
        self.check("let _r = catch_unwind(AssertUnwindSafe(|| { %s }));" % self.OPEN, set(), head=head)

    def test_wrapper_pushed_instead_of_run_is_detached(self):
        head = "use std::panic::AssertUnwindSafe;\n"
        self.check("let mut q = Vec::new();\n    q.push(Box::new(AssertUnwindSafe(|| { %s })));\n    %s"
                   % (self.OPEN, self.DRAIN), head=head)

    def test_control_method_inline_runner(self):
        self.check("let r = Some(1).map(|_| { %s 1 });" % self.OPEN, set())


class Issue8078(Positive):
    """#8078: a fn whose signature holds a `;` (an array return type) is parsed, so it resolves as a receiver root."""

    KEYS = "fn keys() -> [&'static str; 2] {\n    [\"A\", \"B\"]\n}\n"

    def test_control_array_returning_helper_roots_an_inline_chain(self):
        self.check("let _v: Vec<_> = keys().into_iter().map(|k| { %s }).collect();" % self.OPEN, set(), head=self.KEYS)

    def test_array_helper_that_builds_a_parallel_iterator_taints_its_caller(self):
        head = "fn keys() -> [u8; 2] {\n    let _p = (0u8..2).into_par_iter();\n    [1, 2]\n}\n"
        self.check("let _v: Vec<_> = keys().into_iter().map(|k| { %s }).collect();" % self.OPEN, head=head)


class Issue8069(Positive):
    """#8069: a parallel iterator built in a helper (or by an unresolved callee) makes every closure passed to its
    adapters detached; a local, literal or std-rooted receiver keeps the inline treatment."""

    PAR = "fn par() -> impl Sized { (0..3u32).into_par_iter() }\n"

    def test_same_file_helper_builds_a_rayon_iterator(self):
        self.check("par().for_each(|_| { %s });" % self.OPEN, head=self.PAR)

    def test_helper_reaches_the_parallel_iterator_through_another_helper(self):
        head = self.PAR + "fn outer() -> impl Sized { par() }\n"
        self.check("outer().for_each(|_| { %s });" % self.OPEN, head=head)

    def test_tests_common_helper_builds_a_rayon_iterator(self):
        self.put_cf("mod.rs", "pub fn par() -> impl Sized { (0..3u32).into_par_iter() }\n")
        self.check("common::par().for_each(|_| { %s });" % self.OPEN)

    def test_unresolved_callee_roots_the_chain(self):
        self.check("pool::items().into_iter().for_each(|_| { %s });" % self.OPEN)

    def test_control_literal_receiver(self):
        self.check("vec![1].into_iter().for_each(|_| { %s });" % self.OPEN, set())

    def test_control_local_receiver(self):
        self.check("let it = vec![1].into_iter();\n    it.for_each(|_| { %s });" % self.OPEN, set())

    def test_control_non_parallel_same_file_helper(self):
        head = "fn items() -> Vec<u32> { vec![1] }\n"
        self.check("items().into_iter().for_each(|_| { %s });" % self.OPEN, set(), head=head)


class Issue8089(Positive):
    """#8089: a method chain rooted in a local binding inherits the classification of the binding's initialiser, so one
    `let` cannot launder a parallel or unresolved receiver."""

    PAR = "fn par() -> impl Sized { (0..3u32).into_par_iter() }\n"

    def test_let_bound_same_file_parallel_helper(self):
        self.check("let it = par();\n    it.for_each(|_| { %s });" % self.OPEN, head=self.PAR)

    def test_let_mut_bound_parallel_helper(self):
        self.check("let mut it = par();\n    it.for_each(|_| { %s });" % self.OPEN, head=self.PAR)

    def test_let_bound_unresolved_path_constructor(self):
        self.check("let pool = ai_memory::pool::Pool::new();\n    pool.for_each(|_| { %s });" % self.OPEN)

    def test_two_hop_binding(self):
        body = "let a = par();\n    let b = a.filter(|_| true);\n    b.for_each(|_| { %s });" % self.OPEN
        self.check(body, head=self.PAR)

    def test_binding_passed_by_reference(self):
        self.check("let a = par();\n    (&a).for_each(|_| { %s });" % self.OPEN, head=self.PAR)

    def test_binding_through_iter(self):
        self.check("let a = par();\n    a.iter().for_each(|_| { %s });" % self.OPEN, head=self.PAR)

    def test_shadowing_latest_binding_wins(self):
        body = "let it = vec![1].into_iter();\n    let it = par();\n    it.for_each(|_| { %s });" % self.OPEN
        self.check(body, head=self.PAR)

    def test_control_shadowed_back_to_literal(self):
        body = "let it = par();\n    let it = vec![1].into_iter();\n    it.for_each(|_| { %s });" % self.OPEN
        self.check(body, set(), head=self.PAR)

    def test_control_vec_binding(self):
        self.check("let v = vec![1, 2];\n    v.iter().for_each(|_| { %s });" % self.OPEN, set())

    def test_control_array_literal_binding(self):
        self.check("let keys = [1, 2];\n    keys.map(|_| { %s });" % self.OPEN, set())

    def test_control_std_repeat_binding(self):
        body = "let it = std::iter::repeat(1).take(2);\n    it.for_each(|_| { %s });" % self.OPEN
        self.check(body, set())

    def test_control_non_parallel_helper_binding(self):
        head = "fn items() -> Vec<u32> { vec![1] }\n"
        self.check("let v = items();\n    v.iter().for_each(|_| { %s });" % self.OPEN, set(), head=head)


class Issue8090(Positive):
    """#8090: every rayon parallel-iterator entry point taints, not only par_iter / into_par_iter / par_bridge."""

    def test_each_parallel_method_taints_a_helper(self):
        for name in ("par_iter", "par_iter_mut", "into_par_iter", "par_chunks", "par_chunks_mut", "par_lines",
                     "par_bridge", "par_split", "par_windows", "par_extend", "par_sort", "par_sort_by", "par_drain"):
            head = "fn par() -> u8 {\n    let v = Vec::<u8>::new();\n    let _p = v.%s();\n    1\n}\n" % name
            with self.subTest(name=name):
                self.check("par().to_string().chars().for_each(|_| { %s });" % self.OPEN, head=head)

    def test_control_lookalike_name_is_not_parallel(self):
        head = "fn items() -> Vec<u32> {\n    let par_iterations = 3;\n    vec![par_iterations]\n}\n"
        self.check("items().into_iter().for_each(|_| { %s });" % self.OPEN, set(), head=head)


class Issue8091(Positive):
    """#8091: a `{` inside a const block of a fn signature is not the body, so a helper that spawns its closure
    parameter is seen as one."""

    def spawner(self, sig, tail):
        return ("fn spin<F: FnOnce() + Send + 'static>(f: F) %s {\n    std::thread::spawn(f).join().unwrap();\n"
                "    %s\n}\n") % (sig, tail)

    def test_const_block_return_type(self):
        head = "struct A<const N: usize>;\n" + self.spawner("-> A<{ 3 }>", "A")
        self.check("let _a = spin(move || { %s });" % self.OPEN, head=head)

    def test_const_block_array_length(self):
        head = self.spawner("-> [u8; { 2 * 2 }]", "[0; 4]")
        self.check("let _a = spin(move || { %s });" % self.OPEN, head=head)

    def test_const_block_where_clause(self):
        self.check("spin(move || { %s });" % self.OPEN, head=self.spawner("where [(); { 2 }]: Sized", ""))

    def test_control_semicolon_array_signature_still_parses(self):
        head = "fn keys() -> [&'static str; 2] {\n    [\"A\", \"B\"]\n}\n"
        self.check("let _v: Vec<_> = keys().into_iter().map(|k| { %s }).collect();" % self.OPEN, set(), head=head)

    def test_control_inline_helper_with_generic_signature(self):
        head = "fn run<F: FnOnce()>(f: F) -> Vec<Option<u8>> {\n    f();\n    Vec::new()\n}\n"
        self.check("let _a = run(move || { %s });" % self.OPEN, set(), head=head)


class Issue8093(Positive):
    """#8093: a value is safe only when its provenance is proven; a wrapper (Some, Box::new, vec!, an array, a tuple, a
    struct literal) is transparent only when everything inside it is safe."""

    PAR = "fn par() -> impl Sized { (0..3u32).into_par_iter() }\nstruct S<T> { it: T }\n"
    POOL = "ai_memory::pool::Pool::new()"
    CL = "|_| { %s }" % Positive.OPEN

    def shapes(self, root):
        return [
            "Some(%s).unwrap().for_each(%s);" % (root, self.CL),
            "Box::new(%s).for_each(%s);" % (root, self.CL),
            "(%s, 1).0.for_each(%s);" % (root, self.CL),
            "S { it: %s }.it.for_each(%s);" % (root, self.CL),
            "[%s].into_iter().next().unwrap().for_each(%s);" % (root, self.CL),
            "vec![%s].into_iter().next().unwrap().for_each(%s);" % (root, self.CL),
            "let x = Some(%s).unwrap();\n    x.for_each(%s);" % (root, self.CL),
            "let a = [%s];\n    a.into_iter().next().unwrap().for_each(%s);" % (root, self.CL),
            "let t = (%s, 1);\n    t.0.for_each(%s);" % (root, self.CL),
            "let s = S { it: %s };\n    s.it.for_each(%s);" % (root, self.CL),
            "let b = Box::new(%s);\n    b.for_each(%s);" % (root, self.CL),
            "let v = vec![%s];\n    v.into_iter().next().unwrap().for_each(%s);" % (root, self.CL),
        ]

    def test_wrapped_parallel_helper_is_detached(self):
        for body in self.shapes("par()"):
            with self.subTest(body=body):
                self.check(body, head=self.PAR)

    def test_wrapped_unresolved_constructor_is_detached(self):
        for body in self.shapes(self.POOL):
            with self.subTest(body=body):
                self.check(body, head=self.PAR)

    def test_control_wrappers_of_safe_values(self):
        for body in (
            "let v = vec![1, 2];\n    v.iter().for_each(%s);" % self.CL,
            "let s = Some(1);\n    s.map(%s);" % self.CL,
            "let b = Box::new(\"x\");\n    b.chars().for_each(%s);" % self.CL,
            "Some(1).map(%s);" % self.CL,
            "vec![1u8].iter().for_each(%s);" % self.CL,
            "let keys = [\"A\", \"B\"];\n    keys.map(%s);" % self.CL,
            "let t = (1, \"a\");\n    t.1.chars().for_each(%s);" % self.CL,
            "let n = std::vec::Vec::<u8>::new();\n    n.iter().for_each(%s);" % self.CL,
            "std::vec::Vec::<u8>::new().iter().for_each(%s);" % self.CL,
        ):
            with self.subTest(body=body):
                self.check(body, set())


class Issue8094(Positive):
    """#8094: a name bound by a `for` pattern, a match arm, `if let`, `while let` or a closure parameter is detached."""

    PAR = "fn par() -> impl Sized { (0..3u32).into_par_iter() }\n"
    CL = "|_| { %s }" % Positive.OPEN

    def test_for_pattern_binding(self):
        self.check("for it in [par()] {\n        it.for_each(%s);\n    }" % self.CL, head=self.PAR)
        self.check("for pool in [ai_memory::pool::Pool::new()] {\n        pool.for_each(%s);\n    }" % self.CL)

    def test_match_arm_binding(self):
        self.check("match ai_memory::pool::Pool::new() { pool => pool.for_each(%s) }" % self.CL)

    def test_if_let_while_let_closure_param_bindings(self):
        for body in (
            "if let Some(it) = Some(par()) {\n        it.for_each(%s);\n    }" % self.CL,
            "while let Some(it) = Some(par()) {\n        it.for_each(%s);\n        break;\n    }" % self.CL,
            "let mk = |it| { it.for_each(%s); };\n    mk(par());" % self.CL,
        ):
            with self.subTest(body=body):
                self.check(body, head=self.PAR)

    def test_for_binding_shadows_an_outer_safe_let(self):
        body = "let it = vec![1];\n    for it in [par()] {\n        it.for_each(%s);\n    }" % self.CL
        self.check(body, head=self.PAR)

    def test_control_for_loop_closure_runs_on_a_safe_local_outside(self):
        body = "let v = vec![1, 2];\n    for _k in [1, 2] {\n        v.iter().for_each(%s);\n    }" % self.CL
        self.check(body, set())

    def test_control_for_item_of_a_literal_collection_is_safe(self):
        for body in (
            "for k in [\"A\", \"B\"] {\n        k.chars().for_each(%s);\n    }" % self.CL,
            "let keys = vec![\"A\", \"B\"];\n    for k in keys.iter() {\n        k.chars().for_each(%s);\n    }" % self.CL,
        ):
            with self.subTest(body=body):
                self.check(body, set())

    def test_destructuring_for_pattern_is_detached(self):
        self.check("for (it, _n) in [(par(), 1)] {\n        it.for_each(%s);\n    }" % self.CL, head=self.PAR)

    def test_control_literal_loop_item_methods_are_not_a_receiver_hole(self):
        self.check("let v = vec![1];\n    for _k in [\"A\", \"B\"] {\n        v.iter().for_each(%s);\n    }" % self.CL,
                   set())


class Issue8095(Positive):
    """#8095: a binding is visible only in a block that is still open at the use; an inner `let` of a closed block
    does not hide an outer one."""

    PAR = "fn par() -> impl Sized { (0..3u32).into_par_iter() }\n"
    CL = "|_| { %s }" % Positive.OPEN

    def test_closed_inner_block_does_not_hide_outer_parallel_binding(self):
        body = "let it = par();\n    { let it = vec![1u8]; let _ = it; }\n    it.for_each(%s);" % self.CL
        self.check(body, head=self.PAR)

    def test_closed_inner_block_does_not_hide_outer_unresolved_binding(self):
        body = ("let pool = ai_memory::pool::Pool::new();\n    { let pool = vec![1u8]; let _ = pool; }\n"
                "    pool.for_each(%s);" % self.CL)
        self.check(body)

    def test_inner_binding_still_in_force_inside_its_block(self):
        body = "let it = par();\n    { let it = vec![1u8]; it.iter().for_each(%s); }" % self.CL
        self.check(body, set(), head=self.PAR)

    def test_control_inner_block_let_then_outer_safe_use(self):
        body = "let v = vec![1u8];\n    { let v = par(); let _ = v; }\n    v.iter().for_each(%s);" % self.CL
        self.check(body, set(), head=self.PAR)

    def test_control_same_block_rebinding(self):
        body = "let x = par();\n    let x = vec![1];\n    x.iter().for_each(%s);" % self.CL
        self.check(body, set(), head=self.PAR)


class Issue8096(Positive):
    """#8096: PARALLEL_METHODS covers rayon's full par_* adapter set."""

    def test_missing_adapters_taint_a_helper(self):
        for name in ("par_chunk_by", "par_chunk_by_mut", "par_rchunks_exact", "par_rchunks_exact_mut",
                     "par_split_inclusive", "par_split_inclusive_mut", "par_match_indices"):
            head = "fn par() -> u8 {\n    let v = Vec::<u8>::new();\n    let _p = v.%s();\n    1\n}\n" % name
            with self.subTest(name=name):
                self.check("par().to_string().chars().for_each(|_| { %s });" % self.OPEN, head=head)

    def test_list_is_sorted(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("gate8096", str(GATE))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(list(mod.PARALLEL_METHODS), sorted(mod.PARALLEL_METHODS))


class Issue8098(Positive):
    """#8098: a name is safe only when it is PROVEN: a capitalised name is judged like any other (a binding, a const or
    static by its initialiser, a variant, a struct), never trusted for its first letter."""

    CL = "|_| { %s }" % Positive.OPEN
    PAR = "fn par() -> impl Sized { (0..3u32).into_par_iter() }\n"
    POOL_STATIC = "static POOL: std::sync::LazyLock<ai_memory::pool::Pool> = std::sync::LazyLock::new(ai_memory::pool::Pool::new);\n"

    def test_capitalised_let_binding_is_judged_by_its_initialiser(self):
        self.check("#[allow(non_snake_case)]\n    let P = par();\n    P.for_each(%s);" % self.CL, head=self.PAR)

    def test_capitalised_parallel_fn_call_is_detached(self):
        head = "fn Par() -> impl Sized { (0..3u32).into_par_iter() }\n"
        self.check("Par().for_each(%s);" % self.CL, head=head)

    def test_static_holding_an_unresolved_crate_value_is_detached(self):
        self.check("POOL.for_each(%s);" % self.CL, head=self.POOL_STATIC)

    def test_qualified_crate_constant_is_detached(self):
        self.check("ai_memory::pool::GLOBAL.for_each(%s);" % self.CL)

    def test_imported_crate_constant_is_detached(self):
        self.check("GLOBAL.for_each(%s);" % self.CL, head="use ai_memory::pool::GLOBAL;\n")

    def test_controls_stay_clean(self):
        for head, body in (
            ("", "None.map(%s);" % self.CL),
            ("use std::cmp::Ordering;\n", "Some(Ordering::Less).map(%s);" % self.CL),
            ("", "Some(std::cmp::Ordering::Less).map(%s);" % self.CL),
            ('const KEYS: [&str; 2] = ["A", "B"];\n', "KEYS.map(%s);" % self.CL),
            ("enum E { A, B }\n", "Some(E::A).map(%s);" % self.CL),
            ("struct U;\n", "Some(U).map(%s);" % self.CL),
            ("struct T(u8);\n", "Some(T(1)).map(%s);" % self.CL),
        ):
            with self.subTest(body=body):
                self.check(body, set(), head=head)


class Issue8099(Positive):
    """#8099: a closure literal is a whitelisted form only when it is invoked in place or is the argument of an inline
    adapter, and everything it returns is proven; an unresolved value it returns is never blanked away."""

    CL = "|_| { %s }" % Positive.OPEN
    POOL = "ai_memory::pool::Pool::new()"

    def test_iife_returning_an_unresolved_value_is_detached(self):
        self.check("Some((|| %s)()).unwrap().for_each(%s);" % (self.POOL, self.CL))

    def test_iife_through_a_let_is_detached(self):
        self.check("let p = (|| %s)();\n    p.for_each(%s);" % (self.POOL, self.CL))

    def test_map_closure_returning_an_unresolved_value_is_detached(self):
        self.check("std::iter::once(()).map(|_| %s).next().unwrap().for_each(%s);" % (self.POOL, self.CL))

    def test_controls_stay_clean(self):
        for body in (
            "vec![1u8].iter().map(|x| x + 1).for_each(%s);" % self.CL,
            "let f = vec![1u8].into_iter().map(|x| x + 1);\n    f.for_each(%s);" % self.CL,
            "(|| vec![1u8])().iter().for_each(%s);" % self.CL,
        ):
            with self.subTest(body=body):
                self.check(body, set())


class Issue8100(Positive):
    """#8100: a method on a safe receiver is trusted only when it is on the INLINE_METHODS allowlist, and a turbofish
    or `let` type is trusted only when it names std types."""

    CL = "|_| { %s }" % Positive.OPEN
    EXT = "use ai_memory::pool::PoolExt;\n"

    def test_extension_trait_method_inline_is_detached(self):
        self.check("vec![1u8].into_pool().for_each(%s);" % self.CL, head=self.EXT)

    def test_extension_trait_method_through_a_let_is_detached(self):
        self.check("let p = vec![1u8].into_pool();\n    p.for_each(%s);" % self.CL, head=self.EXT)

    def test_non_std_collect_turbofish_is_detached(self):
        self.check("vec![1u8].iter().collect::<ai_memory::pool::Pool>().for_each(%s);" % self.CL)

    def test_non_std_let_annotation_is_detached(self):
        self.check("let p: ai_memory::pool::Pool = vec![1u8].into_iter().collect();\n    p.for_each(%s);" % self.CL)

    def test_declared_std_types_are_the_proof(self):
        """A declared std-only type proves a value whatever its initialiser names (const, static, let, fn return)."""
        crate = "use ai_memory::federation::KEY_A;\n"
        for head, body in (
            (crate + "const KS: [&str; 1] = [KEY_A];\n", "KS.map(%s);" % self.CL),
            (crate + "static KS: [&str; 1] = [KEY_A];\n", "KS.map(%s);" % self.CL),
            (crate, "let ks: [&str; 1] = [KEY_A];\n    ks.map(%s);" % self.CL),
            (crate, "let ks: [(&'static str, Option<&str>); 1] = [(KEY_A, None)];\n    ks.map(%s);" % self.CL),
            (crate + "fn ks() -> [&'static str; 1] { [KEY_A] }\n", "ks().map(%s);" % self.CL),
        ):
            with self.subTest(head=head, body=body):
                self.check(body, set(), head=head)

    def test_declared_non_std_types_stay_detached(self):
        crate = "use ai_memory::federation::KEY_A;\n"
        # r10 (#8107): an untyped array of crate constants is a container; `map` / `iter` on it are inline, but an
        # element extracted from it is judged element by element
        self.check("let ks = [KEY_A];\n    ks.map(%s);" % self.CL, set(), head=crate)
        self.check("let ks = [KEY_A];\n    ks.iter().next().unwrap().for_each(%s);" % self.CL, head=crate)
        self.check("let ks: [ai_memory::Key; 1] = [KEY_A];\n    ks.map(%s);" % self.CL, head=crate)
        self.check("ks().map(%s);" % self.CL, head=crate + "fn ks() -> [ai_memory::Key; 1] { [KEY_A] }\n")

    def test_controls_stay_clean(self):
        for head, body in (
            ("", 'let keys = ["A", "B"];\n    keys.map(%s);' % self.CL),
            ("", "vec![1u8].iter().for_each(%s);" % self.CL),
            ("", '"a\\nb".lines().for_each(%s);' % self.CL),
            ("", "vec![1u8].into_iter().collect::<Vec<u8>>().iter().for_each(%s);" % self.CL),
            ("", "let v: Vec<u8> = vec![1u8].into_iter().collect();\n    v.iter().for_each(%s);" % self.CL),
            ("use std::vec::Vec as V;\n", "V::<u8>::new().iter().for_each(%s);" % self.CL),
        ):
            with self.subTest(body=body):
                self.check(body, set(), head=head)


class FormInventory(Positive):
    """#8098-#8100: the module docstring's form table, SPAN_FORMS and the span_safe branches are one set. Every form
    has a probe whose recorded decision is the one its rule gives; a form with no probe, or a branch with no entry,
    fails here."""

    CL = "|_| { %s }" % Positive.OPEN
    POOL = "ai_memory::pool::Pool::new()"
    POOL_FN = "fn f() -> ai_memory::pool::Pool { ai_memory::pool::Pool::new() }\n"
    POOL_STATIC = "static POOL: std::sync::LazyLock<ai_memory::pool::Pool> = std::sync::LazyLock::new(ai_memory::pool::Pool::new);\n"
    PARAM = "#[test]\nfn reader(p: Vec<u8>) {\n    let _l = ENV_LOCK.blocking_lock();\n    %s\n}\n"

    def probes(self):
        cl = self.CL
        w_ok = "struct W;\nimpl W { fn m(&self) -> u8 { 1 } }\n"
        w_bad = "struct W;\nimpl W { fn m(&self) -> ai_memory::pool::Pool { ai_memory::pool::Pool::new() } }\n"
        keys = 'const KEYS: [&str; 2] = ["A", "B"];\n'
        return [
            # (form, ok, head, body, template)
            ("literal", True, "", "[1u8].iter().for_each(%s);" % cl, None),
            ("keyword", True, "", "Some(true).iter().for_each(%s);" % cl, None),
            ("primitive", True, "", "Some(1 as u8).iter().for_each(%s);" % cl, None),
            ("macro_vec", True, "", "vec![1u8].iter().for_each(%s);" % cl, None),
            ("macro_value", True, "", 'format!("{}", 1).chars().for_each(%s);' % cl, None),
            ("macro_other", False, "", "my_macro!(1).iter().for_each(%s);" % cl, None),
            ("field", True, "struct S { it: u8 }\n", "let s = S { it: 1 };\n    s.it.to_string().chars().for_each(%s);" % cl, None),
            ("label_binder", True, "struct S { it: u8 }\n", "let s = S { it: 1 };\n    s.it.to_string().chars().for_each(%s);" % cl, None),
            ("method_inline", True, "", "vec![1u8].iter().for_each(%s);" % cl, None),
            ("method_resolved", True, w_ok, "let w = W;\n    w.m().to_string().chars().for_each(%s);" % cl, None),
            ("method_resolved", False, w_bad, "let w = W;\n    w.m().for_each(%s);" % cl, None),
            ("method_other", False, "", "vec![1u8].into_pool().for_each(%s);" % cl, None),
            ("call_std", True, "", "Some(1u8).iter().for_each(%s);" % cl, None),
            ("call_resolved", True, "fn f() -> u8 { 1 }\n", "f().to_string().chars().for_each(%s);" % cl, None),
            ("call_resolved", False, self.POOL_FN, "f().for_each(%s);" % cl, None),
            ("call_adt", True, "struct T(u8);\n", "T(1).0.to_string().chars().for_each(%s);" % cl, None),
            ("call_other", False, "", "%s.for_each(%s);" % (self.POOL, cl), None),
            ("name_local", True, "", "let v = vec![1u8];\n    v.iter().for_each(%s);" % cl, None),
            ("name_local", False, "", "let p = %s;\n    p.for_each(%s);" % (self.POOL, cl), None),
            ("name_closure_param", True, "", "Some(vec![1u8]).map(|k| k.iter().for_each(%s));" % cl, None),
            ("name_closure_param", False, "", "let f = |k: Vec<u8>| k.iter().for_each(%s);" % cl, None),
            ("name_opaque", False, "", "if let Some(k) = Some(vec![1u8]) {\n        k.iter().for_each(%s);\n    }" % cl, None),
            ("name_param", True, "", "p.iter().for_each(%s);" % cl, self.PARAM),
            ("name_std", True, "", "None.map(%s);" % cl, None),
            ("name_const", True, keys, "KEYS.iter().for_each(%s);" % cl, None),
            ("name_const", False, self.POOL_STATIC, "POOL.for_each(%s);" % cl, None),
            ("name_fn_item", True, "fn k() -> u8 { 1 }\n", "Some(k).iter().for_each(%s);" % cl, None),
            ("name_fn_item", False, self.POOL_FN.replace("fn f", "fn k"), "Some(k).iter().for_each(%s);" % cl, None),
            ("name_adt", True, "struct U;\n", "Some(U).iter().for_each(%s);" % cl, None),
            ("name_other", False, "use ai_memory::pool::GLOBAL;\n", "GLOBAL.for_each(%s);" % cl, None),
            ("path_std", True, "", "Some(u8::MAX).iter().for_each(%s);" % cl, None),
            ("path_const", True, keys, "self::KEYS.iter().for_each(%s);" % cl, None),
            ("path_const", False, self.POOL_STATIC, "self::POOL.for_each(%s);" % cl, None),
            ("path_variant", True, "enum E { A, B }\n", "Some(E::A).iter().for_each(%s);" % cl, None),
            ("path_other", False, "", "ai_memory::pool::GLOBAL.for_each(%s);" % cl, None),
            ("closure_iife", True, "", "(|| vec![1u8])().iter().for_each(%s);" % cl, None),
            ("closure_iife", False, "", "(|x| x)(%s).for_each(%s);" % (self.POOL, cl), None),
            ("closure_arg", True, "", "Some(1u8).map(|x| x + 1).iter().for_each(%s);" % cl, None),
            ("closure_arg", False, "", "%s.map(|x| x).for_each(%s);" % (self.POOL, cl), None),
            ("closure_other", False, "", "let f = |x: u8| x;\n    Some(f).iter().for_each(%s);" % cl, None),
            ("async_block", False, "", "let a = async { 1u8 };\n    Some(a).iter().for_each(%s);" % cl, None),
            ("turbofish_std", True, "", "Vec::<u8>::new().iter().for_each(%s);" % cl, None),
            ("turbofish_other", False, "", "vec![1u8].iter().collect::<ai_memory::pool::Pool>().for_each(%s);" % cl, None),
            ("block_root", False, "", "let _r = { vec![1u8] }.iter().for_each(%s);" % cl, None),
        ]

    def run_probe(self, form, ok, head, body, template):
        text = WRITER + head + (template or self.LOCKED) % body
        gate.FORM_TRACE = []
        try:
            flagged = self.flagged(text)
            trace = list(gate.FORM_TRACE)
        finally:
            gate.FORM_TRACE = None
        self.assertIn((form, ok), trace, "no %s=%s decision for %r" % (form, ok, body))
        self.assertEqual(flagged, set() if ok else FLAGGED, body)

    def test_each_form_decides_as_its_rule_says(self):
        for probe in self.probes():
            with self.subTest(form=probe[0], ok=probe[1]):
                self.run_probe(*probe)

    def test_every_form_has_a_probe(self):
        probed = {p[0] for p in self.probes()}
        self.assertEqual(probed, set(gate.SPAN_FORMS))
        self.assertEqual(len(gate.SPAN_FORMS), len(set(gate.SPAN_FORMS)))

    def test_every_form_has_a_detached_probe_unless_always_safe(self):
        always_safe = {"literal", "keyword", "primitive", "macro_vec", "macro_value", "field", "method_inline",
                       "label_binder", "call_std", "call_adt", "name_param", "name_std", "name_adt", "path_std",
                       "path_variant", "turbofish_std"}
        detached = {p[0] for p in self.probes() if not p[1]}
        safe = {p[0] for p in self.probes() if p[1]}
        for label in gate.SPAN_FORMS:
            with self.subTest(form=label):
                if label in always_safe:
                    self.assertIn(label, safe)
                else:
                    self.assertIn(label, detached)

    def test_branch_labels_in_the_source_are_the_inventory(self):
        import re
        labels = set(re.findall(r'\bform\(\s*"(\w+)"', GATE.read_text()))
        self.assertEqual(labels, set(gate.SPAN_FORMS))

    def test_docstring_table_lists_every_form(self):
        doc = gate.__doc__ or GATE.read_text()
        for label in gate.SPAN_FORMS:
            with self.subTest(form=label):
                self.assertIn("`%s`" % label, doc)

    def test_allowlist_is_disjoint_from_the_parallel_adapters(self):
        self.assertFalse(set(gate.INLINE_METHODS) & set(gate.PARALLEL_METHODS))
        for name in gate.INLINE_METHODS:
            with self.subTest(name=name):
                self.assertIsNone(gate.PARALLEL_ITER.search(name))

    def test_default_is_detached(self):
        for body in ("vec![1u8].some_new_adapter().for_each(%s);" % self.CL,
                     "Unknown::new().for_each(%s);" % self.CL, "unknown_name.for_each(%s);" % self.CL):
            with self.subTest(body=body):
                self.check(body)


PAR_FN = "fn par(v: &[u8]) -> rayon::slice::Iter<'_, u8> { v.par_iter() }\n"


class Issue8102(Positive):
    """#8102: an annotation with an inferred `_` (or an `impl` / `dyn`) proves nothing about the value, so the
    initialiser decides; a std-only annotation without a placeholder is still the proof."""

    CL = "|_| { %s }" % Positive.OPEN

    def test_inferred_annotations_are_judged_by_the_initialiser(self):
        for body in (
            "let it: _ = par(&[1u8]);\n    it.for_each(%s);",
            "let o: Option<_> = Some(par(&[1u8]));\n    o.unwrap().for_each(%s);",
            "let v: Vec<_> = vec![par(&[1u8])];\n    v.into_iter().next().unwrap().for_each(%s);",
            "let b: Box<_> = Box::new(ai_memory::pool::Pool::new());\n    (*b).for_each(%s);",
        ):
            with self.subTest(body=body):
                self.check(body % self.CL, head=PAR_FN)

    def test_inferred_annotations_over_safe_initialisers_stay_clean(self):
        for body in (
            "let v: Vec<_> = vec![1u8];\n    v.iter().for_each(%s);",
            "let o: Option<_> = Some(1u8);\n    o.iter().for_each(%s);",
            "let it: _ = vec![1u8].into_iter();\n    it.for_each(%s);",
            "vec![1u8].iter().collect::<Vec<_>>().iter().for_each(%s);",
            "let v: Vec<u8> = vec![1u8];\n    v.iter().for_each(%s);",
        ):
            with self.subTest(body=body):
                self.check(body % self.CL, set())


class Issue8103(Positive):
    """#8103: std is decided by what the file binds the name to, never by its spelling; tokio and futures are not std."""

    CL = "|_| { %s }" % Positive.OPEN

    def test_non_std_imports_and_same_file_types_shadow_std_names(self):
        for head, body in (
            ("use ai_memory::pool::Mutex;\n", "Mutex::new(1u8).for_each(%s);"),
            ("use ai_memory::pool::Arc;\n", "let p: Arc<u8> = ai_memory::pool::mk();\n    p.for_each(%s);"),
            ("type Duration = ai_memory::pool::Pool;\n", "Duration::new().for_each(%s);"),
            ("use ai_memory::pool::{Vec, Pool};\n", "let _p: Option<Pool> = None;\n    Vec::new().for_each(%s);"),
            ("use ai_memory::pool::X as Arc;\n", "Arc::new(1u8).for_each(%s);"),
            ("struct Path;\nimpl Path { fn new() -> ai_memory::pool::Pool { ai_memory::pool::Pool::new() } }\n",
             "Path::new().for_each(%s);"),
        ):
            with self.subTest(head=head, body=body):
                self.check(body % self.CL, head=head)

    def test_tokio_and_futures_are_not_std(self):
        for body in (
            "tokio::runtime::Handle::current().for_each(%s);",
            "futures::stream::iter(vec![1u8]).for_each(%s);",
            "Some(tokio::task::spawn_blocking(|| 1u8)).iter().for_each(%s);",
        ):
            with self.subTest(body=body):
                self.check(body % self.CL)

    def test_std_bindings_stay_clean(self):
        for head, body in (
            ("use std::sync::Arc;\n", "Arc::new(vec![1u8]).iter().for_each(%s);"),
            ("use std::sync::{Arc, Mutex as M};\n", "Arc::new(M::new(vec![1u8])).lock().unwrap().iter().for_each(%s);"),
            ("use std::time::Duration as D;\n", "Some(D::from_secs(1)).iter().for_each(%s);"),
            ("use std::collections::HashMap;\n", "let m: HashMap<u8, u8> = HashMap::new();\n    m.iter().for_each(%s);"),
            ("", "std::sync::Mutex::new(vec![1u8]).lock().unwrap().iter().for_each(%s);"),
            ("", "Vec::<u8>::new().iter().for_each(%s);"),
            ("use std::sync::*;\n", "Some(1u8).iter().for_each(%s);"),
        ):
            with self.subTest(head=head, body=body):
                self.check(body % self.CL, set(), head=head)


class Issue8104(Positive):
    """#8104: a const or static is classified by its DECLARED type through the predicate, never by its initialiser;
    a same-file ADT type is safe only with a safe initialiser."""

    CL = "|_| { %s }" % Positive.OPEN

    def test_generic_std_wrapper_of_a_crate_type_is_detached(self):
        for head, body in (
            ("static POOL: std::sync::OnceLock<ai_memory::pool::Pool> = std::sync::OnceLock::new();\n",
             "POOL.get().unwrap().for_each(%s);"),
            ("static P: std::sync::Mutex<Option<ai_memory::pool::Pool>> = std::sync::Mutex::new(None);\n",
             "P.lock().unwrap().for_each(%s);"),
            ("static P: std::sync::Mutex<Vec<ai_memory::pool::Pool>> = std::sync::Mutex::new(Vec::new());\n",
             "P.lock().unwrap().iter().next().unwrap().for_each(%s);"),
            ("const C: Option<ai_memory::pool::Pool> = None;\n", "C.for_each(%s);"),
        ):
            with self.subTest(head=head, body=body):
                self.check(body % self.CL, head=head)

    def test_std_and_same_file_declared_types_stay_clean(self):
        for head, body in (
            ("static P: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());\n",
             "P.lock().unwrap().iter().for_each(%s);"),
            ("struct S(u8);\nconst K: S = S(1);\n", "Some(K).iter().for_each(%s);"),
            ("static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());\n", "Some(LOCK.lock()).iter().for_each(%s);"),
            ("const KEYS: [&str; 2] = [\"A\", \"B\"];\n", "KEYS.map(%s);"),
            ("use std::sync::OnceLock;\nstatic P: OnceLock<Vec<u8>> = OnceLock::new();\n",
             "P.get().unwrap().iter().for_each(%s);"),
        ):
            with self.subTest(head=head, body=body):
                self.check(body % self.CL, set(), head=head)

    def test_same_file_adt_with_an_unsafe_initialiser_is_detached(self):
        head = "struct S(ai_memory::pool::Pool);\nconst K: S = S(ai_memory::pool::Pool::new());\n"
        self.check("Some(K).iter().for_each(%s);" % self.CL, head=head)


class Issue8105(Positive):
    """#8105: an imported non-std trait (or a non-std glob) can supply a method named like an INLINE_METHODS entry,
    so while one exists a method is trusted only when it is provably std."""

    CL = "|_| { %s }" % Positive.OPEN

    def test_imported_trait_methods_are_detached(self):
        for head, body in (
            ("use ai_memory::pool::PoolExt;\n", "vec![1u8].iter().for_each(%s);"),
            ("use ai_memory::pool::PoolExt;\n", "vec![1u8].lines().for_each(%s);"),
            ("use ai_memory::pool::PoolExt as _;\n", "vec![1u8].iter().for_each(%s);"),
            ("use ai_memory::pool::prelude::*;\n", "vec![1u8].iter().for_each(%s);"),
            ("use ai_memory::pool::{Pool, PoolExt};\n", "let _p: Option<Pool> = None;\n    vec![1u8].iter().for_each(%s);"),
        ):
            with self.subTest(head=head, body=body):
                self.check(body % self.CL, head=head)

    def test_std_traits_and_used_imports_stay_clean(self):
        for head, body in (
            ("use std::io::BufRead;\n", '"a".lines().for_each(%s);'),
            ("use ai_memory::pool::Pool;\n", "let _p: Option<Pool> = None;\n    vec![1u8].iter().for_each(%s);"),
            ("use super::*;\n", "vec![1u8].iter().for_each(%s);"),
            ("use ai_memory::db;\n", "vec![1u8].iter().for_each(%s);"),
            ("", "vec![1u8].iter().for_each(%s);"),
        ):
            with self.subTest(head=head, body=body):
                self.check(body % self.CL, set(), head=head)


class Issue8106(Positive):
    """#8106: a fn parameter is classified by its declared type through the predicate; a generic, an `impl Trait`, a
    `dyn` and a type of another crate are detached, a std-only type and `self` are safe."""

    CL = "|_| { %s }" % Positive.OPEN
    CALL = "#[test]\nfn reader() {\n    let _g = ENV_LOCK.blocking_lock();\n    %s\n}\n"

    def run_case(self, helper, call, expect):
        self.assertEqual(self.flagged(WRITER + helper + self.CALL % call), expect)

    def test_untrusted_parameter_types_are_detached(self):
        for helper in (
            "fn drive<I: ParallelIterator<Item = u8>>(it: I) { it.for_each(%s); }\n",
            "fn drive(it: impl ParallelIterator<Item = u8>) { it.for_each(%s); }\n",
            "fn drive(it: &mut dyn Iterator<Item = u8>) { it.for_each(%s); }\n",
            "fn drive(it: ai_memory::pool::Pool) { it.for_each(%s); }\n",
            "fn drive<I>(it: &I) where I: ParallelIterator { it.for_each(%s); }\n",
        ):
            with self.subTest(helper=helper):
                self.run_case(helper % self.CL, "drive(vec![1u8].into_par_iter());", FLAGGED)

    def test_rstest_parameter_of_another_crate_is_detached(self):
        text = WRITER + ("#[rstest::rstest]\nfn reader(p: ai_memory::pool::Pool) {\n"
                         "    let _g = ENV_LOCK.blocking_lock();\n    p.for_each(%s);\n}\n" % self.CL)
        self.assertEqual(self.flagged(text), FLAGGED)

    def test_std_typed_parameters_stay_clean(self):
        for helper in (
            "fn drive(it: Vec<u8>) { it.iter().for_each(%s); }\n",
            "fn drive(it: &[u8]) { it.iter().for_each(%s); }\n",
            "fn drive(it: &str) { it.chars().for_each(%s); }\n",
            "fn drive(mut it: Vec<u8>) { it.drain(..).for_each(%s); }\n",
            "fn drive(m: &std::sync::Mutex<Vec<u8>>) { m.lock().unwrap().iter().for_each(%s); }\n",
        ):
            with self.subTest(helper=helper):
                self.run_case(helper % self.CL, "drive(vec![1u8]);", set())
        text = WRITER + ("#[rstest::rstest]\nfn reader(p: Vec<u8>) {\n"
                         "    let _g = ENV_LOCK.blocking_lock();\n    p.iter().for_each(%s);\n}\n" % self.CL)
        self.assertEqual(self.flagged(text), set())

    def test_self_stays_safe(self):
        head = "struct S;\nimpl S { fn run(&self) { self.m().iter().for_each(%s); }\n    fn m(&self) -> Vec<u8> { vec![1u8] } }\n"
        self.run_case(head % self.CL, "S.run();", set())


class Issue8107(Positive):
    """#8107: a chain rooted in an array / vec! literal whose links are container-level methods is judged without its
    elements; the closure parameter and an element-extracting link still judge the elements."""

    CLK = "|k| { %s k }" % Positive.OPEN
    CL = "|_| { %s }" % Positive.OPEN
    ENVS = "use ai_memory::envs::{A_ENV, B_ENV};\n"

    def test_container_level_chains_over_crate_constants_are_clean(self):
        for body in (
            "let keys = [A_ENV, B_ENV];\n    let _v = keys.map(%s);",
            "let keys = [A_ENV, B_ENV];\n    keys.iter().for_each(%s);",
            "let _v = [A_ENV, B_ENV].map(%s);",
            "let keys = vec![A_ENV, B_ENV];\n    keys.into_iter().for_each(%s);",
            "let keys = &[A_ENV, B_ENV];\n    keys.iter().for_each(%s);",
        ):
            with self.subTest(body=body):
                self.check(body % self.CLK, set(), head=self.ENVS)

    def test_element_extraction_still_judges_the_elements(self):
        for body in (
            "[par(&[1u8])].iter().next().unwrap().for_each(%s);" % self.CL,
            "[par(&[1u8])].map(|k| k.for_each(%s));" % self.CL,
            "let ks = [par(&[1u8])];\n    ks.into_iter().next().unwrap().for_each(%s);" % self.CL,
            "let ks = [par(&[1u8])];\n    ks[0].for_each(%s);" % self.CL,
            "let ks = [A_ENV, B_ENV];\n    ks.iter().next().unwrap().for_each(%s);" % self.CL,
        ):
            with self.subTest(body=body):
                self.check(body, head=PAR_FN + self.ENVS)

    POSTURE = """
use std::sync::Mutex;
static FED_ENV_LOCK: Mutex<()> = Mutex::new(());
struct Posture([(&'static str, Option<std::ffi::OsString>); 5]);
impl Posture {
    fn new(peer: &str, namespace: &str) -> Self {
        use ai_memory::federation::peer_attestation::{
            PEER_ATTESTATION_ENV, TRUST_BODY_AGENT_ID_ENV,
        };
        use ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV;
        use ai_memory::federation::signing::REQUIRE_SIG_ENV;
        const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
        let keys = [
            PEER_ATTESTATION_ENV,
            REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            REQUIRE_SIG_ENV,
            TRUST_BODY_AGENT_ID_ENV,
            REQUIRE_ATTEST_ENV,
        ];
        let guard = Self(keys.map(|k| (k, std::env::var_os(k))));
        let allowlist = json!({peer: {"allowed_namespaces": [namespace]}});
        // SAFETY: every caller holds FED_ENV_LOCK; Drop restores before release.
        unsafe {
            std::env::set_var(PEER_ATTESTATION_ENV, allowlist.to_string());
            std::env::remove_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
            std::env::set_var(REQUIRE_SIG_ENV, "0");
        }
        guard
    }
}

impl Drop for Posture {
    fn drop(&mut self) {
        for (key, previous) in &self.0 {
            unsafe {
                match previous {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

#[test]
fn first() {
    let _l = FED_ENV_LOCK.lock().unwrap();
    let _p = Posture::new("p", "n");
    let _c = db::open(":memory:");
}

#[test]
fn second() {
    let _l = FED_ENV_LOCK.lock().unwrap();
    let _p = Posture::new("p", "n");
    let _c = db::open(":memory:");
}
"""

    def test_untyped_posture_shape_of_3699_passes(self):
        """The text of tests/federation_causal_order_3699.rs at 96abf24ac (the untyped `let keys = [..]`)."""
        self.assertEqual(self.flagged(self.POSTURE), set())


class Issue8120(Positive):
    """#8120: an imported non-std trait keeps trait_risk set while it is only NAMED in a bound, an `impl X for`, a
    `dyn X` or an `impl X`; a name used as a value or in a plain type position is a real use and clears nothing."""

    CL = "|_| { %s }" % Positive.OPEN

    def test_a_trait_named_only_in_a_trait_position_still_shadows_std_methods(self):
        for head in (
            "use ai_memory::pool::PoolExt;\nfn _b<T: PoolExt>(_t: T) {}\n",
            "use ai_memory::pool::PoolExt;\nstruct S;\nimpl PoolExt for S {}\n",
            "use ai_memory::pool::PoolExt;\nfn _d(_t: &dyn PoolExt) {}\n",
            "use ai_memory::pool::PoolExt;\nfn _i(_t: impl PoolExt) {}\n",
            "use ai_memory::pool::PoolExt;\nfn _w<T>(_t: T) where T: PoolExt {}\n",
            "use ai_memory::pool::PoolExt;\nfn _c<T>(_t: T) -> u8 { <T as PoolExt>::ID }\n",
        ):
            with self.subTest(head=head):
                self.check("vec![1u8].iter().for_each(%s);" % self.CL, head=head)

    def test_control_a_name_used_as_a_value_or_type_is_a_real_use(self):
        for head, body in (
            # a value use (not a path root: `Thing::f` may be a trait fn, r13 #8157) makes the import a type
            ("use ai_memory::Thing;\n", "let _t = Thing;\n    vec![1u8].iter().for_each(%s);"),
            ("use ai_memory::pool::Pool;\nfn _p(_p: Pool) {}\n", "vec![1u8].iter().for_each(%s);"),
            ("use ai_memory::pool::Pool;\n", "let _p: Option<Pool> = None;\n    vec![1u8].iter().for_each(%s);"),
        ):
            with self.subTest(head=head, body=body):
                self.check(body % self.CL, set(), head=head)


class Issue8121(Positive):
    """#8121: a generic parameter shadows every std name of the same spelling, in a fn or an impl, in the bound
    list or the where clause, and a `use std::..` of the name does not make it std again."""

    CL = "|_| { %s }" % Positive.OPEN
    PAR = "rayon::iter::ParallelIterator"

    def test_a_generic_named_like_a_std_type_is_not_std(self):
        for head, body in (
            ("fn drive<Vec: %s>(it: Vec) { it.for_each(%%s); }\n" % self.PAR, "drive(vec![1u8].into_par_iter());"),
            ("fn drive<Vec>(it: Vec) where Vec: %s { it.for_each(%%s); }\n" % self.PAR,
             "drive(vec![1u8].into_par_iter());"),
            ("struct W<O>(O);\nimpl<Option: %s<Item = u8>> W<Option> { fn go(it: Option) { it.for_each(%%s); } }\n"
             % self.PAR, "W::go(vec![1u8].into_par_iter());"),
            ("use std::collections::HashMap;\nfn drive<HashMap: %s>(it: HashMap) { it.for_each(%%s); }\n" % self.PAR,
             "drive(vec![1u8].into_par_iter());"),
            ("fn drive<String: %s>(it: String) { it.for_each(%%s); }\n" % self.PAR, "drive(vec![1u8].into_par_iter());"),
            ("fn drive<I: %s>(it: I) { it.for_each(%%s); }\n" % self.PAR, "drive(vec![1u8].into_par_iter());"),
        ):
            with self.subTest(head=head):
                self.check(body, head=head.replace("%s", self.CL))

    def test_control_a_generic_that_is_not_used_as_the_type_stays_std(self):
        for head, body in (
            ("fn f<T>(v: Vec<u8>) { v.iter().for_each(%s); }\n", "f::<u8>(vec![1u8]);"),
            ("struct W<O>(O);\nimpl<O> W<O> { fn go(v: Vec<u8>) { v.iter().for_each(%s); } }\n", "W::<u8>::go(vec![1u8]);"),
        ):
            with self.subTest(head=head):
                self.check(body, set(), head=head.replace("%s", self.CL))


class Issue8122(Positive):
    """#8122: a same-file const is neutral only as an array length (`[u8; N]`); the name of a type that a const of the
    same spelling shadows is still the imported type."""

    CL = "|_| { %s }" % Positive.OPEN

    def test_a_const_named_like_an_imported_type_does_not_make_the_type_neutral(self):
        head = "use ai_memory::pool::Pool;\nconst Pool: u8 = 0;\n"
        for head, body in (
            (head, "let p: Pool = ai_memory::pool::mk();\n    p.for_each(%s);"),
            (head + "fn drive(p: Pool) { p.for_each(%s); }\n", "drive(ai_memory::pool::mk());"),
        ):
            with self.subTest(body=body):
                self.check(body.replace("%s", self.CL), head=head.replace("%s", self.CL))

    def test_control_a_const_array_length_stays_neutral(self):
        for head, body in (
            ("const N: usize = 2;\n", "let a: [u8; N] = [1; N];\n    a.iter().for_each(%s);"),
            ("const N: usize = 2;\nfn f(a: [u8; N]) { a.iter().for_each(%s); }\n", "f([1; N]);"),
        ):
            with self.subTest(body=body):
                self.check(body.replace("%s", self.CL), set(), head=head.replace("%s", self.CL))


class Issue8123(Positive):
    """#8123: the result of an async fn is a closure VALUE under the two-canonical-shape rule: credited only when it is
    awaited in place or handed whole to a known runner, never when it is handed to anything else."""

    BODY = 'async fn body() { let _c = db::open(":memory:"); }\n'
    MK = "fn mk() -> impl FnOnce() { || {} }\n"

    def test_an_async_fn_result_handed_to_a_foreign_call_is_detached(self):
        for body in (
            "ai_memory::pool::Pool::new().run_elsewhere(body());",
            "ai_memory::pool::run_elsewhere(body());",
            "let f = body();\n    ai_memory::pool::run_elsewhere(f);",
            "ai_memory::pool::Pool::new().run_elsewhere(async { body().await });",
        ):
            with self.subTest(body=body):
                self.check(body, head=self.BODY)

    def test_a_fn_returning_a_future_is_a_future_too(self):
        head = 'fn fut() -> impl std::future::Future<Output = ()> { async { let _c = db::open(":memory:"); } }\n'
        self.check("ai_memory::pool::run_elsewhere(fut());", head=head)

    def test_control_futures_driven_in_place_stay_clean(self):
        for body in (
            "futures::executor::block_on(body());",
            "tokio::runtime::Runtime::new().unwrap().block_on(body());",
            "futures::executor::block_on(async { body().await });",
            "futures::executor::block_on(async { tokio::join!(body(), body()); });",
        ):
            with self.subTest(body=body):
                self.check(body, set(), head=self.BODY)

    def test_control_closure_values_consumed_in_place_stay_clean(self):
        for call in ("mk()();", "let v = mk();\n    v();"):
            body = call + "\n    " + self.OPEN
            with self.subTest(body=body):
                self.check(body, set(), head=self.MK)


class Issue8124(Positive):
    """#8124: block_on is a runner by its RESOLVED path (tokio Runtime / Handle, futures executor); a receiver that
    provably is a tokio runtime, however it was built, credits both an async block and an async fn argument."""

    BODY = 'async fn body() { let _c = db::open(":memory:"); }\n'
    OPEN_BLOCK = "async { %s }" % Positive.OPEN
    RT = "fn runtime() -> tokio::runtime::Runtime { tokio::runtime::Runtime::new().unwrap() }\n"

    def test_runtime_receivers_credit_an_async_block(self):
        for head, body in (
            ("", "tokio::runtime::Runtime::new().unwrap().block_on(%s);"),
            (self.RT, "runtime().block_on(%s);"),
            ("", "let rt = tokio::runtime::Runtime::new().unwrap();\n    rt.block_on(%s);"),
            ("use tokio::runtime::Runtime;\n", "Runtime::new().unwrap().block_on(%s);"),
            ("use tokio::runtime::Runtime as Rt;\n", "Rt::new().unwrap().block_on(%s);"),
            ("", "tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(%s);"),
            ("", "tokio::runtime::Handle::current().block_on(%s);"),
            ("", "futures::executor::block_on(%s);"),
            ("use futures::executor::block_on;\n", "block_on(%s);"),
            ("use futures::executor as ex;\n", "ex::block_on(%s);"),
            ("fn drive(rt: &tokio::runtime::Runtime) { rt.block_on(%s); }\n", "drive(&tokio::runtime::Runtime::new().unwrap());"),
        ):
            with self.subTest(head=head, body=body):
                self.check(body.replace("%s", self.OPEN_BLOCK), set(), head=head.replace("%s", self.OPEN_BLOCK))

    def test_runtime_receivers_credit_an_async_fn(self):
        for head, body in (
            (self.RT, "runtime().block_on(body());"),
            ("", "let rt = tokio::runtime::Runtime::new().unwrap();\n    rt.block_on(body());"),
        ):
            with self.subTest(body=body):
                self.check(body, set(), head=self.BODY + head)

    def test_an_unresolved_receiver_is_not_a_runner(self):
        for head, body in (
            ("", "let x = ai_memory::pool::Pool::new();\n    x.block_on(%s);"),
            ("fn runtime() -> ai_memory::pool::Rt { ai_memory::pool::Rt::new() }\n", "runtime().block_on(%s);"),
            ("struct Runtime;\nimpl Runtime { fn block_on<F>(&self, f: F) { ai_memory::pool::stash(f) } }\n",
             "Runtime.block_on(%s);"),
            ("", "ai_memory::pool::block_on(%s);"),
        ):
            with self.subTest(head=head, body=body):
                self.check(body % self.OPEN_BLOCK, head=head)


# r12 (REVIEW-7349-r18, #8136-#8139): the credit side trusts a callee by its RESOLVED path, never by its name. Each row
# is (head, body, flagged); the ONE table feeds the issue classes and the issue mutants below.
R18_CL = "move || { %s }" % Positive.OPEN
R18_BODY = 'async fn body() { let _c = db::open(":memory:"); }\n'
R18_BLOCK_ON = "futures::executor::block_on(async { %s });"
R18_FAN = "use ai_memory::pool::Fan;\n"
R18_PROBES = {
    8136: [
        (R18_BODY, R18_BLOCK_ON % "ai_memory::pool::join!(body());", True),
        (R18_BODY + "use ai_memory::pool::join;\n", R18_BLOCK_ON % "join!(body());", True),
        (R18_BODY, R18_BLOCK_ON % "ai_memory::pool::select!(body());", True),
        (R18_BODY, R18_BLOCK_ON % "ai_memory::pool::detach!(body());", True),
        (R18_BODY + "macro_rules! join { ($e:expr) => { $e }; }\n", R18_BLOCK_ON % "join!(body());", True),
        (R18_BODY, R18_BLOCK_ON % "tokio::join!(body());", False),
        (R18_BODY + "use futures::join;\n", R18_BLOCK_ON % "join!(body());", False),
        (R18_BODY + "use tokio::join as j;\n", R18_BLOCK_ON % "j!(body());", False),
    ],
    8137: [
        (R18_FAN, "vec![1u8].for_each(%s);" % R18_CL, True),
        (R18_FAN, "let v = vec![1u8];\n    v.for_each(%s);" % R18_CL, True),
        (R18_FAN, "[1u8].for_each(%s);" % R18_CL, True),
        (R18_FAN, "let _x: Vec<u8> = vec![1u8].map(%s);" % R18_CL, True),
        (R18_FAN, "vec![1u8].iter().for_each(%s);" % R18_CL, True),
        ("", "vec![1u8].iter().for_each(%s);" % R18_CL, False),
        ("", "let v = vec![1u8];\n    v.iter().for_each(%s);" % R18_CL, False),
        ("use tower::ServiceExt as _;\n", "Some(1u8).map(%s);" % R18_CL, False),
    ],
    8138: [
        ("use ai_memory::pool::PoolExt;\n", "let _n = PoolExt::name(&0u8);\n    vec![1u8].iter().for_each(%s);" % R18_CL, True),
        ("use ai_memory::pool::PoolExt;\n", "let _n = PoolExt::name::<u8>(&0u8);\n    vec![1u8].iter().for_each(%s);" % R18_CL, True),
        ("use ai_memory::pool::PoolExt;\n", "let _n = <u8 as PoolExt>::name(&0u8);\n    vec![1u8].iter().for_each(%s);" % R18_CL, True),
        # r13 (#8157): `Pool::new()` is spelled exactly as a UFCS trait call, and the scratch tree has no src/ that
        # declares Pool a struct, so Pool stays a possible trait: flagged (fail closed). The real tree resolves its
        # own-crate imports through src/ (CommonModel.src_traits / src_types).
        ("use ai_memory::pool::Pool;\n", "let _p = Pool::new();\n    vec![1u8].iter().for_each(%s);" % R18_CL, True),
        ("use ai_memory::pool::Pool;\n", "let _p = Pool::from_parts(&1u8, 2u8);\n    vec![1u8].iter().for_each(%s);" % R18_CL, True),
        ("use ai_memory::pool::PoolExt;\n", "let _p = PoolExt { n: 0 };\n    vec![1u8].iter().for_each(%s);" % R18_CL, False),
    ],
    8139: [
        ("", "let f = async || { %s };\n    futures::executor::block_on(f());" % Positive.OPEN, False),
        ("", "let f = || async { %s };\n    futures::executor::block_on(f());" % Positive.OPEN, False),
        ("", "let f = async move || { %s };\n    futures::executor::block_on(f());" % Positive.OPEN, False),
        ("", "let f = async || { %s };\n    ai_memory::pool::run_elsewhere(f());" % Positive.OPEN, True),
        ("", "let f = || async { %s };\n    ai_memory::pool::run_elsewhere(f());" % Positive.OPEN, True),
        ("", "let f = async || { %s };\n    let g = f();\n    ai_memory::pool::run_elsewhere(g);" % Positive.OPEN, True),
        ("", "let f = async || { %s };\n    ai_memory::pool::run_elsewhere(f);" % Positive.OPEN, True),
        ("", "ai_memory::pool::run_elsewhere((async || { %s })());" % Positive.OPEN, True),
    ],
}


class ReviewR18(Positive):
    """REVIEW-7349-r18: every row of R18_PROBES is decided as its flag says."""

    def run_rows(self, issue):
        for head, body, flagged in R18_PROBES[issue]:
            with self.subTest(head=head, body=body):
                self.check(body, FLAGGED if flagged else set(), head=head)

    def test_8136_a_macro_is_trusted_by_its_resolved_path_only(self):
        self.run_rows(8136)

    def test_8137_a_container_method_is_not_trusted_while_a_crate_trait_may_supply_it(self):
        self.run_rows(8137)

    def test_8138_a_trait_called_through_its_path_still_provides_methods(self):
        self.run_rows(8138)

    def test_8139_an_async_closure_run_by_a_resolved_runner_is_clean(self):
        self.run_rows(8139)


R18_MUTANTS = (  # (issue, FileModel method, original text, mutated text): the mutant must turn a probe of its issue RED
    (8136, "await_macro_arg", "self.callee_origin(path_segments(m.group(1)), m.group(2), CALLEE_MACRO) == STD",
     'm.group(2) in ("join", "try_join", "select")'),
    (8137, "callee_origin", "full = self.method_path(name)", "full = (STD_METHOD_ROOT, name)"),
    (8138, "provider", "self.type_use(name, text)", "re.search(r\"(?<![\\w$'])%s\\b\" % re.escape(name), text)"),
    (8139, "same_thread", "if ASYNC_CLOSURE.match(body, s):", "if False:"),
)


class ReviewR18Mutants(unittest.TestCase):
    """REVIEW-7349-r18: one named mutant per issue, each reverting exactly the new decision; each turns RED."""

    def test_each_issue_mutant_turns_a_probe_red(self):
        src = GATE.read_text()
        methods = {}
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ClassDef) and node.name == "FileModel":
                for fn in node.body:
                    if isinstance(fn, ast.FunctionDef):
                        methods[fn.name] = ast.get_source_segment(src, fn)
        for issue, rule, old, new in R18_MUTANTS:
            with self.subTest(issue=issue, rule=rule):
                seg = methods[rule]
                self.assertEqual(seg.count(old), 1, old)
                mod = types.ModuleType("r18_mutant_%d" % issue)
                mod.__file__ = str(GATE)
                sys.modules[mod.__name__] = mod
                exec(compile(src.replace(seg, seg.replace(old, new)), str(GATE), "exec"), mod.__dict__)
                red = []
                for head, body, flagged in R18_PROBES[issue]:
                    shutil.rmtree(SCRATCH, ignore_errors=True)
                    (SCRATCH / "tests").mkdir(parents=True)
                    (SCRATCH / "tests" / "a.rs").write_text(WRITER + head + Positive.LOCKED % body)
                    if bool(mod.scan_tree(SCRATCH)) != flagged:
                        red.append(body)
                shutil.rmtree(SCRATCH, ignore_errors=True)
                self.assertTrue(red, "the #%d mutant stays GREEN" % issue)


# r13 (REVIEW-7349-r19, #8154-#8158): a callee that does not resolve to an allowlisted crate-qualified path is never
# trusted; there is no bare-name trust. Each row is (head, body, flagged) or (head, body, flagged, files): files maps a
# path under tests/ to the text of a module file the row declares (an included module, tests/common).
R19_SHADOW = "macro_rules! %s { ($f:expr) => { ai_memory::pool::run_elsewhere($f) }; }\n"
R19_PATH_MOD = '#[macro_use]\n#[path = "support/rt.rs"]\nmod rt;\n'
R19_UFCS = "use ai_memory::pool::PoolExt;\n"
R19_ITER = "\n    vec![1u8].iter().for_each(%s);" % R18_CL
R19_GLOB = "use ai_memory::pool::*;\n"
R19_FUT_MAP = "futures::future::FutureExt::map(async {}, |_| { %s })" % Positive.OPEN
R19_PROBES = {
    8154: [
        (R18_BODY + "use tokio::join;\n" + R19_SHADOW % "join", R18_BLOCK_ON % "join!(body());", True),
        (R18_BODY + "use futures::select;\n", (R19_SHADOW % "select") + "    " + R18_BLOCK_ON % "select!(body());", True),
        (R19_PATH_MOD + R18_BODY + "use tokio::join;\n", R18_BLOCK_ON % "join!(body());", True,
         {"support/rt.rs": R19_SHADOW % "join"}),
        ("#[macro_use]\nmod common;\n" + R18_BODY + "use tokio::join;\n", R18_BLOCK_ON % "join!(body());", True,
         {"common/mod.rs": R19_SHADOW % "join"}),
        (R18_BODY + "use tokio::join;\n", R18_BLOCK_ON % "join!(body());", False),
        (R18_BODY + R19_SHADOW % "join", R18_BLOCK_ON % "tokio::join!(body());", False),
    ],
    8155: [
        (R18_FAN, "let o = Some(1u8);\n    o.for_each(%s);" % R18_CL, True),
        (R18_FAN, "let _x = 1u8.map(%s);" % R18_CL, True),
        (R18_FAN, "Some(1u8).map(%s);" % R18_CL, True),
        (R18_FAN, "String::new().map(%s);" % R18_CL, True),
        (R18_FAN, "vec![1u8].clone().for_each(%s);" % R18_CL, True),
        (R19_GLOB, "Some(1u8).for_each(%s);" % R18_CL, True),
        (R19_GLOB, "Vec::<u8>::new().for_each(%s);" % R18_CL, True),
        (R19_GLOB, "vec![1u8].clone().for_each(%s);" % R18_CL, True),
        (R19_GLOB, "let v: Vec<u8> = vec![1u8];\n    v.for_each(%s);" % R18_CL, True),
        (R19_GLOB, "let s = vec![1u8].into_iter();\n    s.inspect(%s);" % R18_CL, True),
        ("", "Some(1u8).map(%s);" % R18_CL, False),
        ("", "let o = Some(1u8);\n    o.map(%s);" % R18_CL, False),
        # a vetted trait (KNOWN_TRAIT_METHODS) supplies exactly its listed methods: tower's ServiceExt has and_then
        ("use tower::ServiceExt as _;\n", "Some(1u8).and_then(%s);" % R18_CL, True),
        ("use tower::ServiceExt as _;\n", "Some(1u8).map(%s);" % R18_CL, False),
        ("extern crate tower as tw;\nuse tw::ServiceExt as _;\n", "Some(1u8).and_then(%s);" % R18_CL, True),
    ],
    8156: [
        ("extern crate ai_memory as futures;\n", R18_BLOCK_ON % Positive.OPEN, True),
        ("extern crate ai_memory as tokio;\n" + R18_BODY, R18_BLOCK_ON % "tokio::join!(body());", True),
        ("extern crate ai_memory as tokio;\nuse tokio::join;\n" + R18_BODY, R18_BLOCK_ON % "join!(body());", True),
        ("use ai_memory::pool as tokio;\n" + R18_BODY, R18_BLOCK_ON % "tokio::join!(body());", True),
        ("mod rt { pub use ai_memory::pool::run_elsewhere as block_on; }\n", "rt::block_on(async { %s });" % Positive.OPEN,
         True),
        ("mod futures { pub mod executor { pub use ai_memory::pool::run_elsewhere as block_on; } }\n",
         R18_BLOCK_ON % Positive.OPEN, True),
        ("use ai_memory::shim::fx;\n", "fx::executor::block_on(async { %s });" % Positive.OPEN, True),
        ("extern crate futures as fx;\n", "fx::executor::block_on(async { %s });" % Positive.OPEN, False),
        ("extern crate futures;\n", R18_BLOCK_ON % Positive.OPEN, False),
    ],
    8157: [
        (R19_UFCS, "let _n = PoolExt::name(0u8);" + R19_ITER, True),
        (R19_UFCS, "let _n = PoolExt::name(&0u8, &1u8);" + R19_ITER, True),
        (R19_UFCS, "let x = 0u8;\n    let _n = PoolExt::name(x);" + R19_ITER, True),
        (R19_UFCS, "let _f = PoolExt::name;" + R19_ITER, True),
        (R19_UFCS, "let _n = PoolExt::default_name();" + R19_ITER, True),
        (R19_UFCS, "let _n = PoolExt::name(&mk());" + R19_ITER, True),
        (R19_UFCS, "let _n = <u8 as PoolExt>::name(&0u8);" + R19_ITER, True),
        (R19_UFCS, "let _p = PoolExt { n: 0 };" + R19_ITER, False),
        # a path-root-only import is a type only when its resolved path is a vetted type (KNOWN_FOREIGN_TYPES) or a
        # struct of the test crate itself; a trait of the test crate supplies the fns it declares
        ("use chrono::Utc;\n", "let _t = Utc::now();" + R19_ITER, False),
        ("use chrono::Local;\n", "let _t = Local::now();" + R19_ITER, True),
        ("mod m { pub struct Posture; impl Posture { pub fn mk() -> Self { Posture } } }\nuse self::m::Posture;\n",
         "let _p = Posture::mk();" + R19_ITER, False),
        ("mod m { pub trait Fan { fn for_each(self, f: u8); } }\nuse self::m::Fan;\n", "let _f = Fan::for_each;" + R19_ITER,
         True),
    ],
    8158: [
        ("", "ai_memory::pool::run_elsewhere(%s);" % R19_FUT_MAP, True),
        ("", "ai_memory::pool::map(%s);" % R18_CL, True),
        ("use ai_memory::pool::spawn_each as for_each;\n", "for_each(%s);" % R18_CL, True),
        ("", "ai_memory::pool::run_elsewhere(futures::stream::StreamExt::for_each(ai_memory::pool::mk(), %s));"
         % R18_CL, True),
        ("", "let _ = ai_memory::pool::catch_unwind(|| { %s });" % Positive.OPEN, True),
        ("", "let _ = futures::future::FutureExt::map(async {}, |_| { %s });" % Positive.OPEN, True),
        ("", "let _ = std::panic::catch_unwind(|| { %s });" % Positive.OPEN, False),
        ("use std::panic;\n", "let _ = panic::catch_unwind(|| { %s });" % Positive.OPEN, False),
        ("", "let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { %s }));" % Positive.OPEN, False),
    ],
}


def r19_write(row):
    """Write the fixture tree of one R19_PROBES row under SCRATCH; returns (head, body, flagged)."""
    head, body, flagged = row[:3]
    shutil.rmtree(SCRATCH, ignore_errors=True)
    (SCRATCH / "tests").mkdir(parents=True)
    for rel, text in (row[3] if len(row) > 3 else {}).items():
        (SCRATCH / "tests" / rel).parent.mkdir(parents=True, exist_ok=True)
        (SCRATCH / "tests" / rel).write_text(text)
    (SCRATCH / "tests" / "a.rs").write_text(WRITER + head + Positive.LOCKED % body)
    return head, body, flagged


class ReviewR19(Positive):
    """REVIEW-7349-r19: every row of R19_PROBES is decided as its flag says."""

    def run_rows(self, issue):
        for row in R19_PROBES[issue]:
            with self.subTest(head=row[0], body=row[1]):
                head, body, flagged = r19_write(row)
                self.assertEqual(self.scan(), FLAGGED if flagged else set())

    def test_8154_a_macro_rules_shadow_beats_an_imported_trusted_macro(self):
        self.run_rows(8154)

    def test_8155_a_method_is_never_trusted_by_its_bare_name(self):
        self.run_rows(8155)

    def test_8156_an_extern_crate_alias_is_resolved_before_a_root_is_trusted(self):
        self.run_rows(8156)

    def test_8157_every_ufcs_shape_keeps_the_trait_in_scope(self):
        self.run_rows(8157)

    def test_8158_a_free_fn_is_never_trusted_by_its_last_segment(self):
        self.run_rows(8158)


class CalleeTrustInvariant(unittest.TestCase):
    """REVIEW-7349-r19: a callee that does not resolve to an allowlisted crate-qualified path is never trusted; there
    is no bare-name trust anywhere in callee_origin. Proven by behaviour (every trusted name under an untrusted path)
    and by structure (every membership test against a trust table sits behind a resolved path)."""

    TRUST_TABLES = ("SAME_THREAD_CALLEES", "INLINE_ROOTS", "AWAIT_MACROS", "WRAPPER_CALLEES", "TRUSTED_FN_PATHS",
                    "TRUSTED_METHOD_PATHS")
    GONE = ("UFCS_ROOT",)  # the borrowed-one-argument UFCS special case (#8157)
    RESOLVERS = ("resolve_path", "method_path")  # the only functions that build a resolved path

    def test_no_name_resolves_to_trust_under_an_untrusted_path(self):
        model = gate.FileModel("use ai_memory::pool::Fan;\nuse tokio::join;\n" + R19_SHADOW % "join")
        for name in sorted(gate.SAME_THREAD_CALLEES):
            for segs in ([], ["ai_memory", "pool"], ["futures", "future", "FutureExt"], ["tokio", "stream"]):
                with self.subTest(name=name, segs=segs):
                    self.assertNotEqual(model.callee_origin(segs, name, gate.CALLEE_FN), gate.STD)
            with self.subTest(method=name):
                self.assertNotEqual(model.callee_origin([], name, gate.CALLEE_METHOD), gate.STD)
        self.assertNotEqual(model.callee_origin([], "join", gate.CALLEE_MACRO), gate.STD)

    def test_every_allowlisted_path_is_trusted_in_a_clean_file(self):
        model = gate.FileModel("")
        paths = getattr(gate, "TRUSTED_FN_PATHS", frozenset())
        self.assertTrue(paths, "the free-fn allowlist is a table of resolved paths")
        for path in sorted(paths):
            with self.subTest(path=path):
                self.assertEqual(model.callee_origin(list(path[:-1]), path[-1], gate.CALLEE_FN), gate.STD)
        for path in sorted(gate.AWAIT_MACROS):
            with self.subTest(path=path):
                self.assertEqual(model.callee_origin(list(path[:-1]), path[-1], gate.CALLEE_MACRO), gate.STD)

    def test_every_trust_membership_test_sits_behind_a_resolved_path(self):
        src = GATE.read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                self.assertNotIn(node.id, self.GONE, "line %d" % node.lineno)
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node

        def enclosing(node):
            while node in parents:
                node = parents[node]
                if isinstance(node, ast.FunctionDef):
                    return node
            return None

        def resolved_from(fn):
            """The names fn binds from a call of a resolver (self.resolve_path / self.method_path)."""
            out = set()
            for sub in ast.walk(fn):
                if isinstance(sub, ast.Assign) and isinstance(sub.value, ast.Call):
                    func = sub.value.func
                    if isinstance(func, ast.Attribute) and func.attr in self.RESOLVERS:
                        out.update(t.id for t in sub.targets if isinstance(t, ast.Name))
            return out

        sites = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Name) or node.id not in self.TRUST_TABLES:
                continue
            fn = enclosing(node)
            if fn is None:
                continue  # a module-level table definition
            cmp_ = parents.get(node)
            line = "%s line %d" % (fn.name, node.lineno)
            self.assertIsInstance(cmp_, ast.Compare, line)
            self.assertTrue(all(isinstance(op, (ast.In, ast.NotIn)) for op in cmp_.ops), line)
            left = cmp_.left
            if fn.name in self.RESOLVERS and isinstance(left, ast.Subscript):
                left = left.value  # a resolver checks the root of the path it builds
            self.assertIsInstance(left, ast.Name, "%s: only a whole resolved path is tested" % line)
            if fn.name in self.RESOLVERS:
                self.assertEqual(left.id, "full", line)
            else:
                self.assertIn(left.id, resolved_from(fn), "%s: a bare name is tested against %s" % (line, node.id))
            sites += 1
        self.assertTrue(sites)


R19_MUTANTS = (  # (name, issue, FileModel method, original text, mutated text): each must turn a probe of its issue RED
    ("n_macro_shadow_off", 8154, "callee_origin",
     "if kind == CALLEE_MACRO and not segs and (name in self.macro_names or MACRO_OPEN in self.macro_names):",
     "if False:"),
    ("n_module_macros_off", 8154, "_index_imports",
     "self.macro_names = self.macro_defs | self.module_macros", "self.macro_names = self.macro_defs"),
    ("n_method_callee_by_name", 8155, "callee_origin", "return STD if full in TRUSTED_METHOD_PATHS else UNKNOWN",
     "return STD if name in SAME_THREAD_CALLEES and not PARALLEL_ITER.search(name) else UNKNOWN"),
    ("n_extern_crate_alias_off", 8156, "_index_imports",
     "for crate, alias in EXTERN_CRATE.findall(with_uses):", "for crate, alias in ():"),
    ("n_path_root_type_use", 8157, "type_use",
     "return any(not PATH_ROOT_USE.match(text, m.end()) for m in uses)", "return any(True for m in uses)"),
    ("n_fn_callee_by_name", 8158, "callee_origin", "return STD if full in TRUSTED_FN_PATHS else CRATE",
     "return STD if full[-1] in SAME_THREAD_CALLEES else CRATE"),
)


class ReviewR19Mutants(unittest.TestCase):
    """REVIEW-7349-r19: one named mutant per new decision (bare-name trust of a method or a free fn, the macro_rules!
    shadow of the file and of a module file, the extern crate index, the path-root type use); each turns RED."""

    def test_each_named_mutant_turns_a_probe_red(self):
        src = GATE.read_text()
        methods = {}
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ClassDef) and node.name == "FileModel":
                for fn in node.body:
                    if isinstance(fn, ast.FunctionDef):
                        methods[fn.name] = ast.get_source_segment(src, fn)
        for name, issue, rule, old, new in R19_MUTANTS:
            with self.subTest(mutant=name):
                seg = methods[rule]
                self.assertEqual(seg.count(old), 1, old)
                mod = types.ModuleType("r19_mutant_" + name)
                mod.__file__ = str(GATE)
                sys.modules[mod.__name__] = mod
                exec(compile(src.replace(seg, seg.replace(old, new)), str(GATE), "exec"), mod.__dict__)
                red = []
                for row in R19_PROBES[issue]:
                    head, body, flagged = r19_write(row)
                    if bool(mod.scan_tree(SCRATCH)) != flagged:
                        red.append(body)
                shutil.rmtree(SCRATCH, ignore_errors=True)
                self.assertTrue(red, "the %s mutant stays GREEN" % name)


# r11 (#8125): per classifying rule, the probes that must be flagged (RED when the rule is loosened). A probe is
# (head, body); %s is the closure `|_| { db::open(..) }` or, for the runtime rule, the async block.
RULE_CL = "|_| { %s }" % Positive.OPEN
# trait_risk from a vetted trait (KNOWN_TRAIT_METHODS) that supplies neither iter, map nor for_each (r13, #8155): the
# for_each callee stays trusted, so only the rule under test can veto the closure argument
RULE_TRAIT = "use tower::ServiceExt as _;\n"
RULE_MAPPER = (  # same-file methods: member_ok resolves them, so only closure_form can veto the closure argument
    "struct S;\nimpl S {\n    fn it(&self) -> Vec<u8> { vec![1u8] }\n"
    "    fn map<F>(&self, _f: F) -> Vec<u8> { vec![1u8] }\n}\n"
)
RULE_PROBES = {
    "arg_inline": [("", "ai_memory::pool::run_elsewhere(%s);"), ("use ai_memory::pool::*;\n", "run_elsewhere(%s);"),
                   ("", "vec![1u8].run_elsewhere(%s);"), ("use ai_memory::pool::{self, run_elsewhere};\n", "run_elsewhere(%s);")],
    "await_macro_arg": [(R18_BODY, R18_BLOCK_ON % "ai_memory::pool::join!(body());"),
                        (R18_BODY + "use ai_memory::pool::select;\n", R18_BLOCK_ON % "select!(body());")],
    "annotation": [("", "let p: Foo = ai_memory::pool::mk();\n    p.for_each(%s);"),
                   ("", "let p: ai_memory::pool::Pool = ai_memory::pool::mk();\n    p.for_each(%s);")],
    "call_ok": [("", "ai_memory::pool::mk().for_each(%s);"),
                ("use ai_memory::pool::Pool;\n", "Pool::new().for_each(%s);"),
                ("fn g<T>(_t: T) {}\n", "T::new().for_each(%s);")],
    "closure_form": [(RULE_TRAIT + RULE_MAPPER, "S.it().map(|_| 1u8).for_each(%s);")],
    "const_ok": [("const K: ai_memory::pool::Pool = ai_memory::pool::K;\n", "K.for_each(%s);"),
                 ("const K: Foo = vec![1u8];\n", "K.for_each(%s);")],
    "macro_ok": [("fn g<T>(_t: T) {}\n", "T::vec![1u8].iter().for_each(%s);"),
                 ("macro_rules! vec { () => {} }\n", "vec![1u8].iter().for_each(%s);")],
    "member_ok": [(RULE_TRAIT, "let v = vec![1u8];\n    v.iter().for_each(%s);")],
    "name_ok": [("fn drive(p: ai_memory::pool::Pool) { p.for_each(%s); }\n", "drive(ai_memory::pool::mk());"),
                ("fn drive<T>(p: T) { p.for_each(%s); }\n", "drive(ai_memory::pool::mk());")],
    "path_ok": [("", "ai_memory::pool::K.for_each(%s);"), ("fn g<T>(_t: T) {}\n", "T::K.for_each(%s);")],
    "returns_safe": [("fn mk() -> Opaque { ai_memory::pool::Pool::new() }\n", "let p = mk();\n    p.for_each(%s);"),
                     ("fn mk() -> impl ai_memory::pool::Tr { ai_memory::pool::Pool::new() }\n",
                      "let p = mk();\n    p.for_each(%s);")],
    "span_safe": [("", "vec![1u8].iter().collect::<ai_memory::pool::Pool>().for_each(%s);"),
                  ("fn g<T>(_t: T) {}\n", "vec![1u8].iter().collect::<T>().for_each(%s);")],
    "type_runtime": [("fn runtime() -> Pair<tokio::runtime::Runtime> { mk_pair() }\n", "runtime().block_on(async { %s });")],
}


# r14 (REVIEW-7349-r20, #8168 G1-G3): a callee is trusted only when it RESOLVES to an allowlisted crate-qualified path.
# Each row is (head, body, flagged, files); files maps a path under the scratch ROOT (Cargo.toml, src/.., tests/..) to its text.
R20_CARGO = '[package]\nname = "ai_memory"\nversion = "0.0.0"\n'
R20_MAP = "Some(1u8).map(%s);" % R18_CL
R20_JOIN = R18_BLOCK_ON % "join!(body());"
R20_NEST = "#[macro_use]\nmod rt;\n" + R18_BODY + "use tokio::join;\n"
R20_PROBES = {
    "G1": [
        # src_lowercase_trait: a lowercase name is a trait when the src/ definition says so
        ("use ai_memory::fan::fan;\n", R20_MAP, True,
         {"Cargo.toml": R20_CARGO, "src/fan.rs": "pub trait fan { fn map(self, f: u8); }\n"}),
        # src_reexport_alias_over_struct_name: the name is a struct in one module and a trait alias in another
        ("use ai_memory::b::Fan;\n", R20_MAP, True,
         {"Cargo.toml": R20_CARGO, "src/a.rs": "pub struct Fan;\n",
          "src/b.rs": "pub trait Real { fn map(self, f: u8); }\npub use self::Real as Fan;\n"}),
        # src_trait_fns_from_macro: a trait whose fns a macro generates supplies any method
        ("use ai_memory::Fan;\n", R20_MAP, True,
         {"Cargo.toml": R20_CARGO,
          "src/lib.rs": "macro_rules! mk_fn { () => { fn map(self, f: u8); }; }\npub trait Fan { mk_fn!(); }\n"}),
        # a trait that a macro generates under a name that is also a struct
        ("use ai_memory::Fan;\n", R20_MAP, True,
         {"Cargo.toml": R20_CARGO, "src/a.rs": "pub struct Fan;\n",
          "src/lib.rs": "macro_rules! mk { ($n:ident) => { pub trait $n { fn map(self, f: u8); } }; }\nmk!(Fan);\n"}),
        # controls: a struct, a plain fn and a trait that declares other methods supply no `map`
        ("use ai_memory::a::Fan;\n", R20_MAP, False, {"Cargo.toml": R20_CARGO, "src/a.rs": "pub struct Fan;\n"}),
        ("use ai_memory::util::helper;\n", R20_MAP, False,
         {"Cargo.toml": R20_CARGO, "src/util.rs": "pub fn helper() {}\n"}),
        ("use ai_memory::fan::fan;\n", R20_MAP, False,
         {"Cargo.toml": R20_CARGO, "src/fan.rs": "pub trait fan { fn other(self); }\n"}),
    ],
    "G2": [
        # cargo_renamed_futures / cargo_renamed_tokio_join: a root name that Cargo.toml points at another crate
        ("", R18_BLOCK_ON % Positive.OPEN, True,
         {"Cargo.toml": R20_CARGO + '[dependencies]\nfutures = { package = "ai_memory_shim", version = "1" }\n'}),
        (R18_BODY + "use tokio::join;\n", R20_JOIN, True,
         {"Cargo.toml": R20_CARGO + '[dependencies]\ntokio = { version = "1", package = "ai_memory_shim" }\n'}),
        ("", R18_BLOCK_ON % Positive.OPEN, True,
         {"Cargo.toml": R20_CARGO + '[dev-dependencies.futures]\nversion = "0.3"\npackage = "ai_memory_shim"\n'}),
        (R18_BODY, R18_BLOCK_ON % "tokio::join!(body());", True,
         {"Cargo.toml": R20_CARGO + '[target.\'cfg(unix)\'.dependencies]\ntokio = { package = "other-crate" }\n'}),
        # a rename that points at a trusted crate maps back to it before the allowlist
        (R18_BODY + "use tk::join;\n", R20_JOIN, False,
         {"Cargo.toml": R20_CARGO + '[dependencies]\ntk = { package = "tokio", version = "1" }\n'}),
        (R18_BODY, R18_BLOCK_ON % "tk::join!(body());", False,
         {"Cargo.toml": R20_CARGO + '[dependencies]\ntk = { package = "tokio" }\n'}),
        ("", "fut::executor::block_on(async { %s });" % Positive.OPEN, False,
         {"Cargo.toml": R20_CARGO + '[dependencies.fut]\npackage = "futures"\n'}),
        # controls: no rename, or a rename onto itself
        ("", R18_BLOCK_ON % Positive.OPEN, False,
         {"Cargo.toml": R20_CARGO + '[dependencies]\nfutures = { version = "0.3" }\n'}),
        ("", R18_BLOCK_ON % Positive.OPEN, False,
         {"Cargo.toml": R20_CARGO + '[dependencies]\nfutures = { package = "futures" }\n'}),
    ],
    "G3": [
        # macro_rules_shadow_via_nested_mod_file: the shadow sits two module files below the test file
        (R20_NEST, R20_JOIN, True,
         {"tests/rt.rs": "#[macro_use]\nmod inner;\n", "tests/rt/inner.rs": R19_SHADOW % "join"}),
        (R20_NEST, R20_JOIN, True,
         {"tests/rt/mod.rs": "#[macro_use]\nmod inner;\n", "tests/rt/inner.rs": R19_SHADOW % "join"}),
        (R20_NEST, R20_JOIN, True,
         {"tests/rt.rs": "#[macro_use]\nmod a;\n", "tests/rt/a.rs": "#[macro_use]\nmod b;\n",
          "tests/rt/a/b.rs": R19_SHADOW % "join"}),
        (R20_NEST, R20_JOIN, True,
         {"tests/rt.rs": "#[macro_use]\nmod x { #[macro_use] mod inner; }\n", "tests/rt/x/inner.rs": R19_SHADOW % "join"}),
        # controls: a nested module without a shadow, and a module file that declares itself through #[path] (a cycle
        # that terminates; a plain `mod rt;` in tests/rt.rs would name tests/rt/rt.rs, which the gate fails closed on)
        (R20_NEST, R20_JOIN, False,
         {"tests/rt.rs": "#[macro_use]\nmod inner;\n", "tests/rt/inner.rs": "pub fn f() {}\n"}),
        (R20_NEST, R20_JOIN, False, {"tests/rt.rs": '#[macro_use]\n#[path = "rt.rs"]\nmod rt;\n'}),
    ],
}


def r20_write(row):
    """Write the fixture tree of one R20_PROBES row under SCRATCH; returns (head, body, flagged)."""
    head, body, flagged, files = row
    shutil.rmtree(SCRATCH, ignore_errors=True)
    (SCRATCH / "tests").mkdir(parents=True)
    for rel, text in files.items():
        (SCRATCH / rel).parent.mkdir(parents=True, exist_ok=True)
        (SCRATCH / rel).write_text(text)
    (SCRATCH / "tests" / "a.rs").write_text(WRITER + head + Positive.LOCKED % body)
    return head, body, flagged


class ReviewR20(Positive):
    """REVIEW-7349-r20 (umbrella #8168 G1-G3): every row of R20_PROBES is decided as its flag says."""

    def run_rows(self, group):
        for row in R20_PROBES[group]:
            with self.subTest(head=row[0], body=row[1], files=sorted(row[3])):
                head, body, flagged = r20_write(row)
                self.assertEqual(self.scan(), FLAGGED if flagged else set())

    def test_g1_a_method_provider_is_decided_from_the_resolved_definition(self):
        self.run_rows("G1")

    def test_g2_a_cargo_package_rename_is_resolved_before_a_root_is_trusted(self):
        self.run_rows("G2")

    def test_g3_a_macro_rules_shadow_in_a_nested_module_file_wins(self):
        self.run_rows("G3")


R21_PROBES = {
    "N1": [
        # a TOML literal string ('x') is as good a package value as a basic string, in every table form
        ("", R18_BLOCK_ON % Positive.OPEN, True,
         {"Cargo.toml": R20_CARGO + "[dependencies]\nfutures = { package = 'ai_memory_shim', version = '1' }\n"}),
        ("", R18_BLOCK_ON % Positive.OPEN, True,
         {"Cargo.toml": R20_CARGO + "[dev-dependencies.futures]\nversion = '0.3'\npackage = 'ai_memory_shim'\n"}),
        ("", R18_BLOCK_ON % Positive.OPEN, True,
         {"Cargo.toml": R20_CARGO + "[dependencies]\nfutures.package = 'ai_memory_shim'\n"}),
        (R18_BODY + "use tokio::join;\n", R20_JOIN, True,
         {"Cargo.toml": R20_CARGO + "[dependencies]\ntokio = { package = 'other-crate' }\n"}),
        # a single-quoted rename onto a trusted crate maps back to it
        (R18_BODY + "use tk::join;\n", R20_JOIN, False,
         {"Cargo.toml": R20_CARGO + "[dependencies]\ntk = { package = 'tokio', version = '1' }\n"}),
        # a single-quoted [package] name is the crate root of the tests
        ("use ai_memory::fan::fan;\n", R20_MAP, True,
         {"Cargo.toml": "[package]\nname = 'ai_memory'\nversion = '0.0.0'\n",
          "src/fan.rs": "pub trait fan { fn map(self, f: u8); }\n"}),
    ],
    "N2": [
        # a lowercase trait in a `#[path]` module file outside src/ is still a trait
        ("use ai_memory::fan::fan;\n", R20_MAP, True,
         {"Cargo.toml": R20_CARGO, "src/lib.rs": '#[path = "../gen/fan.rs"]\npub mod fan;\n',
          "gen/fan.rs": "pub trait fan { fn map(self, f: u8); }\n"}),
        # ... also one level down, through a module file of src/, and through an include!
        ("use ai_memory::a::fan::fan;\n", R20_MAP, True,
         {"Cargo.toml": R20_CARGO, "src/lib.rs": "pub mod a;\n", "src/a.rs": '#[path = "../gen/fan.rs"]\npub mod fan;\n',
          "gen/fan.rs": "pub trait fan { fn map(self, f: u8); }\n"}),
        ("use ai_memory::fan;\n", R20_MAP, True,
         {"Cargo.toml": R20_CARGO, "src/lib.rs": 'include!("../gen/fan.rs");\n',
          "gen/fan.rs": "pub trait fan { fn map(self, f: u8); }\n"}),
        # controls: the outside file declares a struct, or declares other methods
        ("use ai_memory::fan::fan;\n", R20_MAP, False,
         {"Cargo.toml": R20_CARGO, "src/lib.rs": '#[path = "../gen/fan.rs"]\npub mod fan;\n',
          "gen/fan.rs": "pub struct fan;\n"}),
        ("use ai_memory::fan::fan;\n", R20_MAP, False,
         {"Cargo.toml": R20_CARGO, "src/lib.rs": '#[path = "../gen/fan.rs"]\npub mod fan;\n',
          "gen/fan.rs": "pub trait fan { fn other(self); }\n"}),
    ],
    "N3": [
        # a macro_rules! shadow that an include!d file defines is in textual scope
        (R18_BODY + "use tokio::join;\n" + 'include!("shadow.rs");\n', R20_JOIN, True,
         {"tests/shadow.rs": R19_SHADOW % "join"}),
        (R20_NEST, R20_JOIN, True,
         {"tests/rt.rs": '#[macro_use]\ninclude!("shadow.rs");\n', "tests/shadow.rs": R19_SHADOW % "join"}),
        (R20_NEST, R20_JOIN, True,
         {"tests/rt.rs": '#[macro_use]\nmod inner;\n', "tests/rt/inner.rs": 'include!("shadow.rs");\n',
          "tests/rt/shadow.rs": R19_SHADOW % "join"}),
        # controls: an include!d file without a shadow, and one that includes itself (a cycle that terminates)
        (R18_BODY + "use tokio::join;\n" + 'include!("shadow.rs");\n', R20_JOIN, False,
         {"tests/shadow.rs": "pub fn f() {}\n"}),
        (R18_BODY + "use tokio::join;\n" + 'include!("shadow.rs");\n', R20_JOIN, False,
         {"tests/shadow.rs": 'include!("shadow.rs");\n'}),
    ],
}


class ReviewR21(Positive):
    """REVIEW-7349-r21 (umbrella #8168 N1-N3): every row of R21_PROBES is decided as its flag says."""

    def run_rows(self, group):
        for row in R21_PROBES[group]:
            with self.subTest(head=row[0], body=row[1], files=sorted(row[3])):
                r20_write(row)
                self.assertEqual(self.scan(), FLAGGED if row[2] else set())

    def test_n1_a_single_quoted_cargo_package_value_is_a_rename(self):
        self.run_rows("N1")

    def test_n2_a_trait_in_a_path_file_outside_src_is_indexed(self):
        self.run_rows("N2")

    def test_n3_a_macro_rules_shadow_in_an_included_file_wins(self):
        self.run_rows("N3")


# REVIEW-7349 code r22 (umbrella #8168, R22-1 and R22-2), the CLASS fix: the gate fails closed on every module or
# include! target it cannot resolve, read or fully parse. The sweep below crosses attribute orderings, include!
# argument spellings and trait locations; each row is correctly indexed (decided from the definition it reads) or
# the tree is open (a lowercase leaf may be a trait, no bare macro name is trusted). A row is (head, body, flagged,
# files) as in R20_PROBES.
R23_FAN = "pub trait fan { fn map(self, f: u8); }\n"
R23_STRUCT = "pub struct fan;\n"
R23_PATH = '#[path = "../gen/fan.rs"]'
R23_PATH_FORMS = ['#[path = "../gen/fan.rs"]', '#[path = r"../gen/fan.rs"]', '#[path = r#"../gen/fan.rs"#]',
                  '#[path="../gen/fan.rs"]']
R23_ORDERS = ["{P}", "#[cfg(unix)]\n{P}", "{P}\n#[cfg(unix)]", "#[cfg(unix)]\n{P}\n#[allow(dead_code)]",
              "#[macro_use]\n{P}", "{P}\n#[macro_use]", '#[doc = "x"]\n{P}\n#[macro_use]\n#[cfg(all(unix, not(windows)))]',
              "#[macro_use]\n#[cfg(feature = \"a\")]\n{P}\n#[cfg(unix)]"]
R23_INCLUDES_OK = ['include!("{F}");', 'include!(r"{F}");', 'include!(r#"{F}"#);', 'include!["{F}"];',
                   'include!("{F}",);', 'include ! ( "{F}" ) ;', 'std::include!("{F}");']
R23_INCLUDES_OPEN = ['include!(concat!(env!("OUT_DIR"), "/{F}"));', 'include!(env!("OUT_DIR"));', "include!(PATH);",
                     'include!("{F}" );include!(concat!("a", "b"));', 'include!("a\\\\b.rs");',
                     'include!(r"{F}" "x");', "include!();"]


def r23_src(lib, files, use, flagged):
    """A src/ row: the tests import `use` (a lowercase leaf) from a crate whose src/lib.rs and files are given."""
    return ("use ai_memory::%s;\n" % use, R20_MAP, flagged, dict(files, **{"Cargo.toml": R20_CARGO, "src/lib.rs": lib}))


def r23_macro(head, files, flagged, body=R20_JOIN):
    """A test-file row: a bare `join!` is shadowed (flagged) or not by the module files the head declares."""
    return (R18_BODY + "use tokio::join;\n" + head, body, flagged, files)


def r23_src_rows():
    rows = []
    for form in R23_PATH_FORMS:  # attribute orderings x path literal spellings: indexed, so a trait is found, a struct is not
        for order in R23_ORDERS:
            lib = order.replace("{P}", form) + "\npub mod fan;\n"
            rows.append(r23_src(lib, {"gen/fan.rs": R23_FAN}, "fan::fan", True))
            rows.append(r23_src(lib, {"gen/fan.rs": R23_STRUCT}, "fan::fan", False))
    for inc in R23_INCLUDES_OK:  # include! spellings that name a file: indexed
        lib = inc.replace("{F}", "../gen/fan.rs") + "\n"
        rows.append(r23_src(lib, {"gen/fan.rs": R23_FAN}, "fan", True))
        rows.append(r23_src(lib, {"gen/fan.rs": R23_STRUCT}, "fan", False))
    for inc in R23_INCLUDES_OPEN:  # include! spellings the gate cannot read: open, so the lowercase leaf is no proof
        for lib in (inc.replace("{F}", "x.rs") + "\n", "pub mod a;\n", "pub mod a { %s }\n" % inc.replace("{F}", "x.rs")):
            files = {"src/a.rs": inc.replace("{F}", "x.rs") + "\n"} if lib == "pub mod a;\n" else {}
            rows.append(r23_src(lib, files, "a::fan", True))
            rows.append(r23_src(lib, files, "fan", True))
    # trait locations: inline, a submodule of a #[path] file (R22-1 m1), nested modules, an include!d file
    rows += [
        r23_src("pub mod m { pub trait fan { fn map(self, f: u8); } }\n", {}, "m::fan", True),
        r23_src("pub mod m { pub struct fan; }\n", {}, "m::fan", False),
        r23_src('#[path = "../gen/mod.rs"]\npub mod g;\n', {"gen/mod.rs": "pub mod fan;\n", "gen/fan.rs": R23_FAN}, "g::fan::fan", True),
        r23_src('#[path = "../gen/mod.rs"]\npub mod g;\n', {"gen/mod.rs": "pub mod fan;\n", "gen/fan.rs": R23_STRUCT}, "g::fan::fan", False),
        r23_src('#[path = "../gen/g.rs"]\npub mod g;\n', {"gen/g.rs": "pub mod fan;\n", "gen/fan.rs": R23_FAN}, "g::fan::fan", True),
        r23_src('#[macro_use]\n#[path = "../gen/g.rs"]\npub mod g;\n', {"gen/g.rs": "pub mod fan;\n", "gen/fan.rs": R23_FAN}, "g::fan::fan", True),
        r23_src("pub mod a;\n", {"src/a.rs": "pub mod b;\n", "src/a/b.rs": R23_FAN}, "a::b::fan", True),
        r23_src("pub mod a;\n", {"src/a.rs": "pub mod b;\n", "src/a/b.rs": R23_STRUCT}, "a::b::fan", False),
        r23_src("pub mod a;\n", {"src/a/mod.rs": "pub mod b;\n", "src/a/b/mod.rs": R23_FAN}, "a::b::fan", True),
        r23_src("pub mod a { pub mod b; }\n", {"src/a/b.rs": R23_FAN}, "a::b::fan", True),
        r23_src('include!("../gen/inc.rs");\n', {"gen/inc.rs": "pub mod fan;\n", "src/fan.rs": R23_FAN}, "fan::fan", True),
        r23_src('pub mod a;\n', {"src/a.rs": 'include!("../../gen/fan.rs");\n', "gen/fan.rs": R23_FAN}, "a::fan", True),
    ]
    # unresolvable targets, wherever they sit: the tree is open
    for lib, files in (
        ('#[path = "nope.rs"]\npub mod nope;\n', {}),
        ("pub mod nope;\n", {}),
        ('#[cfg_attr(unix, path = "../gen/fan.rs")]\npub mod fan;\n', {"gen/fan.rs": R23_STRUCT}),
        ('#[path = concat!("../gen/", "fan.rs")]\npub mod fan;\n', {"gen/fan.rs": R23_STRUCT}),
        ('#[path = "../gen/g.rs"]\npub mod g;\n', {"gen/g.rs": "pub mod missing;\n"}),
        ('#[path = "../gen/g.rs"]\npub mod g;\n', {"gen/g.rs": 'include!(concat!(env!("OUT_DIR"), "/x.rs"));\n'}),
        ("pub mod a;\n", {"src/a.rs": "pub mod b;\n", "src/a/b.rs": "pub mod gone;\n"}),
        ('#[path = "x.rs"]\n#[path = "y.rs"]\npub mod fan;\n', {"src/x.rs": "pub struct other;\n"}),
    ):
        rows.append(r23_src(lib, files, "nope::fan", True))
        rows.append(r23_src(lib, files, "fan", True))
    return rows


def r23_macro_rows():
    rows, shadow, plain = [], R19_SHADOW % "join", "pub fn f() {}\n"
    for form in ('#[path = "support/rt.rs"]', '#[path = r"support/rt.rs"]', '#[path = r#"support/rt.rs"#]'):
        for order in R23_ORDERS:
            head = order.replace("{P}", form) + "\nmod rt;\n"
            rows.append(r23_macro(head, {"tests/support/rt.rs": shadow}, True))
            rows.append(r23_macro(head, {"tests/support/rt.rs": plain}, False))
    for inc in R23_INCLUDES_OK:
        head = inc.replace("{F}", "shadow.rs") + "\n"
        rows.append(r23_macro(head, {"tests/shadow.rs": shadow}, True))
        rows.append(r23_macro(head, {"tests/shadow.rs": plain}, False))
    for inc in R23_INCLUDES_OPEN:  # unreadable: a bare macro is untrusted, a qualified one is still trusted
        head = inc.replace("{F}", "shadow.rs") + "\n"
        rows.append(r23_macro(head, {}, True))
        rows.append(r23_macro(head, {}, False, R18_BLOCK_ON % "tokio::join!(body());"))
    rows += [
        r23_macro("mod rt;\n", {"tests/rt.rs": "pub mod b;\n", "tests/rt/b.rs": shadow}, True),
        r23_macro("mod rt;\n", {"tests/rt/mod.rs": "pub mod b;\n", "tests/rt/b/mod.rs": shadow}, True),
        r23_macro('#[path = "g/mod.rs"]\nmod rt;\n', {"tests/g/mod.rs": "mod b;\n", "tests/g/b.rs": shadow}, True),
        r23_macro('#[path = "g/mod.rs"]\nmod rt;\n', {"tests/g/mod.rs": "mod b;\n", "tests/g/b.rs": plain}, False),
        r23_macro("mod gone;\n", {}, True),
        r23_macro("mod gone;\n", {}, False, R18_BLOCK_ON % "tokio::join!(body());"),
        r23_macro("mod rt { mod inner; }\n", {"tests/rt/inner.rs": shadow}, True),
        r23_macro("mod rt;\n", {"tests/rt.rs": 'include!(concat!(env!("OUT_DIR"), "/x.rs"));\n'}, True),
        r23_macro("mod rt;\n", {"tests/rt.rs": '#[path = "rt.rs"]\nmod rt;\n'}, False),
    ]
    return rows


def r23_test_crate_rows():
    """A trait of a module file of the test crate is read from that file; an unreadable target opens the crate."""
    head = "mod fan;\nuse crate::fan::fan;\n"
    return [
        ("mod fan;\nuse crate::fan::fan;\n", R20_MAP, True, {"tests/fan.rs": R23_FAN}),
        ("mod fan;\nuse crate::fan::fan;\n", R20_MAP, False, {"tests/fan.rs": R23_STRUCT}),
        ('#[path = "x/y.rs"]\nmod fan;\nuse crate::fan::fan;\n', R20_MAP, True, {"tests/x/y.rs": R23_FAN}),
        ('#[macro_use]\n#[path = "x/y.rs"]\nmod fan;\nuse crate::fan::fan;\n', R20_MAP, True, {"tests/x/y.rs": R23_FAN}),
        ("mod fan;\nuse self::fan::fan;\n", R20_MAP, True, {"tests/fan.rs": R23_FAN}),
        (head + 'include!(concat!(env!("OUT_DIR"), "/x.rs"));\n', R20_MAP, True, {"tests/fan.rs": "pub struct other;\n"}),
        ("mod gone;\nuse crate::gone::fan;\n", R20_MAP, True, {}),
        ('include!("inc.rs");\nuse crate::fan;\n', R20_MAP, True, {"tests/inc.rs": R23_FAN}),
        ('include!("inc.rs");\nuse crate::fan;\n', R20_MAP, False, {"tests/inc.rs": R23_STRUCT}),
    ]


class ReviewR23(Positive):
    """REVIEW-7349 code r22 (umbrella #8168, R22-1 and R22-2): the class sweep. Every row is decided as its flag says:
    a target the gate reads is indexed, a target it cannot read or parse leaves the tree open (fails closed)."""

    def run_rows(self, rows):
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(head=row[0], body=row[1], files=dict(sorted(row[3].items()))):
                r20_write(row)
                self.assertEqual(self.scan(), FLAGGED if row[2] else set())

    def test_src_trait_locations_attribute_orders_and_include_spellings(self):
        self.run_rows(r23_src_rows())

    def test_macro_shadow_locations_attribute_orders_and_include_spellings(self):
        self.run_rows(r23_macro_rows())

    def test_the_test_crate_module_files_are_indexed_or_fail_closed(self):
        self.run_rows(r23_test_crate_rows())

    def test_reviewer_probes_m1_m3_m4_m5(self):
        shadow = R19_SHADOW % "join"
        self.run_rows([
            # m1: a plain `mod fan;` under a #[path]-reached gen/mod.rs
            r23_src('#[path = "../gen/mod.rs"]\npub mod g;\n', {"gen/mod.rs": "pub mod fan;\n", "gen/fan.rs": R23_FAN}, "g::fan::fan", True),
            # m3: a raw string include!
            r23_macro('include!(r"shadow.rs");\n', {"tests/shadow.rs": shadow}, True),
            # m4: #[path] before #[macro_use]
            r23_macro('#[path = "support/rt.rs"]\n#[macro_use]\nmod rt;\n', {"tests/support/rt.rs": shadow}, True),
            # m5: an OUT_DIR include!
            r23_src('include!(concat!(env!("OUT_DIR"), "/fan.rs"));\n', {}, "fan", True),
        ])

    def test_an_unresolved_target_is_named_in_the_diagnostics(self):
        r20_write(r23_src("pub mod nope;\n", {}, "fan", True))
        found = []
        gate.scan_tree(SCRATCH, found)
        self.assertEqual(len(found), 1)
        self.assertIn("src/lib.rs", found[0])
        self.assertIn("nope", found[0])
        r20_write(r23_macro('include!(concat!(env!("OUT_DIR"), "/x.rs"));\n', {}, True))
        found = []
        gate.scan_tree(SCRATCH, found)
        self.assertEqual(len(found), 1)
        self.assertIn("tests/a.rs", found[0])
        self.assertIn("include!", found[0])

    def test_a_fully_resolved_tree_has_no_diagnostics(self):
        for row in (r23_src_rows()[0], r23_macro_rows()[0], r23_test_crate_rows()[0]):
            r20_write(row)
            found = []
            gate.scan_tree(SCRATCH, found)
            self.assertEqual(found, [])


# G4 (REVIEW-7349-r20): the exact trust tables, as literals; they are the whole of the credit side of callee_origin.
PINNED_FN_PATHS = frozenset((
    ("std", "panic", "catch_unwind"), ("std", "panic", "AssertUnwindSafe"), ("core", "panic", "AssertUnwindSafe"),
    ("tokio", "time", "timeout")))
PINNED_METHOD_NAMES = (
    "map", "and_then", "or_else", "unwrap_or_else", "map_or", "map_or_else", "map_err", "ok_or_else", "is_some_and",
    "is_none_or", "is_ok_and", "is_err_and", "filter", "filter_map", "flat_map", "find", "find_map", "any", "all",
    "position", "rposition", "take_while", "skip_while", "map_while", "inspect", "fold", "try_fold", "for_each",
    "sort_by", "sort_by_key", "sort_unstable_by", "sort_unstable_by_key", "retain", "max_by", "max_by_key", "min_by",
    "min_by_key", "get_or_insert_with", "or_insert_with", "query_row", "query_map", "query_and_then", "block_on",
    "timeout", "catch_unwind", "AssertUnwindSafe", "with_default", "call_once", "call_once_force", "get_or_init",
    "get_or_try_init", "force")
PINNED_METHOD_PATHS = frozenset(("std", name) for name in PINNED_METHOD_NAMES)


class TrustTablePins(unittest.TestCase):
    """REVIEW-7349-r20 G4: the allowlists are pinned by literal sets, so dropping or adding an entry fails here."""

    def test_trusted_fn_paths_are_exactly_the_pinned_set(self):
        self.assertEqual(gate.TRUSTED_FN_PATHS, PINNED_FN_PATHS)

    def test_trusted_method_paths_are_exactly_the_pinned_set(self):
        self.assertEqual(gate.TRUSTED_METHOD_PATHS, PINNED_METHOD_PATHS)

    def test_the_pinned_sets_name_the_runner_wrappers(self):
        for path in (("std", "panic", "catch_unwind"), ("std", "panic", "AssertUnwindSafe"), ("tokio", "time", "timeout")):
            with self.subTest(path=path):
                self.assertIn(path, PINNED_FN_PATHS)
                self.assertIn(path, gate.TRUSTED_FN_PATHS)


class DepRootsParse(unittest.TestCase):
    """REVIEW-7349-r20 G2: the line-based Cargo.toml reader maps every rename form and marks a contested name."""

    def test_rename_forms_and_ambiguity(self):
        manifest = SCRATCH / "dep-roots"
        manifest.mkdir(parents=True, exist_ok=True)
        (manifest / "Cargo.toml").write_text(
            '[package]\nname = "x"\n[dependencies]\ntk = { package = "tokio", version = "1" }\n'
            'fu.package = "other-crate"\nplain = "1"\nsame = { version = "1" }\n'
            '[dev-dependencies.tk2]\npackage = "tokio"\n'
            '[build-dependencies]\ntk = { package = "tokio-util" }\n'
        )
        roots = gate.CommonModel._dep_roots(manifest)
        self.assertEqual(roots["fu"], "other_crate")
        self.assertEqual(roots["tk2"], "tokio")
        self.assertEqual(roots["tk"], gate.DEP_AMBIGUOUS)
        for name in ("plain", "same"):
            self.assertNotIn(name, roots)


class RuleProbes(Positive):
    """#8125: one test per classifying rule; each asserts that every probe of the rule is flagged. A loosened rule (the
    gate with its origin predicate replaced) turns one of them RED: see RuleInventory."""

    def probe(self, rule):
        for head, body in RULE_PROBES[rule]:
            with self.subTest(head=head, body=body):
                body = body.replace("%s", RULE_CL if "block_on" not in body else Positive.OPEN)
                self.check(body, head=head.replace("%s", RULE_CL))


for _rule in RULE_PROBES:
    setattr(RuleProbes, "test_rule_%s_is_flagged" % _rule, lambda self, rule=_rule: self.probe(rule))


class RuleInventory(unittest.TestCase):
    """#8125: the inventory of classifying rules is DERIVED, never hand-kept. Every FileModel method that calls an
    origin predicate is registered with @origin_rule, every registered rule has probes, and loosening the rule turns
    its probes RED (two mutants per rule: the rule always credits, and the rule credits UNKNOWN as well as STD)."""

    PREDICATES = ("type_origin", "path_origin", "method_origin", "callee_origin")
    SITE = re.compile(r"self\.(?:type_origin|path_origin|method_origin|callee_origin)\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*(==|!=)\s*STD")

    def setUp(self):
        self.src = GATE.read_text()
        self.methods = {}
        for node in ast.walk(ast.parse(self.src)):
            if isinstance(node, ast.ClassDef) and node.name == "FileModel":
                for fn in node.body:
                    if isinstance(fn, ast.FunctionDef):
                        self.methods[fn.name] = ast.get_source_segment(self.src, fn)

    def derived(self):
        return {name for name, text in self.methods.items() if name not in self.PREDICATES
                and re.search(r"self\.(?:%s)\(" % "|".join(self.PREDICATES), text)}

    def test_every_method_that_calls_an_origin_predicate_is_a_registered_rule(self):
        got = self.derived()
        # the indexers and predicates' own helpers are not classifiers: they feed the predicate, they do not use it
        self.assertEqual(got - set(gate.ORIGIN_RULES), set(), "a classifier that is not registered with @origin_rule")
        self.assertEqual(set(gate.ORIGIN_RULES) - got, set(), "a registered rule that calls no origin predicate")

    def test_every_registered_rule_has_probes(self):
        self.assertEqual(set(gate.ORIGIN_RULES), set(RULE_PROBES))
        for rule, probes in RULE_PROBES.items():
            self.assertTrue(probes, rule)

    def mutate(self, rule, kind):
        seg = self.methods[rule]
        sites = list(self.SITE.finditer(seg))
        self.assertTrue(sites, "%s has no origin comparison to mutate" % rule)

        def swap(m):
            if kind == "always":
                return "False" if m.group(1) == "!=" else "True"
            return m.group(0)[:m.start(1) - m.start(0)] + ("== CRATE" if m.group(1) == "!=" else "!= CRATE")

        def weak(m):
            text = m.group(0)
            head = text[:m.start(1) - m.start(0)]
            return head + ("== CRATE" if m.group(1) == "!=" else "!= CRATE")

        new = self.SITE.sub(swap if kind == "always" else weak, seg)
        self.assertNotEqual(new, seg)
        self.assertEqual(self.src.count(seg), 1)
        mod = types.ModuleType("mutant_%s_%s" % (rule, kind))
        mod.__file__ = str(GATE)
        sys.modules[mod.__name__] = mod
        exec(compile(self.src.replace(seg, new), str(GATE), "exec"), mod.__dict__)
        return mod

    NAMED_MUTANTS = (  # the two mutants REVIEW-7349-r17 #8125 reported GREEN: (rule, original text, mutated text)
        ("closure_form", "self.method_origin(tail.group(2)) == STD", "tail.group(2) in INLINE_METHODS"),
        ("returns_safe", "self.type_origin(fn.ret) == STD", "self.type_origin(fn.ret) != CRATE"),
    )

    def test_the_reported_mutants_turn_their_probes_red(self):
        for rule, old, new in self.NAMED_MUTANTS:
            with self.subTest(rule=rule):
                seg = self.methods[rule]
                self.assertEqual(seg.count(old), 1, old)
                mod = types.ModuleType("named_mutant_" + rule)
                mod.__file__ = str(GATE)
                sys.modules[mod.__name__] = mod
                exec(compile(self.src.replace(seg, seg.replace(old, new)), str(GATE), "exec"), mod.__dict__)
                red = 0
                for head, body in RULE_PROBES[rule]:
                    text = WRITER + head.replace("%s", RULE_CL) + Positive.LOCKED % body.replace("%s", RULE_CL)
                    shutil.rmtree(SCRATCH, ignore_errors=True)
                    (SCRATCH / "tests").mkdir(parents=True)
                    (SCRATCH / "tests" / "a.rs").write_text(text)
                    red += mod.scan_tree(SCRATCH) != FLAGGED
                shutil.rmtree(SCRATCH, ignore_errors=True)
                self.assertTrue(red, "the reported %s mutant stays GREEN" % rule)

    def test_loosening_a_rule_turns_its_probes_red(self):
        for rule in sorted(RULE_PROBES):
            for kind in ("always", "weak"):
                with self.subTest(rule=rule, mutant=kind):
                    mutant = self.mutate(rule, kind)
                    red = []
                    for head, body in RULE_PROBES[rule]:
                        body = body.replace("%s", RULE_CL if "block_on" not in body else Positive.OPEN)
                        text = WRITER + head.replace("%s", RULE_CL) + Positive.LOCKED % body
                        shutil.rmtree(SCRATCH, ignore_errors=True)
                        (SCRATCH / "tests").mkdir(parents=True)
                        (SCRATCH / "tests" / "a.rs").write_text(text)
                        if mutant.scan_tree(SCRATCH) != FLAGGED:
                            red.append(body)
                    shutil.rmtree(SCRATCH, ignore_errors=True)
                    self.assertTrue(red, "no probe of %s goes RED under the %s mutant" % (rule, kind))


class TypeOriginInventory(unittest.TestCase):
    """r10: every rule that classifies a type or a value calls the ONE predicate type_origin; the spelling-based
    helpers (a hard-coded std type set, an inline-runner name set standing in for std) cannot come back."""

    def setUp(self):
        self.src = (REPO / "scripts" / "check-test-env-mutation.py").read_text()
        tree = ast.parse(self.src)
        self.methods = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "FileModel":
                for fn in node.body:
                    if isinstance(fn, ast.FunctionDef):
                        self.methods[fn.name] = ast.get_source_segment(self.src, fn)

    def test_the_predicate_and_its_three_results_exist(self):
        for const in ("STD", "CRATE", "UNKNOWN"):
            self.assertTrue(hasattr(gate, const), const)
        self.assertEqual(len({gate.STD, gate.CRATE, gate.UNKNOWN}), 3)
        self.assertIn("type_origin", self.methods)
        self.assertTrue(self.methods["type_origin"].count('"""') >= 2, "type_origin carries a docstring")

    def test_every_classifying_rule_calls_the_predicate(self):
        for name in sorted(gate.ORIGIN_RULES):
            with self.subTest(rule=name):
                self.assertRegex(self.methods[name], r"\b(?:type_origin|path_origin|name_origin|method_origin|callee_origin)\(")

    def test_spelling_based_helpers_are_gone(self):
        for old in ("RECEIVER_STD_TYPES", "def types_ok", "self.types_ok("):
            with self.subTest(old=old):
                self.assertNotIn(old, self.src)
        for name in ("macro_ok", "annotation", "const_ok", "name_ok", "span_safe"):
            self.assertNotIn("inline_imports", self.methods[name], name)
            self.assertNotIn("INLINE_ROOTS", self.methods[name], name)

    def test_origin_of_type_text(self):
        model = gate.FileModel("use std::sync::Arc;\nuse ai_memory::pool::Pool;\nstruct S;\n")
        for text, want in (
            ("Vec<u8>", gate.STD), ("Arc<Vec<u8>>", gate.STD), ("&'static str", gate.STD), ("[&str; 2]", gate.STD),
            ("std::sync::Mutex<()>", gate.STD), ("Pool", gate.CRATE), ("Arc<Pool>", gate.CRATE), ("S", gate.CRATE),
            ("Vec<_>", gate.UNKNOWN), ("_", gate.UNKNOWN), ("impl Iterator<Item = u8>", gate.UNKNOWN),
            ("dyn Iterator<Item = u8>", gate.UNKNOWN), ("T", gate.UNKNOWN), ("tokio::sync::Mutex<()>", gate.CRATE),
            ("Mutex<()>", gate.UNKNOWN),
        ):
            with self.subTest(text=text):
                self.assertEqual(model.type_origin(text), want)


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
