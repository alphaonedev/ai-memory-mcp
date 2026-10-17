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
from unittest import mock
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

    def test_b_lock_taken_inside_a_loop_covers_the_open_in_that_loop(self):
        body = "for _ in 0..2 {\n        let _g = ENV_LOCK.blocking_lock();\n        %s\n    }" % OPEN
        self.assertEqual(self.flagged(WRITER + test_fn("reader", body)), set())

    def test_b_lock_taken_inside_a_block_on_closure_covers_the_open_there(self):
        body = "rt.block_on(async {\n        let _g = ENV_LOCK.lock().await;\n        %s\n    });" % OPEN
        self.assertEqual(self.flagged(WRITER + test_fn("reader", body)), set())

    def test_b_once_helper_called_in_a_closure_is_followed(self):
        text = (test_fn("a", "rt.block_on(async {\n        common::permissive_attestation_for_tests();\n"
                             "        %s\n    });" % OPEN)
                + test_fn("b", "std::thread::spawn(|| {\n        common::permissive_attestation_for_tests();\n"
                               "        %s\n    });" % OPEN))
        self.assertEqual(self.flagged(text), set())

    def test_b_lock_helper_called_inside_a_loop_is_followed(self):
        helper = "fn take() -> MutexGuard<'static, ()> { ENV_LOCK.blocking_lock() }\n"
        body = "for _ in 0..2 {\n        let _g = take();\n        %s\n    }" % OPEN
        self.assertEqual(self.flagged(WRITER + helper + test_fn("reader", body)), set())

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

    def test_h_guard_dropped_after_the_open_is_held(self):
        text = WRITER + reader("let g = ENV_LOCK.blocking_lock();", OPEN + "\n    drop(g);")
        self.assertEqual(self.flagged(text), set())

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


class Issue7387(Fixture):
    """#7387: a guard moved out of its binding is released at the move."""

    def test_guard_moved_away_is_not_held(self):
        consume = "fn consume<T>(_t: T) {}\n"
        for prefix in ("let h = Holder { _g: g };\n    drop(h);", "let h = Holder { g };\n    drop(h);",
                       "consume(g);", "let mut o = Some(g);\n    o.take();", "let h = (g, 1);\n    drop(h);",
                       "let h = g;\n    drop(h);", "let v = vec![g];\n    drop(v);", "let _w = consume(g);",
                       "let h = g;\n    let k = Holder { _g: h };\n    std::mem::drop(k);",
                       "let mut o = Some(g);\n    o = None;"):
            with self.subTest(prefix=prefix):
                text = WRITER + HOLDER + consume + reader("let g = ENV_LOCK.blocking_lock();\n    " + prefix)
                self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_guard_moved_into_a_live_binding_is_held(self):
        # The guard lives on in the let-bound container until that container is released
        # (the FedEnv constructor of tests/signal_recipient_validation_4408.rs has this shape).
        for prefix in ("let _h = Holder { _g: g };", "let _h = Holder { _g: Some(g) };", "let _v = vec![g];",
                       "let _o = Some(g);", "let _t = (1, g);", "let h = g;\n    let _k = Holder { _g: h };"):
            with self.subTest(prefix=prefix):
                text = WRITER + HOLDER + reader("let g = ENV_LOCK.blocking_lock();\n    " + prefix)
                self.assertEqual(self.flagged(text), set())

    def test_option_take_releases_the_guard(self):
        text = WRITER + reader("let mut g = Some(ENV_LOCK.blocking_lock());\n    g.take();")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})
        text = WRITER + reader("let mut g = Some(ENV_LOCK.blocking_lock());\n    let _ = std::mem::take(&mut g);")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_guard_only_borrowed_is_still_held(self):
        for prefix in ("let _r = &g;", "let _r = &*g;", "let _m = &mut g;"):
            with self.subTest(prefix=prefix):
                text = WRITER + reader("let mut g = ENV_LOCK.blocking_lock();\n    " + prefix)
                self.assertEqual(self.flagged(text), set())

    def test_guard_moved_after_the_open_is_held(self):
        text = WRITER + HOLDER + reader("let g = ENV_LOCK.blocking_lock();", OPEN + "\n    let _h = Holder { _g: g };")
        self.assertEqual(self.flagged(text), set())


class Issue7389(Fixture):
    """#7389: every spelling of drop releases the guard."""

    def test_every_drop_spelling_releases_the_guard(self):
        for call in ("drop::<_>(g)", "drop::<tokio::sync::MutexGuard<'_, ()>>(g)", "std::mem::drop(g)",
                     "core::mem::drop(g)", "mem::drop(g)", "drop ( g )"):
            with self.subTest(call=call):
                text = WRITER + reader("let g = ENV_LOCK.blocking_lock();\n    %s;" % call)
                self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})


class Issue7390(Fixture):
    """#7390: a guard held in a let-bound struct literal lives for the rest of the block."""

    def test_guard_in_a_let_bound_struct_literal_is_held(self):
        for prefix in ("let _h = Holder { _g: ENV_LOCK.blocking_lock() };",
                       "let _h = Holder {\n        _g: ENV_LOCK.blocking_lock(),\n    };",
                       "let _h = Holder { _g: Holder { _g: ENV_LOCK.blocking_lock() } };"):
            with self.subTest(prefix=prefix):
                self.assertEqual(self.flagged(WRITER + HOLDER + reader(prefix)), set())

    def test_struct_literal_in_an_inner_block_is_still_scoped_to_it(self):
        text = WRITER + HOLDER + reader("{ let _h = Holder { _g: ENV_LOCK.blocking_lock() }; }")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_struct_literal_dropped_before_the_open_is_not_held(self):
        text = WRITER + HOLDER + reader("let h = Holder { _g: ENV_LOCK.blocking_lock() };\n    drop(h);")
        self.assertEqual(self.flagged(text), {"tests/a.rs::reader"})

    def test_if_block_is_not_a_struct_literal(self):
        text = WRITER + reader("if X == Y { let _g = ENV_LOCK.blocking_lock(); }")
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
        with mock.patch.object(Path, "read_text", ascii_read), mock.patch.object(Path, "write_text", ascii_write):
            self.assertEqual(gate.main(["--root", root, "--update-baseline"]), 0)
            self.assertEqual(gate.read_baseline(SCRATCH / gate.BASELINE_REL), {"tests/a.rs::" + name})
            self.assertEqual(gate.main(["--root", root]), 0)


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
