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
