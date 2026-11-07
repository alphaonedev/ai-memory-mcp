"""Guard for #8301 and #8305: the shared-namespace-claims self-test must not hardcode migrations.rs ceilings
and must clean up after itself.

Case 2 of ``scripts/check-shared-namespace-claims.sh --self-test`` builds a ceiling fixture whose
candidate values must straddle the projected merge-result size of src/storage/migrations.rs. Hardcoded
literals rot whenever that file grows, so every ceiling value is derived from the measured size
(``_N``) at run time. The fixture branches live in the git directory shared by every worktree, so each
run names its worktrees and branches per run and removes them on every exit path (#8305).
"""
import os
import re
import signal
import subprocess
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GATE = ROOT / "scripts" / "check-shared-namespace-claims.sh"
PASS_PREFIX = "shared-namespace-claims self-test: PASS"
SELF_TEST_MARK = "self-test: PASS"
REGION_START = "B=$(git rev-parse HEAD)"
START_TIMEOUT_S = 300
EXIT_TIMEOUT_S = 120
POLL_S = 0.2
# Numbers that legitimately appear in the fixture region and are NOT ceilings: the migration rung
# prefixes of the renumber fixture (sqlite 0083/0084, postgres 0056/0057) and the issue number
# 3152 of the duplicate-branch fixture branch name. Everything else with 4+ digits is refused.
ALLOWED_TOKENS = frozenset(["0083", "0084", "0056", "0057", "3152"])
DIGIT_RUN = re.compile(r"\d{4,}")
GROUPED = re.compile(r"\d{1,3}(?:_\d{3})+")
RADIX = re.compile(r"(?<![A-Za-z0-9_])0[xXoO][0-9A-Fa-f]+")
ARITH = re.compile(r"\$\(\(([^()]*)\)\)")
DERIVED = re.compile(r"(?<![A-Za-z0-9_])_N(?![A-Za-z0-9_])|\$CPASS|\$CRED")
CEILING_VAR = re.compile(r"(?<![A-Za-z0-9_])(CPASS|CRED)=")
CEILING_PRINTF_ARG = re.compile(r"\\n' \"\$(CPASS|CRED)\" \|")
COMMENT = re.compile(r"\s#(\s.*)?$")


def _gate_text():
    return GATE.read_text(encoding="utf-8")


def _fixture_region(text):
    start = text.index(REGION_START)
    end = text.index(SELF_TEST_MARK, start)
    return text[start:end].splitlines()


def _code_lines(text):
    return [COMMENT.sub("", line) for line in _fixture_region(text)]


def _scan_arg(line, index):
    """Return the shell word starting at ``index``: stops at a closing paren, ``;``, ``&``, ``|`` or a blank at depth 0."""
    depth = 0
    out = []
    for ch in line[index:]:
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and ch in ";&| \t":
            break
        out.append(ch)
    return "".join(out)


def ceiling_violations(code_lines):
    """Every way a fixture ceiling can be something other than a value derived from ``_N``."""
    bad = []
    for line in code_lines:
        for tok in DIGIT_RUN.findall(line):
            if tok not in ALLOWED_TOKENS:
                bad.append("literal %s: %s" % (tok, line.strip()[:110]))
        for tok in GROUPED.findall(line):
            bad.append("digit-group literal %s: %s" % (tok, line.strip()[:110]))
        for tok in RADIX.findall(line):
            bad.append("radix literal %s: %s" % (tok, line.strip()[:110]))
        for body in ARITH.findall(line):
            if not re.search(r"[A-Za-z_$]", RADIX.sub("", body)):
                bad.append("all-literal arithmetic: %s" % line.strip()[:110])
        for match in CEILING_VAR.finditer(line):
            if not DERIVED.search(_scan_arg(line, match.end())):
                bad.append("%s not derived from _N: %s" % (match.group(1), line.strip()[:110]))
        for match in re.finditer(r"(?<![A-Za-z0-9_])_grp\s+", line):
            if not DERIVED.search(_scan_arg(line, match.end())):
                bad.append("_grp argument not derived from _N: %s" % line.strip()[:110])
        if "qual_10_module_size_ceiling.rs" in line and "printf" in line and not CEILING_PRINTF_ARG.search(line):
            bad.append("ceiling printf argument is not $CPASS/$CRED: %s" % line.strip()[:110])
    return bad


class SharedNamespaceSelfTest8301(unittest.TestCase):
    def test_self_test_passes(self):
        proc = subprocess.run(
            ["nice", "-n", "19", "bash", str(GATE), "--self-test"],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout[-1500:])
        self.assertIn(PASS_PREFIX, proc.stdout)

    def test_fixture_has_no_hardcoded_ceiling_literal(self):
        offenders = ceiling_violations(_code_lines(_gate_text()))
        self.assertEqual(offenders, [], "a self-test fixture ceiling is not derived from _N")

    def test_ceiling_assignments_exist_and_derive_from_n(self):
        code = "\n".join(_code_lines(_gate_text()))
        for var in ("CPASS", "CRED"):
            self.assertRegex(code, r"(?<![A-Za-z0-9_])%s=\$\(_grp \$\(\(_N [+-] " % var, "%s must be derived from _N" % var)

    def test_fixture_asserts_both_verdict_directions(self):
        region = "\n".join(_fixture_region(_gate_text()))
        self.assertIn('grep -qF "$CPASS PASSES"', region)
        self.assertIn('grep -qF "$CRED WOULD RED"', region)

    def test_verdict_assertions_are_tied_per_fixture(self):
        region = "\n".join(_fixture_region(_gate_text()))
        self.assertIn('"IDENTICAL PAIR $C1 + $C2 both write $CRED"', region)
        self.assertIn('"$C3=$CPASS"', region)

    def test_c4_control_is_pinned_against_the_llm_ceiling(self):
        region = "\n".join(_fixture_region(_gate_text()))
        self.assertIn('"src/llm.rs"', region)
        self.assertIn('[ "$_LC" = "$CRED" ] || [ "$_LC" = "$CPASS" ]', region)
        self.assertIn("self-test ABORT: llm.rs base ceiling", region)

    def test_grp_renders_gate_digit_group_format(self):
        text = _gate_text()
        self.assertNotIn("sed -E ':a", text, "the ;-joined sed label is not portable to BSD sed (#8301 F1)")
        defs = [line for line in text.splitlines() if line.strip().startswith("_grp()")]
        self.assertEqual(len(defs), 1, defs)
        self.assertIn("python3 -c", defs[0])
        for value, want in (("7471", "7_471"), ("1234567", "1_234_567"), ("999", "999")):
            proc = subprocess.run(["bash", "-c", defs[0] + '; _grp "$1"', "bash", value],
                                  cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  universal_newlines=True, check=False)
            self.assertEqual(proc.stdout.strip(), want, proc.stdout)
        self.assertIn('"$(_grp 7471)" != "7_471"', text)
        self.assertIn("self-test ABORT: _grp does not render", text)

    def test_missing_migrations_aborts_by_name(self):
        text = _gate_text()
        self.assertEqual(text.count("self-test ABORT: migrations.rs missing or empty at $B"), 2)
        self.assertIn("''|*[!0-9]*|0)", text)
        self.assertIn('git show "$B:src/storage/migrations.rs" >', text)

    def test_fixture_names_are_per_run_and_cleaned_by_trap(self):
        text = _gate_text()
        self.assertIn('RUN="$$-$(date +%s)"', text)
        self.assertIn('FB2="fixture/3152-dup-v2-$RUN"', text)
        self.assertIn('FB3="fixture/3152-dup-v3-$RUN"', text)
        self.assertNotRegex(text, r"fixture/3152-dup-v[23](?![-\w])", "a fixed fixture branch name is shared by every worktree")
        self.assertNotIn("selftest; rm -rf", text)
        self.assertIn("trap cleanup EXIT", text)
        self.assertIn("trap 'cleanup; exit 130' INT", text)
        self.assertIn("trap 'cleanup; exit 143' TERM", text)
        self.assertIn('git worktree remove --force "$d"', text)
        self.assertIn('git branch -D "$FB2" "$FB3"', text)
        prune = text.index("git worktree prune", text.index("trap cleanup EXIT"))
        self.assertLess(prune, text.index("mk a1") if "mk a1" in text else text.index('mk()'), "prune must run before the first fixture")

    def test_mk_reports_the_worktree_add_error(self):
        adds = [line for line in _gate_text().splitlines() if "git worktree add" in line]
        self.assertEqual(len(adds), 1, adds)
        self.assertNotIn("2>/dev/null", adds[0])
        self.assertIn("self-test ABORT: git worktree add failed", adds[0])

    def test_killed_run_leaves_no_fixture_worktrees_or_branches(self):
        proc = subprocess.Popen(
            ["nice", "-n", "19", "bash", str(GATE), "--self-test"],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, start_new_session=True,
        )
        pid = proc.pid
        scratch = ROOT / ".local-runs"
        deadline = time.time() + START_TIMEOUT_S
        started = False
        while time.time() < deadline and proc.poll() is None:
            if list(scratch.glob("shared-claims-selftest-%d-*/a1" % pid)):
                started = True
                break
            time.sleep(POLL_S)
        try:
            self.assertTrue(started, "the self-test never created its first fixture worktree")
            os.killpg(pid, signal.SIGTERM)
            proc.communicate(timeout=EXIT_TIMEOUT_S)
        finally:
            if proc.poll() is None:
                os.killpg(pid, signal.SIGKILL)
                proc.communicate()
        left_dirs = list(scratch.glob("shared-claims-selftest-%d-*" % pid))
        self.assertEqual(left_dirs, [], "scratch directory left behind by a killed run")
        listing = subprocess.run(["git", "worktree", "list", "--porcelain"], cwd=str(ROOT), stdout=subprocess.PIPE,
                                 universal_newlines=True, check=True).stdout
        self.assertNotIn("shared-claims-selftest-%d-" % pid, listing, "worktree registry entry left behind")
        branches = subprocess.run(["git", "branch", "--list", "fixture/3152-dup-v*-%d-*" % pid], cwd=str(ROOT),
                                  stdout=subprocess.PIPE, universal_newlines=True, check=True).stdout
        self.assertEqual(branches.strip(), "", "fixture branch left behind by a killed run")


if __name__ == "__main__":
    unittest.main()
