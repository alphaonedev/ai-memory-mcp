"""Guard for #8301: the shared-namespace-claims self-test must not hardcode migrations.rs ceilings.

Case 2 of ``scripts/check-shared-namespace-claims.sh --self-test`` builds a ceiling fixture whose
candidate values must straddle the projected merge-result size of src/storage/migrations.rs. Hardcoded
literals rot whenever that file grows, so the values are derived from the measured size at run time.
"""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GATE = ROOT / "scripts" / "check-shared-namespace-claims.sh"
PASS_PREFIX = "shared-namespace-claims self-test: PASS"
LITERAL = re.compile(r"[0-9]_[0-9]{3}")


def _fixture_region(text):
    start = text.index("B=$(git rev-parse HEAD)")
    end = text.index("self-test: PASS", start)
    return text[start:end].splitlines()


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
        offenders = []
        for line in _fixture_region(GATE.read_text(encoding="utf-8")):
            code = re.sub(r"\s#\s.*$", "", line)
            if LITERAL.search(code):
                offenders.append(line.strip()[:120])
        self.assertEqual(offenders, [], "hardcoded digit-group ceiling literal in the self-test fixture")

    def test_fixture_asserts_both_verdict_directions(self):
        region = "\n".join(_fixture_region(GATE.read_text(encoding="utf-8")))
        self.assertIn('grep -q "$CPASS PASSES"', region)
        self.assertIn('grep -q "$CRED WOULD RED"', region)


if __name__ == "__main__":
    unittest.main()
