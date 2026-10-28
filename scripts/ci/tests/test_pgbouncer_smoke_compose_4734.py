"""Guard the pgbouncer smoke stack against #4734 regressions.

The compose file must publish 6432 on loopback only and must not carry a
fixed fallback password: POSTGRES_PASSWORD is required (`${VAR:?msg}`), and
the smoke script may not default it to a literal either.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent.parent / "infra" / "pgbouncer"
COMPOSE = ROOT / "docker-compose.yml"
SMOKE = ROOT / "smoke-test.sh"


def _compose_lines():
    return [ln for ln in COMPOSE.read_text().splitlines() if not ln.lstrip().startswith("#")]


class PgbouncerSmokeComposeTest(unittest.TestCase):
    def test_published_6432_is_loopback_only(self):
        ports = [ln.strip() for ln in _compose_lines() if re.search(r"\b6432:6432\b", ln)]
        self.assertTrue(ports, "no 6432 publish found; update this guard if the publish was dropped")
        for entry in ports:
            self.assertRegex(entry, r'"?127\.0\.0\.1:6432:6432"?', entry)

    def test_compose_has_no_default_password(self):
        lines = [ln for ln in _compose_lines() if "POSTGRES_PASSWORD" in ln]
        self.assertTrue(lines)
        for ln in lines:
            self.assertNotRegex(ln, r"\$\{POSTGRES_PASSWORD:?-", ln)
        self.assertTrue(
            any(re.search(r"\$\{POSTGRES_PASSWORD:\?[^}]+\}", ln) for ln in lines),
            "POSTGRES_PASSWORD must be required via ${POSTGRES_PASSWORD:?message}",
        )

    def test_smoke_script_has_no_literal_default_password(self):
        text = SMOKE.read_text()
        self.assertNotRegex(text, r"POSTGRES_PASSWORD:-(?!\$\()[^}\s]")


if __name__ == "__main__":
    unittest.main()
