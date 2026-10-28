"""Guard the pgbouncer smoke stack against #4734 / #4735 regressions.

Compose is parsed (PyYAML when importable, otherwise a structured stdlib
parse of services -> ports / environment / network_mode; trailing comments are
stripped either way): every published port of every service must bind
127.0.0.1, only the pgbouncer service may publish, network_mode is forbidden,
and every password key must be the required form ${POSTGRES_PASSWORD:?...}.
Scripts (smoke-test.sh, measure-envelope.sh): the PW assignment must be exactly
the secrets.token_hex generator, the userlist is written under umask 077,
docker exec never carries the password in argv, and teardown cannot depend on
a variable that is unset.
"""
import pathlib
import re
import unittest

try:  # CI Python may not ship PyYAML; the fallback below is a real structured parse.
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

REPO = pathlib.Path(__file__).resolve().parent.parent.parent.parent
PGB = REPO / "infra" / "pgbouncer"
COMPOSE = PGB / "docker-compose.yml"
SMOKE = PGB / "smoke-test.sh"
ENVELOPE = REPO / "infra" / "pillar4-envelope" / "measure-envelope.sh"
SCRIPTS = (SMOKE, ENVELOPE)
LITERAL_DEFAULTS = ("ai_memory_smoke", "ai_memory_envelope")
REQUIRED_PW = re.compile(r"^\$\{POSTGRES_PASSWORD:\?[^}]+\}$")
PW_ASSIGN = re.compile(
    r"""^PW="\$\{POSTGRES_PASSWORD:-\$\(python3 -c 'import secrets; print\(secrets\.token_hex\(\d+\)\)'\)\}"$"""
)


def _strip_comment(line):
    """Drop a trailing ` # ...` comment that is outside quotes."""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _fallback_parse(text):
    """Structured stdlib parse: services -> {ports, environment, network_mode}."""
    services, svc, section = {}, None, None
    in_services = False
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        body = line.strip()
        if indent == 0:
            in_services = body == "services:"
            svc = section = None
            continue
        if not in_services:
            continue
        if indent == 2 and body.endswith(":"):
            svc = body[:-1]
            services[svc] = {"ports": [], "environment": {}, "network_mode": None}
            section = None
        elif svc is None:
            continue
        elif indent == 4:
            key, _, val = body.partition(":")
            val = val.strip()
            section = key
            if key == "network_mode":
                services[svc]["network_mode"] = _unquote(val)
            elif key == "ports" and val.startswith("["):
                services[svc]["ports"] = [_unquote(v) for v in val.strip("[]").split(",") if v.strip()]
            elif key == "environment" and val.startswith("{"):
                for pair in val.strip("{}").split(","):
                    k, _, v = pair.partition(":")
                    services[svc]["environment"][k.strip()] = _unquote(v)
        elif section == "ports" and indent >= 6:
            if body.startswith("- "):
                item = body[2:].strip()
                if re.match(r"^[A-Za-z_]+:\s", item + " "):
                    k, _, v = item.partition(":")
                    services[svc]["ports"].append({k.strip(): _unquote(v)})
                else:
                    services[svc]["ports"].append(_unquote(item))
            elif ":" in body and isinstance(services[svc]["ports"][-1], dict):
                k, _, v = body.partition(":")
                services[svc]["ports"][-1][k.strip()] = _unquote(v)
        elif section == "environment" and indent >= 6:
            if body.startswith("- "):
                k, _, v = body[2:].partition("=")
            else:
                k, _, v = body.partition(":")
            services[svc]["environment"][k.strip()] = _unquote(v)
    return services


def _yaml_parse(text):
    doc = yaml.safe_load(text)
    out = {}
    for name, spec in (doc.get("services") or {}).items():
        env = spec.get("environment") or {}
        if isinstance(env, list):
            env = dict(item.split("=", 1) for item in env)
        out[name] = {
            "ports": list(spec.get("ports") or []),
            "environment": {k: "" if v is None else str(v) for k, v in env.items()},
            "network_mode": spec.get("network_mode"),
        }
    return out


def _services():
    text = COMPOSE.read_text()
    return _yaml_parse(text) if yaml is not None else _fallback_parse(text)


def _code_lines(path):
    return [ln for ln in path.read_text().splitlines() if not ln.lstrip().startswith("#")]


def _joined(path):
    return re.sub(r"\\\n\s*", " ", "\n".join(_code_lines(path)))


class ComposeParity(unittest.TestCase):
    def test_both_parsers_agree_on_head(self):
        if yaml is None:
            self.skipTest("PyYAML not installed; fallback parser is the one in use")
        text = COMPOSE.read_text()
        a, b = _yaml_parse(text), _fallback_parse(text)
        self.assertEqual(set(a), set(b))
        for name in a:
            self.assertEqual([str(p) for p in a[name]["ports"]], [str(p) for p in b[name]["ports"]], name)
            self.assertEqual(a[name]["environment"], b[name]["environment"], name)


class PgbouncerSmokeComposeTest(unittest.TestCase):
    def test_every_publish_is_loopback_only(self):
        services = _services()
        self.assertIn("pgbouncer", services)
        for name, spec in services.items():
            if name != "pgbouncer":
                self.assertEqual(spec["ports"], [], "service %s must publish nothing" % name)
            for entry in spec["ports"]:
                if isinstance(entry, dict):
                    self.assertEqual(str(entry.get("host_ip", "")), "127.0.0.1", "%s: %r" % (name, entry))
                else:
                    self.assertRegex(str(entry), r"^127\.0\.0\.1:\d+:\d+(/(tcp|udp))?$", "%s: %r" % (name, entry))
        ports = services["pgbouncer"]["ports"]
        self.assertTrue(ports, "no pgbouncer publish found; update this guard if it was dropped")
        self.assertTrue(any("6432" in str(p) for p in ports))

    def test_images_are_pinned(self):
        text = "\n".join(_strip_comment(ln) for ln in COMPOSE.read_text().splitlines())
        images = re.findall(r"(?m)^\s*image:\s*(\S+)", text)
        self.assertTrue(images)
        for image in images:
            last = image.rsplit("/", 1)[-1]
            tag = last.split(":", 1)[1] if ":" in last else ""
            self.assertTrue(tag, "%s: image must carry an explicit tag" % image)
            self.assertNotRegex(tag, r"(?i)latest", "%s: floating tag" % image)

    def test_no_host_network(self):
        for name, spec in _services().items():
            self.assertIsNone(spec["network_mode"], "%s must not set network_mode" % name)

    def test_compose_passwords_are_required_not_defaulted(self):
        seen = 0
        for name, spec in _services().items():
            for key, value in spec["environment"].items():
                if "password" in key.lower():
                    seen += 1
                    self.assertRegex(value, REQUIRED_PW, "%s.%s must be the required form" % (name, key))
                for lit in LITERAL_DEFAULTS:
                    self.assertNotIn(lit, value, "%s.%s" % (name, key))
        self.assertGreaterEqual(seen, 1)
        for lit in LITERAL_DEFAULTS:
            self.assertNotIn(lit, COMPOSE.read_text())

    def test_scripts_generate_random_password(self):
        for path in SCRIPTS:
            code = [ln.strip() for ln in _code_lines(path)]
            assigns = [ln for ln in code if re.match(r"^PW=", ln)]
            self.assertEqual(len(assigns), 1, "%s: expected one PW= assignment" % path.name)
            self.assertRegex(assigns[0], PW_ASSIGN, "%s: %s" % (path.name, assigns[0]))
            self.assertIn('export POSTGRES_PASSWORD="$PW"', code, path.name)
            for ln in code:
                if re.search(r"POSTGRES_PASSWORD:?-", ln):
                    self.assertRegex(ln, PW_ASSIGN, "%s: %s" % (path.name, ln))
            for lit in LITERAL_DEFAULTS:
                self.assertNotIn(lit, path.read_text(), path.name)

    def test_backend_auth_matches_pooler_md5(self):
        text = "\n".join(_strip_comment(ln) for ln in COMPOSE.read_text().splitlines())
        self.assertRegex(text, r"POSTGRES_HOST_AUTH_METHOD:\s*md5")
        self.assertIn("/20-md5-password.sql", text)
        sql = (COMPOSE.parent / "md5-password.sql").read_text()
        self.assertIn("password_encryption = 'md5'", sql)
        self.assertIn("\\getenv smoke_pw POSTGRES_PASSWORD", sql)
        for lit in LITERAL_DEFAULTS:
            self.assertNotIn(lit, sql)

    def test_pooler_runs_as_userlist_owner(self):
        text = "\n".join(_strip_comment(ln) for ln in COMPOSE.read_text().splitlines())
        self.assertRegex(text, r"(?m)^\s*user:\s*\"?\$\{PGBOUNCER_UID:\?[^}]*\}:\$\{PGBOUNCER_GID:\?[^}]*\}")
        for path in SCRIPTS:
            code = [ln.strip() for ln in _code_lines(path)]
            self.assertIn('PGBOUNCER_UID="$(id -u)"', code, path.name)
            self.assertIn('PGBOUNCER_GID="$(id -g)"', code, path.name)
            self.assertIn("export PGBOUNCER_UID PGBOUNCER_GID", code, path.name)

    def test_userlist_written_owner_only(self):
        for path in SCRIPTS:
            writes = [ln for ln in _code_lines(path) if ".userlist.generated.txt" in ln and ">" in ln]
            self.assertTrue(writes, path.name)
            for ln in writes:
                self.assertRegex(ln, r"umask 077", "%s: userlist must be written under umask 077: %s" % (path.name, ln))

    def test_psql_pooled_forwards_stdin(self):
        # The probes feed SQL by heredoc; without -i docker exec drops stdin
        # and psql runs nothing (the count came back empty).
        text = _joined(SMOKE)
        self.assertRegex(text, r"psql_pooled\(\)\s*\{\s*docker exec -i\b")

    def test_docker_exec_has_no_password_in_argv(self):
        text = _joined(SMOKE)
        execs = [ln for ln in text.splitlines() if "docker exec" in ln]
        self.assertTrue(execs)
        for ln in execs:
            self.assertNotRegex(ln, r"PGPASSWORD=", ln)
            self.assertNotRegex(ln, r"\$\{?PW\b", ln)
        for ln in text.splitlines():
            if re.match(r"^\s*POOLED_URL=", ln):
                self.assertNotRegex(ln, r"\$\{?PW\b", ln)

    def test_teardown_does_not_hide_failure(self):
        # The variable is exported before any compose call (checked above), and
        # teardown must not swallow a failed `down` silently.
        for path in SCRIPTS:
            text = "\n".join(_code_lines(path))
            downs = [ln for ln in text.splitlines() if "docker compose" in ln and " down " in ln]
            self.assertTrue(downs, path.name)
            for ln in downs:
                self.assertNotRegex(ln, r"2>&1\s*\|\|\s*true", "%s: down failure must be loud: %s" % (path.name, ln))
            self.assertIn("still running", text, "%s: must fail loudly when containers remain" % path.name)


if __name__ == "__main__":
    unittest.main()
