"""Guard the pgbouncer smoke stack against #4734 / #4735 regressions.

Compose is parsed (PyYAML when importable, otherwise a structured stdlib
parse of services -> ports / environment / network_mode; trailing comments are
stripped either way): every published port of every service must bind
127.0.0.1, only the pgbouncer service may publish, network_mode is forbidden,
and every password key must be the required form ${POSTGRES_PASSWORD:?...}.
Scripts (smoke-test.sh, measure-envelope.sh): the PW assignment must be exactly
the secrets.token_hex generator, the userlist is written under umask 077,
docker exec never carries the password in argv, and teardown cannot depend on
a variable that is unset, and a failed `down` is never swallowed. SCRAM end to
end: no md5 in any executable line of the compose file, scripts or SQL, and the
userlist is the role's stored SCRAM verifier (#4732). The scripts refuse uid 0
(PgBouncer refuses root). SQL is parsed (comments dropped), not substring-matched.
r5: the generator must be token_hex(>=16); every docker exec in both scripts is
password-free in argv; the cleanup trap and its exit status are pinned; the
non-SCRAM verifier refusal exists; the userlist is removed before the write;
the postgres healthcheck probes 127.0.0.1; pgbouncer.ini pins auth_type.
r6: indented exit 0, a disarmed trap, every password spelling on every docker
exec/run, an extra verifier arm, a widened userlist mode, a reused exit code,
the [4/4] SHOW CONFIG check, and a per-run compose project name are pinned.
r7: every FAIL/FATAL echo must be followed by an explicit non-zero literal exit
in its own branch (a bare exit, `exit $?` or a deleted exit is refused) and
every step marker is pinned; the password variable is an allowlist (only the
PW assignment, the exports and the compose lines may name it, an alias or a
psql_pooled call-site argument fails, and the smoke refuses a pooled URL that
carries a password); the refusing catch-all arms are pinned to their exact text
(no `||`); the generated userlist name is gitignored; exit code 1 is documented
as covering bring-up and teardown failures too.
r8: only `rc=$?` and `rc=1` may assign rc (any other spelling fails); the exit-74
refusal sits above the PW assignment and the first docker line; the run-name
sanitiser arm and a 64-character bound (exit 65) are pinned in both scripts; the
password guard also refuses whole-environment dumps and any redirect outside an
allowlist.
r9: the cleanup() body of each script equals its exact statement list (any other
`rc=$?`, a loop or a new statement is refused); shell tracing (`set -x`/`-v`,
`-o xtrace`/`verbose`), bare set/export, declare/typeset/env/printenv as a command
word (quoted or not, also as a docker exec command), `docker inspect`,
`docker compose ... config`, `<>` redirects, any `environ`/`ENVIRON`/`getenv` word are
refused; the redirect-target variables are pinned to their single assignment and the
python3/awk call sites to an exact-line allowlist.
r10: after deleting backslashes and quotes from a code line, env/printenv/declare/typeset
are refused anywhere on it (no start anchor), as are a bare set/export and `local -n`;
a heredoc body line starting with a backslash (psql shell escape) is refused; the
compose file names POSTGRES_PASSWORD exactly once (postgres.environment) and has no
env_file; every psql_pooled call carries the FAIL-and-exit-1 or-branch; a `) || true`
subshell, a function named like a builtin or any function outside the pinned set, a
second cleanup() or trap, a negated .gitignore line and a fake heredoc opener are refused.
"""
import fnmatch
import pathlib
import re
import shutil
import subprocess
import unittest

try:  # CI Python may not ship PyYAML; the fallback below is a real structured parse.
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

REPO = pathlib.Path(__file__).resolve().parent.parent.parent.parent
PGB = REPO / "infra" / "pgbouncer"
COMPOSE = PGB / "docker-compose.yml"
INI = PGB / "pgbouncer.ini"
SMOKE = PGB / "smoke-test.sh"
ENVELOPE = REPO / "infra" / "pillar4-envelope" / "measure-envelope.sh"
SCRIPTS = (SMOKE, ENVELOPE)
README_FOR = {SMOKE: PGB / "README.md", ENVELOPE: REPO / "infra" / "pillar4-envelope" / "README.md"}
USERLIST_REF = re.compile(r"\.userlist\.generated|\$\{?USERLIST\b")
PW_SPELLING = re.compile(r"\$\{?(?:PW|POSTGRES_PASSWORD|PGPASSWORD)\b")
EXIT_ZERO = re.compile(r"(?<![\w-])exit\s+[\"']?0+[\"']?(?![\w])")
DOCKER_EXEC_RUN = re.compile(r"\bdocker\b.*\s(?:exec|run)\s")
PW_TOKEN = re.compile(r"\b(?:PW|POSTGRES_PASSWORD|PGPASSWORD)\b")
PW_BY_NAME = re.compile(r"-e PGPASSWORD(?![=\w])")
BANNED_INDIRECTION = re.compile(r"\bprintf -v\b|\$\{!|\bev" + r"al\b")
FAIL_ECHO = re.compile(r"\becho\b.*\b(?:FAIL|FATAL):")
EXIT_SAME_LINE = re.compile(r">&2; exit [1-9]\d*(?: ;;|;? \}(?:;? \})?|;)?$")
EXIT_NEXT_LINE = re.compile(r"^exit [1-9]\d*$")
REFUSING_ARM = re.compile(r"""^(?:'[^']*'|\*|''\|\*[^)]*)\) echo "FATAL: [^"]+" >&2; exit [1-9]\d* ;;$""")
RC_ASSIGN = re.compile(r"\brc\s*[-+*/%|&^]?=\s*(\S*?)\s*(?:;|\}|\)|$)")
RC_OTHER_WRITERS = re.compile(r"\b(?:let|declare|typeset|local|readonly|read|mapfile|unset)\b.*\brc\b|printf -v rc\b|\(\(\s*rc\b")
RUN_CASE_ARM = """''|*[!a-z0-9_-]*) echo "FATAL: AI_MEMORY_SMOKE_RUN must match [a-z0-9_-]+" >&2; exit 65 ;;"""
RUN_LENGTH_BOUND = [
    'if [ "${#RUN}" -gt 64 ]; then',
    'echo "FATAL: AI_MEMORY_SMOKE_RUN must be at most 64 characters" >&2',
    "exit 65",
    "fi",
]
ENV_DUMPERS = re.compile(
    r"(?:^|[;&|(`]|\$\(|\b(?:then|do|else|command|exec|xargs|sudo|nohup|nice|time)\s|/)\s*env\b(?!-)|--env-file|\bprintenv\b|\bexport\s+-p\b|\bdeclare\s+-[a-zA-Z]*[xp]\b|\btypeset\s+-[a-zA-Z]*[xp]\b"
    r"|/proc/(?:self|thread-self|\$\$|\$\{?BASHPID\}?|\d+)/environ|\bcompgen\s+-[a-zA-Z]*[ev]\b|\bset\s*$|\bexport\s*$|\btee\b"
)
REDIRECT = re.compile(r"(?<![-<=>])(?:\d?(?:>>?|<>)|&>)(?!&\d)\s*(\S+)")
SHELL_TRACE = re.compile(
    r"(?<![\w-])set\s+(?:-\S*\s+)*?(?:-[a-zA-Z]*[xv][a-zA-Z]*(?![\w-])|-[a-zA-Z]*o\s+[\"']?(?:xtrace|verbose))"
)
# r10 S9: matched on a line with `\`, `"` and `'` deleted, anywhere on the line.
DUMP_WORD = re.compile(r"(?<![\w-])(?:env|printenv|declare|typeset)(?![\w-])")
BARE_SET = re.compile(r"\bset\s*(?:$|[;&|)])")
BARE_EXPORT = re.compile(r"\bexport\s*(?:$|[;&|)])")
LOCAL_NAMEREF = re.compile(r"\blocal\s+-[a-zA-Z]*n")
PSQL_META = re.compile(r"^\s*\\")
EXEC_DUMP = re.compile(r"\bdocker\b.*\bexec\b.*\s[\"']?(?:env|printenv|set|export|declare|typeset)[\"']?(?:\s|$)")
DOCKER_DISCLOSE = re.compile(r"\bdocker\b.*\binspect\b|\bdocker\b.*\bcompose\b.*\bconfig\b|\bdocker-compose\b.*\bconfig\b")
ENVIRON_WORD = re.compile(r"\benviron\b|\bENVIRON\b|\bgetenv\b")
INTERPRETER = re.compile(r"\b(?:python[0-9.]*|awk|gawk|mawk|nawk|perl|ruby|node|php|lua)\b")
PW_GEN = """PW="${POSTGRES_PASSWORD:-$(python3 -c 'import secrets; print(secrets.token_hex(16))')}\""""
INTERPRETER_SITES = {
    SMOKE: [
        PW_GEN,
        """pool_mode="$(printf '%s\\n' "$cfg" | awk -F'|' '$1 == "pool_mode" { print $2 }')\"""",
        """auth_type="$(printf '%s\\n' "$cfg" | awk -F'|' '$1 == "auth_type" { print $2 }')\"""",
    ],
    ENVELOPE: [
        PW_GEN,
        "need python3",
        "now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }",
        "cur_id=$(python3 -c 'import json,sys",
        """read -r p50 p95 p99 shed reqs < <(cat "$step_out"/w*.txt 2>/dev/null | python3 -c '""",
        """over_p95=$(python3 -c "print(1 if $p95 > $P95_BUDGET_MS else 0)")""",
        """over_shed=$(python3 -c "print(1 if $shed > $SHED_RATE_KNEE else 0)")""",
    ],
}
TARGET_ASSIGNMENTS = {
    SMOKE: {"USERLIST": ['USERLIST=".userlist.generated.$RUN.txt"']},
    ENVELOPE: {
        "USERLIST": ['USERLIST="../pgbouncer/.userlist.generated.$RUN.txt"'],
        "RESULTS_DIR": ['RESULTS_DIR="${RESULTS_DIR:-./.local-runs/envelope-$$}"'],
        "STORE_URL_FILE": ['STORE_URL_FILE="$RESULTS_DIR/.store-url"'],
        "out": ["""local wid="$1" out="$2" deadline="$3" n=0 prev_id="" bodyf="${out}.body\""""],
    },
}
CLEANUP_BODY = {
    SMOKE: [
        "rc=$?",
        """docker compose -p "$PROJECT" down -v >/dev/null || { echo "WARN: compose down failed" >&2; rc=1; }""",
        """if [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ]; then""",
        """echo "FATAL: compose project $PROJECT still running after teardown" >&2""",
        "rc=1",
        "fi",
        """rm -f "$USERLIST\"""",
        """exit "$rc\"""",
    ],
    ENVELOPE: [
        "rc=$?",
        """[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true""",
        """docker compose -p "$PROJECT" -f "$POOL_COMPOSE" down -v >/dev/null || { echo "WARN: compose down failed" >&2; rc=1; }""",
        """if [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ]; then""",
        """echo "FATAL: compose project $PROJECT still running after teardown" >&2""",
        "rc=1",
        "fi",
        """rm -f "$USERLIST" "${STORE_URL_FILE:-}\"""",
        """exit "$rc\"""",
    ],
}
REDIRECT_TARGETS = {
    "Q$USERLIST",
    "Q$STORE_URL_FILE",
    "Q$RESULTS_DIR/daemon.log",
    "Q$out",
    "/dev/null",
}
STEP_MARKER = re.compile(r"""^echo "\[(\d+)/(\d+)\] """)
POOLED_URL_LITERAL = 'POOLED_URL="postgres://ai_memory@pgbouncer:6432/ai_memory"'
POOLED_URL_ENVELOPE = 'POOLED_URL="postgres://ai_memory:${PW}@127.0.0.1:6432/ai_memory"'
COMPOSE_PW_LINE = re.compile(
    r'^POSTGRES_PASSWORD="\$PW" docker compose -p "\$PROJECT"(?: -f "\$POOL_COMPOSE")? up -d --wait(?: postgres)?$'
)
PSQL_FAIL_BRANCH = r""" \|\| \{ echo "FAIL: [^"]+" >&2; exit 1; \}"""
PSQL_POOLED_SITES = (
    re.compile(r"^psql_pooled <<'SQL'" + PSQL_FAIL_BRANCH + "$"),
    re.compile(r"""^path_count="\$\(psql_pooled <<'SQL'$"""),
    re.compile(r"""^st="\$\(psql_pooled -c 'SHOW statement_timeout;'\)\"""" + PSQL_FAIL_BRANCH + "$"),
)
PSQL_HEREDOC_CLOSER = re.compile(r"""^\)\"""" + PSQL_FAIL_BRANCH + "$")
PINNED_FUNCTIONS = {
    SMOKE: {"cleanup", "psql_pooled"},
    ENVELOPE: {"cleanup", "need", "now_ms", "worker"},
}
# r11 Q14: a definition is a command word, so it is read at line start and after ; && || { ( |.
CMD_START = r"(?:^|[;&|{(])\s*"
FUNCTION_DEF = re.compile(
    CMD_START
    + r"(?:function\s+([\w.:-]+)|([\w.:-]+)\s*\(\)(?=\s*(?:\{|\(|\[\[|(?:if|for|while|until|case|select)\b))|([\w:-]+)\s*\(\)\s*$)"
)
CLEANUP_DEF = re.compile(CMD_START + r"(?:function\s+cleanup\b|cleanup\s*\(\))")
ALIAS_DEF = re.compile(CMD_START + r"alias\s")
# r11 Q16: an escaped `<` before `<word` is an input redirect, not a heredoc opener.
HEREDOC_TOKEN = re.compile(r"\"[^\"]*\"|'[^']*'|(?<![<\\])<<(?!<)-?\s*(?:'(\w+)'|\"(\w+)\"|\\?(\w+))")
GROUP_OR_NEUTRAL = re.compile(r"\s*\"?\s*\|\|\s*(?:true\b|:(?![\w-])|echo\b)")
GROUP_PIPED = re.compile(r"\s*\"?\s*\|(?!\|).*\|\|\s*(?:true\b|:(?![\w-])|echo\b)")
CAVEAT = re.compile(r"Any other non-zero status[^.]*\.")
COMPOSE_NAMES = {"AI_MEMORY_SMOKE_RUN", "POSTGRES_PASSWORD", "PGBOUNCER_UID", "PGBOUNCER_GID"}
OR_TRUE_AFTER_GROUP = re.compile(r"\)\s*\|\|\s*(?:true|:)(?![\w-])")
PSQL_POOLED_DEF = 'docker exec -i -e PGPASSWORD "$PG_CONTAINER" psql "$POOLED_URL" -v ON_ERROR_STOP=1 -tA "$@"'
GITIGNORE = PGB / ".gitignore"
LITERAL_DEFAULTS = ("ai_memory_smoke", "ai_memory_envelope")
REQUIRED_PW = re.compile(r"^\$\{POSTGRES_PASSWORD:\?[^}]+\}$")
PW_ASSIGN = re.compile(
    r"""^PW="\$\{POSTGRES_PASSWORD:-\$\(python3 -c 'import secrets; print\(secrets\.token_hex\((?:1[6-9]|[2-9]\d|\d{3,})\)\)'\)\}"$"""
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


def _sql_statements(path):
    """Parse SQL: drop `--` comments (whole-line and trailing), split on `;`."""
    lines = []
    for ln in path.read_text().splitlines():
        lines.append(ln.split("--", 1)[0])
    return [" ".join(s.split()) for s in " ".join(lines).split(";") if s.strip()]


def _compose_code(path=COMPOSE):
    return "\n".join(_strip_comment(ln) for ln in path.read_text().splitlines())


def _joined(path):
    return re.sub(r"\\\n\s*", " ", "\n".join(_code_lines(path)))


def _norm_lines(path):
    """Joined code lines with whitespace runs collapsed, blank lines dropped."""
    return [" ".join(ln.split()) for ln in _joined(path).splitlines() if ln.strip()]


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

    def test_compose_password_is_referenced_once_and_no_env_file(self):
        # r10 S10: a second ${POSTGRES_PASSWORD} (under any key, in any service)
        # would copy the password into another container's environment, which
        # `docker inspect` shows; env_file would load an arbitrary file.
        text = _compose_code()
        self.assertEqual(
            len(re.findall(r"\$\{?POSTGRES_PASSWORD\b", text)), 1, "compose must name POSTGRES_PASSWORD exactly once"
        )
        # r11 S11: compose interpolates every exported variable and the smoke also
        # exports PGPASSWORD (same secret); only these four names may be interpolated.
        names = set(re.findall(r"(?<!\$)\$\{?([A-Za-z_]\w*)", text))
        self.assertEqual(names, COMPOSE_NAMES, "compose may interpolate only %s" % sorted(COMPOSE_NAMES))
        services = _services()
        self.assertRegex(services["postgres"]["environment"].get("POSTGRES_PASSWORD", ""), REQUIRED_PW)
        for name, spec in services.items():
            if name != "postgres":
                self.assertNotIn("POSTGRES_PASSWORD", "".join(spec["environment"].values()), name)
        self.assertNotRegex(text, r"(?m)^\s*-?\s*env_file\s*:", "no service may set env_file")

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

    def test_scram_end_to_end_no_md5_anywhere(self):
        # #4732: the backend keeps its default SCRAM auth and the pooler
        # userlist is the role's stored SCRAM verifier. md5 must not appear in
        # any executable line of the compose file, the scripts or any SQL.
        self.assertFalse((PGB / "md5-password.sql").exists(), "md5 re-store SQL must stay deleted")
        sql_files = sorted(PGB.glob("*.sql"))
        self.assertTrue(sql_files)
        code = {COMPOSE.name: _compose_code()}
        for path in SCRIPTS:
            code[path.name] = "\n".join(_code_lines(path))
        for path in sql_files:
            code[path.name] = "\n".join(_sql_statements(path))
        for name, text in code.items():
            self.assertNotRegex(text, r"(?i)md5", "%s must not use md5" % name)
        compose = code[COMPOSE.name]
        self.assertNotIn("POSTGRES_HOST_AUTH_METHOD", compose)
        self.assertNotRegex(compose, r"initdb\.d/\d+-(?!role-defaults)")
        for path in SCRIPTS:
            text = code[path.name]
            self.assertIn("pg_authid", text, path.name)
            self.assertIn("rolpassword", text, path.name)
            self.assertIn("SCRAM-SHA-256$", text, path.name)

    def test_role_defaults_sql_is_real(self):
        # Parse, do not substring-match: a commented-out or deleted statement
        # must fail this guard (the smoke asserts statement_timeout = 30s).
        statements = _sql_statements(PGB / "role-defaults.sql")
        self.assertEqual(
            statements,
            [
                "ALTER ROLE ai_memory SET statement_timeout = '30s'",
                "ALTER ROLE ai_memory SET lock_timeout = '5s'",
            ],
        )
        self.assertIn("./role-defaults.sql:/docker-entrypoint-initdb.d/", _compose_code())

    def test_scripts_refuse_to_run_as_root(self):
        # PgBouncer exits with "should not run as root"; fail fast, before the
        # first docker call, with a non-zero exit.
        guard = re.compile(r'^if \[ "\$\(id -u\)" -eq 0 \]; then$')
        for path in SCRIPTS:
            code = [ln.strip() for ln in _code_lines(path)]
            idx = [i for i, ln in enumerate(code) if guard.match(ln)]
            self.assertEqual(len(idx), 1, "%s: expected one root guard" % path.name)
            block = code[idx[0] : idx[0] + 4]
            self.assertTrue(any(re.match(r"^exit [1-9]\d*$", ln) for ln in block), "%s: %r" % (path.name, block))
            self.assertTrue(any("FATAL" in ln and ">&2" in ln for ln in block), path.name)
            first_docker = min(i for i, ln in enumerate(code) if re.search(r"\bdocker\b", ln) and not ln.startswith("echo"))
            self.assertLess(idx[0], first_docker, path.name)

    def test_pooler_runs_as_userlist_owner(self):
        text = "\n".join(_strip_comment(ln) for ln in COMPOSE.read_text().splitlines())
        self.assertRegex(text, r"(?m)^\s*user:\s*\"?\$\{PGBOUNCER_UID:\?[^}]*\}:\$\{PGBOUNCER_GID:\?[^}]*\}")
        for path in SCRIPTS:
            code = [ln.strip() for ln in _code_lines(path)]
            self.assertIn('PGBOUNCER_UID="$(id -u)"', code, path.name)
            self.assertIn('PGBOUNCER_GID="$(id -g)"', code, path.name)
            self.assertIn("export PGBOUNCER_UID PGBOUNCER_GID", code, path.name)

    def test_psql_pooled_forwards_stdin(self):
        # The probes feed SQL by heredoc; without -i docker exec drops stdin
        # and psql runs nothing (the count came back empty).
        text = _joined(SMOKE)
        self.assertRegex(text, r"psql_pooled\(\)\s*\{\s*docker exec -i\b")

    def test_postgres_healthcheck_probes_loopback(self):
        # N5: without -h the probe uses the unix socket, which the image's
        # temporary init server also serves.
        probes = re.findall(r"pg_isready[^\"]*", _compose_code())
        self.assertTrue(probes)
        for probe in probes:
            self.assertIn("-h 127.0.0.1", probe)

    def test_pooler_auth_type_is_pinned(self):
        # #4732: the pin refuses md5 entries; a plain-text entry is still accepted by
        # the pooler, so the verifier check in the scripts is what refuses plain rows.
        lines = [_strip_comment(ln).strip() for ln in INI.read_text().splitlines()]
        values = [ln for ln in lines if re.match(r"^auth_type\s*=", ln)]
        self.assertEqual(len(values), 1, values)
        self.assertRegex(values[0], r"^auth_type\s*=\s*scram-sha-256$")

    def test_teardown_does_not_hide_failure(self):
        # Teardown must not swallow a failed `down`: no `|| true` / `|| :` /
        # `|| exit 0`, no stderr or combined-output redirect to /dev/null, and
        # the failure branch must be a group that sets rc=1.
        swallow = re.compile(
            r"\|\|\s*(?:true|:|exit\s+0)(?![\w-])|2>\s*/dev/null|2>&1|&>|>&\s*/dev/null|>\s*/dev/null\s+2>"
        )
        for path in SCRIPTS:
            text = _joined(path)
            downs = [ln for ln in text.splitlines() if "docker compose" in ln and " down " in ln]
            self.assertTrue(downs, path.name)
            for ln in downs:
                self.assertNotRegex(ln, swallow, "%s: down failure must be loud: %s" % (path.name, ln))
                self.assertRegex(ln, r"\|\|\s*\{[^}]*\brc=1\b[^}]*\}", "%s: need `|| { ...; rc=1; }`: %s" % (path.name, ln))
            self.assertIn("still running", text, "%s: must fail loudly when containers remain" % path.name)

    def test_userlist_written_owner_only(self):
        for path in SCRIPTS:
            writes = [ln for ln in _code_lines(path) if USERLIST_REF.search(ln) and ">" in ln]
            self.assertTrue(writes, path.name)
            for ln in writes:
                self.assertRegex(ln, r"umask 077", "%s: userlist must be written under umask 077: %s" % (path.name, ln))

    def test_userlist_mode_is_never_widened(self):
        # r4 security LOW-2: nothing after the write may widen the mode. No chmod
        # or install anywhere, and every line naming the userlist is one of the
        # assignment, the rm -f, or the umask-077 write.
        allowed = (
            r'^USERLIST="(?:\.\./pgbouncer/)?\.userlist\.generated\.\$RUN\.txt"$',
            r'^rm -f "\$USERLIST"(?: "\$\{STORE_URL_FILE:-\}")?$',
            r"""^\(umask 077; printf '%s\\n' "\$VERIFIER_ROW" > "\$USERLIST"\)$""",
        )
        for path in SCRIPTS:
            for ln in (c.strip() for c in _code_lines(path)):
                self.assertNotRegex(ln, r"\b(?:chmod|install)\b", "%s: mode change: %s" % (path.name, ln))
                if USERLIST_REF.search(ln):
                    self.assertTrue(any(re.match(a, ln) for a in allowed), "%s: unexpected userlist line: %s" % (path.name, ln))

    def test_docker_exec_and_run_have_no_password_in_argv(self):
        # r4 P3: every docker exec / docker run in BOTH scripts is password-free in
        # argv for the named spellings; the r7 allowlist test covers every other line.
        for path in SCRIPTS:
            text = _joined(path)
            cmds = [ln for ln in text.splitlines() if DOCKER_EXEC_RUN.search(ln)]
            self.assertTrue(any(re.search(r"\bdocker exec\b", ln) for ln in cmds), path.name)
            for ln in cmds:
                self.assertNotRegex(ln, r"PGPASSWORD=", "%s: %s" % (path.name, ln))
                self.assertNotRegex(ln, PW_SPELLING, "%s: %s" % (path.name, ln))
            for ln in text.splitlines():
                if re.match(r"^\s*\w*URL=", ln) and path == SMOKE:
                    self.assertNotRegex(ln, PW_SPELLING, ln)
            if path == ENVELOPE:
                # Its POOLED_URL carries the password (0600 file, #4577); it must
                # never reach a docker exec / run argv.
                for ln in cmds:
                    self.assertNotIn("POOLED_URL", ln, ln)

    def test_cleanup_is_defined_once_and_trapped_once(self):
        # r10 Q9: a second cleanup() after the trap line replaces the pinned body at runtime.
        for path in SCRIPTS:
            code = [ln.strip() for ln in _code_lines(path)]
            defs = [ln for ln in code if CLEANUP_DEF.search(ln)]
            self.assertEqual(defs, ["cleanup() {"], "%s: exactly one cleanup() definition (CLEANUP_BODY): %r" % (path.name, defs))
            self.assertEqual(code.count("trap cleanup EXIT"), 1, "%s: exactly one trap cleanup line (CLEANUP_BODY)" % path.name)

    def test_cleanup_trap_and_exit_status_are_pinned(self):
        # N1 + r4 P1/P2: exactly one trap in the script and it is the cleanup
        # arming; cleanup() starts with rc=$? and ends with exit "$rc"; the smoke
        # has no `exit 0` at all, the envelope exactly one inside its knee branch.
        for path in SCRIPTS:
            code = [ln.strip() for ln in _code_lines(path)]
            traps = [ln for ln in code if re.search(r"\btrap\b", ln)]
            self.assertEqual(traps, ["trap cleanup EXIT"], "%s: trap disarmed or duplicated: %r" % (path.name, traps))
            start = code.index("cleanup() {")
            end = code.index("}", start)
            body = code[start + 1 : end]
            # r9 S6: `rc=$?` anywhere but the first line is itself a reset, and a
            # loop can overwrite rc; the body is the exact statement list.
            self.assertEqual(body, CLEANUP_BODY[path], "%s: cleanup() body differs from CLEANUP_BODY" % path.name)
            self.assertEqual(body[0], "rc=$?", "%s: rc=$? must be the first statement" % path.name)
            self.assertEqual(body[-1], 'exit "$rc"', "%s: cleanup must exit with rc" % path.name)
            self.assertLess(end, code.index("trap cleanup EXIT"), path.name)
            for ln in code:
                for val in RC_ASSIGN.findall(ln):
                    self.assertIn(val, ("$?", "1"), "%s: rc reset or odd assignment: %s" % (path.name, ln))
                self.assertNotRegex(ln, RC_OTHER_WRITERS, "%s: rc written by a non-plain statement: %s" % (path.name, ln))
            zeros = [i for i, ln in enumerate(code) if EXIT_ZERO.search(ln)]
            if path == SMOKE:
                self.assertEqual(zeros, [], "%s: exit 0 hides a failed property" % path.name)
            else:
                self.assertEqual(len(zeros), 1, "%s: expected one success exit" % path.name)
                before = [ln for ln in code[: zeros[0]] if re.match(r"^(?:if\b|elif\b|else\b|fi\b)", ln)]
                self.assertEqual(before[-1], 'if [ -n "$KNEE" ]; then', "%s: exit 0 outside the knee branch" % path.name)

    def test_fail_sites_cannot_be_neutralised(self):
        # r10 Q8: an exit inside a subshell does not end the script, so a FAIL site
        # in `( ... ) || true` is fail-open; a function named exit/return/trap (or
        # any function outside the pinned set) can shadow the builtins.
        for path in SCRIPTS:
            lines = _norm_lines(path)
            for k, ln in enumerate(lines):
                self.assertNotRegex(ln, OR_TRUE_AFTER_GROUP, "%s: a group or-true'd away: %s" % (path.name, ln))
                if FAIL_ECHO.search(ln):
                    self.assertNotRegex(ln, r"\(\s*[^)]*\becho\b", "%s: FAIL echo inside a subshell: %s" % (path.name, ln))
                    prev = lines[k - 1] if k else ""
                    self.assertFalse(prev.endswith("("), "%s: FAIL echo inside a subshell: %s" % (path.name, ln))
                self.assertIsNone(ALIAS_DEF.search(ln), "%s: alias can shadow a builtin: %s" % (path.name, ln))
            for where, group in self._groups(lines, path.name):
                self.assertFalse(group["bad"], "%s: FAIL site in a group that can be neutralised (%s): %s" % (path.name, group["why"], where))
            names = set()
            for ln in lines:
                for m in FUNCTION_DEF.finditer(ln):
                    names.add(m.group(1) or m.group(2) or m.group(3))
            for banned in ("exit", "return", "trap", "builtin", "command"):
                self.assertNotIn(banned, names, "%s: function named %s" % (path.name, banned))
            self.assertEqual(names, PINNED_FUNCTIONS[path], "%s: function set differs from the pinned list" % path.name)

    def test_non_scram_verifier_is_refused(self):
        # N3 + r4 P4: the case has exactly two arms, the SCRAM arm and one
        # catch-all that exits non-zero, so no permissive arm can be added.
        for path in SCRIPTS:
            code = [ln.strip() for ln in _code_lines(path)]
            start = code.index('case "$VERIFIER_ROW" in')
            end = code.index("esac", start)
            arms = [ln for ln in code[start + 1 : end] if ln]
            self.assertEqual(len(arms), 2, "%s: unexpected extra case arm: %r" % (path.name, arms))
            self.assertEqual(arms[0], "'\"ai_memory\" \"SCRAM-SHA-256$'*) ;;", path.name)
            # r5 Q3: the exact refusing arm, echo to stderr then exit as separate
            # statements; `>&2 || exit 73` would continue to the userlist write.
            self.assertEqual(
                arms[1],
                '*) echo "FATAL: role ai_memory has no SCRAM-SHA-256 verifier" >&2; exit 73 ;;',
                path.name,
            )
            self.assertNotIn("||", arms[1], path.name)
            self.assertRegex(arms[1], REFUSING_ARM, path.name)

    def test_userlist_removed_before_write(self):
        # N4: umask only applies to a new file. A leftover 0644 file must be
        # removed (or chmod 600) before the verifier is written.
        for path in SCRIPTS:
            code = [ln.strip() for ln in _code_lines(path)]
            writes = [i for i, ln in enumerate(code) if USERLIST_REF.search(ln) and ">" in ln]
            self.assertEqual(len(writes), 1, path.name)
            prior = code[code.index("trap cleanup EXIT") : writes[0]]
            removed = any(re.match(r'^rm -f "\$USERLIST"$', ln) for ln in prior)
            self.assertTrue(removed, "%s: rm -f of the userlist must precede the write" % path.name)

    def test_exit_codes_are_distinct_and_documented(self):
        # r4 P5: every exit code >= 64 has exactly one meaning in a script, is
        # named in the script header and in that script's README.
        for path in SCRIPTS:
            code = [ln.strip() for ln in _code_lines(path)]
            codes = [int(c) for ln in code for c in re.findall(r"(?<![\w-])exit\s+(\d+)", ln)]
            big = sorted(c for c in codes if c >= 64)
            # 65 has one meaning (bad AI_MEMORY_SMOKE_RUN) at two pinned sites:
            # the character class and the 64-character bound.
            self.assertEqual(big.count(65), 2, "%s: exit 65 sites" % path.name)
            big = [c for c in big if c != 65] + [65]
            self.assertEqual(len(big), len(set(big)), "%s: exit code reused: %r" % (path.name, big))
            header = "\n".join(ln for ln in path.read_text().splitlines()[:50] if ln.startswith("#"))
            readme = README_FOR[path].read_text()
            for c in big:
                self.assertRegex(header, r"\b%d\b" % c, "%s: exit %d missing from the header" % (path.name, c))
                self.assertRegex(readme, r"\b%d\b" % c, "%s: exit %d missing from the README" % (path.name, c))
        env = "\n".join(_code_lines(ENVELOPE))
        verifier = re.search(r"no SCRAM-SHA-256 verifier.*?exit (\d+)", env)
        knee = re.search(r"NO KNEE.*?\n\s*exit (\d+)", env, re.S)
        self.assertTrue(verifier and knee)
        self.assertNotEqual(verifier.group(1), knee.group(1))

    def test_pool_mode_step_asserts_effective_config(self):
        # r4 P6: [4/4] reads SHOW CONFIG and fails non-zero on a mismatch.
        text = _joined(SMOKE)
        self.assertNotRegex(text, r"SHOW pool_mode", "SHOW pool_mode is not a valid admin command")
        self.assertIn("SHOW CONFIG;", text)
        self.assertNotRegex(text.split("[4/4]", 1)[1], r"\|\|\s*true|2>\s*/dev/null")
        code = [ln.strip() for ln in _code_lines(SMOKE)]
        for var, want in (("pool_mode", "transaction"), ("auth_type", "scram-sha-256")):
            check = 'if [ "$%s" != "%s" ]; then' % (var, want)
            self.assertIn(check, code, "[4/4] must compare %s" % var)
            tail = code[code.index(check) + 1 : code.index(check) + 4]
            self.assertTrue(any(re.match(r"^exit [1-9]\d*$", ln) for ln in tail), "%s: mismatch must exit non-zero" % var)

    def test_compose_project_name_is_derived_per_run(self):
        # Collision fix: project, container names and the userlist derive from a
        # per-run suffix, every compose call names the project, and the trap
        # removes only that project.
        for path in SCRIPTS:
            code = [ln.strip() for ln in _code_lines(path)]
            self.assertIn('RUN="${AI_MEMORY_SMOKE_RUN:-$(date +%s)-$$}"', code, path.name)
            self.assertIn('export AI_MEMORY_SMOKE_RUN="$RUN"', code, path.name)
            # r8 S3: the sanitiser arm is pinned to its exact text, followed by
            # the length bound with its own exit-65 refusal.
            self.assertEqual(code.count(RUN_CASE_ARM), 1, "%s: RUN sanitiser arm changed" % path.name)
            at = code.index(RUN_CASE_ARM)
            self.assertEqual(code[at - 1], 'case "$RUN" in', path.name)
            self.assertEqual(code[at + 1], "esac", path.name)
            self.assertEqual(code[at + 2 : at + 6], RUN_LENGTH_BOUND, "%s: RUN length bound missing or changed" % path.name)
            for var in ("PROJECT", "PG_CONTAINER"):
                found = [ln for ln in code if ln.startswith(var + "=")]
                self.assertEqual(len(found), 1, "%s: %s" % (path.name, var))
                self.assertRegex(found[0], r'^%s="ai-memory-pgbouncer-[^"]*\$RUN[^"]*"$' % var, "%s: %s is not per-run" % (path.name, found[0]))
            for ln in _joined(path).splitlines():
                if re.search(r"\bdocker compose\b", ln) and not ln.lstrip().startswith("echo"):
                    self.assertIn('-p "$PROJECT"', ln, "%s: compose call without the per-run project: %s" % (path.name, ln))
        compose = _compose_code()
        names = re.findall(r"(?m)^\s*container_name:\s*(\S+)", compose)
        self.assertEqual(len(names), 2, names)
        for name in names:
            self.assertIn("${AI_MEMORY_SMOKE_RUN:?", name, "container_name must be per-run: %s" % name)
            self.assertTrue(name.startswith("ai-memory-pgbouncer-"), name)
        self.assertRegex(compose, r"\./\.userlist\.generated\.\$\{AI_MEMORY_SMOKE_RUN:\?[^}]*\}\.txt:/etc/pgbouncer/userlist\.txt:ro")

    def test_every_fail_site_exits_nonzero_in_its_own_branch(self):
        # r5 Q1: a FAIL:/FATAL: echo is followed, in the same branch, by an
        # explicit `exit <non-zero literal>` (same statement list, or the next
        # line). A bare `exit`, `exit $?`, a deleted exit or `|| exit` all fail.
        # The only other form is the teardown's `rc=1`, which cleanup() turns
        # into `exit "$rc"` (pinned by the trap test).
        for path in SCRIPTS:
            lines = _norm_lines(path)
            sites = [i for i, ln in enumerate(lines) if FAIL_ECHO.search(ln)]
            self.assertGreaterEqual(len(sites), 5, "%s: FAIL/FATAL sites vanished: %r" % (path.name, sites))
            for i in sites:
                nxt = lines[i + 1] if i + 1 < len(lines) else ""
                ok = bool(EXIT_SAME_LINE.search(lines[i])) or bool(EXIT_NEXT_LINE.match(nxt)) or nxt == "rc=1"
                self.assertTrue(ok, "%s: FAIL/FATAL echo without an explicit non-zero exit: %s | next: %s" % (path.name, lines[i], nxt))

    def test_every_step_marker_is_pinned(self):
        # r5 Q1: not only [4/4]. The markers run 1..N once each, in order, and
        # the smoke ends with its PASS line as the last statement.
        # The envelope's step 4 only defines the worker function and prints
        # nothing, so its printed markers are 1, 2, 3 and 5 of 5.
        want = {SMOKE: (4, [1, 2, 3, 4]), ENVELOPE: (5, [1, 2, 3, 5])}
        for path, (total, printed) in want.items():
            code = [ln.strip() for ln in _code_lines(path)]
            marks = [STEP_MARKER.match(ln) for ln in code if STEP_MARKER.match(ln)]
            self.assertEqual([int(m.group(1)) for m in marks], printed, path.name)
            self.assertEqual({int(m.group(2)) for m in marks}, {total}, path.name)
        code = [ln.strip() for ln in _code_lines(SMOKE) if ln.strip()]
        self.assertRegex(code[-1], r'^echo "PASS: PgBouncer pooler validated ', "the PASS line must be last")

    @staticmethod
    def _redirect_targets(path):
        return PgbouncerSmokeComposeTest._scan_redirects(_norm_lines(path), path.name)

    @staticmethod
    def _scan_redirects(lines, name):
        """Redirect targets outside heredoc bodies; quoted text is neutralised
        to `Q<content>` (with `>` and `<` blanked) so a quoted target survives."""
        targets, heredoc = [], None
        for ln in lines:
            ln = ln if heredoc else re.sub(r"\(\(.*?\)\)", " ", ln)  # arithmetic is not a redirect or heredoc
            if heredoc:
                if ln == heredoc:
                    heredoc = None
                continue
            plain = re.sub(
                r"\"([^\"]*)\"|'([^']*)'",
                lambda m: "Q" + re.sub(r"[<>]", "_", m.group(1) if m.group(1) is not None else m.group(2)),
                ln,
            )
            targets.extend(t.rstrip(");&|") for t in REDIRECT.findall(plain))
            for tok in HEREDOC_TOKEN.finditer(ln):
                word = tok.group(1) or tok.group(2) or tok.group(3)
                if word:
                    heredoc = word
                    break
        if heredoc is not None:
            raise AssertionError("%s: heredoc terminator %s never found; the redirect scan would be blind" % (name, heredoc))
        return targets

    @staticmethod
    def _groups(lines, name):
        """r11 Q15: every ( ) and { } group over the code lines, across lines, outside
        quotes, comments and heredoc bodies; returns (location, group). group["bad"] is set
        when a FAIL echo sits inside a subshell, or in a group that closes with `|| true`,
        `|| :` or `|| echo ...`, or is a pipeline element followed by `| ... || true`."""
        out, stack, heredoc, in_sq = [], [], None, False
        for n, raw in enumerate(lines):
            if heredoc:
                heredoc = None if raw == heredoc else heredoc
                continue
            ln = re.sub(r"\(\(.*?\)\)", lambda m: " " * len(m.group()), raw if in_sq else _strip_comment(raw))
            fail = FAIL_ECHO.search(ln)
            fail_at = fail.start() if fail else -1
            i = 0
            while i < len(ln):
                ch, nxt = ln[i], ln[i + 1 : i + 2]
                if i == fail_at:
                    for g in stack:
                        g["fail"] = True
                step = 1
                top = stack[-1]["kind"] if stack else ""
                if in_sq:
                    in_sq = ch != "'"
                elif ch == "\\":
                    step = 2
                elif ch == "$" and nxt in ("(", "{"):
                    stack.append({"kind": "(" if nxt == "(" else "p", "sub": True, "fail": False, "at": "line %d col %d" % (n + 1, i + 1)})
                    step = 2
                elif top == "dq":
                    if ch == '"':
                        stack.pop()
                elif ch == '"':
                    stack.append({"kind": "dq", "fail": False})
                elif ch == "'":
                    in_sq = True
                elif ch in "({":
                    stack.append({"kind": ch, "sub": False, "fail": False, "at": "line %d col %d" % (n + 1, i + 1)})
                elif (ch == ")" and top == "(") or (ch == "}" and top in ("{", "p")):
                    group = stack.pop()
                    if group["kind"] != "p":
                        tail = ln[i + 1 :]
                        sub_fail = group["fail"] and group["kind"] == "("
                        piped = bool(GROUP_OR_NEUTRAL.match(tail) or GROUP_PIPED.match(tail))
                        group["bad"] = group["fail"] and (sub_fail or piped)
                        group["why"] = "subshell" if sub_fail else "closes with or-true or in a pipeline"
                        out.append(("%s %s%s" % (group["at"], "$" if group["sub"] else "", group["kind"]), group))
                i += step
            if not in_sq:
                for tok in HEREDOC_TOKEN.finditer(ln):
                    word = tok.group(1) or tok.group(2) or tok.group(3)
                    if word:
                        heredoc = word
                        break
        if heredoc is not None or in_sq or stack:
            raise AssertionError("%s: the group scan lost sync (heredoc %r, open groups %d)" % (name, heredoc, len(stack)))
        return out

    def test_group_scan_selftest(self):
        # r11 Q15: D3 (subshell carrying a command, closed by `|| echo ok`), D4 (brace group as
        # a pipeline element), D1/D2 style one-line definitions after ; && || { ( |.
        bad = lambda lines: [g["bad"] for _, g in self._groups(lines, "t")]  # noqa: E731
        self.assertEqual(bad(['( cd x', 'echo "FAIL: a" >&2; exit 1', ') || echo ok']), [True])
        self.assertEqual(bad(['{ echo "FAIL: a" >&2; exit 1; } | cat || true']), [True])
        self.assertEqual(bad(['{ echo "FAIL: a" >&2; exit 1; }']), [False])
        self.assertEqual(bad(['x="$(psql <<\'SQL\'', 'echo ) {', 'SQL', ')" || { echo "FAIL: a" >&2; exit 1; }']), [False, False])
        for text in ("; exit() { :; }", "&& cleanup() { :; }", "|| alias x=y", "{ exit() { :; }", "( exit() { :; }", "true | exit() { :; }"):
            self.assertTrue(FUNCTION_DEF.search(text) or ALIAS_DEF.search(text), text)
        self.assertFalse(FUNCTION_DEF.search('x="$(date)"') or ALIAS_DEF.search("echo alias_set"))

    def test_redirect_scan_heredoc_opener_is_anchored(self):
        # r10 Q11: arithmetic `<<` and a here-string are not heredocs; an opener
        # whose terminator never appears fails the guard instead of blinding it.
        scan = self._scan_redirects
        self.assertEqual(scan(["x=$((1<<4))", "echo y > sixth.txt"], "t"), ["sixth.txt"])
        self.assertEqual(scan(["cat <<<word > out.txt"], "t"), ["out.txt"])
        self.assertEqual(scan(["cat <<'EOF' > a.txt", "echo b > c.txt", "EOF", "echo d > e.txt"], "t"), ["a.txt", "e.txt"])
        with self.assertRaises(AssertionError):
            scan(["cat <<'EOF'", "echo b > c.txt"], "t")
        # r11 Q16 (D7): an escaped `<` makes `<<word` an input redirect, so the next line is code.
        self.assertEqual(scan(["cat \\<<word > a.txt", "echo b > c.txt"], "t"), ["a.txt", "c.txt"])

    def test_dump_word_patterns_selftest(self):
        # r10 S9: the words are refused anywhere once quotes and backslashes are deleted;
        # env-w${wid} (a file-name prefix) and uppercase SQL SET LOCAL are not hits.
        strip = lambda s: re.sub(r"[\\\"']", "", s)  # noqa: E731
        for bad in ("timeout 5 env", "sh -c env", "e\"\"nv", "\\env", "builtin declare -x", "bash -c 'set'", "x; export"):
            s = strip(bad)
            self.assertTrue(DUMP_WORD.search(s) or BARE_SET.search(s) or BARE_EXPORT.search(s), bad)
        self.assertTrue(LOCAL_NAMEREF.search("local -n ref=x"))
        for ok in ("w${wid} env-w${wid}.txt", "SET LOCAL search_path = a, b", "set -euo pipefail", "envelope"):
            s = strip(ok)
            self.assertFalse(DUMP_WORD.search(s) or BARE_SET.search(s) or BARE_EXPORT.search(s), ok)

    def test_exit_status_caveat_is_identical_in_the_four_docs(self):
        # r11 Q13: one caveat sentence, identical (whitespace collapsed) in both
        # script headers and both READMEs.
        found = []
        for path in SCRIPTS:
            lead = path.read_text().splitlines()[:50]
            header = " ".join(ln.lstrip("# ").strip() for ln in lead if ln.startswith("#"))
            readme = README_FOR[path].read_text()
            for where, text in ((path.name + " header", header), (path.name + " README", readme)):
                hits = CAVEAT.findall(" ".join(text.split()))
                self.assertEqual(len(hits), 1, "%s: exactly one caveat sentence: %r" % (where, hits))
                found.append(hits[0])
        self.assertEqual(len(set(found)), 1, "the caveat sentence differs between the four docs: %r" % sorted(set(found)))

    def test_smoke_header_lists_exactly_the_exit_codes_used(self):
        # r11 Q13: one header row per code: 0 plus every `exit N` on a code line.
        used = {int(c) for ln in _code_lines(SMOKE) for c in re.findall(r"(?<![\w-])exit\s+(\d+)", ln)}
        header = [ln for ln in SMOKE.read_text().splitlines()[:50] if ln.startswith("#")]
        rows = [int(m.group(1)) for m in (re.match(r"^#\s{2,}(\d+)\s{2,}\S", ln) for ln in header) if m]
        self.assertEqual(rows, sorted(set(rows)), "the header rows must be unique and ascending")
        self.assertEqual(set(rows), used | {0}, "smoke header exit table differs from the exit codes the script uses")

    def _assert_exec_surface(self, path):
        """r9 S7: tracing, bare builtins, dump commands, container metadata,
        interpreter call sites and the redirect-target variables are pinned."""
        name = path.name
        lines = _norm_lines(path)
        for ln in lines:
            self.assertNotRegex(ln, SHELL_TRACE, "%s: shell tracing prints expanded secrets: %s" % (name, ln))
            bare = re.sub(r"[\\\"']", "", ln)
            self.assertNotRegex(bare, DUMP_WORD, "%s: env/printenv/declare/typeset word on a code line: %s" % (name, ln))
            self.assertNotRegex(bare, BARE_SET, "%s: bare set lists the environment: %s" % (name, ln))
            self.assertNotRegex(bare, BARE_EXPORT, "%s: bare export lists the environment: %s" % (name, ln))
            self.assertNotRegex(bare, LOCAL_NAMEREF, "%s: local -n nameref can read the password: %s" % (name, ln))
            self.assertNotRegex(ln, PSQL_META, "%s: psql backslash command (shell escape) in a heredoc: %s" % (name, ln))
            self.assertNotRegex(ln, EXEC_DUMP, "%s: docker exec of an environment dumper: %s" % (name, ln))
            self.assertNotRegex(ln, DOCKER_DISCLOSE, "%s: docker inspect/compose config discloses env: %s" % (name, ln))
            self.assertNotRegex(ln, ENVIRON_WORD, "%s: environ access: %s" % (name, ln))
        sites = [ln for ln in lines if INTERPRETER.search(ln)]
        self.assertEqual(sites, INTERPRETER_SITES[path], "%s: interpreter call sites differ from the allowlist" % name)
        for var in ("USERLIST", "STORE_URL_FILE", "RESULTS_DIR", "out"):
            writers = [
                ln
                for ln in lines
                if re.search(r"(?<![\w$])%s\+?=" % var, ln)
                or re.search(r"\b(?:for|read|mapfile|printf -v|unset|local|declare|typeset|readonly|let)\b[^=]*\b%s\b" % var, ln)
            ]
            self.assertEqual(writers, TARGET_ASSIGNMENTS[path].get(var, []), "%s: %s assigned outside its pinned line" % (name, var))

    def test_no_environment_dump_and_no_stray_redirect(self):
        # r8 S4: the name allowlist cannot see a command that copies the password
        # without naming it. No whole-environment dumper, and every `>` redirect
        # targets the userlist, the envelope store-url file, the daemon log, the
        # per-worker result file or /dev/null.
        for path in SCRIPTS:
            for ln in _norm_lines(path):
                self.assertNotRegex(ln, ENV_DUMPERS, "%s: command can dump the whole environment: %s" % (path.name, ln))
            self._assert_exec_surface(path)
            targets = self._redirect_targets(path)
            self.assertGreaterEqual(len(targets), 2, "%s: redirect scan found nothing" % path.name)
            for target in targets:
                self.assertIn(target, REDIRECT_TARGETS, "%s: redirect outside the allowlist: %s" % (path.name, target))

    def test_password_variable_is_an_allowlist(self):
        # r5 Q2: only these lines may name the password variable (PW,
        # POSTGRES_PASSWORD, PGPASSWORD): the PW= assignment, the exports, the
        # `POSTGRES_PASSWORD="$PW" docker compose` lines and, in the envelope
        # only, its documented POOLED_URL (0600 store file, #4577). `-e PGPASSWORD`
        # (by name, inherited) is stripped first. An alias (printf -v, export
        # POOLED_URL=..., any other assignment), a psql_pooled call-site argument
        # or an indirection (`printf -v`, `${!x}`, the shell word that re-parses
        # a string) fails.
        for path in SCRIPTS:
            counts = {"assign": 0, "export_pw": 0, "export_pgpw": 0, "compose": 0, "envelope_url": 0}
            for ln in _norm_lines(path):
                self.assertNotRegex(ln, BANNED_INDIRECTION, "%s: indirection can hide the password: %s" % (path.name, ln))
                rest = PW_BY_NAME.sub("", ln)
                if not PW_TOKEN.search(rest):
                    continue
                if re.match(r"^PW=", rest) and PW_ASSIGN.match(rest):
                    counts["assign"] += 1
                elif rest == 'export POSTGRES_PASSWORD="$PW"':
                    counts["export_pw"] += 1
                elif rest == 'export PGPASSWORD="$PW"' and path == SMOKE:
                    counts["export_pgpw"] += 1
                elif COMPOSE_PW_LINE.match(rest):
                    counts["compose"] += 1
                elif rest == POOLED_URL_ENVELOPE and path == ENVELOPE:
                    counts["envelope_url"] += 1
                else:
                    self.fail("%s: line names the password outside the allowlist: %s" % (path.name, ln))
            want = {"assign": 1, "export_pw": 1, "export_pgpw": 1 if path == SMOKE else 0, "compose": 2, "envelope_url": 1 if path == ENVELOPE else 0}
            self.assertEqual(counts, want, path.name)

    def test_smoke_pooled_url_has_no_userinfo_password(self):
        # r5 Q2: the smoke's pooled URL is the literal without a password, it is
        # assigned once (no second assignment, no export, no printf -v), every
        # psql_pooled call site passes no argument that could carry a secret, and
        # the script refuses a URL whose userinfo carries a password (exit 74).
        code = _norm_lines(SMOKE)
        assigns = [ln for ln in code if re.search(r"\bPOOLED_URL\s*=", ln)]
        self.assertEqual(assigns, [POOLED_URL_LITERAL])
        self.assertFalse([ln for ln in code if re.search(r"\b(?:export|declare|typeset|readonly|local)\b.*\bPOOLED_URL\b", ln)])
        self.assertIn(PSQL_POOLED_DEF, code)
        sites = [ln for ln in code if "psql_pooled" in ln and not ln.startswith("psql_pooled()")]
        self.assertEqual(len(sites), 3, sites)
        for ln in sites:
            self.assertTrue(any(rx.match(ln) for rx in PSQL_POOLED_SITES), "psql_pooled call site outside the allowlist: %s" % ln)
        # r10 Q7: a failed psql_pooled step must return the documented exit 1; the
        # heredoc call carries the or-branch on its opener or on its closing line.
        for k, ln in enumerate(code):
            if re.match(r"""^(?:path_count="\$\()?psql_pooled <<'SQL'""", ln):
                if ln.startswith("psql_pooled"):
                    self.assertRegex(ln, PSQL_FAIL_BRANCH + "$", "psql_pooled heredoc call without the FAIL or-branch")
                else:
                    closer = code[code.index("SQL", k) + 1]
                    self.assertRegex(closer, PSQL_HEREDOC_CLOSER, "psql_pooled heredoc call without the FAIL or-branch")
        at = code.index(POOLED_URL_LITERAL)
        # r8 S2: the refusal precedes the password and every container call.
        first_pw = next(i for i, ln in enumerate(code) if ln.startswith("PW="))
        first_docker = next(i for i, ln in enumerate(code) if re.search(r"\bdocker\b", ln))
        self.assertLess(at + 3, first_pw, "the exit-74 refusal must come before the PW assignment")
        self.assertLess(at + 3, first_docker, "the exit-74 refusal must come before the first docker line")
        self.assertEqual(
            code[at + 1 : at + 4],
            [
                'case "${POOLED_URL#*://}" in',
                '*:*@*) echo "FATAL: POOLED_URL must not carry a password in its userinfo" >&2; exit 74 ;;',
                "esac",
            ],
        )

    def test_gitignore_covers_the_generated_userlist(self):
        # r5 Q4: the per-run file holds the role's SCRAM verifier. The compose
        # bind path decides the name; the ignore file must match it for any run.
        bind = re.search(r"\./(\.userlist\.generated\.\$\{AI_MEMORY_SMOKE_RUN:\?[^}]*\}\.txt):/etc/pgbouncer/userlist\.txt", _compose_code())
        self.assertTrue(bind, "compose userlist bind path not found")
        patterns = [ln.strip() for ln in GITIGNORE.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
        self.assertTrue(patterns)
        self.assertFalse([p for p in patterns if p.startswith("!")], "negated .gitignore lines re-include the file: %r" % patterns)
        for run in ("1793223336-12345", "r7code", "a_b-c"):
            name = re.sub(r"\$\{AI_MEMORY_SMOKE_RUN:\?[^}]*\}", run, bind.group(1))
            self.assertEqual(name, ".userlist.generated.%s.txt" % run)
            self.assertTrue(any(fnmatch.fnmatchcase(name, pat) for pat in patterns), "%s is not gitignored: %r" % (name, patterns))
        self.assertFalse(any(fnmatch.fnmatchcase("userlist.txt", pat) for pat in patterns), "the committed userlist.txt must stay tracked")

    def test_git_ignores_the_generated_userlist(self):
        # r10 Q10: fnmatch is not git semantics; ask git itself when it is installed.
        git = shutil.which("git")
        if git is None:
            self.skipTest("git not on PATH; the fnmatch half in gitignore_covers_the_generated_userlist still ran")
        probe = subprocess.run(
            [git, "-C", str(PGB), "check-ignore", "--no-index", "-q", ".userlist.generated.r10code.txt"],
            capture_output=True,
            check=False,
        )
        if probe.returncode not in (0, 1):
            self.skipTest("not inside a git work tree (git rc %d)" % probe.returncode)
        self.assertEqual(probe.returncode, 0, "git does not ignore the generated userlist name")

    def test_exit_code_one_is_documented_with_bring_up_and_teardown(self):
        # r5 Q6 (decision: document, no new code): 1 covers a failed property,
        # a failed stack bring-up (including the concurrent-run bind failure) and
        # a failed teardown, in each script header and each README.
        for path in SCRIPTS:
            header = " ".join(ln.lstrip("# ").strip() for ln in path.read_text().splitlines()[:50] if ln.startswith("#"))
            readme = " ".join(README_FOR[path].read_text().split())
            for where, text in (("header", header), ("README", readme)):
                self.assertRegex(text, r"\b1\b[^;]*bring-up[^;]*teardown", "%s %s: exit code 1 must name bring-up and teardown" % (path.name, where))
        self.assertRegex(" ".join(README_FOR[SMOKE].read_text().split()), r"\b1\b[^;]*bind failure")


if __name__ == "__main__":
    unittest.main()
