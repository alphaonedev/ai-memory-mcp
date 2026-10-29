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
r12: compose interpolation follows the escape rule (an odd run of dollars before a name is an
interpolation, a run of three or more is refused); YAML anchors, aliases and merge keys, the keys
extends/include/secrets/configs/env_file and any top-level key besides name and services are refused;
a definition after then/do/else/elif/time/`!` is read as a definition; the group scan tracks do..done
and case..esac and RAISES on a closer with no opener; a trailing comment holds no heredoc opener; both
script headers are pinned to the exit codes the script uses (code 1 from its rc=1 site).
r13: PyYAML is required (the guard fails without it) and the compose scalars are scanned AS DECODED,
because compose interpolates after decoding; refused in the YAML: a backslash escape in a double-quoted
scalar, block scalars, a scalar or flow collection over several lines, a `$` inside a quoted scalar
(one pinned `user:` scalar excepted); every `docker compose` call passes the pinned `-f` and
`--project-directory`, the infra directory holds one compose file and no `.env`, and no COMPOSE_*
variable is read or exported; a definition after a case pattern paren or if/while/until is read as a
definition; if..fi and case..esac are groups, and a FAIL-bearing group may be followed only by end of
line, `;`, `;;` or an enclosing closer.
r14: a FAIL-bearing group may not be followed by `&&` (bash ignores set -e in a non-final element of an
`&&` list) and may not sit in condition position (if, elif, while, until, `!`, or piped after `&&` /
`||`); an explicit YAML tag is refused; a compose call has no global docker flag and no further file,
project-directory, env-file or project-name path after the pin.
r15: condition position lasts from if, elif, while or until to the matching `then` or `do`, across `;`,
newlines, comments and blank lines (a state machine in the group scan); a FAIL-bearing function is judged
by its call sites (statement position only: not `&`, not a pipeline element, not a non-final `&&` / `||`
element, not a condition), and the psql_pooled, worker, need and now_ms bodies are pinned whole;
measure-envelope.sh fails the run when a load worker exits non-zero, and psql_pooled returns non-zero to
the callers that check it; the compose pin is also read on quote-removed shell words (shlex), so no
spelling adds a file, project-directory, env-file, project-name or profile flag; the pillar4-envelope
listing is checked too; the docker daemon and config selection names (DOCKER_HOST, DOCKER_CONTEXT,
DOCKER_CONFIG, DOCKER_CERT_PATH, DOCKER_TLS_VERIFY, DOCKER_API_VERSION, any DOCKER_ name) and the docker
context subcommand are refused in both scripts.
r16: shell comments are removed by one quote-aware pre-pass (_strip_shell_comments) before every shell
reader (shlex words, the compose call text count, declarations, the redirect and group scans, the code
lines), so a quote inside a trailing comment no longer opens a quote; the envelope worker-status block is
pinned exactly (REAPING_PINS) and every wait in both scripts is a statement or `wait "$p" || NAME=$?` with
a later statement-position check that reaches a FAIL exit; the exact group counts are named constants and
their failure message names the constant and the lockstep remedy.
"""
import fnmatch
import pathlib
import re
import shlex
import shutil
import subprocess
import unittest

import yaml  # r13 S14: required (the guard FAILS, never skips, without it); compose is scanned decoded

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
        "out": ['local wid="$1" out="$2" deadline="$3" n=0 prev_id=""'],
    },
}
CLEANUP_BODY = {
    SMOKE: [
        "rc=$?",
        """docker compose -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" -p "$PROJECT" down -v >/dev/null || { echo "WARN: compose down failed" >&2; rc=1; }""",
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
        """docker compose -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" -p "$PROJECT" down -v >/dev/null || { echo "WARN: compose down failed" >&2; rc=1; }""",
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
    r'^POSTGRES_PASSWORD="\$PW" docker compose -f "\$COMPOSE_FILE_PINNED" --project-directory "\$COMPOSE_DIR" -p "\$PROJECT" up -d --wait(?: postgres)?$'
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
# r11 Q14 / r12 N3+S13 / r13 K1+S16: a definition is a command word, so it is read at line start,
# after ; && || { ( ) | (the `)` closes a case pattern or a group), after the reserved words
# then do else elif time if while until, and after the `!` negation.
CMD_START = r"(?:^|[;&|{()]|(?<![\w$\[\\])!|(?<![\w.:$-])(?:then|do|else|elif|time|if|while|until)(?![\w.:-]))\s*"
FUNCTION_DEF = re.compile(
    CMD_START
    + r"(?:function\s+([\w.:-]+)|([\w.:-]+)\s*\(\)(?=\s*(?:\{|\(|\[\[|(?:if|for|while|until|case|select)\b))|([\w:-]+)\s*\(\)\s*$)"
)
CLEANUP_DEF = re.compile(CMD_START + r"(?:function\s+cleanup\b|cleanup\s*\(\))")
ALIAS_DEF = re.compile(CMD_START + r"alias\s")
# r11 Q16: an escaped `<` before `<word` is an input redirect, not a heredoc opener.
HEREDOC_TOKEN = re.compile(r"\"[^\"]*\"|'[^']*'|(?<![<\\])<<(?!<)-?\s*(?:'(\w+)'|\"(\w+)\"|\\?(\w+))")
# r13 K3+S17 / r14 K5: what may follow the closer of a group that holds a FAIL site: end of line, `;`,
# `;;` (not `;&` or `;;&`), or the closer of an enclosing group (`)`, `}`, fi, done, esac; that group
# holds the same FAIL site and is judged by its own tail). `&&` is NOT accepted: bash ignores set -e for
# a failure in any non-final element of an `&&` list, so `done && :` swallows a piped loop's failure.
CLOSER_TAIL_TOKEN = re.compile(r"\s*(?:;;(?!&)|;(?![;&])|[)}]|(?:fi|done|esac)(?![\w-]))")
# r14 K6: a FAIL-bearing group whose construct is preceded, on the same command, by one of these is in
# condition position (if, elif, while, until, `!`), where set -e does not apply.
CONDITION_WORDS = ("if", "elif", "while", "until", "!")
# r15 K7: the condition state machine of _scan_groups. bash ignores set -e in the condition list of if,
# elif, while and until, and that list runs from the keyword to the matching `then` or `do` across `;`,
# newlines, comments and blank lines. The scan keeps a stack of open heads, one entry per keyword:
#   push   `if` (after its if..fi group opens) and `elif` end at `then`; `while` and `until` end at `do`;
#          `for` and `select` push a non-condition entry that ends at `do`, so each `do` pops its own head;
#   pop    `then` / `do` pop the top entry only when it ends with that word and was pushed at the same
#          group depth; any other `then` or `do` RAISES, and so does an entry still open at the end;
#   judge  every group opened, and every call of a FAIL-bearing function made, while an if, elif, while
#          or until entry is open carries that keyword in its context, so _context_bad refuses it.
# `!` negates one pipeline: it stays in the command words until `;` or the end of a line that does not
# end in `|`, `&&`, `||` or `!`.
# r15 K8: a function body runs in the set -e context of its call, so a FAIL-bearing function (its body
# group holds a FAIL site, directly or through a call of another FAIL-bearing function) is judged by its
# calls: each is at statement position (no `!` or condition keyword before it, not a pipeline element,
# and followed only by end of line, `;`, `;;` or a closer, so not by `&`, `|`, `&&` or `||`); the only
# other use of the name is the trap operand `trap NAME EXIT`. Names are read quote-removed.
FUNC_BODY_PREFIX = re.compile(r"(?:^|[\s;&|(){])(?:function\s+([\w.:-]+)(?:\s*\(\))?|([\w.:-]+)\s*\(\))\s*$")
STATIC_WORD = re.compile(r"""(?:"(?:\\.|[^"\\])*"|'[^']*'|\\.|[^\s;&|()<>"'\\])+""")
ASSIGNMENT_PREFIX = re.compile(r"(?:(?:^|(?<=\s))[A-Za-z_]\w*=\S*\s+)+$")
TRAP_OPERAND = re.compile(r"(?:^|[\s;&|(){])trap\s+$")
CALL_PREFIX_WORD = re.compile(r"(?:^|[\s;&|(){])(?:time|!)$")


def _closer_tail_ok(tail):
    """True when the text after a group closer starts with an accepted tail. The first token decides:
    `;` / `;;` end the list, and an enclosing closer hands the judgement to that enclosing group, which
    holds the same FAIL site and is judged by its own tail (so `done ) || true` is refused through the
    subshell and `done && : || true` is refused at `&&`)."""
    return not tail.strip() or bool(CLOSER_TAIL_TOKEN.match(tail))


def _unquote_word(text):
    """r15 K8 + S20: one static shell word with its quotes and backslashes removed."""
    out = []
    for m in re.finditer(r'"((?:\\.|[^"\\])*)"|\'([^\']*)\'|\\(.)|(.)', text, re.S):
        if m.group(1) is not None:
            out.append(re.sub(r"\\(.)", r"\1", m.group(1)))
        else:
            out.append(next(g for g in m.groups()[1:] if g is not None))
    return "".join(out)


def _call_tail(text):
    """r15 K8: the text after a call's arguments, from the first unquoted `;`, `&`, `|`, `)` or `}` word
    (a redirect such as `>&2`, `2>&1` or `&>` is an argument; `$( )` and `${ }` are skipped)."""
    quote, depth, i = None, 0, 0
    while i < len(text):
        ch, nxt = text[i], text[i + 1 : i + 2]
        if quote:
            if ch == quote:
                quote = None
            elif ch == "\\" and quote == '"':
                i += 1
        elif ch == "\\":
            i += 1
        elif ch in "\"'":
            quote = ch
        elif ch == "$" and nxt in ("(", "{"):
            depth += 1
            i += 1
        elif ch in ")}" and depth:
            depth -= 1
        elif ch in "<>" and nxt == "&" or ch == "&" and nxt == ">":
            i += 1
        elif ch in ";&|)" or (ch == "}" and (i == 0 or text[i - 1] in " \t;")):
            return text[i:]
        i += 1
    return ""


def _context_bad(ctx):
    """r14 K6: the words before a group on its command (if/elif/while/until/`!` and the operators
    `|`, `&&`, `||`). Condition position is refused; so is a piped group after `&&` or `||` (an
    unpiped `|| { echo FAIL; exit 1; }` is the real fail branch: its `exit` ends the shell itself)."""
    if any(w in CONDITION_WORDS for w in ctx):
        return True
    ops = [i for i, w in enumerate(ctx) if w in ("&&", "||")]
    return bool(ops) and "|" in ctx[ops[-1] + 1 :]
CAVEAT = re.compile(r"Any other non-zero status[^.]*\.")
COMPOSE_NAMES = {"AI_MEMORY_SMOKE_RUN", "POSTGRES_PASSWORD", "PGBOUNCER_UID", "PGBOUNCER_GID"}
# r12 S12: compose features that can move a second secret into a container.
DOLLAR_RUN = re.compile(r"(\$+)\{?([A-Za-z_]\w*)?")
YAML_ANCHOR_ALIAS = re.compile(r"(?:^|[\s,\[{:])[&*][A-Za-z0-9_-]+", re.M)
YAML_MERGE_KEY = re.compile(r"""(?m)^\s*(?:-\s*)?["']?<<["']?\s*:""")
COMPOSE_BANNED_KEYS = re.compile(r"""(?<![\w.-])["']?(?:extends|include|secrets|configs|env_file)["']?\s*:""")
COMPOSE_TOP_KEY = re.compile(r"""^["']?([\w-]+)["']?\s*:""")
OR_TRUE_AFTER_GROUP = re.compile(r"\)\s*\|\|\s*(?:true|:)(?![\w-])")
PSQL_POOLED_DEF = 'docker exec -i -e PGPASSWORD "$PG_CONTAINER" psql "$POOLED_URL" -v ON_ERROR_STOP=1 -tA "$@" || return 1'
GITIGNORE = PGB / ".gitignore"
LITERAL_DEFAULTS = ("ai_memory_smoke", "ai_memory_envelope")
REQUIRED_PW = re.compile(r"^\$\{POSTGRES_PASSWORD:\?[^}]+\}$")
PW_ASSIGN = re.compile(
    r"""^PW="\$\{POSTGRES_PASSWORD:-\$\(python3 -c 'import secrets; print\(secrets\.token_hex\((?:1[6-9]|[2-9]\d|\d{3,})\)\)'\)\}"$"""
)


def _strip_comment(line):
    """Drop a trailing ` # ...` comment that is outside quotes (YAML and INI lines only; r16 K11: shell
    text goes through _strip_shell_comments)."""
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
    return _yaml_parse(text)


def _code_lines(path):
    """The lines of a script without its whole-line comments. r16 K11: a line is a comment only when the
    shared pre-pass (_strip_shell_comments) removes all of it, so a `#` line inside a quoted string or a
    heredoc body stays; a script the pre-pass cannot read fails the guard."""
    text = path.read_text()
    code, problem = _strip_shell_comments(text, path.name)  # r18 K15: the problem names script, line and column
    if problem:
        raise AssertionError(problem)
    return [ln for ln, kept in zip(text.splitlines(), code.splitlines()) if not (ln.lstrip().startswith("#") and not kept.strip())]


def _sql_statements(path):
    """Parse SQL: drop `--` comments (whole-line and trailing), split on `;`."""
    lines = []
    for ln in path.read_text().splitlines():
        lines.append(ln.split("--", 1)[0])
    return [" ".join(s.split()) for s in " ".join(lines).split(";") if s.strip()]


def _compose_code(path=COMPOSE):
    return "\n".join(_strip_comment(ln) for ln in path.read_text().splitlines())


def _compose_scan(text):
    """r12 S12: (interpolated names, refusals) of comment-free compose text. A run of dollars
    escapes in pairs, so an ODD run followed by a name is an interpolation (r12 N1); a run of
    three or more is refused outright, as are YAML anchors, aliases, merge keys, the keys
    extends/include/secrets/configs/env_file and any top-level key besides name and services."""
    names, problems = _interpolations(text)
    if YAML_ANCHOR_ALIAS.search(text):
        problems.append("YAML anchor or alias")
    if YAML_MERGE_KEY.search(text):
        problems.append("YAML merge key")
    for m in COMPOSE_BANNED_KEYS.finditer(text):
        problems.append("banned key %s" % m.group(0).strip("\"' :"))
    tops = set()
    for ln in text.splitlines():
        if ln.strip() and not ln[0].isspace():
            key = COMPOSE_TOP_KEY.match(ln)
            if key is None:
                problems.append("top-level line that is not a key: %r" % ln[:20])
            else:
                tops.add(key.group(1))
    if tops != {"name", "services"}:
        problems.append("top-level keys %s differ from name, services" % sorted(tops))
    return names, problems


COMPOSE_QUOTED_DOLLAR_OK = {
    '"${PGBOUNCER_UID:?set PGBOUNCER_UID (smoke-test.sh exports id -u)}:${PGBOUNCER_GID:?set PGBOUNCER_GID (smoke-test.sh exports id -g)}"'
}


def _interpolations(value):
    """(names, problems) of one scalar under the compose escape rule (an odd run of dollars before
    a name interpolates; a run of three or more is refused)."""
    names, problems = set(), []
    for m in DOLLAR_RUN.finditer(value):
        if len(m.group(1)) >= 3:
            problems.append("a run of %d dollars (escape plus interpolation)" % len(m.group(1)))
        if len(m.group(1)) % 2 == 1 and m.group(2):
            names.add(m.group(2))
    return names, problems


def _decoded_scan(text):
    """r13 K4+S14: (interpolated names, refusals) of the compose file as YAML DECODES it, because
    compose interpolates the decoded scalar, not the raw text. Needs PyYAML. Every scalar value
    (keys included) goes through the escape rule; and every construct in which the raw text and the
    decoded scalar can differ is refused: a backslash escape in a double-quoted scalar, a block
    scalar (`|`, `>`), a scalar continued over several lines (folded join, escaped line break,
    comment-looking continuation), a flow collection over several lines, and a `$` inside a quoted
    scalar except the one pinned `user:` scalar."""
    names, problems, flow = set(), [], []
    try:
        events = list(yaml.parse(text))
    except yaml.YAMLError as exc:
        return names, ["the compose text does not parse: %s" % str(exc).splitlines()[0]]
    for ev in events:
        # r14 S18: compose decodes an explicit tag (`!!binary`, `!!str`, a verbatim tag) BEFORE it
        # interpolates, so the raw text and the scalar the checks below see are not what it renders.
        if isinstance(ev, (yaml.ScalarEvent, yaml.MappingStartEvent, yaml.SequenceStartEvent)) and ev.tag is not None:
            problems.append("explicit YAML tag %r" % ev.tag)
        if isinstance(ev, yaml.ScalarEvent):
            raw = text[ev.start_mark.index : ev.end_mark.index]
            if ev.start_mark.line != ev.end_mark.line:
                problems.append("scalar over several lines: %r" % raw[:30])
            if ev.style in ("|", ">"):
                problems.append("block scalar")
            if ev.style == '"' and "\\" in raw:
                problems.append("backslash escape in a double-quoted scalar: %r" % raw[:30])
            if ev.style in ('"', "'") and "$" in raw and raw not in COMPOSE_QUOTED_DOLLAR_OK:
                problems.append("dollar inside a quoted scalar: %r" % raw[:30])
            found, bad = _interpolations(ev.value)
            names |= found
            problems.extend(bad)
        elif isinstance(ev, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            flow.append((bool(ev.flow_style), ev.start_mark.line))
        elif isinstance(ev, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            is_flow, line = flow.pop()
            if is_flow and ev.end_mark.line != line:
                problems.append("flow collection over several lines")
    return names, problems


INFRA_ALLOWED = {".gitignore", "README.md", "docker-compose.yml", "pgbouncer.ini", "role-defaults.sql", "smoke-test.sh", "userlist.txt"}
PINNED_COMPOSE_ARGS = ' -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" '
COMPOSE_OWN_NAMES = {"COMPOSE_FILE_PINNED", "COMPOSE_DIR"}


# r14 S19: every compose invocation, with or without a global docker flag between the two words.
COMPOSE_INVOCATION = re.compile(r"\bdocker\b(?:\s+-{1,2}[\w-]+(?:[ =]\S+)?)*\s+compose\b")
COMPOSE_EXTRA_ARG = re.compile(
    r"(?<![\w$./-])(?:-f|--file|--project-directory|--env-file)(?![\w-])|(?<![\w$./-])(?:-p|--project-name)(?:\s+|=)\S*/"
)


def _command_tail(text):
    """The rest of one shell command: up to the first unquoted newline, `;`, `|`, `&&` or unmatched `)`."""
    quote, depth = None, 0
    for i, ch in enumerate(text):
        if quote:
            quote = None if ch == quote else quote
        elif ch in "\"'":
            quote = ch
        elif ch == "\\":
            continue
        elif text.startswith("$(", i):
            depth += 1
        elif ch == ")":
            if depth == 0:
                return text[:i]
            depth -= 1
        elif ch in ";|\n" or text.startswith("&&", i):
            return text[:i]
    return text


def _compose_pin_refusals(body):
    """r13 S15 + r14 S19: refusals for the code of one script. EVERY compose invocation (`docker`, then
    only the word compose: a global docker flag in between is refused) is followed by the pinned
    -f and --project-directory, and the rest of that command (a backslash continuation included) carries
    no further -f, --file, --project-directory, --env-file or --project-name with a path; no docker-compose
    (v1) binary, no COMPOSE_* name other than the two derived ones (so COMPOSE_FILE,
    COMPOSE_PATH_SEPARATOR, COMPOSE_PROJECT_NAME are neither read nor exported), no export of those two,
    and each assigned at most once."""
    problems = []
    words, problem = _shell_words(body)
    code, _ = _strip_shell_comments(body)  # r16 K11: the text count reads the same comment-free code
    body = re.sub(r"\\\n\s*", " ", body)
    if problem:
        problems.append(problem)
    else:
        word_problems, calls = _compose_word_refusals(words)
        problems.extend(word_problems)
        text_calls = len(COMPOSE_INVOCATION.findall(re.sub(r"\\\n\s*", " ", code)))
        if calls != text_calls:
            problems.append("compose calls read as words (%d) and as text (%d) differ" % (calls, text_calls))
    for m in COMPOSE_INVOCATION.finditer(body):
        if " ".join(m.group().split()) != "docker compose":
            problems.append("a global docker flag between docker and compose: %s" % m.group())
        if not body[m.end() :].startswith(PINNED_COMPOSE_ARGS):
            problems.append("docker compose call without the pinned -f and --project-directory")
            continue
        rest = _command_tail(body[m.end() + len(PINNED_COMPOSE_ARGS) :]).replace('"', "").replace("'", "")
        if COMPOSE_EXTRA_ARG.search(rest):
            problems.append("a further -f, --file, --project-directory, --env-file or --project-name path after the pin")
    if re.search(r"\bdocker-compose\b(?!\.ya?ml)", body):
        problems.append("docker-compose binary")
    for m in re.finditer(r"\bCOMPOSE_\w*", body):
        if m.group() not in COMPOSE_OWN_NAMES:
            problems.append("reads or sets %s" % m.group())
    if re.search(r"\bexport\b[^\n]*\bCOMPOSE_", body):
        problems.append("exports a COMPOSE_ variable")
    for name in sorted(COMPOSE_OWN_NAMES):
        if len(re.findall(r"\b%s=" % name, body)) > 1:
            problems.append("%s assigned more than once" % name)
    return problems


def _infra_dir_refusals(names, allowed=None, compose_files=("docker-compose.yml",)):
    """r13 S15: the infra/pgbouncer listing holds the allowlisted files (plus the per-run generated
    userlist) and exactly one compose file; a compose override, compose.yaml, .env or *.env fails.
    r15 S20: the same check reads the infra/pillar4-envelope listing (ENVELOPE_ALLOWED, no compose file)."""
    allowed = INFRA_ALLOWED if allowed is None else allowed
    problems = []
    for name in names:
        if name in allowed or (allowed is INFRA_ALLOWED and fnmatch.fnmatch(name, ".userlist.generated.*.txt")):
            continue
        problems.append("file not on the allowlist: %s" % name)
    if [n for n in names if re.search(r"(?i)compose.*\.ya?ml$", n)] != list(compose_files):
        problems.append("the directory must hold exactly the compose files %s" % (list(compose_files),))
    return problems


# r15 S20: the infra/pillar4-envelope listing; `.local-runs` is the gitignored RESULTS_DIR parent.
ENVELOPE_ALLOWED = {".gitignore", ".local-runs", "README.md", "measure-capacity-ramp.sh", "measure-envelope.sh", "usl-fit.py"}
# r15 S20: the compose pin is also read on shell WORDS (shlex, posix, after the r16 comment pre-pass and after the heredoc bodies
# are dropped and the backslash continuations joined), so quoting, escapes and attached values cannot
# respell a flag. A compose call is the word docker (or a path ending in /docker) followed by the word
# compose; its next six words are exactly the pin, and each later word of that command is a plain word or
# a lone $NAME that neither is nor starts with a refused flag. A redirect operator and its target are
# skipped; any other operator after the pin is refused; ANSI-C ($'...') and locale ($"...") quoting is
# refused outright; and the call count read as words equals the count read as text.
SHELL_OPERATOR_CHARS = "();<>|&\n"
REDIRECT_OPERATOR = re.compile(r"^(?:[<>]{1,3}[&|]?|&>>?|<>)$")
COMPOSE_PIN_WORDS = ["-f", "$COMPOSE_FILE_PINNED", "--project-directory", "$COMPOSE_DIR", "-p", "$PROJECT"]
COMPOSE_REFUSED_FLAG = re.compile(r"^(?:--(?:file|project-directory|env-file|project-name|profile)|-[A-Za-z]*[fp])")
COMPOSE_PLAIN_WORD = re.compile(r"^(?:[A-Za-z0-9_./:=@+-]+|\$[A-Za-z_]\w*)$")
DOCKER_SUBCOMMAND = re.compile(r"^[a-z]+$")
# r15 S21: the docker client picks its daemon, TLS material, config (and so its context) and API version
# from DOCKER_HOST, DOCKER_TLS_VERIFY, DOCKER_CERT_PATH, DOCKER_CONFIG, DOCKER_CONTEXT, DOCKER_API_VERSION.
# Neither script may name any DOCKER_ variable in any form (assignment, export, prefix word, declare,
# local or readonly operand, ${NAME:=...} default), read raw or quote-removed, nor run docker context.
DAEMON_SELECTION_NAMES = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "DOCKER_API_VERSION")
DAEMON_SELECTION_NAME = re.compile(r"DOCKER_\w*")


# r16 K11 / S22, r17 K12 / S23, r18 K13 / S24, K14, K15: shell comments are removed by ONE pre-pass that every
# shell reader of this guard uses (_code_lines, _shell_words and so the compose word pin and the
# daemon-selection check, the text count of compose calls, _self_referencing_declarations, the redirect
# scan's heredoc openers and the group scan). The rule: a `#` that begins a word outside single and double
# quotes, heredocs, command and arithmetic substitutions, process substitutions, backquotes, `[[ ... ]]` and
# regex or extglob groups starts a comment that runs to the end of the line; a word begins at the start of
# the text or of a line, after unquoted, unescaped whitespace or one of ; & | < >, after an opening
# bracket, after a reserved word, and after a `)` that closes an OPERATOR bracket. The pre-pass keeps a
# stack of what each open bracket is, and whether the next word is in COMMAND position: the start of the
# text or of a line, after ; ;; & && || |, after an OPERATOR `(`, `$(`, `<(`, `>(` or an opening backquote,
# after a case pattern `)`, and after one of the reserved words then do else elif if while until for time !
# {. OPERATOR brackets: a `(` at a word start in command position (a subshell), the `((` of an arithmetic
# command or of `for ((`, and the `)` that ends a case pattern. Every other `(` is a WORD bracket: `$(`,
# `$((`, `<(`, `>(`, a `(` directly after `=` or `+=` (an array assignment, also as a declare, local,
# readonly, export or typeset operand), a `(` directly after an extglob sigil @ ? * + !, every `(` inside
# `[[ ... ]]` (regex and pattern groups; the `]]` closer is tracked so no bracket kind leaks past it) and
# every `(` outside command position; a backquote pair is one too. A `)` that pops a WORD bracket and a
# closing backquote never begin a word, so `$(date)#c`, `a=(x)#c`, `[[ a =~ (a)#c ]]` and
# `[[ a == @(a)#c ]]` keep the `#` as text and the rest of the line as code, while `(echo a)#c`,
# `(echo a) #c`, `case $v in a)#c` and `a=(x) #c` end in a comment. `case` and `esac` are keywords only in
# command position (`esac` also as the pattern-list terminator after `;;`); in argument position
# (`echo case`, `: $(: case)`, `case esac in`) they are plain words and never touch the stack. Inside
# `$((...))`, `((...))`, `[[ ... ]]`, a regex or extglob group and a backquote pair a `#` is text
# (base#digits, regex and pattern text). A `#` inside a word (${x#y}, $#, a#b, --flag=#), after a
# backslash, or inside '...', "...", $'...' or ${...} is text. A heredoc body starts after the LOGICAL line
# of its opener ends (a `\`-newline continuation and a multi-line quoted string belong to that line); each
# opener on the line takes its body in order, copied unchanged. Fail closed: a quote, backquote,
# substitution, bracket, `[[`, case or heredoc still open at the end of the text, an arithmetic `$((` or
# `((` closed by a lone `)`, an unmatched `)` (also one an open case cannot place) and an `esac` keyword
# with no open case arm are a problem, never a guess; every problem names the
# script, the 1-based line and the 1-based column of the offending character (`smoke-test.sh: line 54 col
# 22: ...`). A single quote directly inside ${...} inside double quotes is refused (bash reads it as text
# there and as a quote outside double quotes). The bash agreement selftest
# (test_shell_comment_prepass_agrees_with_bash) is the contract: each of its rows runs in bash and the
# pre-pass keeps the row's `echo RAN` exactly when bash runs it. The comment text is removed, the newline
# kept, so line numbers do not move. History: before round 16 shlex read the comment text as code
# (commenters off); in round 16 any `)` and a closing backquote began a word; in rounds 16-17 every plain
# `(` was a subshell, so a `#` after an array assignment, a regex group or an extglob group hid the rest of
# a line that bash runs.
COMMENT_WORD_BREAK = " \t\n;&|()<>"
WORD_BRACKETS = ("$(", "<(", "=(", "w(")  # `<(` stands for <( and >(; `=(` an array assignment; `w(` any other word paren
ARITH_BRACKETS = ("$((", "((", "a(")  # `a(` is a plain paren inside arithmetic
CMD_CONTEXTS = ("", "(", "$(", "<(", "`", "case-arm")  # r18 K13: the contexts where a command (and an OPERATOR `(`) can start
NO_COMMENT_CONTEXTS = ("[[", "w(")  # r18 K13: inside [[ ]] and a regex or extglob group a `#` is text
SHELL_KEYWORD = re.compile(r"(case|esac|then|do|else|elif|if|while|until|for|time|in|\[\[|\]\]|!(?=\s)|\{(?=\s))(?=[\s;&|()<>`]|$)")


def _line_col(text, at):
    """r18 K15: the 1-based (line, column) of offset `at` in text."""
    return text.count("\n", 0, at) + 1, at - (text.rfind("\n", 0, at) + 1) + 1


def _strip_shell_comments(text, name="text"):
    """r16 K11, r18 K13 / S24, K14, K15: (comment-free text, problem or None); the rule is the comment block
    above. A problem reads `<name>: line L col C: <what>` (1-based, the offending character)."""
    out, stack, where, i, n = [], [], [], 0, len(text)
    word_start, cmd_pos, keep, line_start = True, True, 0, 0  # keep: out[:keep] is never stripped as trailing blanks

    def problem(at, what, src=text):
        line, col = _line_col(src, at)
        return None, "%s: line %d col %d: %s" % (name, line, col, what)

    def push(kind, at):
        stack.append(kind)
        where.append(at)

    def pop():
        where.pop()
        return stack.pop()

    while i < n:
        ch, nxt = text[i], text[i + 1 : i + 2]
        top = stack[-1] if stack else ""
        if top == "'":
            out.append(ch)
            i += 1
            if ch == "'":
                pop()
            continue
        if ch == "\\":
            out.extend(text[i : i + 2])
            i += 2
            keep = len(out)
            if nxt != "\n":
                word_start = cmd_pos = False
            continue
        if top == "$'":
            out.append(ch)
            i += 1
            if ch == "'":
                pop()
            continue
        if ch == "$" and text[i + 1 : i + 3] == "((":
            push("$((", i)  # r17 K12: an arithmetic substitution is a WORD bracket
            out.extend("$((")
            i += 3
            word_start = cmd_pos = False
            continue
        if ch == "$" and nxt in ("(", "{"):
            push("$" + nxt, i)
            out.extend(ch + nxt)
            i += 2
            word_start = cmd_pos = nxt == "("  # r18 K13: a command substitution starts in command position
            continue
        if top in ARITH_BRACKETS:
            # r17 K12: inside $((...)) or ((...)) a `#` is text; only the matching `))` closes it
            if ch == ")" and top != "a(":
                if nxt != ")":
                    return problem(i, "an arithmetic %s closed by a lone )" % top)
                pop()
                out.extend("))")
                i += 2
                word_start, cmd_pos = top == "((", False
                continue
            if ch == ")":
                pop()
            elif ch == "(":
                push("a(", i)
            elif ch in "'\"`":
                push(ch, i)
            out.append(ch)
            i += 1
            word_start = cmd_pos = ch == "`"
            continue
        if top in ('"', "${"):
            if ch == "`":
                push("`", i)
                word_start = cmd_pos = True
                out.append(ch)
                i += 1
                continue
            if top == '"' and ch == '"':
                pop()
            elif top == "${" and ch == "}":
                pop()
            elif top == "${" and ch == '"':
                push('"', i)
            elif top == "${" and ch == "'":
                if '"' in stack:
                    return problem(i, "a single quote inside ${...} inside double quotes")
                push("'", i)
            out.append(ch)
            i += 1
            word_start = False
            continue
        # code: top level, $( ), <( ), ( ), a backquote pair, [[ ]], a word paren or a case
        if ch == "#" and word_start and "`" not in stack and top not in NO_COMMENT_CONTEXTS:
            j = text.find("\n", i)
            j = n if j < 0 else j
            while len(out) > keep and out[-1] in " \t":
                out.pop()
            i = j
            continue
        if word_start:
            # r18 K14: reserved words only where bash reads them (case and esac only in command position)
            match = SHELL_KEYWORD.match(text, i)
            word = match.group(1) if match else ""
            handled = True
            if top == "case" and word == "in":
                stack[-1] = "case-in"
            elif top == "case-in" and word == "esac":
                pop()
                cmd_pos = False
            elif top == "[[" and word == "]]":
                pop()
                cmd_pos = False
            elif word and word not in ("in", "]]") and top in CMD_CONTEXTS and cmd_pos:
                if word == "case":
                    push("case", i)
                    cmd_pos = False
                elif word == "esac":
                    if top != "case-arm":
                        return problem(i, "esac with no open case" if not any(k.startswith("case") for k in stack) else "esac while a %s is open" % top)
                    pop()
                    cmd_pos = False
                elif word == "[[":
                    push("[[", i)
                    cmd_pos = False
            else:
                handled = False
            if handled:
                out.extend(word)
                i += len(word)
                word_start = True
                continue
        if ch == ";" and nxt in (";", "&") and top == "case-arm":
            stack[-1] = "case-in"  # r18 K14: ;; ;& ;;& end a case arm; the next word is a pattern
            j = i + 2 + int(nxt == ";" and text[i + 2 : i + 3] == "&")
            out.extend(text[i:j])
            i = j
            word_start, cmd_pos = True, False
            continue
        if word_start and ch not in COMMENT_WORD_BREAK:
            cmd_pos = False  # a word begins, so the command is named and no OPERATOR `(` follows it
        prev = out[-1] if out and len(out) > keep else ""
        if ch in ";&|\n" and top in CMD_CONTEXTS and not (ch == "&" and prev in ("<", ">")):
            cmd_pos = True
        # r17 K12: only a `)` that pops an OPERATOR bracket begins a word; r18 K13: only a `(` at a word start
        # in command position is an OPERATOR bracket
        begins = ch in COMMENT_WORD_BREAK and ch != ")"
        if ch == "'":
            push("'", i)
        elif ch == '"':
            push('"', i)
        elif ch == "$" and nxt in ("'", '"'):
            push("$'" if nxt == "'" else '"', i)
            out.append(ch)
            i += 1
            ch = nxt
        elif ch == "`":
            if top == "`":
                pop()
                begins = cmd_pos = False
            else:
                push("`", i)
                begins = cmd_pos = True
        elif ch == "(":
            if prev in ("<", ">"):
                push("<(", i)  # a process substitution: a WORD bracket that holds a command
                cmd_pos = True
            elif top == "case-in" and word_start:
                push("p(", i)  # the optional `(` before a case pattern
            elif word_start and cmd_pos and top in CMD_CONTEXTS:
                if nxt == "(":
                    push("((", i)  # an arithmetic command (also `for ((`): an OPERATOR bracket
                    out.extend("((")
                    i += 2
                    word_start = cmd_pos = False
                    continue
                push("(", i)  # a subshell: an OPERATOR bracket, its body starts in command position
            elif prev == "=" and top in CMD_CONTEXTS:
                push("=(", i)  # an array assignment (name=( or name+=( ): a WORD bracket
            else:
                push("w(", i)  # an extglob or regex group, a paren inside [[ ]] or outside command position
        elif ch == ")":
            if top in WORD_BRACKETS:
                pop()
                begins = cmd_pos = False
            elif top == "(":
                pop()
                begins, cmd_pos = True, False
            elif top in ("p(", "case-in"):
                if top == "p(":
                    pop()
                stack[-1] = "case-arm"  # the pattern ends: an OPERATOR close, a command follows
                begins = cmd_pos = True
            elif top in ("case", "case-arm"):
                return problem(i, "a ) the open case cannot place")
            else:
                return problem(i, "an unmatched )" if not stack else "an unmatched ) inside %s" % top)
        out.append(ch)
        i += 1
        word_start = begins
        if ch == "\n":
            # r18 S24 note: the heredoc bodies start after the LOGICAL line of their openers ends
            logical = re.sub(r"\(\(.*?\)\)", lambda m: " " * len(m.group()), "".join(out[line_start:]))
            for tok in HEREDOC_TOKEN.finditer(logical):
                word = tok.group(1) or tok.group(2) or tok.group(3)
                if not word:
                    continue
                while True:
                    if i >= n:
                        return problem(line_start + tok.start(), "heredoc %s is never closed" % word, "".join(out))
                    j = text.find("\n", i)
                    j = n if j < 0 else j
                    body = text[i:j]
                    out.extend(text[i : j + 1])
                    i = j + 1
                    if body.strip() == word:
                        break
                keep = len(out)
            line_start = len(out)
    if stack:
        return problem(where[-1], "a quote, backquote, substitution, bracket or case left open at the end of the text (%s)" % " ".join(stack))
    return "".join(out), None


def _drop_heredoc_bodies(text):
    """r15 S20: the code text without heredoc bodies; (text, open terminator or None)."""
    kept, heredoc = [], None
    for ln in text.split("\n"):
        if heredoc is not None:
            heredoc = None if ln.strip() == heredoc else heredoc
            continue
        kept.append(ln)
        for tok in HEREDOC_TOKEN.finditer(ln):
            word = tok.group(1) or tok.group(2) or tok.group(3)
            if word:
                heredoc = word
                break
    return "\n".join(kept), heredoc


def _ansi_or_locale_quote(code):
    """r15 S20: True when $'...' or $\"...\" quoting appears outside single quotes."""
    quote, i = None, 0
    while i < len(code):
        ch = code[i]
        if quote == "'":
            quote = None if ch == "'" else quote
        elif ch == "\\":
            i += 1
        elif quote == '"':
            quote = None if ch == '"' else quote
        elif ch == "$" and code[i + 1 : i + 2] in ("'", '"'):
            return True
        elif ch in "\"'":
            quote = ch
        i += 1
    return False


def _shell_words(body):
    """r15 S20: (words, problem) for code text: shlex in posix mode, comments removed, operators split out
    (a newline outside quotes is an operator token), after the heredoc bodies are dropped and the
    backslash continuations joined. An unreadable text is a problem, never an empty word list.
    r16 K11: comments are removed first by _strip_shell_comments (the shared pre-pass), so shlex reads code
    only; commenters stay off because a `#` left after the pre-pass is text (${x#y}, $#, a#b, "#")."""
    body, problem = _strip_shell_comments(body)
    if problem:
        return None, problem
    code, open_heredoc = _drop_heredoc_bodies(body)
    if open_heredoc is not None:
        return None, "heredoc %s is never closed" % open_heredoc
    if _ansi_or_locale_quote(code):
        return None, "ANSI-C or locale quoting ($' or $\")"
    lex = shlex.shlex(re.sub(r"\\\n", " ", code), posix=True, punctuation_chars=SHELL_OPERATOR_CHARS)
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""  # r16 K11: every comment is already gone (the pre-pass above); a `#` here is text
    try:
        return list(lex), None
    except ValueError as exc:
        return None, "the shell words cannot be read: %s" % exc


def _is_operator(word):
    return bool(word) and set(word) <= set(SHELL_OPERATOR_CHARS)


def _is_docker(word):
    return word == "docker" or word.endswith("/docker")


def _compose_word_refusals(words):
    """r15 S20: (refusals, compose call count) read on the shell words of one script."""
    problems, calls = [], 0
    for k, word in enumerate(words):
        if not _is_docker(word):
            continue
        nxt = words[k + 1] if k + 1 < len(words) else "\n"
        if _is_operator(nxt):
            continue
        if not DOCKER_SUBCOMMAND.match(nxt):
            problems.append("a docker word that is not a plain subcommand (a global flag or a respelling)")
            continue
        if nxt != "compose":
            continue
        calls += 1
        if words[k + 2 : k + 8] != COMPOSE_PIN_WORDS:
            problems.append("compose call words differ from the pin %s" % " ".join(COMPOSE_PIN_WORDS))
            continue
        j = k + 8
        while j < len(words):
            w = words[j]
            if _is_operator(w):
                if REDIRECT_OPERATOR.match(w):
                    j += 2
                    continue
                if set(w) <= set(";&|()\n") and not set(w) & set("<>"):
                    break
                problems.append("an operator after the compose pin: %r" % w)
                break
            if COMPOSE_REFUSED_FLAG.match(w):
                problems.append("a further file, project-directory, env-file, project-name or profile flag after the pin")
            elif not COMPOSE_PLAIN_WORD.match(w):
                problems.append("a word after the compose pin that is not a plain word or a lone $NAME")
            j += 1
    return problems, calls


def _daemon_selection_refusals(body):
    """r15 S21: refusals for a DOCKER_ name or a docker context call in one script, raw and as words."""
    problems = []
    if DAEMON_SELECTION_NAME.search(body):
        problems.append("names a DOCKER_ daemon or config selection variable")
    if re.search(r"\bdocker\s+context\b", body):
        problems.append("runs docker context")
    words, problem = _shell_words(body)
    if problem:
        return problems + [problem]
    for k, w in enumerate(words):
        if DAEMON_SELECTION_NAME.search(w):
            problems.append("names a DOCKER_ variable once quotes are removed")
        if _is_docker(w) and words[k + 1 : k + 2] == ["context"]:
            problems.append("runs docker context once quotes are removed")
    return problems


def _joined(path):
    return re.sub(r"\\\n\s*", " ", "\n".join(_code_lines(path)))


def _norm_lines(path):
    """Joined code lines with whitespace runs collapsed, blank lines dropped."""
    return [" ".join(ln.split()) for ln in _joined(path).splitlines() if ln.strip()]


class ComposeParity(unittest.TestCase):
    def test_both_parsers_agree_on_head(self):
        text = COMPOSE.read_text()
        a, b = _yaml_parse(text), _fallback_parse(text)
        self.assertEqual(set(a), set(b))
        for name in a:
            self.assertEqual([str(p) for p in a[name]["ports"]], [str(p) for p in b[name]["ports"]], name)
            self.assertEqual(a[name]["environment"], b[name]["environment"], name)


DECLARATION_WORDS = ("local", "declare", "typeset", "readonly", "export")


def _self_referencing_declarations(lines):
    """r15: a declaration builtin expands all its words before it assigns any, so a word that reads a name
    assigned earlier in the SAME command sees the old (under set -u: unbound) value. Returns the offending
    (line number, name) pairs; a line shlex cannot split is returned as (n, "unparsable")."""
    out = []
    for n, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if stripped.split(" ", 1)[0] not in DECLARATION_WORDS:
            continue
        code, problem = _strip_shell_comments(stripped)  # r16 K11: the shared comment pre-pass first
        try:
            if problem:
                raise ValueError(problem)
            words = shlex.split(code.split(";", 1)[0], posix=True)
        except ValueError:
            out.append((n, "unparsable"))
            continue
        assigned = []
        for word in words[1:]:
            if word.startswith("-"):
                continue
            name, _, value = word.partition("=")
            for ref in re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", value):
                if ref in assigned:
                    out.append((n, ref))
            assigned.append(name)
    return out


# r16 K9: the worker-status collection of measure-envelope.sh (the #8299 fix, round 15) pinned exactly, as
# _norm_lines reads it: one contiguous block, once, and worker_rc named on no other line.
REAPING_PINS = {
    SMOKE: (),
    ENVELOPE: (
        'for w in $(seq 1 "$conc"); do',
        'worker "$w" "$step_out/w${w}.txt" "$deadline" &',
        'pids+=($!)',
        'done',
        'worker_rc=0',
        'for p in "${pids[@]}"; do wait "$p" || worker_rc=$?; done',
        '[ "$worker_rc" -eq 0 ] || { echo "FAIL: a load worker exited with status $worker_rc at concurrency $conc" >&2; exit 1; }',
    ),
}
# r16 K9: the structural rule for every `wait` in both scripts, read on the comment-free shell words. A wait
# site is the word wait where a command starts (after an operator, a keyword or a prefix word such as
# builtin, command, exec, nohup, time, env or !). It is accepted in exactly two forms, each at statement
# position (after a newline, `;`, do, then, else or `{`) with at least one operand and no option:
#   statement: `wait "$p"` ended by a newline or `;` (set -e ends the script with the waited status);
#   captured:  `wait "$p" || NAME=$?` ended by a newline or `;`, where NAME is named bare (assigned, reset,
#              declared, read, unset) nowhere between the wait and its check, nor earlier in the loop body
#              holding the wait, and the check is the next statement-position `[ "$NAME" -eq 0 ] || {`
#              group or `if [ "$NAME" -ne 0 ]; then` arm that holds an `echo "FAIL: ..."` and an `exit`
#              with a literal non-zero status.
# Every compound command enclosing the wait is closed by a closer followed only by a newline, `;`, a
# redirect or another closer (so not `|| true`, `&`, `|`, `&&`). Refused therefore: `|| true`, `|| :`,
# `|| NAME=0`, a wait with no operand, a dropped status, a check with `-ge 0` or any other comparison, a
# check that does not run at statement position (`true || [ ... ]`) and a reset of NAME after the wait.
# A wait word built at runtime ("$fn" indirection) stays the structural residual on #8285.
WAIT_STATEMENT_PREV = ("\n", ";", "do", "then", "else", "{")
WAIT_COMMAND_PREV = WAIT_STATEMENT_PREV + (
    "&", "&&", "||", "|", "(", "!", "if", "elif", "while", "until", "builtin", "command", "exec", "nohup", "time", "env",
    "nice", "timeout", "eval",
)
WAIT_RC_CAPTURE = re.compile(r"^([A-Za-z_]\w*)=\$\?$")
GROUP_OPENERS = ("do", "{", "if", "case", "(", "then")
GROUP_CLOSERS = ("done", "}", "fi", "esac", ")")


def _bare_name(word, name):
    return bool(re.search(r"(?<![$\w{])%s(?!\w)" % re.escape(name), word))


def _wait_check_ok(words, k, name):
    """r16 K9: True when words[k:] starts a statement-position check of NAME that reaches a FAIL exit."""
    if k > 0 and words[k - 1] not in WAIT_STATEMENT_PREV:
        return False
    ref = ("$" + name, "${" + name + "}")
    if words[k : k + 2] == ["if", "["] and words[k + 2] in ref and words[k + 3 : k + 6] == ["-ne", "0", "]"]:
        j, end = k + 6, "fi"
        while j < len(words) and words[j] in (";", "\n"):
            j += 1
        if words[j : j + 1] != ["then"]:
            return False
    elif words[k : k + 1] == ["["] and words[k + 1] in ref and words[k + 2 : k + 7] == ["-eq", "0", "]", "||", "{"]:
        j, end = k + 6, "}"
    else:
        return False
    body, depth = [], 0
    for w in words[j + 1 :]:
        if w in ("{", "if"):
            depth += 1
        elif w == end and depth == 0:
            break
        elif w in ("}", "fi"):
            depth -= 1
        body.append(w)
    else:
        return False
    echo = "echo" in body and any(w.startswith("FAIL:") for w in body[body.index("echo") :])
    exits = [body[m + 1] for m, w in enumerate(body[:-1]) if w == "exit"]
    return echo and any(re.match(r"^[1-9]\d*$", x) for x in exits)


def _wait_refusals(body):
    """r16 K9: refusals for the wait sites of one script (the rule above), read on the shell words."""
    words, problem = _shell_words(body)
    if problem:
        return [problem]
    problems = []
    for k, w in enumerate(words):
        prev = words[k - 1] if k else "\n"
        if w != "wait" or prev not in WAIT_COMMAND_PREV:
            continue
        if prev not in WAIT_STATEMENT_PREV:
            problems.append("a wait outside statement position (after %r)" % prev)
            continue
        j, operands = k + 1, 0
        while j < len(words) and not _is_operator(words[j]):
            if words[j].startswith("-"):
                problems.append("a wait option: %s" % words[j])
            operands += 1
            j += 1
        while j < len(words) and REDIRECT_OPERATOR.match(words[j]):
            j += 2
        if not operands:
            problems.append("a wait with no operand (its status is always 0)")
            continue
        nxt = words[j] if j < len(words) else "\n"
        name = None
        if nxt == "||":
            m = WAIT_RC_CAPTURE.match(words[j + 1]) if j + 1 < len(words) else None
            if not m:
                problems.append("a wait status dropped or replaced after || (%s)" % (words[j + 1] if j + 1 < len(words) else "end"))
                continue
            name, j = m.group(1), j + 2
            nxt = words[j] if j < len(words) else "\n"
        if nxt not in ("\n", ";"):
            problems.append("a wait followed by %r (its status does not reach a FAIL exit)" % nxt)
            continue
        # every enclosing compound command is closed by a plain closer
        depth, m, loop_start = 0, j, None
        while m < len(words):
            x = words[m]
            if x in GROUP_OPENERS and x != "then":
                depth += 1
            elif x in GROUP_CLOSERS:
                depth -= 1
                if depth < 0:
                    after = m + 1
                    while after < len(words) and REDIRECT_OPERATOR.match(words[after]):
                        after += 2
                    tail = words[after] if after < len(words) else "\n"
                    if tail not in ("\n", ";") + GROUP_CLOSERS:
                        problems.append("a compound command holding a wait is followed by %r" % tail)
                        break
                    depth = 0
            m += 1
        if name is None:
            continue
        # the loop body holding the wait does not reset NAME before it
        depth, b = 0, k - 1
        while b >= 0:
            x = words[b]
            if x in GROUP_CLOSERS:
                depth += 1
            elif x in GROUP_OPENERS and x != "then":
                if depth == 0:
                    loop_start = b
                    break
                depth -= 1
            b -= 1
        if loop_start is not None and words[loop_start] == "do" and any(_bare_name(x, name) for x in words[loop_start:k]):
            problems.append("%s is reset in the loop body before the wait" % name)
            continue
        for c in range(j, len(words)):
            if _bare_name(words[c], name) and words[c] != "$" + name:
                problems.append("%s is assigned, declared or reset between the wait and its check" % name)
                break
            if words[c] in ("[", "if") and any(r in words[c + 1 : c + 3] for r in ("$" + name, "${" + name + "}")):
                if not _wait_check_ok(words, c, name):
                    problems.append("the check of %s is not a statement-position -eq 0 / -ne 0 test reaching a FAIL exit" % name)
                break
        else:
            problems.append("%s is never checked after the wait" % name)
    return problems


def _reaping_pin_refusals(path, lines):
    """r16 K9: the REAPING_PINS block of one script, contiguous and once; its rc name on no other line."""
    pin = REAPING_PINS[path]
    if not pin:
        return [] if not any(re.search(r"(?:^|[\s;&|(){}])wait(?:$|[\s;&|()])", ln) for ln in lines) else ["a wait in a script with no reaping pin"]
    starts = [k for k in range(len(lines)) if tuple(lines[k : k + len(pin)]) == pin]
    if len(starts) != 1:
        return ["the worker-status block differs from REAPING_PINS (found %d times)" % len(starts)]
    outside = [ln for k, ln in enumerate(lines) if not starts[0] <= k < starts[0] + len(pin) and "worker_rc" in ln]
    return ["worker_rc named outside the pinned block: %s" % ln for ln in outside]


FUNCTION_BODIES = {  # r15 K8: the whole body of each function, as _norm_lines reads it
    SMOKE: {
        'psql_pooled': (
            'psql_pooled() {',
            'docker exec -i -e PGPASSWORD "$PG_CONTAINER" psql "$POOLED_URL" -v ON_ERROR_STOP=1 -tA "$@" || return 1',
            '}',
        ),
    },
    ENVELOPE: {
        'need': (
            'need() { command -v "$1" >/dev/null 2>&1 || { echo "FATAL: \'$1\' not found on PATH" >&2; exit 69; }; }',
        ),
        'now_ms': (
            "now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }",
        ),
        'worker': (
            'worker() {',
            'local wid="$1" out="$2" deadline="$3" n=0 prev_id=""',
            'local bodyf="${out}.body"',
            'while [ "$(date +%s)" -lt "$deadline" ]; do',
            'n=$((n+1))',
            'local agent="env-w${wid}" title="w${wid}-m${n}"',
            'local t0 code t1 cur_id',
            't0=$(now_ms)',
            'code=$(curl -s -o "$bodyf" -w \'%{http_code}\' -X POST "$BASE/memories" -H \'content-type: application/json\' -H "x-agent-id: $agent" -d "{\\"title\\":\\"$title\\",\\"content\\":\\"envelope load $title\\",\\"namespace\\":\\"envelope\\",\\"tier\\":\\"short\\"}" 2>/dev/null || echo "000")',
            't1=$(now_ms)',
            'echo "store $code $((t1-t0))" >> "$out"',
            "cur_id=$(python3 -c 'import json,sys",
            'try: print(json.load(open(sys.argv[1])).get("id",""))',
            'except Exception: print("")\' "$bodyf" 2>/dev/null || echo "")',
            'if [ -n "$prev_id" ] && [ -n "$cur_id" ]; then',
            't0=$(now_ms)',
            'code=$(curl -s -o /dev/null -w \'%{http_code}\' -X POST "$BASE/links" -H \'content-type: application/json\' -H "x-agent-id: $agent" -d "{\\"source_id\\":\\"$prev_id\\",\\"target_id\\":\\"$cur_id\\",\\"relation\\":\\"related_to\\"}" 2>/dev/null || echo "000")',
            't1=$(now_ms)',
            'echo "link $code $((t1-t0))" >> "$out"',
            'fi',
            '[ -n "$cur_id" ] && prev_id="$cur_id"',
            't0=$(now_ms)',
            'code=$(curl -s -o /dev/null -w \'%{http_code}\' "$BASE/recall?q=envelope&namespace=envelope&limit=5" -H "x-agent-id: $agent" 2>/dev/null || echo "000")',
            't1=$(now_ms)',
            'echo "recall $code $((t1-t0))" >> "$out"',
            'done',
            'rm -f "$bodyf"',
            '}',
        ),
    },
}


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
        names, problems = _compose_scan(text)
        self.assertEqual(problems, [], "compose uses a form that can move a secret: %r" % problems)
        self.assertEqual(names, COMPOSE_NAMES, "compose may interpolate only %s" % sorted(COMPOSE_NAMES))
        # r13 S14: the same rule on the DECODED scalars, which is what compose interpolates.
        decoded_names, decoded_problems = _decoded_scan(COMPOSE.read_text())
        self.assertEqual(decoded_problems, [], "compose has a raw/decoded divergence: %r" % decoded_problems)
        self.assertEqual(decoded_names, COMPOSE_NAMES, "decoded scalars interpolate %s" % sorted(decoded_names))
        services = _services()
        self.assertRegex(services["postgres"]["environment"].get("POSTGRES_PASSWORD", ""), REQUIRED_PW)
        for name, spec in services.items():
            if name != "postgres":
                self.assertNotIn("POSTGRES_PASSWORD", "".join(spec["environment"].values()), name)
        self.assertNotRegex(text, r"(?m)^\s*-?\s*env_file\s*:", "no service may set env_file")

    def test_compose_scan_selftest(self):
        # r12 S12 + N1: rows R1 R1b (three-dollar escape), R2 (alias), R5 R6 (top-level secrets and
        # configs), R7 (extends), R12 (include), F1 F1b (escaped dollar then a second name) are refused;
        # F2b (a literal escaped `$$HOME`) and R11 (a .env file, no effect) are not.
        base = _compose_code()
        port = '    ports:\n      - "127.0.0.1:6432:6432"'
        self.assertEqual(_compose_scan(base)[1], [])
        legit = base.replace(port, "    environment:\n      SMOKE_NOTE: $$HOME\n" + port, 1)
        self.assertEqual(_compose_scan(legit), (COMPOSE_NAMES, []))
        rows = {
            "R1": "    environment:\n      X: $$$PGPASSWORD\n",
            "R1b": "    environment:\n      X: $$${PGPASSWORD}\n",
            "F1": "    environment:\n      - X=$$$PGPASSWORD\n",
            "F1b": "    labels:\n      - x=$$${PGPASSWORD}\n",
            "R2": "    x-a: &a ${PGPASSWORD}\n    labels:\n      smoke.copy: *a\n",
            "R4": "    <<: *a\n",
            "R7": "    extends:\n      file: other.yml\n      service: s\n",
            "R3": "    env_file: .smoke.env\n",
        }
        for row, extra in rows.items():
            names, problems = _compose_scan(base.replace(port, extra + port, 1))
            self.assertTrue(problems or names != COMPOSE_NAMES, "row %s is not refused" % row)
        top = {
            "R12": "include:\n  - other.yml\n",
            "R5": "secrets:\n  s:\n    environment: PGPASSWORD\n",
            "R6": "configs:\n  c:\n    environment: PGPASSWORD\n",
        }
        for row, extra in top.items():
            self.assertTrue(_compose_scan(base.rstrip("\n") + "\n" + extra)[1], "row %s is not refused" % row)
        # N1 parity alone (no run of three): an odd run is an interpolation, an even run is not.
        self.assertEqual(_compose_scan("a: $$$$HOME\nb: $${HOME}\nc: ${HOME}")[0], {"HOME"})
        self.assertEqual(_compose_scan("a: $$HOME")[0], set())

    def test_decoded_scan_selftest(self):
        # r13 S14 / K4: every construct in which the raw text and the decoded scalar differ is
        # refused (backslash escapes, block scalars, folded joins, multi-line flow, a dollar inside
        # quotes); the legitimate forms (F2b `$$HOME`, E4 `$ {NAME}`, E5 `$${NAME}`) are not.
        base = COMPOSE.read_text()
        port = '    ports:\n      - "127.0.0.1:6432:6432"'
        self.assertEqual(_decoded_scan(base), (COMPOSE_NAMES, []))
        legit = {
            "F2b": "    environment:\n      SMOKE_NOTE: $$HOME\n",
            "E4": "    environment:\n      SMOKE_NOTE: $ {PGPASSWORD}\n",
            "E5": "    environment:\n      SMOKE_NOTE: $${PGPASSWORD}\n",
            "dq-plain": '    environment:\n      SMOKE_NOTE: "plain text"\n',
            "sq-plain": "    environment:\n      SMOKE_NOTE: 'plain text'\n",
        }
        for row, extra in legit.items():
            self.assertEqual(_decoded_scan(base.replace(port, extra + port, 1)), (COMPOSE_NAMES, []), row)
        refused = {
            "hex-escape": '    environment:\n      X: "\\x24{PGPASSWORD}"\n',
            "unicode-escape": '    environment:\n      X: "\\u0024{PGPASSWORD}"\n',
            "escaped-line-break": '    environment:\n      X: "$\\\n        {PGPASSWORD}"\n',
            "block-pipe": "    labels:\n      smoke.copy: |\n        ${PGPASSWORD}\n",
            "block-fold": "    labels:\n      smoke.copy: >-\n        ${PGPASSWORD}\n",
            "folded-join": "    labels:\n      smoke.copy: aaa\n        ${PGPASSWORD}\n",
            "multi-line-flow": "    environment: {A: b,\n      C: ${PGPASSWORD}}\n",
            "dollar-in-dq": '    environment:\n      X: "$PGPASSWORD"\n',
            "dollar-in-sq": "    environment:\n      X: '${PGPASSWORD}'\n",
            "comment-continuation": '    labels:\n      smoke.copy: "a\n# b\n      ${PGPASSWORD}"\n',
            "plain-second-name": "    environment:\n      X: ${PGPASSWORD}\n",
            "dollar-run": "    environment:\n      X: $$$PGPASSWORD\n",
            # r14 S18: an explicit tag is decoded by compose before it interpolates: X1 `!!binary`
            # under a non-environment key, X2 under environment, X3 `!!str` carrying a dollar, X4 a
            # tagged mapping, plus a tagged sequence and a verbatim tag
            "X1-binary-hostname": "    hostname: !!binary |\n      JHtQR1BBU1NXT1JEfQ==\n",
            "X1b-binary-flow": "    hostname: !!binary JHtQR1BBU1NXT1JEfQ==\n",
            "X2-binary-environment": "    environment:\n      X: !!binary JHtQR1BBU1NXT1JEfQ==\n",
            "X3-str-tag-dollar": "    hostname: !!str ${PGPASSWORD}\n",
            "X3b-str-tag-plain": "    hostname: !!str plain\n",
            "X4-tagged-mapping": "    environment: !!map\n      X: plain\n",
            "X4b-tagged-sequence": "    dns: !!seq\n      - 1.1.1.1\n",
            "X4c-verbatim-tag": "    hostname: !<tag:yaml.org,2002:str> plain\n",
            "X4d-local-tag": "    hostname: !x plain\n",
        }
        for row, extra in refused.items():
            names, problems = _decoded_scan(base.replace(port, extra + port, 1))
            self.assertTrue(problems or names != COMPOSE_NAMES, "row %s is not refused" % row)
            if row.startswith(("X1", "X2", "X3", "X4")):
                self.assertTrue([p for p in problems if p.startswith("explicit YAML tag")], "row %s: the tag rule did not fire" % row)

    def test_decoded_environment_and_labels_are_pinned_on_head(self):
        # r13 S14: the head environment keys, the absence of labels/command/entrypoint and the
        # decoded values are pinned, so an interpolation shows here as well as in the scan.
        doc = yaml.safe_load(COMPOSE.read_text())
        self.assertEqual(set(doc), {"name", "services"})
        env_keys = {name: sorted((spec.get("environment") or {})) for name, spec in doc["services"].items()}
        # A new environment key is allowed (its value is scanned below); the head keys must stay.
        self.assertTrue({"POSTGRES_DB", "POSTGRES_PASSWORD", "POSTGRES_USER"} <= set(env_keys["postgres"]), env_keys)
        for name, spec in doc["services"].items():
            self.assertNotIn("labels", spec, name)
            self.assertNotIn("command", spec, name)
            self.assertNotIn("entrypoint", spec, name)
            for value in (spec.get("environment") or {}).values():
                found, bad = _interpolations(str(value))
                self.assertEqual(bad, [], name)
                self.assertTrue(found <= {"POSTGRES_PASSWORD"}, "%s: %s" % (name, sorted(found)))

    def test_compose_discovery_is_pinned(self):
        # r13 S15: with `-f` compose reads only the named file (it neither discovers a sibling
        # compose.yaml or override file nor honours COMPOSE_FILE; Docker Compose v5.6.0), so the
        # scripts pin it; the infra directory holds exactly one compose file and no `.env`; and
        # neither script exports or reads a COMPOSE_* variable except the two derived ones.
        for path, dir_line in ((SMOKE, 'COMPOSE_DIR="$PWD"'), (ENVELOPE, 'COMPOSE_DIR="$PWD/../pgbouncer"')):
            code = [ln.strip() for ln in _code_lines(path) if ln.strip()]
            self.assertEqual(code.count(dir_line), 1, "%s: COMPOSE_DIR assignment" % path.name)
            pin = 'COMPOSE_FILE_PINNED="$COMPOSE_DIR/docker-compose.yml"'
            self.assertEqual(code.count(pin), 1, "%s: COMPOSE_FILE_PINNED assignment" % path.name)
            at = code.index(dir_line)
            self.assertEqual(code.count('cd "$(dirname "$0")"'), 1, path.name)
            self.assertLess(code.index('cd "$(dirname "$0")"'), at, "%s: COMPOSE_DIR must follow the cd" % path.name)
            self.assertEqual(code[at + 1], pin, path.name)
            body = "\n".join(code)
            self.assertEqual(_compose_pin_refusals(body), [], path.name)
            self.assertEqual(_daemon_selection_refusals(body), [], path.name)
            self.assertGreaterEqual(len(re.findall(r"\bdocker compose\b", body)), 3, path.name)
            first = re.search(r"\bdocker compose\b", body)
            self.assertGreater(first.start(), body.index(pin), "%s: compose call before the pin" % path.name)
        self.assertEqual(_infra_dir_refusals(sorted(p.name for p in PGB.iterdir())), [])
        envelope_names = sorted(p.name for p in ENVELOPE.parent.iterdir())
        self.assertEqual(_infra_dir_refusals(envelope_names, ENVELOPE_ALLOWED, ()), [], "pillar4-envelope listing")

    def test_compose_discovery_selftest(self):
        ok = 'x docker compose -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" -p "$PROJECT" up'
        self.assertEqual(_compose_pin_refusals(ok), [])
        # legit: other options after the pin, `-p` with a variable, a later command that has its own -f
        self.assertEqual(_compose_pin_refusals(ok + ' --wait && grep -f x y | cat'), [])
        self.assertEqual(_compose_pin_refusals(ok + ' down -v >/dev/null || { echo "WARN -f" >&2; }'), [])
        self.assertEqual(_compose_pin_refusals('docker ps -aq --filter "label=com.docker.compose.project=$P"'), [])
        for row, text in {
            "no-f": 'docker compose -p "$P" up',
            "other-f": 'docker compose -f ./x.yml --project-directory "$COMPOSE_DIR" up',
            "f-after-p": 'docker compose -p "$P" -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" up',
            "no-project-directory": 'docker compose -f "$COMPOSE_FILE_PINNED" -p "$P" up',
            "v1-binary": 'docker-compose -f "$COMPOSE_FILE_PINNED" up',
            "export-file": 'export COMPOSE_FILE=/x/decoy.yml\n' + ok,
            "read-file": 'echo "$COMPOSE_FILE"\n' + ok,
            "separator": 'COMPOSE_PATH_SEPARATOR=: ' + ok,
            "project-name": 'COMPOSE_PROJECT_NAME=x ' + ok,
            "second-pin": 'COMPOSE_FILE_PINNED="$COMPOSE_DIR/x.yml"\nCOMPOSE_FILE_PINNED=/other.yml\n' + ok,
            "export-dir": 'export COMPOSE_DIR\n' + ok,
            # r14 S19: Y1 a second -f, Y2 `-f -` fed by a heredoc, Y3 a second -f over a line
            # continuation, Y4 a second --project-directory, Y5 a global docker flag (unpinned), Y6 a
            # global flag with another file only, plus --file, --env-file, --project-name with a path
            "Y1-second-f": ok + " -f ./extra.yml",
            "Y2-stdin-f": ok + " -f - <<'EOF'",
            "Y3-continuation": ok + " \\\n  -f ./extra.yml",
            "Y4-second-project-directory": ok + " --project-directory /elsewhere",
            "Y5-global-flag-unpinned": 'docker --debug compose -p "$P" up',
            "Y6-global-flag-other-file": 'docker -H unix:///x compose -f ./other.yml up',
            "Y6b-global-flag-pinned": 'docker --context=x compose -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" up',
            "Y7-long-file": ok + " --file=./extra.yml",
            "Y8-env-file": ok + " --env-file ./x.env",
            "Y9-project-name-path": ok + " --project-name /x/y",
            "Y10-second-invocation": ok + "\n" + 'docker compose -p "$P" up',
            "Y11-after-and": ok + ' -p "$P" up && docker compose -f ./z.yml ps',
        }.items():
            self.assertTrue(_compose_pin_refusals(text), "row %s is not refused" % row)
        listing = sorted(INFRA_ALLOWED)
        self.assertEqual(_infra_dir_refusals(listing + [".userlist.generated.r1.txt"]), [])
        for row, extra in {
            "override-yaml": "compose.override.yaml",
            "override-yml": "docker-compose.override.yml",
            "compose-yaml": "compose.yaml",
            "docker-compose-yaml": "docker-compose.yaml",
            "dotenv": ".env",
            "named-env": "smoke.env",
            "stray": "notes.txt",
        }.items():
            self.assertTrue(_infra_dir_refusals(listing + [extra]), "row %s is not refused" % row)
        self.assertTrue(_infra_dir_refusals([n for n in listing if n != "docker-compose.yml"]), "no compose file")
        envelope = sorted(ENVELOPE_ALLOWED)
        self.assertEqual(_infra_dir_refusals(envelope, ENVELOPE_ALLOWED, ()), [])
        for extra in (".env", "x.env", "docker-compose.override.yml", "compose.override.yaml", "docker-compose.yml", "compose.yaml"):
            self.assertTrue(_infra_dir_refusals(envelope + [extra], ENVELOPE_ALLOWED, ()), "envelope row %s is not refused" % extra)

    def test_compose_word_pin_and_daemon_selection_selftest(self):
        # r15 S20: R1-R10 are the reviewer's ten S20/S21 GREEN/GREEN shapes rebuilt from the finding text
        # (constructed equivalents: escapes, an attached short value, a short project name, a profile, a brace
        # word, ANSI-C quoting, a respelt command word, and the local-proxy DOCKER_HOST prefix), each one a
        # spelling the round-14 check accepted; each is refused now, raw text or words. The quoted forms the
        # round-14 check already refused after quote removal stay as own rows.
        ok = 'x docker compose -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" -p "$PROJECT" up'
        for legit in (ok, ok + " -d --wait postgres", ok + " down -v >/dev/null || { echo x; }", ok + " up 2>&1 | cat", "need docker", 'docker ps -aq --filter "label=x"'):
            self.assertEqual(_compose_pin_refusals(legit), [], legit)
            self.assertEqual(_daemon_selection_refusals(legit), [], legit)
        refused = {
            "R1-escaped-long-flag": ok + " --fi\\le ./extra.yml",
            "R2-escaped-profile": ok + " --profi\\le extra",
            "R3-escaped-flag": ok + " -\\f ./extra.yml",
            "R4-attached-short-value": ok + " -fextra.yml",
            "R5-short-project-name": ok + " -p other",
            "R6-escaped-project-directory": ok + " --project-director\\y ./other",
            "R7-profile": ok + " --profile extra",
            "R8-brace-word": ok + " -{f,} ./extra.yml",
            "R9-ansi-c-flag": ok + " $'-f' ./extra.yml",
            "R10-local-proxy-prefix": "DOCKER_HOST=tcp://127.0.0.1:2399 " + ok,
            "own-single-quoted-flag": ok + " '-f' ./extra.yml",
            "own-double-quoted-flag": ok + ' "-f" ./extra.yml',
            "own-attached-dot-value": ok + " -f./extra.yml",
            "own-attached-equals-value": ok + " -f=./extra.yml",
            "own-split-long-flag": ok + " --fi''le=./extra.yml",
            "own-brace-pair": ok + " {-f,./extra.yml}",
            "own-quoted-short-project": ok + ' -p"other"',
            "own-quoted-compose-other-file": 'docker "compose" -f ./x.yml up',
            "own-escaped-compose-other-file": "docker co\\mpose -f ./x.yml up",
            "own-quoted-docker-global-flag": '"docker" --host x compose -f "$COMPOSE_FILE_PINNED" up',
            "own-long-file-quoted-value": ok + ' --file "./extra.yml"',
            "own-env-file-attached": ok + " --env-file=./x.env",
            "own-project-name-attached": ok + " --project-name=other",
            "own-second-p": ok + " -p other",
            "own-combined-short": ok + " -df ./extra.yml",
            "own-locale-quote": ok + ' $"-f" ./extra.yml',
            "own-glob-word": ok + " -[f] ./extra.yml",
            "own-expansion-word": ok + " ${X:--f} ./extra.yml",
            "own-process-substitution": ok + " <(cat x)",
            "own-path-docker": "/usr/bin/docker compose -f ./x.yml up",
        }
        for row, text in refused.items():
            self.assertTrue(_compose_pin_refusals(text) or _daemon_selection_refusals(text), "row %s is not refused" % row)
        # r15 S21: one row per name and per form, and the docker context subcommand in any spelling
        forms = {
            "assignment": "{n}=x\n",
            "export": "export {n}=x\n",
            "export-name": "{n}=x; export {n}\n",
            "prefix-word": "{n}=x ",
            "env-prefix": "env {n}=x ",
            "declare": "declare -x {n}=x\n",
            "local": "local {n}=x\n",
            "readonly": "readonly {n}=x\n",
            "default": ': "${{{n}:=x}}"\n',
            "quoted-name": "export {q}=x\n",
            "escaped-name": "export {e}=x\n",
        }
        for name in DAEMON_SELECTION_NAMES:
            for form, shape in forms.items():
                text = shape.format(n=name, q=name[:4] + '""' + name[4:], e=name[:1] + "\\" + name[1:]) + ok
                self.assertTrue(_daemon_selection_refusals(text), "S21 %s %s is not refused" % (name, form))
        for text in ("docker context use x", 'docker "context" use x', "docker con\\text use x", "/usr/bin/docker context ls",
                     "docker 'context' create x", "x; docker context inspect"):
            self.assertTrue(_daemon_selection_refusals(text), text)
        for text in (ok + " -f", "x='" , ok + " <<'EOF'"):
            self.assertTrue(_compose_pin_refusals(text), "fail closed: %r" % text)
        # r16 K11 / S22: a quote in one trailing comment and a quote in a later one no longer make the code
        # between them one word (each row GREEN on b5621ab07, measured with the b5621ab07 functions). A
        # quote-respelt pinned call first keeps the word and text call counts equal, as in the review row.
        pin = 'docker compose -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" -p "$PROJECT"'
        first = 'd"ocker" compose -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" -p "$PROJECT" ps\n'
        k11 = {
            "S20-comment-quote-pair": first + "true # it's a note\n" + pin + " -\\f /x/decoy.yml ps # that's all",
            "S20-comment-quote-hide-backslash-f": first + "true # it's\n" + pin + " -\\f /x/decoy.yml up # it's",
            "K11-comment-pair-project-directory": first + "true # it's\n" + pin + " --project-director\\y /x ps # that's",
            "K11-comment-pair-docker-host": "true # it's\nexport D\"\"OCKER_HOST=tcp://127.0.0.1:2399 # that's\n" + ok,
            "K11-comment-pair-for-loop": first + "for i in 1; do # it's\n  " + pin + " -\\f /x/decoy.yml ps\ndone # that's",
            "own-K11-double-quote-pair": first + 'true # say "hi\n' + pin + ' -\\f /x/decoy.yml ps # bye"',
            "own-K11-tab-comment": first + "true\t# it's\n" + pin + " -\\f /x/decoy.yml ps\t# it's",
            "own-K11-semicolon-comment": first + "true;# it's\n" + pin + " --fi\\le /x/decoy.yml ps;# it's",
            "own-K11-paren-comment": first + "( true # it's\n" + pin + " -\\f /x/decoy.yml ps ) # it's",
        }
        for row, text in k11.items():
            self.assertTrue(_compose_pin_refusals(text) or _daemon_selection_refusals(text), "row %s is not refused" % row)
        # re-judged (r15 S20-comment-quote-alone): a lone quote in a comment is a comment, not code; legit now
        for legit in (ok + " # it's a note", "# it's\n" + ok, ok + " # a \"quote", ok + " # ${x"):
            self.assertEqual(_compose_pin_refusals(legit), [], legit)
            self.assertEqual(_daemon_selection_refusals(legit), [], legit)
        self.assertTrue(_compose_pin_refusals(ok + " it's"), "an open quote in code still fails closed")

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
        code, problem = _strip_shell_comments("\n".join(lines), name)  # r16 K11: the shared comment pre-pass
        if problem:
            raise AssertionError("%s; the redirect scan would be blind" % problem)
        for ln, kept in zip(lines, code.split("\n")):
            kept = re.sub(r"\(\(.*?\)\)", " ", kept)
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
            for tok in HEREDOC_TOKEN.finditer(kept):  # r12 N4 + r16 K11: a comment holds no opener
                word = tok.group(1) or tok.group(2) or tok.group(3)
                if word:
                    heredoc = word
                    break
        if heredoc is not None:
            raise AssertionError("%s: heredoc terminator %s never found; the redirect scan would be blind" % (name, heredoc))
        return targets

    @staticmethod
    def _close_group(stack, out, tail):
        """Pop the top group and, for ( ) { } and do..done, record whether it can be neutralised.
        Returns the group (None for a ${ } group)."""
        group = stack.pop()
        if group["kind"] == "p":
            return None
        sub_fail = group["fail"] and group["kind"] == "("
        unsafe = not _closer_tail_ok(tail)
        in_context = _context_bad(group["ctx"])
        group["bad"] = group["fail"] and (sub_fail or unsafe or in_context)
        group["why"] = (
            "subshell" if sub_fail else "a token other than end of line, ; ;; or a closer follows it" if unsafe else "condition or piped list position"
        )
        out.append(("%s %s%s" % (group["at"], "$" if group["sub"] else "", group["kind"]), group))
        return group

    @staticmethod
    def _groups(lines, name):
        """r15 K8: the group scan run to a fixpoint over the FAIL-bearing functions (a function whose body
        group holds a FAIL site, directly or through a call of another FAIL-bearing function). The last
        pass is returned; its call records have kind "call"."""
        funcs = set()
        while True:
            out = PgbouncerSmokeComposeTest._scan_groups(lines, name, funcs)
            found = {g["func"] for _, g in out if g["kind"] != "call" and g.get("func") and g["fail"]}
            if found <= funcs:
                return out
            funcs |= found

    @staticmethod
    def _scan_groups(lines, name, fail_funcs):
        """r11 Q15 + r12 N2/N5 + r13 K2 + r14 K5/K6 + r15 K7/K8: every ( ) { } do..done if..fi (elif and
        else arms belong to the if) and case..esac group over the code lines (a case pattern paren pops
        nothing), across lines, outside quotes, comments and heredoc bodies; returns (location, group).
        group["bad"] is set when a FAIL echo sits inside a subshell, or in a group whose closer is
        followed by anything but end of line, `;`, `;;` or an enclosing closer (r13 K3, r14 K5: not
        `&&`; a redirect, a pipe, `||`, a lone `&`), or in a group opened in condition position: while
        an if / elif / while / until head is open (r15 K7, the state machine described at
        CONDITION_WORDS) or after `!` or (when piped) `&&` / `||` on its command (r14 K6). r15 K8: each
        use of a function in fail_funcs is a call record, bad unless it is at statement position; it
        marks every enclosing group FAIL-bearing. A closer with no opener, a `then` or `do` with no open
        head, and a head left open RAISE (fail closed)."""
        out, stack, heredoc, in_sq = [], [], None, False
        words, loops, cond = [], [], []  # words: !, | && || on the current command; cond: open heads
        pending_func = None
        code, problem = _strip_shell_comments("\n".join(lines), name)  # r16 K11: the shared comment pre-pass
        if problem:
            raise AssertionError("%s; the group scan would be blind" % problem)
        lines = code.split("\n")

        def cond_words():
            return [c["word"] for c in cond if c["word"] in CONDITION_WORDS]

        def opener(kind, sub, n, i, ctx, func=None):
            stack.append(
                {"kind": kind, "sub": sub, "fail": False, "at": "line %d col %d" % (n + 1, i + 1), "ctx": list(ctx) + cond_words(),
                 "saved": list(words), "func": func}
            )

        def cmd_start(prev):
            prev = prev.rstrip()
            return not prev or prev[-1] in ";&|({" or bool(re.search(r"(?:^|[\s;&|(){])(?:then|do|else|elif|if|while|until)$", prev))

        def call_start(prev):
            prev = ASSIGNMENT_PREFIX.sub("", prev.rstrip() + " ").rstrip()
            return cmd_start(prev) or prev.endswith((")", "}")) or bool(CALL_PREFIX_WORD.search(prev))

        def pop_head(word, n, i):
            if not cond or cond[-1]["end"] != word or cond[-1]["depth"] != len(stack):
                raise AssertionError("%s: line %d col %d: %s with no open head that ends there" % (name, n + 1, i + 1, word))
            cond.pop()

        for n, raw in enumerate(lines):
            if heredoc:
                heredoc = None if raw == heredoc else heredoc
                continue
            ln = re.sub(r"\(\(.*?\)\)", lambda m: " " * len(m.group()), raw)  # r16 K11: comments already gone
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
                if fail_funcs and not in_sq and top != "dq" and ch not in " \t" and (i == 0 or ln[i - 1] in " \t;&|(){}"):
                    m = STATIC_WORD.match(ln, i)
                    used = _unquote_word(m.group()) if m else ""
                    rest = ln[i + len(m.group()) :] if m else ""
                    prev = ln[:i]
                    definition = re.match(r"\s*\(\)", rest) or re.search(r"(?:^|\s)function\s+$", prev)
                    trap = TRAP_OPERAND.search(prev) and re.match(r"\s+EXIT\s*(?:$|;)", rest)
                    if used in fail_funcs and not definition and not trap:
                        at = "line %d col %d" % (n + 1, i + 1)
                        ctx = words + cond_words()
                        statement = call_start(prev)
                        tail = _call_tail(rest)
                        bad = not statement or "|" in words or _context_bad(ctx) or not _closer_tail_ok(tail)
                        why = ("a FAIL-bearing function used outside statement position" if not statement
                               else "a FAIL-bearing function called where set -e does not reach its body")
                        for g in stack:
                            g["fail"] = True
                        out.append(("%s call %s" % (at, used), {"kind": "call", "sub": False, "func": used, "fail": True, "bad": bad,
                                                                "why": why, "ctx": ctx, "at": at}))
                if in_sq:
                    in_sq = ch != "'"
                elif ch == "\\":
                    step = 2
                elif ch == "$" and nxt in ("(", "{"):
                    opener("(" if nxt == "(" else "p", True, n, i, words)
                    words.clear()
                    step = 2
                elif top == "dq":
                    if ch == '"':
                        stack.pop()
                elif ch == '"':
                    stack.append({"kind": "dq", "fail": False})
                elif ch == "'":
                    in_sq = True
                elif ch == ";":
                    words.clear()
                elif ch == "&" and nxt == "&":
                    words.append("&&")
                    step = 2
                elif ch == "|":
                    words.append("||" if nxt == "|" else "|")
                    step = 2 if nxt == "|" else 1
                elif ch == "!" and nxt in (" ", "\t", "") and cmd_start(ln[:i]):
                    words.append("!")
                elif ch in "({":
                    m = FUNC_BODY_PREFIX.search(ln[:i])
                    func = (m.group(1) or m.group(2)) if m else (pending_func if not ln[:i].strip() else None)
                    opener(ch, False, n, i, words, func)
                    words.clear()
                elif ch == ")" and top == "case":
                    words.clear()  # r12 N5: a case pattern paren closes no group
                elif ch in ")}" and not ((ch == ")" and top == "(") or (ch == "}" and top in ("{", "p"))):
                    raise AssertionError("%s: line %d col %d: closing %s with no matching opener" % (name, n + 1, i + 1, ch))
                elif ch in ")}":
                    saved = stack[-1]["saved"]
                    PgbouncerSmokeComposeTest._close_group(stack, out, ln[i + 1 :])
                    words[:] = saved + ["g"]
                elif ch.isalpha() and (i == 0 or ln[i - 1] in " \t;&|(){}`"):
                    word = re.match(r"[A-Za-z]+", ln[i:]).group()
                    after = ln[i + len(word) : i + len(word) + 1]
                    step = len(word)
                    if after == "" or after in " \t;&|()":
                        if word == "do":
                            pop_head("do", n, i)
                            ctx = loops.pop() if loops else []
                            opener("do", False, n, i, ctx)
                            stack[-1]["saved"] = list(ctx)
                            words.clear()
                        elif word == "case":
                            opener("case", False, n, i, words)
                            words.clear()
                        elif word == "if":
                            opener("if", False, n, i, words)
                            cond.append({"word": "if", "end": "then", "depth": len(stack)})
                            words.clear()
                        elif word in ("while", "until", "for", "select"):
                            loops.append(list(words))
                            cond.append({"word": word, "end": "do", "depth": len(stack)})
                            if word in ("while", "until"):
                                words.clear()
                        elif word == "elif":
                            if top != "if":
                                raise AssertionError("%s: line %d col %d: elif outside an if" % (name, n + 1, i + 1))
                            cond.append({"word": "elif", "end": "then", "depth": len(stack)})
                            words.clear()
                        elif word == "then":
                            pop_head("then", n, i)
                            words.clear()
                        elif word == "else":
                            words.clear()
                        elif word in ("done", "esac", "fi"):
                            if top != {"done": "do", "esac": "case", "fi": "if"}[word]:
                                raise AssertionError("%s: line %d col %d: %s with no matching opener" % (name, n + 1, i + 1, word))
                            saved = stack[-1]["saved"]
                            PgbouncerSmokeComposeTest._close_group(stack, out, ln[i + len(word) :])
                            words[:] = saved + ["g"]
                i += step
            if not in_sq:
                if not (words and words[-1] in ("|", "&&", "||", "!")):
                    words.clear()
                m = FUNC_BODY_PREFIX.search(ln)
                pending_func = (m.group(1) or m.group(2)) if m else None
                for tok in HEREDOC_TOKEN.finditer(ln):
                    word = tok.group(1) or tok.group(2) or tok.group(3)
                    if word:
                        heredoc = word
                        break
        if heredoc is not None or in_sq or stack or cond:
            raise AssertionError("%s: the group scan lost sync (heredoc %r, open groups %d, open heads %d)" % (name, heredoc, len(stack), len(cond)))
        return out

    def test_group_scan_selftest(self):
        # r11 Q15: D3 (subshell carrying a command, closed by `|| echo ok`), D4 (brace group as
        # a pipeline element), D1/D2 style one-line definitions after ; && || { ( |.
        bad = lambda lines: [g["bad"] for _, g in self._groups(lines, "t")]  # noqa: E731
        self.assertEqual(bad(['( cd x', 'echo "FAIL: a" >&2; exit 1', ') || echo ok']), [True])
        self.assertEqual(bad(['{ echo "FAIL: a" >&2; exit 1; } | cat || true']), [True])
        self.assertEqual(bad(['{ echo "FAIL: a" >&2; exit 1; }']), [False])
        # r12 N2: a loop is a group (F3 bad, F3b legit); N5: a case pattern paren pops nothing (F11 bad)
        self.assertEqual(bad(["cat x | while read l; do", 'echo "FAIL: a" >&2; exit 1', "done || true"]), [True])
        self.assertEqual(bad(["cat x | while read l; do", 'echo "FAIL: a" >&2; exit 1', "done"]), [False])
        self.assertEqual(bad(["( case $x in", '0) echo "FAIL: a" >&2; exit 1 ;;', "esac ) || echo ok"]), [False, True])
        self.assertEqual(bad(['case $x in', '0) echo "FAIL: a" >&2; exit 1 ;;', "esac"]), [False])
        # r13 K2: if..fi (elif and else arms included) and case..esac are groups the closer rule covers
        fail = 'echo "FAIL: a" >&2; exit 1'
        self.assertEqual(bad(["cat x | if true; then", fail, "fi || true"]), [True])
        self.assertEqual(bad(["cat x | if true; then :; elif false; then", fail, "else :; fi || true"]), [True])
        self.assertEqual(bad(["cat x | case $x in", "0) " + fail + " ;;", "esac || true"]), [True])
        self.assertEqual(bad(["if true; then", fail, "fi"]), [False])
        self.assertEqual(bad(["if true; then", "if false; then", fail, "fi", "fi"]), [False, False])
        # r13 K3 + S17: a redirect, a pipe, `||` with anything, a lone `&` after the closer are refused;
        # end of line, `;`, `&&`, `;;`, an enclosing closer are not.
        loop = ["cat x | while read l; do", fail]
        for tail in ("done 2>&1 || true", "done </dev/null | cat || true", "done || printf ok", "done || /bin/true",
                     "done || command true", "done &", "done | cat", "done > /dev/null", "done >> x", "done &> x", "done 2> x",
                     "done < x", "done || :", "done || echo ok", "done ;&",
                     # r14 K5 (H1, H1b, H15b): `&&` is no longer accepted, and the whole tail is judged
                     "done && :", "done && true", "done && : || true", "done && x", "done;&& x"):
            self.assertEqual(bad(loop + [tail]), [True], tail)
        for tail in ("done", "done;", "done ; :", "done # note", "done ;; ", "done; : && true"):
            self.assertEqual(bad(loop + [tail]), [False], tail)
        self.assertEqual(bad(["{ " + fail + "; } 2>&1 || true"]), [True])
        self.assertEqual(bad(["{ " + fail + "; } | cat || /bin/true"]), [True])
        self.assertEqual(bad(["{ " + fail + "; } &"]), [True])
        self.assertEqual(bad(["{ " + fail + "; } && :"]), [True])
        self.assertEqual(bad(["if true; then", "{ " + fail + "; }", "fi"]), [False, False])
        # r14 K5: H4 `{ piped loop; } && :`, H5 piped case `esac && :`, H6b piped if `fi && true`,
        # H13 piped until `done && :`, H1 / H1b piped loop `done && :` / `done && true`
        self.assertEqual(bad(["{ cat x | while read l; do " + fail + "; done; } && :"]), [False, True])
        self.assertEqual(bad(["cat x | case $x in", "0) " + fail + " ;;", "esac && :"]), [True])
        self.assertEqual(bad(["cat x | if true; then", fail, "fi && true"]), [True])
        self.assertEqual(bad(["cat x | until false; do", fail, "done && :"]), [True])
        self.assertEqual(bad(["cat x | if true; then", fail, "fi; true"]), [False])
        # r14 K6: a FAIL-bearing group in condition position (H2 if, H3 `!`, H14 while, elif, until) is
        # refused; the same words outside a FAIL-bearing group, and an unpiped `|| { FAIL; exit 1; }`, are not.
        body = ["cat x | while read l; do", fail, "done"]
        self.assertEqual(bad(["if " + body[0], body[1], body[2] + "; then :; fi"]), [True, False])
        self.assertEqual(bad(["! " + body[0], body[1], body[2]]), [True])
        self.assertEqual(bad(["while " + body[0], body[1], body[2] + "; do break; done"]), [True, False])
        self.assertEqual(bad(["until " + body[0], body[1], body[2] + "; do break; done"]), [True, False])
        self.assertEqual(bad(["if false; then :; elif " + body[0], body[1], body[2] + "; then :; fi"]), [True, False])
        self.assertEqual(bad(["true && " + body[0], body[1], body[2]]), [True])
        self.assertEqual(bad(["true || " + body[0], body[1], body[2]]), [True])
        self.assertEqual(bad(["if { " + fail + "; }; then :; fi"]), [True, False])
        self.assertEqual(bad(["if true; then", "! cat x | while read l; do", fail, "done", "fi"]), [True, False])
        self.assertEqual(bad(["true || { " + fail + "; }"]), [False])
        self.assertEqual(bad(["true && { " + fail + "; }"]), [False])
        self.assertEqual(bad(["[ ! -n x ] && { " + fail + "; }"]), [False])
        self.assertEqual(bad(["if true; then", "! cat x | while read l; do :; done", fail, "fi"]), [False, False])
        self.assertEqual(bad(["if true; then", "cat x | while read l; do", fail, "done", "fi"]), [False, False])
        self.assertEqual(bad(["while read l; do", fail, "done < x"]), [True])
        self.assertEqual(bad(["if true; then", "while read l; do :; done", fail, "fi"]), [False, False])
        for unmatched in (["echo a )"], ["echo a }"], ["done"], ["esac"], ["case x in", "a) : ;;"], ["do : "]):
            with self.assertRaises(AssertionError, msg=unmatched):
                self._groups(unmatched, "t")
        self.assertEqual(bad(['x="$(psql <<\'SQL\'', 'echo ) {', 'SQL', ')" || { echo "FAIL: a" >&2; exit 1; }']), [False, False])
        for text in (
            "; exit() { :; }", "&& cleanup() { :; }", "|| alias x=y", "{ exit() { :; }", "( exit() { :; }", "true | exit() { :; }",
            "if true; then exit() { :; }; fi", "do exit() { :; }", "&& ! exit() { :; }", "else function exit { :; }",
            "elif true; then alias exit=true", "then cleanup() { :; }", "time exit() { :; }", "! exit() { :; }",
            # r13 K1 + S16: after a case pattern paren and after the if, while and until keywords
            "case $x in *) exit() { :; } ;; esac", "case 1 in 1) function exit { :; } ;; esac", "case 1 in 1) alias exit=true ;; esac",
            "if exit() { :; }; then", "while exit() { :; }; do", "until exit() { :; }; do", "if function exit { :; }; then",
            "while alias exit=true; do", "until cleanup() { :; }; do",
        ):
            self.assertTrue(FUNCTION_DEF.search(text) or ALIAS_DEF.search(text), text)
        self.assertFalse(FUNCTION_DEF.search('x="$(date)"') or ALIAS_DEF.search("echo alias_set"))
        self.assertFalse(FUNCTION_DEF.search("echo undo() x") or FUNCTION_DEF.search("*[!a-z0-9_-]*) echo x"))

    # r16 K10: the exact group counts of the groups listing, one constant per number. A script edit that moves
    # one fails with _count_pin_message, which names the script, both numbers, the constant and the remedy.
    SMOKE_GROUPS_EXPECTED = 34
    SMOKE_FAIL_GROUPS_EXPECTED = 15
    SMOKE_FAIL_CALLS_EXPECTED = 0
    ENVELOPE_GROUPS_EXPECTED = 58
    ENVELOPE_FAIL_GROUPS_EXPECTED = 12
    ENVELOPE_FAIL_CALLS_EXPECTED = 4

    @staticmethod
    def _count_pin_message(script, what, measured, pinned, constant):
        return (
            "%s: %s measured %d, pinned %d in %s; if the script edit is intended, update %s in this test in the same "
            "commit and record the new count in the PR body Round section (the pin and the script change in lockstep)"
            % (script, what, measured, pinned, constant, constant)
        )

    def _assert_counts(self, name, out, prefix):
        groups = [(w, g) for w, g in out if g["kind"] != "call"]
        measured = (
            ("group count", len(groups), "GROUPS"),
            ("FAIL-bearing group count", sum(1 for _, g in groups if g["fail"]), "FAIL_GROUPS"),
            ("calls of FAIL-bearing functions", len(out) - len(groups), "FAIL_CALLS"),
        )
        for what, value, suffix in measured:
            constant = "%s_%s_EXPECTED" % (prefix, suffix)
            pinned = getattr(self, constant)
            self.assertEqual(value, pinned, self._count_pin_message(name, what, value, pinned, constant))

    def test_count_pin_message_names_the_constant_selftest(self):
        # r16 K10: a deliberate miscount (one extra FAIL-bearing group, the code r12 legit row c6) fails with a
        # message that names the script, the constant and the lockstep remedy.
        lines = _norm_lines(SMOKE) + ['if true; then :; fi; true || { echo "FAIL: one" >&2; exit 1; }']
        with self.assertRaises(AssertionError) as caught:
            self._assert_counts(SMOKE.name, self._groups(lines, SMOKE.name), "SMOKE")
        text = str(caught.exception)
        groups = [g for _, g in self._groups(lines, SMOKE.name) if g["kind"] != "call"]
        measured = "measured %d, pinned %d" % (len(groups), self.SMOKE_GROUPS_EXPECTED)
        for part in ("smoke-test.sh", "SMOKE_GROUPS_EXPECTED", "lockstep", measured, "PR body Round section"):
            self.assertIn(part, text)
        msg = self._count_pin_message("measure-envelope.sh", "group count", 59, 58, "ENVELOPE_GROUPS_EXPECTED")
        self.assertIn("ENVELOPE_GROUPS_EXPECTED", msg)
        self.assertIn("lockstep", msg)

    def test_real_closers_and_contexts_are_clean_and_the_dotenv_comment_is_true(self):
        # r14 K5 + K6 + INFO: on the real scripts no FAIL-bearing group is followed by `&&` or
        # preceded by a condition word (the groups listing: bad 0), the FAIL-bearing group count floors are
        # pinned, and the compose-pin comment states what compose does with a `.env` next to the file.
        # r15 INFO 3: exact counts (groups, FAIL-bearing groups, calls of FAIL-bearing functions), measured
        # on this head. Smoke 34 / 15 / 0 as in round 14 (psql_pooled holds no FAIL site, so it has no call
        # records). Envelope 58 / 12 / 4: the round-15 worker-status check replaces `wait ... || true` inside
        # the existing `for p ...; do ... done` loop and adds one `|| { echo FAIL ...; exit 1; }` group (57 + 1
        # groups); that group and the enclosing `for conc ...; do ... done` step loop become FAIL-bearing
        # (10 + 2); the 4 calls are `need docker|curl|cargo|python3`, each at statement position.
        # r16 K10: the six numbers are the *_EXPECTED constants above; the failure message names the constant.
        for path, prefix in ((SMOKE, "SMOKE"), (ENVELOPE, "ENVELOPE")):
            out = self._groups(_norm_lines(path), path.name)
            self._assert_counts(path.name, out, prefix)
            for where, g in out:
                self.assertFalse(g["bad"], "%s: %s" % (path.name, where))
                if g["fail"]:
                    self.assertFalse(_context_bad(g["ctx"]), "%s: %s" % (path.name, where))
            comment = " ".join(ln.lstrip("# ").strip() for ln in path.read_text().splitlines() if ln.lstrip().startswith("#"))
            self.assertIn("compose still reads a .env in that directory for interpolation", comment, path.name)
            self.assertIn("the environment outranks .env", comment, path.name)
            self.assertNotIn("a .env that sets COMPOSE_FILE", comment, path.name)

    def test_condition_state_selftest(self):
        # r15 K7: N20-N25 (the review rows) and own rows: a FAIL-bearing group opened anywhere in a
        # condition list (across newlines, `;`, comments, blank lines) is refused; real-shaped conditions,
        # then/do bodies, N6 `fi ;;` and N19 `time {...}` are not; a head without its then/do raises.
        bad = lambda lines: [g["bad"] for _, g in self._groups(lines, "t")]  # noqa: E731
        fail = 'echo "FAIL: a" >&2; exit 1'
        loop = ["cat x | while read l; do", fail, "done"]
        refused = {
            "N20-if-newline": ["if"] + loop + ["then :; fi"],
            "N21-while-newline": ["while"] + loop + ["do break; done"],
            "N22-if-comment": ["if # c"] + loop + ["then :; fi"],
            "N23-if-semicolons": ["if true; cat x | while read l; do " + fail + "; done; then :; fi"],
            "N24-if-true-newline": ["if true"] + loop + ["then :; fi"],
            "N25-elif-newline": ["if false; then :", "elif"] + loop + ["then :; fi"],
            "own-until-newline": ["until"] + loop + ["do break; done"],
            "own-blank-and-comment-lines": ["if true", "", "# note", ""] + loop + ["then :; fi"],
            "own-while-semicolon-comment": ["while true; # c"] + loop + ["do break; done"],
            "own-and-newline": ["if true &&"] + loop + ["then :; fi"],
            "own-brace-group-newline": ["if true", "{ " + fail + "; }", "then :; fi"],
            "own-negation-newline": ["!"] + loop,
            "own-elif-semicolons": ["if false; then :; elif true; cat x | while read l; do " + fail + "; done; then :; fi"],
            "own-nested-if-head": ["while if true", "then " + loop[0], fail, "done; fi; do break; done"],
        }
        for row, lines in refused.items():
            self.assertTrue(any(bad(lines)), "row %s is not refused" % row)
        legit = {
            "real-if-substitution": ['if [ -n "$(docker ps -aq)" ]; then', fail, "fi"],
            "real-while-head": ['while [ "$(date +%s)" -lt "$d" ]; do', ":", "done"],
            "then-on-its-own-line": ["if true", "then", fail, "fi"],
            "do-on-its-own-line": ["while read l", "do", fail, "done"],
            "piped-loop-in-for-body": ["for w in a b; do"] + loop + ["done"],
            "piped-loop-in-then-body": ["if true; then"] + loop + ["fi"],
            "N6-fi-in-case-arm": ["case $x in", "a) if true; then", fail, "fi ;;", "esac"],
            "N19-time-group": ["time { cat x | while read l; do " + fail + "; done; }"],
        }
        for row, lines in legit.items():
            self.assertFalse(any(bad(lines)), "legit row %s is refused" % row)
        for lines in (["then"], ["if true"], ["while true"], ["if true; do :; done"], ["for x in a"], ["elif true; then :"], ["do"]):
            with self.assertRaises(AssertionError, msg=lines):
                self._groups(lines, "t")

    def test_function_call_sites_selftest(self):
        # r15 K8: N26 (a FAIL group in worker(), called with `&` and reaped by `wait ... || true`), N27 (a
        # piped FAIL loop then `:` in psql_pooled(), called as `psql_pooled <<'SQL' || {...}`) and own rows
        # are refused; statement calls, a final `&&` / `||` element, the trap operand and calls of
        # functions without a FAIL site are not.
        fail = 'echo "FAIL: a" >&2; exit 1'
        body = ["f() {", "cat x | while read l; do " + fail + "; done", ":", "}"]
        bad = lambda lines: any(g["bad"] for _, g in self._groups(lines, "t"))  # noqa: E731
        refused = {
            "N26-worker-background": ["worker() {", 'code=""', '[ -n "$code" ] || { ' + fail + "; }", "}", "worker 1 x y &",
                                      "pids+=($!)", 'for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done'],
            "N27-psql-pooled-or-list": ["psql_pooled() {", "cat x | while read l; do " + fail + "; done", ":", "}",
                                        "psql_pooled <<'SQL' || { " + fail + "; }", "SELECT 1;", "SQL"],
            "own-or-true": body + ["f || true"],
            "own-and-list": body + ["f && :"],
            "own-if-head": body + ["if f; then :; fi"],
            "own-while-head-newline": body + ["while", "f", "do break; done"],
            "own-negated": body + ["! f"],
            "own-pipeline-first": body + ["f | cat"],
            "own-pipeline-last": body + ["cat x | f"],
            "own-substitution": body + ['x="$(f)"'],
            "own-quoted-name": body + ['"f" &'],
            "own-escaped-name": body + ["\\f &"],
            "own-transitive": body + ["g() { f; }", "g &"],
            "own-brace-next-line": ["f()", "{", "cat x | while read l; do " + fail + "; done", "}", "f &"],
            "own-function-keyword": ["function f {", "cat x | while read l; do " + fail + "; done", "}", "f &"],
            "own-eval-operand": body + ["eval f"],
            "own-assignment-prefix": body + ["X=1 f &"],
            "own-time-or": body + ["time f || true"],
        }
        for row, lines in refused.items():
            self.assertTrue(bad(lines), "row %s is not refused" % row)
        legit = {
            "statement": body + ["f"],
            "statement-then-more": body + ["f; :"],
            "final-and-element": body + ["true && f"],
            "final-or-element": body + ["true || f"],
            "then-body": body + ["if true; then", "f", "fi"],
            "trap-operand": body + ["trap f EXIT"],
            "redirected": body + ["f >/dev/null 2>&1"],
            "no-fail-site-background": ["g() { :; }", "g &", "wait"],
            "real-need": ["need() { command -v \"$1\" >/dev/null 2>&1 || { echo \"FATAL: '$1' not found on PATH\" >&2; exit 69; }; }",
                          "need docker", "need curl"],
            "real-psql-pooled": ["psql_pooled() {", PSQL_POOLED_DEF, "}", "psql_pooled <<'SQL' || { " + fail + "; }", "SELECT 1;", "SQL"],
            "real-worker": ["worker() {", 'rm -f "$bodyf"', "}", "worker 1 x y &", "worker_rc=0",
                            'for p in "${pids[@]}"; do wait "$p" || worker_rc=$?; done',
                            '[ "$worker_rc" -eq 0 ] || { ' + fail + "; }"],
        }
        for row, lines in legit.items():
            self.assertFalse(bad(lines), "legit row %s is refused" % row)

    def test_wait_sites_reach_a_fail_group(self):
        # r16 K9: the worker-status block is pinned exactly (REAPING_PINS) and every wait in both scripts
        # follows the structural rule (_wait_refusals); wait-site list: measure-envelope.sh:237 only.
        for path in SCRIPTS:
            lines = _norm_lines(path)
            self.assertEqual(_reaping_pin_refusals(path, lines), [], path.name)
            body = "\n".join(ln.strip() for ln in _code_lines(path) if ln.strip())
            self.assertEqual(_wait_refusals(body), [], path.name)
        body = "\n".join(ln.strip() for ln in _code_lines(ENVELOPE) if ln.strip())
        words, _ = _shell_words(body)
        self.assertEqual(sum(1 for k, w in enumerate(words) if w == "wait" and words[k - 1] in WAIT_COMMAND_PREV), 1)

    def test_wait_sites_selftest(self):
        # r16 K9: w1-w7 are the code r12 rows (each GREEN on b5621ab07), applied to the real envelope text;
        # own rows add other spellings. Each is refused by the wait rule or the reaping pin.
        real = ENVELOPE.read_text()
        wait_line = 'for p in "${pids[@]}"; do wait "$p" || worker_rc=$?; done'
        check_line = '[ "$worker_rc" -eq 0 ] || { echo "FAIL: a load worker exited with status $worker_rc at concurrency $conc" >&2; exit 1; }'
        self.assertEqual((real.count(wait_line), real.count(check_line)), (1, 1))
        rows = {
            "w1-or-rc-zero": (wait_line, wait_line.replace("worker_rc=$?", "worker_rc=0")),
            "w2-no-operand": (wait_line, wait_line.replace('wait "$p"', "wait")),
            "w3-reset-after-wait": (wait_line, wait_line + "\n  worker_rc=0"),
            "w4-ge-zero": (check_line, check_line.replace("-eq 0", "-ge 0")),
            "w5-or-colon": (wait_line, wait_line.replace("worker_rc=$?", ":")),
            "w6-or-true-devnull": (wait_line, wait_line.replace('wait "$p" || worker_rc=$?', 'wait "$p" 2>/dev/null || true')),
            "w7-check-true-or": (check_line, "true || " + check_line),
            "own-builtin-wait": (wait_line, wait_line.replace('wait "$p"', 'builtin wait "$p"')),
            "own-quoted-wait-or-true": (wait_line, wait_line.replace('wait "$p" || worker_rc=$?', '"wait" "$p" || true')),
            "own-wait-background": (wait_line, wait_line.replace('wait "$p" || worker_rc=$?', 'wait "$p" &')),
            "own-if-wait": (wait_line, wait_line.replace('wait "$p" || worker_rc=$?', 'if wait "$p"; then :; fi')),
            "own-reset-in-loop": (wait_line, wait_line.replace("do wait", "do worker_rc=0; wait")),
            "own-loop-or-true": (wait_line, wait_line.replace("; done", "; done || true")),
            "own-check-no-exit": (check_line, check_line.replace("; exit 1; }", "; }")),
            "own-check-exit-zero": (check_line, check_line.replace("exit 1", "exit 0")),
            "own-check-ne-zero-if-no-fail": (check_line, 'if [ "$worker_rc" -ne 0 ]; then echo "note" >&2; fi'),
            "own-local-rc-after": (wait_line, wait_line + "\n  local worker_rc"),
            "own-wait-n": (wait_line, wait_line.replace('wait "$p"', 'wait -n "$p"')),
        }
        for row, (old, new) in rows.items():
            text = real.replace(old, new, 1)
            body = "\n".join(ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))
            lines = [" ".join(ln.split()) for ln in re.sub(r"\\\n\s*", " ", body).splitlines() if ln.strip()]
            self.assertTrue(_wait_refusals(body) or _reaping_pin_refusals(ENVELOPE, lines), "row %s is not refused" % row)
            self.assertTrue(_wait_refusals(body), "row %s: the wait rule alone must refuse it" % row)
        legit = {
            "real-lines": "worker_rc=0\nfor p in a; do wait \"$p\" || worker_rc=$?; done\n" + check_line,
            "statement-wait": 'x &\nwait "$!"\necho done',
            "if-ne-check": 'rc=0\nwait "$p" || rc=$?\nif [ "$rc" -ne 0 ]; then\necho "FAIL: worker $rc" >&2\nexit 1\nfi',
            "wait-as-argument": 'echo wait; printf "%s" "please wait"',
            "compose-wait-flag": 'docker compose -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" -p "$PROJECT" up -d --wait',
        }
        for row, text in legit.items():
            self.assertEqual(_wait_refusals(text), [], "legit row %s is refused" % row)
        self.assertEqual(_reaping_pin_refusals(SMOKE, ["wait \"$p\""]), ["a wait in a script with no reaping pin"])

    def test_shell_comment_prepass_selftest(self):
        # r16 K11 / S22: one pre-pass reads comments for every shell reader. A `#` that begins a word starts a
        # comment; inside a word, after a backslash or in quotes it is text; an open quote in code fails closed.
        strip = lambda s: _strip_shell_comments(s)[0]  # noqa: E731
        self.assertEqual(strip("true # it's a note\nx # that's all"), "true\nx")
        for text in ('echo ${x#y}', "echo $#", "echo a#b", "f --flag=#", 'echo "#"', "echo '#'", "echo \\#x", "echo ${#RUN}",
                     "echo $'#'", 'echo "$(echo a#b)"'):
            self.assertEqual(strip(text), text, text)
        self.assertEqual(strip("a;# c\nb"), "a;\nb")
        self.assertEqual(strip("x=$(true # c\n)"), "x=$(true\n)")
        self.assertEqual(strip("cat <<'EOF'\n# body ' kept\nEOF\nz # c"), "cat <<'EOF'\n# body ' kept\nEOF\nz")
        self.assertEqual(strip("case x in\n  a) y ;; # c'\nesac"), "case x in\n  a) y ;;\nesac")
        for text in ("x='", 'x="a', "x=$(a", "cat <<EOF\nno end", 'echo "${x:-\'a\'}"', 'echo "$(echo #)"'):
            self.assertIsNotNone(_strip_shell_comments(text)[1], "fail closed: %r" % text)
        self.assertIsNone(_strip_shell_comments("x=1 # it's\n")[1])
        # the same pre-pass feeds the group scan: a quote in a comment never opens a quote there
        groups = self._groups(['true # it\'s', '{ echo "FAIL: a" >&2; exit 1; }', "x # that's"], "t")
        self.assertEqual([g["bad"] for _, g in groups], [False])

    # r17 K12 / S23: lines that bash runs after a WORD bracket closes; each one ends in `echo RAN`.
    BASH_RUNS_AFTER = (
        ": $(true)#x; echo RAN",
        ": `true`#x; echo RAN",
        ": $((1+1))#x; echo RAN",
        ": <(true)#x; echo RAN",
        ": >(true)#x; echo RAN",
        ": $( $(true) )#y; echo RAN",
        ': `echo ")"`#x; echo RAN',
        ": `true #c` ; echo RAN",
        ": ${x#y}; echo RAN",
        # r18 K13 / S24: a `)` that closes an array assignment, a regex group or an extglob group is inside a word
        "a=(x)#y; echo RAN",  # array-assign-close-hash
        "declare -a a=(x)#y; echo RAN",  # declare-array-close-hash
        "a+=(x)#y; echo RAN",  # append
        "a=($(true))#y; echo RAN",  # a command substitution inside an array
        "[[ x =~ (y)#z ]] || echo RAN",  # regex-group-close-hash
        "[[ x =~ (y|w)#z ]] || echo RAN",  # regex-group-close-hash-or
        "shopt -s extglob\n: @(x)#y; echo RAN",  # extglob-at-close-hash
        "[[ x == @(y)#z ]] || echo RAN",  # extglob-in-cond
        # r18 S24 note: a heredoc opener whose logical line goes on (a continuation, a multi-line string)
        ": <<E \\\nx\n' #\nE\necho RAN",  # heredoc-cont-quote
        ": <<E \"a\nb\"\n' #\nE\necho RAN",  # heredoc-ml-string-quote
        # r18 K14: case and esac in argument position are plain words
        ": $(: case)#x; echo RAN",
        "case esac in y) : ;; esac; : $(true)#x; echo RAN",
        "echo case >/dev/null; : $(true)#x; echo RAN",
        ": esac; : $(true)#x; echo RAN",
        ": $(: case)#x; echo RAN\ncase esac in y) : ;; esac\ncase esac in y) : ;; esac\necho END",
    )
    # and lines where bash reads a comment after an OPERATOR bracket closes or after a blank
    BASH_COMMENT_AFTER = (
        "(true)#c; echo RAN",
        "(true) #c; echo RAN",
        "((1))#c; echo RAN",
        "case a in a)#c; echo RAN\n;; esac",
        "case a in a) #c; echo RAN\n;; esac",  # r18: the legit comment rows
        "a=(x) #c; echo RAN",
        "{ (true)#c; echo RAN\n}",
        "if true; then (true)#c; echo RAN\nfi",
    )
    # r18: a comment inside an array assignment is a comment (bash runs the line after it)
    BASH_RUNS_AFTER_COMMENT = ("a=(x #c\n); echo RAN",)

    def test_shell_comment_prepass_bracket_selftest(self):
        # r17 K12 / S23: a `)` that closes $( $(( <( >( and a closing backquote never begin a word, so a `#`
        # right after one is text and the rest of the line stays code; a `)` that closes a plain subshell, an
        # arithmetic command or a case pattern does begin one. Inside a backquote pair `#` is text.
        strip = lambda s: _strip_shell_comments(s)[0]  # noqa: E731
        for text in self.BASH_RUNS_AFTER:
            self.assertEqual(strip(text), text, text)
        for text in ("x=$(true)#x", "x=`true`#x", "x=$((1+1))#x", "cat <(true)#x", "tee >(true)#x", "x=$( $(true) )#y",
                     'x=`echo ")"`#x', "echo $((16#ff))", "for ((i=0; i<1; i++)); do :; done"):
            self.assertEqual(strip(text), text, text)
        self.assertEqual(strip("(true)#c; echo RAN"), "(true)")
        self.assertEqual(strip("(true) #c; echo RAN"), "(true)")
        self.assertEqual(strip("((1))#c; echo RAN"), "((1))")
        self.assertEqual(strip("case a in a)#c; echo RAN\n;; esac"), "case a in a)\n;; esac")
        self.assertEqual(strip("x=$(( $(date +%s) + 3 )) # c"), "x=$(( $(date +%s) + 3 ))")
        self.assertEqual(strip("read -r a < <(cat x) # c"), "read -r a < <(cat x)")
        self.assertEqual(strip("x=`echo #` # c"), "x=`echo #`")
        for text in (": `true", ": $((1) )", ": `true`#x `"):
            self.assertIsNotNone(_strip_shell_comments(text)[1], "fail closed: %r" % text)
        # r18 K13: array, regex and extglob closes are WORD closes; a blank before `#` still starts a comment
        self.assertEqual(strip("a=(x)#y; echo RAN"), "a=(x)#y; echo RAN")
        self.assertEqual(strip("a=(x) #c; echo RAN"), "a=(x)")
        self.assertEqual(strip("a=(x #c\n); echo RAN"), "a=(x\n); echo RAN")
        self.assertEqual(strip("[[ x =~ (y)#z ]] || echo RAN # c"), "[[ x =~ (y)#z ]] || echo RAN")
        self.assertEqual(strip("case a in a) #c; echo RAN\n;; esac"), "case a in a)\n;; esac")
        # a compose call or a daemon selection after a closing WORD bracket is read by the pin readers
        pin = "docker compose" + PINNED_COMPOSE_ARGS + '-p "$PROJECT"'
        decoy = pin + " -\\f ./decoy.yml up -d --wait"
        rows = [": $(true)#x; " + decoy, ": `true`#x; " + decoy, ": `true #a`; " + decoy, ": $((1))#x; " + decoy,
                "n=$((0))#c " + decoy, "X=`true`#c " + decoy, "X=$(true)#c " + decoy, ": <(true)#x; " + decoy,
                ": >(true)#x; " + decoy, ": $( $(true) )#y; " + decoy, ': `echo ")"`#x; ' + decoy,
                ": $((1))#x; " + pin + " --project-director\\y /x up -d --wait",
                ": $((1))#x; " + pin + " --fi\\le=./decoy.yml up -d --wait",
                ": `true`#x; export D\"\"OCKER_HOST=tcp://127.0.0.1:2399", ': `true`#x; docker con""text use x',
                # r18 K13 / S24: one decoy row per WORD bracket kind the round-17 pass read as a subshell
                "_r=(x)#y; " + decoy, "_r+=(x)#y; " + decoy, "declare -a _r=(x)#y; " + decoy, "_r=($(true))#y; " + decoy,
                "[[ x =~ (y)#z ]] || " + decoy, "[[ x =~ (y|w)#z ]] || " + decoy, "[[ x == @(y)#z ]] || " + decoy,
                "shopt -s extglob\n: @(x)#y; " + decoy,
                "_r=(x)#y; " + pin + " --project-director\\y /x up -d --wait", "_r=(x)#y; " + pin + " --fi\\le=./decoy.yml up -d --wait",
                # r18 S24 note: heredoc openers whose logical line goes on; r18 K14: case words in argument position
                ": <<E \\\nx\n' #\nE\n" + decoy, ": <<E \"a\nb\"\n' #\nE\n" + decoy,
                ": $(: case)#x; " + decoy, "case esac in y) : ;; esac; : $(true)#x; " + decoy, "echo case; : $(true)#x; " + decoy]
        for row in rows:
            self.assertTrue(_compose_pin_refusals(row) or _daemon_selection_refusals(row), row)
        self.assertEqual(_compose_pin_refusals("(true) #c " + decoy), [])
        self.assertEqual(_compose_pin_refusals("_r=(x) #c " + decoy), [])

    def test_shell_comment_prepass_case_fail_closed_selftest_8270_r18(self):
        # r18 K14: an esac keyword with no open case arm, a `)` an open case cannot place, an unmatched `)`
        # and an unterminated case fail closed
        for text in ("esac", ": x)", "case x in a) : ) ;; esac", "case x in a) :", "case x )", "(true))"):
            self.assertIsNotNone(_strip_shell_comments(text)[1], "fail closed: %r" % text)

    def test_shell_comment_prepass_problem_line_col_selftest_8270_r18(self):
        # r18 K15: a problem names the script, the 1-based line and the 1-based column of the offending character
        self.assertEqual(_strip_shell_comments("true\n: `x\n", "smoke-test.sh")[1],
                         "smoke-test.sh: line 2 col 3: a quote, backquote, substitution, bracket or case left open at the end of the text (`)")
        self.assertEqual(_strip_shell_comments("a\nb; c)\n", "smoke-test.sh")[1], "smoke-test.sh: line 2 col 5: an unmatched )")

    def test_shell_comment_prepass_agrees_with_bash(self):
        # r17 K12 / S23: the pre-pass keeps `echo RAN` exactly when bash runs it (rows are inert: `:`, true, echo)
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash not installed")
        # r18: this test is the contract of the rule block above _strip_shell_comments; a fail-closed problem
        # on a row counts as not keeping `echo RAN`
        for text in self.BASH_RUNS_AFTER + self.BASH_COMMENT_AFTER + self.BASH_RUNS_AFTER_COMMENT:
            run = subprocess.run([bash, "--norc", "--noprofile", "-c", text], capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual("echo RAN" in (_strip_shell_comments(text)[0] or ""), "RAN" in run.stdout, text)

    def test_declarations_do_not_read_their_own_names(self):
        # r15: `local out="$2" bodyf="${out}.body"` expanded "${out}" before `local` assigned it; under
        # set -u every envelope worker exited at its first line, and the old `wait ... || true` hid it.
        for path in (SMOKE, ENVELOPE):
            self.assertEqual(_self_referencing_declarations(_norm_lines(path)), [], path.name)
        check = _self_referencing_declarations
        self.assertEqual(check(['  local a="$1" b="${a}.x"']), [(1, "a")])
        self.assertEqual(check(["  local a=1 b=$a"]), [(1, "a")])
        self.assertEqual(check(['  export A="x" B="$A"; echo']), [(1, "A")])
        self.assertEqual(check(['  declare -r a=1 b="${a:-2}"']), [(1, "a")])
        self.assertEqual(check(['  local a="$1"', '  local b="${a}.x"']), [])
        self.assertEqual(check(['  local a="$b" b=1']), [])
        self.assertEqual(check(["  local a='unclosed"]), [(1, "unparsable")])

    def test_function_bodies_are_pinned_whole(self):
        # r15 K8: the whole body of psql_pooled (smoke) and of worker, need and now_ms (envelope), as
        # _norm_lines reads them (cleanup is pinned by CLEANUP_BODY); a FAIL site, a swallowed status or a
        # changed return cannot enter a function body without changing this pin.
        for path, bodies in FUNCTION_BODIES.items():
            lines = _norm_lines(path)
            for fname, expected in bodies.items():
                starts = [k for k, ln in enumerate(lines) if ln.startswith("%s() {" % fname)]
                self.assertEqual(len(starts), 1, "%s: one %s() definition" % (path.name, fname))
                k = starts[0]
                end = k if lines[k].endswith("}") else lines.index("}", k)
                self.assertEqual(tuple(lines[k : end + 1]), expected, "%s: %s() body differs from FUNCTION_BODIES" % (path.name, fname))
        self.assertEqual({p: sorted(b) for p, b in FUNCTION_BODIES.items()}, {SMOKE: ["psql_pooled"], ENVELOPE: ["need", "now_ms", "worker"]})

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

    def test_headers_list_exactly_the_exit_codes_used(self):
        # r11 Q13 + r12 N6: one header row per code, in BOTH scripts: 0 plus every `exit N` on a
        # code line plus 1 when a code line assigns `rc=1` (the teardown status cleanup() exits with).
        for path in SCRIPTS:
            code = _code_lines(path)
            used = {int(c) for ln in code for c in re.findall(r"(?<![\w-])exit\s+(\d+)", ln)}
            if any(re.search(r"(?<![\w-])rc=1(?![\w-])", ln) for ln in code):
                used.add(1)
            header = [ln for ln in path.read_text().splitlines()[:50] if ln.startswith("#")]
            rows = [int(m.group(1)) for m in (re.match(r"^#\s{2,}(\d+)\s{2,}\S", ln) for ln in header) if m]
            self.assertEqual(rows, sorted(set(rows)), "%s: the header rows must be unique and ascending" % path.name)
            self.assertEqual(set(rows), used | {0}, "%s: header exit table differs from the exit codes the script uses" % path.name)

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
