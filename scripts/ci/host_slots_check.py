#!/usr/bin/env python3
"""Check the host-slot configuration against itself and the workflow files (#9231).

The slot configuration (scripts/ci/host_slots.json) lists every registered self-hosted
runner, names every host semaphore gate, its slot count and the runners that serve a leg
gated by it. Rules:

* the configuration is well typed (one error line, never a traceback, on a malformed file);
* serving runners are registered runners, none listed twice, and never exceed the slot count,
  so a job that holds a runner always finds a slot and never idles in the semaphore wait;
* every occurrence of the token host_semaphore (any case) in every file under .github is either a
  fully classified call or a finding with its reason (an allowlist, fail closed by construction).
  A fully classified call is `python3 [no-argument flags] scripts/ci/host_semaphore.py` with the
  literal path, exactly one literal configured `--name` in any position and exactly one
  `--max-wait-secs` before the ` -- ` of the wrapped command, whose value is a plain decimal within
  the ceiling or the plain read of HOST_SEMAPHORE_MAX_WAIT_SECS. Each call on a line is checked on
  its own; comments are stripped before the flags are parsed. The only other admitted sites are the
  HOST_SEMAPHORE_* environment names in ENV_NAMES and the prose comment lines in COMMENT_SITES, each
  with its reason. Every configured gate is called;
* HOST_SEMAPHORE_MAX_WAIT_SECS has exactly one definition across the workflows and composite
  actions, parsed with the YAML subset parser of scripts/ci/taint_boundary.py, and is a plain
  decimal (PLAIN_DECIMAL_PATTERN of scripts/ci/host_slot_limits.py) from 1 to IDLE_SEAT_CEILING_SECS,
  the values host_semaphore.py also accepts at run time;
* in the run text of those files HOST_SEMAPHORE_MAX_WAIT_SECS appears only as its env mapping key or as
  a plain `$KEY` / `${KEY}` read: any other use (an assignment, export, declare, read, `${KEY:=v}`, an env
  prefix, an expression read) is refused, so the one parsed definition is the only value;
* the slot count of the gated leg in ci.yml equals the configured slots.

CI runs it inside the existing "Shard partition and wiring unit tests (#6344)" step: the #9231 unit
tests execute this script on the repository (a failing script is a red test).

Usage: python3 -I scripts/ci/host_slots_check.py
Exit 0 when everything holds, 1 with one line per violation, 2 on a malformed configuration.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import taint_boundary  # noqa: E402  (the repository's own YAML subset parser)
# the one ceiling and the one wait grammar, shared with host_semaphore.py
from host_slot_limits import IDLE_SEAT_CEILING_SECS, PLAIN_DECIMAL_PATTERN  # noqa: E402

REPO = HERE.parents[1]
CONFIG_PATH = HERE / 'host_slots.json'
GITHUB_DIR = REPO / '.github'
WAIT_KEY = 'HOST_SEMAPHORE_MAX_WAIT_SECS'
SLOTS_KEY = 'HOST_SEMAPHORE_SLOTS'
MAX_SLOTS = 64
GATE_NAME_RE = re.compile(r'[A-Za-z0-9_-]+')  # used with fullmatch: no trailing newline slips through
PLAIN_DECIMAL_RE = re.compile(PLAIN_DECIMAL_PATTERN)  # used with fullmatch, exactly as the wrapper does
SHOWN_VALUE_MAX = 64  # a refused value is shown cut to this many characters
# decision: an allowlist of token sites over a list of forbidden call spellings, because a list of forbidden
# forms is never complete (`-m`, a variable or split path, a glob, a second call after `;`); every site that is
# not a fully classified call is a finding by construction (#9231 F1).
TOKEN_RE = re.compile(r'host_semaphore', re.IGNORECASE)  # IGNORECASE: a macOS runner opens HOST_SEMAPHORE.PY too
# The environment names of the gated leg: each holds the token but names no script.
ENV_NAMES = ('HOST_SEMAPHORE_SLOTS', 'HOST_SEMAPHORE_MAX_WAIT_SECS', 'HOST_SEMAPHORE_HELD')
ENV_NAME_RE = re.compile(r'(?<![A-Za-z0-9_])(?:%s)(?![A-Za-z0-9_])' % '|'.join(ENV_NAMES))
ENV_LIKE_RE = re.compile(r'HOST_SEMAPHORE_[A-Za-z0-9_]*', re.IGNORECASE)
# {(file under .github, comment line stripped): reason} - prose comments that hold the token and run nothing.
COMMENT_SITES = {
    ('workflows/ci.yml', '# scripts/ci/host_semaphore.py) admits 2 compile+test phases at'):
        'prose: the slot budget comment of the linux-fed leg (#7914)',
    ('workflows/ci.yml', '# re-run this very script under host_semaphore.py (the slot is held'):
        'prose: the comment above the one call of the linux-fed leg (#7914)',
}
SCRIPT_PATH = 'scripts/ci/host_semaphore.py'
# Python options that take no argument; -c, -m, -W and -X take one, so a call with them is not classified.
CALL_RE = re.compile(r'(?<![^\s;&|(])python3(?:\s+-[bBdEiIOPqRsSuvx]+)*\s+(?:\./)?'
                     + re.escape(SCRIPT_PATH) + r'(?=[\s;&|)]|$)')
# The wrapper's own arguments end at its ` -- `, at a shell separator or at the next call on the line.
SEGMENT_END_RE = re.compile(r'\s--(?=\s|$)|[;&|)`]')
NAME_FLAG_RE = re.compile(r'(?:^|\s)--name(?:=|\s+)(\S+)')
MAX_WAIT_FLAG_RE = re.compile(r'(?:^|\s)--max-wait-secs(?:=|\s+|$)(\S*)')
# #9847: the only flags a workflow call of the wrapper may give (--config and --root steer it off the checked
# configuration and lock root); --slots must be the one bounded read of SLOTS_KEY
FLAG_NAME = '--name'
FLAG_MAX_WAIT = '--max-wait-secs'
FLAG_SLOTS = '--slots'
FLAG_LABEL = '--label'
FLAG_POLL = '--poll-secs'
CALL_FLAGS = (FLAG_NAME, FLAG_MAX_WAIT, FLAG_SLOTS, FLAG_LABEL, FLAG_POLL)
SLOTS_READ = '"$%s"' % SLOTS_KEY
WAIT_KEY_READS = ('$%s' % WAIT_KEY, '${%s}' % WAIT_KEY, '"$%s"' % WAIT_KEY, '"${%s}"' % WAIT_KEY)
QUOTE_CHARS = '\'"\\'
# decision: an allowlist of the env mapping key and a plain $ / ${} read over a list of forbidden assignment
# forms, because shell has open-ended ways to write a variable (export, declare, readonly, local, read,
# printf -v, ${:=}, eval, env X=) and an allowlist fails closed on each (#9231 R2-C).
WAIT_KEY_USE_RE = re.compile(r'(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])' % WAIT_KEY)
WAIT_KEY_MAPPING_RE = re.compile(r'\s*%s\s*:' % WAIT_KEY)
SLOTS_EXPR_RE = re.compile(r"&& '(%s)' \|\| '0'" % PLAIN_DECIMAL_PATTERN)
EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_MALFORMED = 2

# Findings of the token scan, one exact reason per form (the file is the first %s).
F_NOT_A_CALL = '%s: a host_semaphore.py reference that is not a python3 call'
F_MODULE = '%s: host_semaphore run as a module (-m); call the literal path scripts/ci/host_semaphore.py'
F_VARIABLE = '%s: a host_semaphore path built from a variable or a substitution'
F_GLOB = '%s: a host_semaphore path with a glob character'
F_SPLIT = '%s: a host_semaphore path split by a quote or a backslash'
F_ENV_NAME = '%s: %s is not a listed HOST_SEMAPHORE_ environment name'
F_COMMENT = '%s: a host_semaphore reference in a comment that is not a listed comment site'
F_NOT_TEXT = '%s: not UTF-8 text, so the host_semaphore token scan cannot read it'
F_NO_NAME = '%s: a host_semaphore.py call without exactly one literal --name'
F_UNCONFIGURED = '%s: calls the unconfigured gate %s'
F_NO_WAIT = '%s: a host_semaphore.py call without exactly one --max-wait-secs'
F_WAIT_NOT_LITERAL = ('%s: a host_semaphore.py call whose --max-wait-secs is neither a literal nor a plain read of '
                      + WAIT_KEY)
F_WAIT_VALUE = '%s: a host_semaphore.py call whose --max-wait-secs %s'
F_NEVER_CALLED = '%s: configured but no workflow calls it'
F_UNKNOWN_FLAG = '%s: a host_semaphore.py call with the flag %s, which is not one of ' + ', '.join(CALL_FLAGS)
F_FLAG_QUOTED = '%s: a host_semaphore.py call with a flag spelled with a quote or a backslash'
F_SLOTS_VALUE = '%s: a host_semaphore.py call whose --slots is not ' + SLOTS_READ
F_POLL_VALUE = '%s: a host_semaphore.py call whose --poll-secs is not a plain decimal integer'
F_FLAG_NO_VALUE = '%s: a host_semaphore.py call whose %s has no value'
F_POSITIONAL = ('%s: a host_semaphore.py call with a word before its -- that is neither a wrapper flag nor its '
                'value (the wrapper would run it as the command)')


class ConfigError(Exception):
    """The slot configuration is malformed; the message is the one error line."""


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _string_list(value, where):
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConfigError('%s must be a list of non-empty strings' % where)
    return value


def load_config(path=CONFIG_PATH):
    """The parsed, type and range checked configuration; ConfigError with one line otherwise."""
    try:
        cfg = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ConfigError('%s is unreadable or not JSON (%s)' % (Path(path).name, type(exc).__name__))
    if not isinstance(cfg, dict):
        raise ConfigError('top level must be an object')
    _string_list(cfg.get('registered_runners'), 'registered_runners')
    gates = cfg.get('gates')
    if not isinstance(gates, dict) or not gates:
        raise ConfigError('gates must be a non-empty object')
    for name, gate in gates.items():
        if not GATE_NAME_RE.fullmatch(name):
            raise ConfigError('gate name %r is not a plain name' % name)
        if not isinstance(gate, dict):
            raise ConfigError('gate %s must be an object' % name)
        if not _is_int(gate.get('slots')) or not 1 <= gate['slots'] <= MAX_SLOTS:
            raise ConfigError('gate %s: slots must be an integer from 1 to %d' % (name, MAX_SLOTS))
        if not isinstance(gate.get('label'), str) or not gate['label']:
            raise ConfigError('gate %s: label must be a non-empty string' % name)
        _string_list(gate.get('serving_runners'), 'gate %s: serving_runners' % name)
    return cfg


def config_violations(cfg):
    """One line per gate whose serving runners exceed its slots, repeat, or are not registered."""
    found = []
    registered = cfg['registered_runners']
    if len(set(registered)) != len(registered):
        found.append('registered_runners: a runner is listed twice')
    for name, gate in sorted(cfg['gates'].items()):
        runners = gate['serving_runners']
        if len(set(runners)) != len(runners):
            found.append('%s: a serving runner is listed twice' % name)
        for runner in runners:
            if runner not in registered:
                found.append('%s: serving runner %s is not a registered runner' % (name, runner))
        if len(runners) > gate['slots']:
            found.append('%s: %d serving runners for %d slots' % (name, len(runners), gate['slots']))
    return found


def wait_value_finding(value):
    """Why VALUE is not an accepted wait (the reason, starting with 'is'), or None; the wrapper's grammar."""
    if not isinstance(value, str) or not PLAIN_DECIMAL_RE.fullmatch(value):
        return 'is not a plain decimal integer'
    if value == '0':
        return 'is 0; the wait is at least 1 s'
    # the length first: a huge digit string is above the ceiling without converting it
    if len(value) > len(str(IDLE_SEAT_CEILING_SECS)) or int(value) > IDLE_SEAT_CEILING_SECS:
        return 'is above the %d s idle seat ceiling' % IDLE_SEAT_CEILING_SECS
    return None


def _shown(value):
    """repr(VALUE), cut to SHOWN_VALUE_MAX characters so a huge value never floods the output."""
    text = repr(value)
    return text if len(text) <= SHOWN_VALUE_MAX else text[:SHOWN_VALUE_MAX] + '...'


def _code_lines(text):
    """The text with comment-only lines blanked and shell line continuations joined."""
    lines = [('' if line.lstrip().startswith('#') else line) for line in text.splitlines()]
    return re.sub(r'\\\n', ' ', '\n'.join(lines)).splitlines()


def _comment_start(line):
    """The index where the shell or YAML comment of LINE starts (an unquoted # at a word start), or len(LINE)."""
    quote = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif quote == "'":
            if char == "'":
                quote = None
        elif char == '\\':
            escaped = True
        elif quote == '"':
            if char == '"':
                quote = None
        elif char in '\'"':
            quote = char
        elif char == '#' and (index == 0 or line[index - 1].isspace()):
            return index
    return len(line)


def _quoted_mask(text):
    """For each index of TEXT: True when that character lies inside a quoted span or follows a backslash.

    One linear pass, so checking every flag of a segment stays linear in its length."""
    mask = []
    quote = None
    escaped = False
    for char in text:
        mask.append(quote is not None or escaped)
        if escaped:
            escaped = False
        elif quote == "'":
            if char == "'":
                quote = None
        elif char == '\\':
            escaped = True
        elif quote == '"':
            if char == '"':
                quote = None
        elif char in '\'"':
            quote = char
    return mask


def _dequoted(word):
    return ''.join(char for char in word if char not in QUOTE_CHARS)


def _token_count(word):
    """Occurrences of the token in WORD once quotes and backslashes are removed, the listed env names left out."""
    plain = _dequoted(word)
    return len(TOKEN_RE.findall(plain)) - len(ENV_NAME_RE.findall(plain))


def _site_reason(wf, word, previous, in_comment):
    """The exact finding for a token site in WORD that is not a classified call."""
    if in_comment:
        return F_COMMENT % wf
    if previous == '-m' or word.startswith('-m'):
        return F_MODULE % wf
    # #9844 D3: a word whose only token sites are unlisted HOST_SEMAPHORE_ names (a `$HOST_SEMAPHORE_X` read) is
    # named as such; a word that also holds the token outside those names keeps the path reasons below
    plain = _dequoted(word)
    unlisted = [env_like.group(0) for env_like in ENV_LIKE_RE.finditer(plain) if env_like.group(0) not in ENV_NAMES]
    if unlisted and not TOKEN_RE.search(ENV_LIKE_RE.sub(' ', plain)):
        return F_ENV_NAME % (wf, unlisted[0][:SHOWN_VALUE_MAX])
    if '$' in word or '`' in word:
        return F_VARIABLE % wf
    if any(char in word for char in '*?['):
        return F_GLOB % wf
    if any(char in word for char in QUOTE_CHARS):
        return F_SPLIT % wf
    for env_like in ENV_LIKE_RE.finditer(_dequoted(word)):
        if env_like.group(0) not in ENV_NAMES:
            return F_ENV_NAME % (wf, env_like.group(0)[:SHOWN_VALUE_MAX])
    return F_NOT_A_CALL % wf


def _shell_words(segment, quoted):
    """(start, word) for each word of SEGMENT: a run of characters that holds no unquoted, unescaped blank."""
    words = []
    start = None
    for index, char in enumerate(segment):
        if char.isspace() and not quoted[index]:
            if start is not None:
                words.append((start, segment[start:index]))
                start = None
        elif start is None:
            start = index
    if start is not None:
        words.append((start, segment[start:]))
    return words


def _flag_findings(wf, segment, quoted):
    """#9847: every word of SEGMENT is one of the five wrapper flags, its value, or a finding.

    decision: an allowlist of the flags a workflow call may give over a list of the dangerous ones (--config,
    --root), because every other flag or word steers the wrapper outside what this checker proves: an unknown flag
    or one argparse refuses, a --slots other than the one bounded read, or a stray word that argparse takes as the
    start of the wrapped command, which would swallow every flag after it."""
    found = []
    words = _shell_words(segment, quoted)
    index = 0
    while index < len(words):
        start, word = words[index]
        index += 1
        if quoted[start] or not word.startswith('-'):
            found.append(F_POSITIONAL % wf)
            continue
        flag, joined, value = word.partition('=')
        if any(char in flag for char in QUOTE_CHARS):
            found.append(F_FLAG_QUOTED % wf)
        elif flag not in CALL_FLAGS:
            found.append(F_UNKNOWN_FLAG % (wf, flag[:SHOWN_VALUE_MAX]))
        if not joined:
            value = None
            if index < len(words) and not _word_is_flag(words[index], quoted):
                value = words[index][1]
                index += 1
        if flag in (FLAG_NAME, FLAG_MAX_WAIT) or flag not in CALL_FLAGS:
            continue  # --name and --max-wait-secs have their own findings; an unknown flag is already one
        if value is None:
            found.append(F_FLAG_NO_VALUE % (wf, flag))
        elif flag == FLAG_SLOTS:
            if value != SLOTS_READ:
                found.append(F_SLOTS_VALUE % wf)
        elif flag == FLAG_POLL:
            if not PLAIN_DECIMAL_RE.fullmatch(value):
                found.append(F_POLL_VALUE % wf)
    return found


def _word_is_flag(item, quoted):
    """True when the word ITEM = (start, word) starts with an unquoted --, so it is never taken as a value.

    decision: only -- marks a flag here over any leading -, because a value such as -5 is one argparse takes as
    the value (and the wait check names it), while a --word after a flag is the next flag."""
    start, word = item
    return not quoted[start] and word.startswith('--')


def _call_findings(wf, cfg, segment, called):
    """The findings of one classified call whose own arguments are SEGMENT."""
    # a flag spelled inside a quoted argument (`--label "--name x"`) is text the shell passes as one word, not a flag
    quoted = _quoted_mask(segment)
    return _name_wait_findings(wf, cfg, segment, called, quoted) + _flag_findings(wf, segment, quoted)


def _name_wait_findings(wf, cfg, segment, called, quoted):
    """The --name and --max-wait-secs findings of one classified call."""
    names = [match.group(1) for match in NAME_FLAG_RE.finditer(segment) if not quoted[match.start(1) - 1]]
    if len(names) != 1 or not GATE_NAME_RE.fullmatch(names[0]):
        return [F_NO_NAME % wf]
    found = []
    called.add(names[0])
    if names[0] not in cfg['gates']:
        found.append(F_UNCONFIGURED % (wf, names[0]))
    waits = [match for match in MAX_WAIT_FLAG_RE.finditer(segment) if not quoted[match.start(1) - 1]]
    if len(waits) != 1:
        found.append(F_NO_WAIT % wf)
        return found
    value = waits[0].group(1)
    if value in WAIT_KEY_READS:
        return found  # the one parsed definition, bounded by bound_violations
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '\'"':
        value = value[1:-1]
    if any(char in value for char in '$`*?[\'"\\'):
        found.append(F_WAIT_NOT_LITERAL % wf)
    else:
        problem = wait_value_finding(value)
        if problem:
            found.append(F_WAIT_VALUE % (wf, problem))
    return found


def _line_findings(wf, cfg, line, called):
    """The findings of one logical line: each call checked on its own, each other token site a finding."""
    code_end = 0 if line.lstrip().startswith('#') else _comment_start(line)
    code = line[:code_end]
    calls = list(CALL_RE.finditer(code))
    found = []
    path_starts = set()
    for number, call in enumerate(calls):
        path_starts.add(code.index('scripts/', call.start()) - (2 if code[:call.end()].endswith(
            './' + SCRIPT_PATH) else 0))
        stop = calls[number + 1].start() if number + 1 < len(calls) else len(code)
        rest = code[call.end():stop]
        # #9844 D1: a ;, --, ) or backtick inside quotes or after a backslash is text of one word, not the end
        rest_quoted = _quoted_mask(rest)
        end = next((match for match in SEGMENT_END_RE.finditer(rest) if not rest_quoted[match.start()]), None)
        found.extend(_call_findings(wf, cfg, rest[:end.start()] if end else rest, called))
    listed = (wf, line.strip()) in COMMENT_SITES and code_end == 0
    previous = ''
    for match in re.finditer(r'\S+', line):
        word = match.group(0)
        count = _token_count(word)
        if match.start() in path_starts:
            count -= 1
        if count > 0 and not listed:
            found.extend([_site_reason(wf, word, previous, match.start() >= code_end)] * count)
        previous = word
    return found


def call_site_violations(cfg, workflow_texts):
    """Every token site that is not a classified call, every finding of a call, and every gate never called."""
    called = set()
    found = []
    for wf, text in sorted(workflow_texts.items()):
        if text is None:
            found.append(F_NOT_TEXT % wf)
            continue
        # a backslash-newline joins two lines into one shell line; comments stay, so a token there still counts
        for line in re.sub(r'\\\n', '', text).splitlines():
            if TOKEN_RE.search(_dequoted(line)):
                found.extend(_line_findings(wf, cfg, line, called))
    for name in sorted(set(cfg['gates']) - called):
        found.append(F_NEVER_CALLED % name)
    return found


def _allowed_wait_key_use(line, start, end):
    """True when the key at LINE[START:END] is the env mapping key or a plain $KEY / ${KEY} read."""
    if start == len(line) - len(line.lstrip()) and WAIT_KEY_MAPPING_RE.match(line):
        return True
    if line[start - 1:start] == '$' and (start < 2 or line[start - 2] != '$'):
        return True
    return line[max(0, start - 2):start] == '${' and line[end:end + 1] == '}'


def wait_key_violations(texts):
    """One line per use of the wait key in run text that is neither its env mapping key nor a plain read."""
    found = []
    for rel, text in sorted(texts.items()):
        for line in _code_lines(text):
            for use in WAIT_KEY_USE_RE.finditer(line):
                if not _allowed_wait_key_use(line, use.start(), use.end()):
                    found.append('%s: %s is used other than as its env mapping key or a plain $ read; '
                                 'set it only in the one env mapping' % (rel, WAIT_KEY))
    return found


def _env_definitions(node, key, out):
    """Every value of KEY found in any `env` mapping of the parsed YAML document NODE."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == 'env' and isinstance(v, dict) and key in v:
                out.append(v[key])
            _env_definitions(v, key, out)
    elif isinstance(node, list):
        for item in node:
            _env_definitions(item, key, out)


def parsed_env_values(workflow_texts, key):
    """[(file, value)] of every definition of KEY in the workflows, parsed (comments and quoting ignored)."""
    found = []
    for wf, text in sorted(workflow_texts.items()):
        values = []
        _env_definitions(taint_boundary.parse_yaml(text, wf), key, values)
        found.extend((wf, value) for value in values)
    return found


def bound_violations(cfg, workflow_texts):
    """The wait bound is defined once and is an accepted wait (the wrapper's grammar); slots match the config."""
    found = []
    waits = parsed_env_values(workflow_texts, WAIT_KEY)
    if len(waits) != 1:
        found.append('%s must be defined exactly once, found %d' % (WAIT_KEY, len(waits)))
    for wf, value in waits:
        if _is_int(value):  # a bare 600 is an integer scalar for the parser; quoting must not matter
            value = str(value)
        problem = wait_value_finding(value)
        if problem == 'is not a plain decimal integer':
            found.append('%s: %s is not a plain integer (%s)' % (wf, WAIT_KEY, _shown(value)))
        elif problem and problem.startswith('is above'):
            shown = value if len(value) <= SHOWN_VALUE_MAX else value[:SHOWN_VALUE_MAX] + '...'
            found.append('%s: %s %s %s' % (wf, WAIT_KEY, shown, problem))
        elif problem:
            found.append('%s: %s %s' % (wf, WAIT_KEY, problem))
    slots = parsed_env_values(workflow_texts, SLOTS_KEY)
    configured = {gate['slots'] for gate in cfg['gates'].values()}
    for wf, value in slots:
        match = SLOTS_EXPR_RE.search(value) if isinstance(value, str) else None
        count = match.group(1) if match else ''
        if not count or len(count) > len(str(MAX_SLOTS)) or int(count) not in configured:
            found.append('%s: %s %s matches no configured slot count %s'
                         % (wf, SLOTS_KEY, _shown(value), sorted(configured)))
    if not slots:
        found.append('%s is defined nowhere' % SLOTS_KEY)
    return found


def github_texts(github_dir=GITHUB_DIR):
    """{relative path: text} of every .yml and .yaml file under .github (workflows and composite actions)."""
    paths = sorted(p for pattern in ('*.yml', '*.yaml') for p in github_dir.rglob(pattern))
    return {str(p.relative_to(github_dir)): p.read_text(encoding='utf-8') for p in paths}


def github_all_texts(github_dir=GITHUB_DIR):
    """{relative path: text, or None when not UTF-8} of every file under .github: the token scan reads them all."""
    found = {}
    for path in sorted(p for p in github_dir.rglob('*') if p.is_file()):
        try:
            found[path.relative_to(github_dir).as_posix()] = path.read_bytes().decode('utf-8')
        except UnicodeDecodeError:
            found[path.relative_to(github_dir).as_posix()] = None
    return found


def main():
    try:
        cfg = load_config()
        texts = github_texts()
        # every .github text, composite actions included: a definition there counts and is bounded too
        problems = (config_violations(cfg) + call_site_violations(cfg, github_all_texts())
                    + bound_violations(cfg, texts) + wait_key_violations(texts))
    except (ConfigError, taint_boundary.YamlError) as exc:
        print('host_slots_check: malformed: %s' % exc)
        return EXIT_MALFORMED
    for line in problems:
        print('host_slots_check: %s' % line)
    return EXIT_VIOLATION if problems else EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
