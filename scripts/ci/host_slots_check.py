#!/usr/bin/env python3
"""Check the host-slot configuration against itself and the workflow files (#9231, #9851).

The slot configuration (scripts/ci/host_slots.json) lists every registered self-hosted
runner, names every host semaphore gate, its slot count and the runners that serve a leg
gated by it. Rules:

* the configuration is well typed and gives no key twice in one object (one error line, never a
  traceback, on a malformed file);
* serving runners are registered runners, none listed twice, and never exceed the slot count,
  so a job that holds a runner always finds a slot and never idles in the semaphore wait;
* every occurrence of the token host_semaphore (any case) in every file under .github is a canonical
  call or a finding with its reason (an allowlist, fail closed by construction; #9851). Outside the
  HOST_SEMAPHORE_* environment names of ENV_NAMES the token may appear only on a content line of a
  `run: |` literal block of a .yml or .yaml file (any other YAML style, a key, a comment line, another
  file type: a finding). That line is made only of letters, digits, space and `_ . / = : , -` (any other
  character, named by its code point, is a finding: no quote, expansion, escape, glob, comment, operator,
  tab or non-ASCII character reaches the grammar). Its words, split on spaces only, are
  `[exec] python3 [no-argument flags] scripts/ci/host_semaphore.py`, then only the five wrapper flags
  --name, --max-wait-secs, --slots, --label and --poll-secs, each with one word as its value, then ` -- `
  and a command. Exactly one configured --name; exactly one --max-wait-secs, a plain decimal within the
  ceiling; --slots is required and equals the configured slot count; --label and --poll-secs at most
  once, --poll-secs a plain decimal. The checker judges what the runner executes (#9847): the parsed YAML
  document (escapes such as \\x5f and \\u005f decoded, block scalars folded) is read too, and its `run` values
  with every backslash-newline continuation joined. Its token lines equal the block lines this scan read, a
  joined line that holds the token is a finding, and so is a decoded key or value that holds the token where
  no raw line does. Every configured gate is called;
* the step that calls the wrapper is judged as a whole (#9879 invariant A). A job is gated when a step run value
  names a wrapper fragment (ci/host, host_sem, semaphore.py) or a job, step or workflow env sets
  HOST_SEMAPHORE_SLOTS. A1: the run value starts with CANONICAL_PREFIX (compared line for line after removing
  whole comment and blank lines only; its holes are a configured gate name and that gate's slot count). A2: no
  other line of the value names the wrapper. A3: `shell` is exactly bash on the step, no working-directory, no
  defaults.run at job or workflow level. A4: the step env keys are a subset of GATED_STEP_ENV_KEYS, and no step,
  job or workflow env of a gated job sets a key that changes what bash or python3 load (BASH_ENV, ENV, PATH,
  SHELLOPTS, BASHOPTS, PYTHON*, BASH_FUNC_*, LD_*). A5: exactly one wrapper step per gated job; a run value that
  names the wrapper outside a workflow job step is a finding;
* no spelling of the wrapper path that the runner or the shell resolves first passes (#9879 invariant B). B1: a
  run line that names ci/host holds, with quote characters removed, only CANONICAL_CHARS. B2: no run line of a
  gated job holds an expression `${{`. B3: no line names host_sem or semaphore.py together with `${{`, a glob
  character or a dollar-quote. A YAML file the subset parser cannot read that names a fragment is a finding.
  Known limits: a line with no literal fragment (a path taken wholly from a variable; #9882) and keys an earlier
  step writes through $GITHUB_ENV or $GITHUB_PATH (#9885); both are closed at run time;
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
import string
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import taint_boundary  # noqa: E402  (the repository's own YAML subset parser)
# the one ceiling, the one wait grammar and the one duplicate-key hook, shared with host_semaphore.py
from host_slot_limits import (  # noqa: E402
    IDLE_SEAT_CEILING_SECS, PLAIN_DECIMAL_PATTERN, DuplicateKeyError, no_duplicate_keys)

REPO = HERE.parents[1]
CONFIG_PATH = HERE / 'host_slots.json'
GITHUB_DIR = REPO / '.github'
YAML_SUFFIXES = ('.yml', '.yaml')
WAIT_KEY = 'HOST_SEMAPHORE_MAX_WAIT_SECS'
SLOTS_KEY = 'HOST_SEMAPHORE_SLOTS'
MAX_SLOTS = 64
GATE_NAME_RE = re.compile(r'[A-Za-z0-9_-]+')  # used with fullmatch: no trailing newline slips through
PLAIN_DECIMAL_RE = re.compile(PLAIN_DECIMAL_PATTERN)  # used with fullmatch, exactly as the wrapper does
SHOWN_VALUE_MAX = 64  # a refused value is shown cut to this many characters
# decision: a canonical-form allowlist over a better bash and YAML emulation, because a checker that only admits
# text it can read with no interpretation cannot disagree with bash (#9851, the parser differential class). A
# workflow may name the wrapper only on a line of a `run: |` literal block (the one YAML style whose lines are the
# lines the shell runs), the line is made only of CANONICAL_CHARS (no quote, expansion, glob, comment, operator,
# escape, tab or non-ASCII character: nothing the shell interprets), and its words, split on spaces only, follow
# the one call grammar of _call_findings. Every other site of the token is a finding by construction.
TOKEN_RE = re.compile(r'host_semaphore', re.IGNORECASE)  # IGNORECASE: a macOS runner opens HOST_SEMAPHORE.PY too
# The environment names of the gated leg: each holds the token but names no script; they are outside this rule.
ENV_NAMES = ('HOST_SEMAPHORE_SLOTS', 'HOST_SEMAPHORE_MAX_WAIT_SECS', 'HOST_SEMAPHORE_HELD')
ENV_NAME_RE = re.compile(r'(?<![A-Za-z0-9_])(?:%s)(?![A-Za-z0-9_])' % '|'.join(ENV_NAMES))
ENV_LIKE_RE = re.compile(r'HOST_SEMAPHORE_[A-Za-z0-9_]*', re.IGNORECASE)
CANONICAL_CHARS = frozenset(string.ascii_letters + string.digits + ' _./=:,-')
NON_CANONICAL_RE = re.compile(r'[^A-Za-z0-9 _./=:,-]')  # the complement of CANONICAL_CHARS, one linear search
# `run: |` with an optional `- ` sequence entry, chomping and indentation indicators and a trailing YAML comment
RUN_BLOCK_RE = re.compile(r'( *)(- +)?run: *\|[1-9+-]{0,2}(?: +#.*)?')
SCRIPT_PATH = 'scripts/ci/host_semaphore.py'
SCRIPT_WORDS = (SCRIPT_PATH, './' + SCRIPT_PATH)
PYTHON_WORD = 'python3'
EXEC_WORD = 'exec'
SEPARATOR = '--'
# Python options that take no argument; -c, -m, -W and -X take one, so a call with them is not classified.
PYTHON_FLAG_RE = re.compile(r'-[bBdEiIOPqRsSuvx]+')
# #9847: the only flags a workflow call of the wrapper may give (--config and --root steer it off the checked
# configuration and lock root)
FLAG_NAME = '--name'
FLAG_MAX_WAIT = '--max-wait-secs'
FLAG_SLOTS = '--slots'
FLAG_LABEL = '--label'
FLAG_POLL = '--poll-secs'
CALL_FLAGS = (FLAG_NAME, FLAG_MAX_WAIT, FLAG_SLOTS, FLAG_LABEL, FLAG_POLL)
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
F_ENV_NAME = '%s: %s is not a listed HOST_SEMAPHORE_ environment name'
F_NOT_TEXT = '%s: not UTF-8 text, so the host_semaphore token scan cannot read it'
F_NOT_YAML = '%s: a host_semaphore reference in a file that is not a .yml or .yaml workflow'
F_OUTSIDE_BLOCK = '%s: a host_semaphore reference outside a run: | literal block'
F_CHAR = ('%s: a host_semaphore line with the character %s, outside the canonical call characters '
          '(letters, digits, space and _ . / = : , -)')
F_YAML_UNREADABLE = '%s: the YAML subset parser cannot read this file, so its host_semaphore lines are not checked'
F_DECODED_DIFFERS = '%s: the host_semaphore lines of the parsed run values differ from its run: | block lines'
F_JOINED = ('%s: a host_semaphore line joined from two or more lines by a backslash-newline continuation (the shell '
            'runs the joined line, which is never a canonical call)')
F_ESCAPED = ('%s: a parsed YAML key or value outside the run values holds host_semaphore where no raw line does (an '
             'escaped spelling)')
# decision: scan the decoded step scripts (YAML parsed, continuations joined) as the primary source and keep the
# raw-line scan only as a cross-check, over patching the two reported spellings, because the reviewer's M-A and M-B
# are one root (#9847, PR 9851 delta r2): the checker judges what the runner will execute, not the source text.
# A YAML spelling whose decoded text differs from its raw text needs a backslash (an escape such as \x5f, \u005f
# or \U0000005f, or a continuation): YAML folding joins with a space and the parser refuses multi-line quoted and plain
# scalars. So a file with neither the token nor a backslash holds no decoded token the raw lines miss.
CONTINUATION = '\\'
F_TOKEN_AGAIN = '%s: a host_semaphore.py call line that names host_semaphore again'
F_NO_NAME = '%s: a host_semaphore.py call without exactly one plain --name'
F_UNCONFIGURED = '%s: calls the unconfigured gate %s'
F_NO_WAIT = '%s: a host_semaphore.py call without exactly one --max-wait-secs'
F_WAIT_VALUE = '%s: a host_semaphore.py call whose --max-wait-secs %s'
F_NEVER_CALLED = '%s: configured but no workflow calls it'
F_UNKNOWN_FLAG = '%s: a host_semaphore.py call with the flag %s, which is not one of ' + ', '.join(CALL_FLAGS)
F_SLOTS_VALUE = '%s: a host_semaphore.py call whose --slots is not the configured slot count'
F_POLL_VALUE = '%s: a host_semaphore.py call whose --poll-secs is not a plain decimal integer'
F_FLAG_NO_VALUE = '%s: a host_semaphore.py call whose %s has no value'
F_REPEATED = '%s: a host_semaphore.py call that gives %s more than once'
F_POSITIONAL = ('%s: a host_semaphore.py call with a word before its -- that is neither a wrapper flag nor its '
                'value (the wrapper would run it as the command)')
F_NO_COMMAND = '%s: a host_semaphore.py call without a -- followed by a command'

# #9879 invariant A: the step that calls the wrapper is judged as a whole, by a template, not line by line.
# decision: a canonical PREFIX template on the existing step over splitting the test step in two, because a split
# adds a fail-open path (green CI with no tests when two predicates disagree) and a prefix is still equal or not
# (NOTICE-9879-r1b). The prefix is compared line for line with whole comment lines and blank lines removed only; its
# two holes are the gate name and the slot literal. decision: the holes take GATE_NAME_RE and digits over the whole
# of CANONICAL_CHARS, because a space in a hole would add a word to the exec line.
GATE_HOLE = '{gate}'
SLOTS_HOLE = '{slots}'
CANONICAL_PREFIX = (
    'set -euo pipefail',
    'if [ "${HOST_SEMAPHORE_SLOTS:-0}" -gt 0 ] && [ -z "${HOST_SEMAPHORE_HELD:-}" ]; then',
    '  export HOST_SEMAPHORE_HELD=1',
    '  mkdir -p .local-runs',
    '  cp -- "$0" .local-runs/semaphore-step',
    '  exec python3 -I scripts/ci/host_semaphore.py --name {gate} --slots {slots} --max-wait-secs 600'
    ' --label linux-fed/enterprise-fed -- bash --noprofile --norc -eo pipefail .local-runs/semaphore-step',
    'fi',
)
PREFIX_RES = tuple(
    re.compile(re.escape(line).replace(re.escape(GATE_HOLE), '(?P<gate>[A-Za-z0-9_-]+)')
               .replace(re.escape(SLOTS_HOLE), '(?P<slots>[0-9]+)'))
    for line in CANONICAL_PREFIX)
SHELL_BASH = 'bash'
# The step env keys of the wrapper step today, by name: a new key is a finding until this constant changes in a
# reviewed diff.
GATED_STEP_ENV_KEYS = frozenset((
    'AI_MEMORY_NO_CONFIG', 'TIER', 'CI_NODE', 'TEST_IMPACT', 'DOCS_ONLY', 'TEST_IMPACT_REASON', 'TEST_IMPACT_COUNT',
    'TEST_IMPACT_TOTAL', 'JOB_TIMEOUT_MIN', 'CI_PG_ISOLATE_OFF', SLOTS_KEY, WAIT_KEY))
# decision: refuse the keys that change what bash or python3 load (BASH_ENV, ENV, PYTHON*, as the notice names) and
# also PATH, BASH_FUNC_* (an exported function shadows python3), LD_*, SHELLOPTS and BASHOPTS, over the three named
# forms only, because each one runs other code before or instead of the wrapper. Compared upper-cased (fail closed).
LOADER_ENV_KEYS = frozenset(('BASH_ENV', 'ENV', 'PATH', 'SHELLOPTS', 'BASHOPTS'))
LOADER_ENV_PREFIXES = ('PYTHON', 'BASH_FUNC_', 'LD_')
ENV_LEVELS = ('step', 'job', 'workflow')
# #9879 invariant B: the wrapper's path fragments. A run value that names one of them names the wrapper.
WRAPPER_FRAGMENT_RE = re.compile(r'ci/host|host_sem|semaphore\.py', re.IGNORECASE)
PATH_FRAGMENT_RE = re.compile(r'ci/host', re.IGNORECASE)
NAME_FRAGMENT_RE = re.compile(r'host_sem|semaphore\.py', re.IGNORECASE)
# an expression opener, a glob character or a dollar-quote (ANSI-C or locale quoting)
FRAGMENT_OPENER_RE = re.compile(r'\$\{\{|[*?\[]|\$\'|\$"')
EXPR_OPENER = '${{'
QUOTES = ('"', "'")
WORKFLOW_DIR = 'workflows/'
F_PREFIX = '%s: job %s: the wrapper step does not start with the canonical prefix (statement %d differs)'
F_PREFIX_GATE = ('%s: job %s: the canonical prefix calls gate %s with --slots %s, not a configured gate with its '
                 'slot count')
F_WRAPPER_AGAIN = '%s: job %s: the wrapper step names the wrapper outside its canonical exec line'
F_SHELL = '%s: job %s: the wrapper step does not set shell: bash exactly'
F_WORKDIR = '%s: job %s: the wrapper step sets working-directory, which changes where its run value starts'
F_DEFAULTS_RUN = '%s: job %s: a defaults.run at %s level changes the shell or directory of the wrapper step'
F_ENV_FORM = '%s: job %s: the %s env is not a plain mapping, so its keys cannot be checked'
F_STEP_ENV_KEY = '%s: job %s: the wrapper step sets env key %s, which is not in GATED_STEP_ENV_KEYS'
F_LOADER_ENV = '%s: job %s: the %s env sets %s, which changes what the shell or interpreter loads'
F_STEPS = '%s: job %s: %d steps name the wrapper; a gated job has exactly one'
F_JOB_NOT_CALLED = '%s: job %s sets HOST_SEMAPHORE_SLOTS but no step of it calls the wrapper'
F_RUN_OUTSIDE_STEP = '%s: a run value that names the wrapper outside a step of a workflow job'
F_GATED_EXPR = ('%s: job %s: a run line of a gated job holds an expression ${{ (the runner substitutes it into the '
                'script before bash reads it)')
F_PATH_CHAR = ('%s: a run line names ci/host and, with quotes removed, holds a character outside the canonical call '
               'characters')
F_FRAGMENT_FORM = ('%s: a line names a wrapper fragment (host_sem, semaphore.py) with an expression, a glob character '
                   'or a dollar-quote')
F_STEPS_UNREADABLE = '%s: the YAML subset parser cannot read this file, so its wrapper steps are not checked'


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
        cfg = json.loads(Path(path).read_text(encoding='utf-8'), object_pairs_hook=no_duplicate_keys)
    # before ValueError (DuplicateKeyError is one): a repeated key is malformed, never "the last one wins" (#9851)
    except DuplicateKeyError:
        raise ConfigError('%s has a duplicate key' % Path(path).name)
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
    """The text with comment-only lines blanked and shell line continuations joined.

    #9847: a backslash-newline joins with nothing, as bash removes it before it splits words (a join with a space
    would split `HOST_SEMAPHORE_MAX_\\` + `WAIT_SECS=1` into two words the scan never matches)."""
    lines = [('' if line.lstrip().startswith('#') else line) for line in text.splitlines()]
    return '\n'.join(lines).replace(CONTINUATION + '\n', '').split('\n')


def _joined_lines(value):
    """(logical line, True when a backslash-newline joined it) for each line of the shell script VALUE.

    Every line that ends with a backslash continues on the next (fail closed: an escaped backslash or a backslash
    inside single quotes is joined too, so the scan reads more joins than the shell, never fewer). A join counts
    only when text follows it: a backslash before an empty line or the end of the script adds nothing, and the
    raw scan has already judged that line. Linear."""
    out = []
    parts = []
    for segment in value.split('\n'):
        if segment.endswith(CONTINUATION):
            parts.append(segment[:-1])
            continue
        if parts:
            parts.append(segment)
            out.append((''.join(parts), any(parts[1:])))
            parts = []
        else:
            out.append((segment, False))
    if parts:
        out.append((''.join(parts), any(parts[1:])))
    return out


def _token_text(line):
    """LINE with every character outside CANONICAL_CHARS deleted, the text the token is searched in.

    decision: search the token with the non-canonical characters deleted over searching the raw line, because the
    shell joins `host_sema\\phore`, `host_"sema"phore` and `host_sema''phore` into the token, so a line that spells
    it split by a quote or an escape still holds it (and is then an F_CHAR finding). A spelling that leaves no
    token here (an expression, a glob, a dollar-quote) still names a wrapper fragment, which gated_step_violations
    judges (#9879). Known limit, stated in docs/ci/CARRIER-BRANCH-GATES.md: a line with no literal wrapper fragment
    at all (a path taken wholly from a variable); #9882 closes it at run time."""
    return NON_CANONICAL_RE.sub('', line)


def _holds_token(line):
    """True when LINE names the token outside the listed environment names."""
    return TOKEN_RE.search(ENV_NAME_RE.sub(' ', _token_text(line))) is not None


def _env_name_finding(wf, line):
    """F_ENV_NAME when the only token sites of LINE are unlisted HOST_SEMAPHORE_ names (#9844 D3), else None."""
    plain = ENV_NAME_RE.sub(' ', _token_text(line))
    unlisted = ENV_LIKE_RE.search(plain)
    if unlisted and not TOKEN_RE.search(ENV_LIKE_RE.sub(' ', plain)):
        return F_ENV_NAME % (wf, unlisted.group(0)[:SHOWN_VALUE_MAX])
    return None


def _is_call_line(line):
    """True when LINE holds the token and is not only unlisted environment names: it must be a classified call."""
    return _holds_token(line) and _env_name_finding('', line) is None


def _placed_lines(text):
    """(line, True when it is a content line of a `run: |` literal block) for each line of TEXT.

    The lines are split on a newline only (a carriage return stays in the line and is not a canonical
    character). A block holds the blank lines and the lines indented deeper than its key after the header."""
    key_indent = None
    for line in text.split('\n'):
        if key_indent is not None:
            if not line.strip() or len(line) - len(line.lstrip(' ')) > key_indent:
                yield line, True
                continue
            key_indent = None
        yield line, False
        header = RUN_BLOCK_RE.fullmatch(line)
        if header:
            key_indent = len(header.group(1)) + len(header.group(2) or '')


class _Decoded:
    """What the parsed YAML document holds, as the runner reads it (#9847)."""

    def __init__(self):
        self.call_lines = []  # the stripped call lines of every `run` value, split as written
        self.joined = 0  # the logical lines of `run` values that a continuation joined and that hold the token
        self.other = 0  # the lines of every other key or string value that hold the token


def _decoded_scan(node, out):
    """Fill the _Decoded OUT from every string of the parsed YAML document NODE (keys included)."""
    stack = [node]
    while stack:  # an explicit stack: a deep document never reaches the recursion limit
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str):
                    out.other += sum(1 for line in key.split('\n') if _holds_token(line))
                if key == 'run' and isinstance(value, str):
                    out.call_lines.extend(line.strip() for line in value.split('\n') if _is_call_line(line))
                    out.joined += sum(1 for line, joined in _joined_lines(value) if joined and _holds_token(line))
                else:
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(reversed(node))
        elif isinstance(node, str):
            out.other += sum(1 for line in node.split('\n') if _holds_token(line))


def _call_words(wf, words):
    """(index after the script word, None) when WORDS start a classified call, else (None, the finding)."""
    index = 1 if words[:1] == [EXEC_WORD] else 0
    if words[index:index + 1] != [PYTHON_WORD]:
        return None, F_NOT_A_CALL % wf
    index += 1
    while index < len(words) and PYTHON_FLAG_RE.fullmatch(words[index]):
        index += 1
    if index >= len(words) or words[index] not in SCRIPT_WORDS:
        return None, F_NOT_A_CALL % wf
    return index + 1, None


def _flag_values(wf, words, index, found):
    """{flag: [value, ...]} of the wrapper words from INDEX to the first --, and the index of that --.

    #9847: every word before the -- is one of the five wrapper flags, its value, or a finding. decision: an
    allowlist of the flags a workflow call may give over a list of the dangerous ones (--config, --root), because
    every other flag or word steers the wrapper outside what this checker proves. A value is one canonical word,
    the next word when it does not start with - or the text after =. decision: a next word that starts with - is
    never a value over taking a one-dash word as one, because argparse reads `--label -x` as a missing value (and
    `-5` as a number), so the checker could otherwise admit a call the wrapper parses differently."""
    values = {flag: [] for flag in CALL_FLAGS}
    while index < len(words) and words[index] != SEPARATOR:
        word = words[index]
        index += 1
        if not word.startswith('--'):
            found.append(F_POSITIONAL % wf)
            continue
        flag, joined, value = word.partition('=')
        if not joined:
            value = None
            if index < len(words) and not words[index].startswith('-'):
                value = words[index]
                index += 1
        if flag not in CALL_FLAGS:
            found.append(F_UNKNOWN_FLAG % (wf, flag[:SHOWN_VALUE_MAX]))
        elif value or flag in (FLAG_NAME, FLAG_MAX_WAIT):
            values[flag].append(value or None)  # --name and --max-wait-secs: an empty one fails "exactly one"
        else:
            found.append(F_FLAG_NO_VALUE % (wf, flag))
    return values, index


def _call_findings(wf, cfg, line, called):
    """The findings of one call line of a `run: |` block: the charset first, then the one call grammar."""
    bad = NON_CANONICAL_RE.search(line)
    if bad:
        # the character is named by its code point, so no control or bidi character reaches the output
        return [F_CHAR % (wf, 'U+%04X' % ord(bad.group(0)))]
    words = [word for word in line.split(' ') if word]
    index, finding = _call_words(wf, words)
    if finding:
        return [finding]
    if _holds_token(' '.join(words[index:])):
        return [F_TOKEN_AGAIN % wf]
    found = []
    values, index = _flag_values(wf, words, index, found)
    if index + 1 >= len(words):
        found.append(F_NO_COMMAND % wf)
    names = values[FLAG_NAME]
    gate = None
    if len(names) != 1 or names[0] is None or not GATE_NAME_RE.fullmatch(names[0]):
        found.append(F_NO_NAME % wf)
    else:
        called.add(names[0])
        gate = cfg['gates'].get(names[0])
        if gate is None:
            found.append(F_UNCONFIGURED % (wf, names[0][:SHOWN_VALUE_MAX]))
    waits = values[FLAG_MAX_WAIT]
    if len(waits) != 1 or waits[0] is None:
        found.append(F_NO_WAIT % wf)
    else:
        problem = wait_value_finding(waits[0])
        if problem:
            found.append(F_WAIT_VALUE % (wf, problem))
    for flag in (FLAG_SLOTS, FLAG_LABEL, FLAG_POLL):
        if len(values[flag]) > 1:
            found.append(F_REPEATED % (wf, flag))
    slots = values[FLAG_SLOTS]
    # decision: --slots is required and equal to the configured count over the wrapper default, because the
    # default is a second slot count the configuration does not hold
    if not slots or (gate is not None and slots[0] != str(gate['slots'])):
        found.append(F_SLOTS_VALUE % wf)
    polls = values[FLAG_POLL]
    if polls and not PLAIN_DECIMAL_RE.fullmatch(polls[0]):
        found.append(F_POLL_VALUE % wf)
    return found


def _decoded_findings(wf, text, block_lines, outside):
    """The findings of the parsed document of TEXT, the script the runner executes.

    F_YAML_UNREADABLE when it cannot be parsed; F_DECODED_DIFFERS when its run values do not hold exactly the
    BLOCK_LINES the raw scan read; one F_JOINED per joined logical run line that holds the token; F_ESCAPED when
    the other keys and values hold more token lines than the OUTSIDE raw lines (each already a finding) plus the
    block lines YAML reads under another key (a move that F_DECODED_DIFFERS already reports)."""
    decoded = _Decoded()
    try:
        _decoded_scan(taint_boundary.parse_yaml(text, wf), decoded)
    except (taint_boundary.Unclassifiable, RecursionError, ValueError):
        return [F_YAML_UNREADABLE % wf]
    found = [] if sorted(decoded.call_lines) == sorted(block_lines) else [F_DECODED_DIFFERS % wf]
    found.extend([F_JOINED % wf] * decoded.joined)
    if decoded.other > outside + max(0, len(block_lines) - len(decoded.call_lines)):
        found.append(F_ESCAPED % wf)
    return found


def call_site_violations(cfg, workflow_texts):
    """Every token site that is not a classified call, every finding of a call, and every gate never called.

    The decoded document is what the runner executes (#9847): a file that holds the token or a backslash is
    parsed, and every decoded token site the raw lines did not read (an escape, a continuation join, a folded,
    quoted or escaped run value) is a finding, never clean. The raw scan reads the canonical call lines."""
    called = set()
    found = []
    for wf, text in sorted(workflow_texts.items()):
        if text is None:
            found.append(F_NOT_TEXT % wf)
            continue
        if not wf.endswith(YAML_SUFFIXES):
            joined = text.replace(CONTINUATION + '\n', '')
            if any(_holds_token(line) for source in (text, joined) for line in source.split('\n')):
                found.append(F_NOT_YAML % wf)
            continue
        block_lines = []
        outside = 0
        holds_token = False
        for line, in_block in _placed_lines(text):
            if not _holds_token(line):
                continue
            holds_token = True
            reason = _env_name_finding(wf, line)
            if reason is None and not in_block:
                reason = F_OUTSIDE_BLOCK % wf
            if not in_block:
                outside += 1
            if reason is not None:
                found.append(reason)
                continue
            block_lines.append(line.strip())
            found.extend(_call_findings(wf, cfg, line, called))
        if holds_token or CONTINUATION in text:
            found.extend(_decoded_findings(wf, text, block_lines, outside))
    for name in sorted(set(cfg['gates']) - called):
        found.append(F_NEVER_CALLED % name)
    return found


def _names_wrapper(line):
    """True when LINE names a wrapper fragment (ci/host, host_sem, semaphore.py; any case) outside the listed
    environment names, searched with the non-canonical characters deleted as _holds_token does."""
    return WRAPPER_FRAGMENT_RE.search(ENV_NAME_RE.sub(' ', _token_text(line))) is not None


def _fragment_form(line):
    """True when LINE names host_sem or semaphore.py together with an expression opener, a glob character or a
    dollar-quote (#9879 invariant B: a spelling the runner or the shell resolves before the wrapper runs)."""
    if not FRAGMENT_OPENER_RE.search(line):
        return False
    return NAME_FRAGMENT_RE.search(ENV_NAME_RE.sub(' ', _token_text(line))) is not None


def _path_char(line):
    """True when LINE, with quote characters removed only, names ci/host and holds a non-canonical character."""
    quoteless = line.replace(QUOTES[0], '').replace(QUOTES[1], '')
    if PATH_FRAGMENT_RE.search(quoteless) and NON_CANONICAL_RE.search(quoteless):
        return True
    return False


def _logical_lines(value):
    """The lines of the run VALUE as written, then every logical line a backslash-newline continuation joined."""
    return value.split('\n') + [line for line, joined in _joined_lines(value) if joined]


def _run_values(node):
    """Every string under a `run` key at any depth of the parsed YAML document NODE (explicit stack, linear)."""
    stack = [node]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if key == 'run' and isinstance(value, str):
                    yield value
                else:
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)


def _shown_name(name):
    """NAME as is when it is a plain name, else its cut repr (no control or bidi character reaches the output)."""
    return name if isinstance(name, str) and GATE_NAME_RE.fullmatch(name) else _shown(name)


def _is_loader_key(key):
    """True when the env KEY changes what bash or python3 load before or instead of the wrapper."""
    upper = str(key).upper()
    return upper in LOADER_ENV_KEYS or upper.startswith(LOADER_ENV_PREFIXES)


def _env_mapping(found, where, level, holder):
    """The env mapping of HOLDER (a step, job or workflow), {} when absent; F_ENV_FORM and {} when not a mapping."""
    env = holder.get('env') if isinstance(holder, dict) else None
    if env is None:
        return {}
    if not isinstance(env, dict):
        found.append(F_ENV_FORM % (where + (level,)))
        return {}
    return env


def _prefix_findings(cfg, where, value):
    """A1 and A2 for the run VALUE of a wrapper step: the canonical prefix first, then one wrapper line only."""
    found = []
    statements = [line for line in value.split('\n')
                  if line.strip(' \t') and not line.lstrip(' \t').startswith('#')]
    for index, pattern in enumerate(PREFIX_RES):
        match = pattern.fullmatch(statements[index]) if index < len(statements) else None
        if match is None:
            found.append(F_PREFIX % (where + (index + 1,)))
            break
        holes = match.groupdict()
        if holes:
            gate = cfg['gates'].get(holes['gate'])
            if gate is None or holes['slots'] != str(gate['slots']):
                found.append(F_PREFIX_GATE % (where + (holes['gate'][:SHOWN_VALUE_MAX],
                                                        holes['slots'][:SHOWN_VALUE_MAX])))
    wrapper_lines = sum(1 for line in _logical_lines(value) if _names_wrapper(line))
    if wrapper_lines > 1:
        found.append(F_WRAPPER_AGAIN % where)
    return found


def _wrapper_step_findings(cfg, where, step):
    """A1 to A4 for one step whose run value names the wrapper."""
    found = _prefix_findings(cfg, where, step['run'])
    if step.get('shell') != SHELL_BASH:
        found.append(F_SHELL % where)
    if 'working-directory' in step:
        found.append(F_WORKDIR % where)
    env = _env_mapping(found, where, ENV_LEVELS[0], step)
    for key in env:
        if key not in GATED_STEP_ENV_KEYS:
            found.append(F_STEP_ENV_KEY % (where + (_shown_name(key),)))
    return found


def _gated_job_findings(cfg, wf, doc, job_id, job):
    """Invariant A (A1 to A5) and the expression rule of invariant B for one job of the workflow document DOC.

    A job is gated when a step run value names the wrapper or the job or a step env sets HOST_SEMAPHORE_SLOTS; the
    workflow env counts too (it reaches every job). Returns (findings, the number of wrapper run values seen)."""
    where = (wf, _shown_name(job_id))
    steps = job.get('steps') if isinstance(job, dict) else None
    steps = [step for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []
    runs = [step for step in steps if isinstance(step.get('run'), str)]
    wrapper_steps = [step for step in runs if any(_names_wrapper(line) for line in _logical_lines(step['run']))]
    scratch = []
    slot_envs = [_env_mapping(scratch, where, level, holder)
                 for level, holder in (('job', job), ('workflow', doc))] + [
        _env_mapping(scratch, where, ENV_LEVELS[0], step) for step in steps]
    if not wrapper_steps and not any(SLOTS_KEY in env for env in slot_envs):
        return [], 0
    found = []
    if not wrapper_steps:
        found.append(F_JOB_NOT_CALLED % where)
    if len(wrapper_steps) > 1:
        found.append(F_STEPS % (where + (len(wrapper_steps),)))
    loader_envs = []
    for step in wrapper_steps:
        found.extend(_wrapper_step_findings(cfg, where, step))
        loader_envs.append((ENV_LEVELS[0], _env_mapping([], where, ENV_LEVELS[0], step)))
    for level, holder in (('job', job), ('workflow', doc)):
        defaults = holder.get('defaults') if isinstance(holder, dict) else None
        if defaults is not None and (not isinstance(defaults, dict) or 'run' in defaults):
            found.append(F_DEFAULTS_RUN % (where + (level,)))
        loader_envs.append((level, _env_mapping(found, where, level, holder)))
    for level, env in loader_envs:
        found.extend(F_LOADER_ENV % (where + (level, _shown_name(key))) for key in env if _is_loader_key(key))
    for step in runs:
        found.extend(F_GATED_EXPR % where for line in step['run'].split('\n') if EXPR_OPENER in line)
    return found, len(wrapper_steps)


def _line_rule_count(lines, rule):
    return sum(1 for line in lines if rule(line))


def gated_step_violations(cfg, workflow_texts):
    """Invariants A and B of #9879: the step that calls the wrapper is judged as a whole, and every spelling of the
    wrapper path that the runner or the shell resolves before the wrapper runs is a finding.

    Per file: the jobs of a workflow (invariant A and the gated-job expression rule), then a run value that names
    the wrapper outside a step of a workflow job (a composite action, another key), then F_PATH_CHAR and
    F_FRAGMENT_FORM (each counted on the raw lines and on the decoded run lines, the larger count). Known limit
    (docs/ci/CARRIER-BRANCH-GATES.md): a line with no literal fragment, the path taken wholly from a variable."""
    found = []
    for wf, text in sorted(workflow_texts.items()):
        if text is None:
            continue  # call_site_violations reports F_NOT_TEXT
        raw_lines = text.split('\n')
        fragments = _line_rule_count(raw_lines, _fragment_form)
        is_yaml = wf.endswith(YAML_SUFFIXES)
        if not is_yaml:
            found.extend([F_FRAGMENT_FORM % wf] * fragments)
            continue
        try:
            doc = taint_boundary.parse_yaml(text, wf)
        except (taint_boundary.Unclassifiable, RecursionError, ValueError):
            if any(_names_wrapper(line) for line in raw_lines):
                found.append(F_STEPS_UNREADABLE % wf)
            found.extend([F_FRAGMENT_FORM % wf] * fragments)
            continue
        run_lines = [line for value in _run_values(doc) for line in _logical_lines(value)]
        wrapper_runs = sum(1 for value in _run_values(doc) if any(_names_wrapper(line) for line in _logical_lines(value)))
        in_steps = 0
        jobs = doc.get('jobs') if isinstance(doc, dict) and wf.startswith(WORKFLOW_DIR) else None
        for job_id, job in (jobs.items() if isinstance(jobs, dict) else ()):
            job_found, job_wrappers = _gated_job_findings(cfg, wf, doc, job_id, job)
            found.extend(job_found)
            in_steps += job_wrappers
        found.extend([F_RUN_OUTSIDE_STEP % wf] * (wrapper_runs - in_steps))
        found.extend([F_PATH_CHAR % wf] * _line_rule_count(run_lines, _path_char))
        found.extend([F_FRAGMENT_FORM % wf] * max(fragments, _line_rule_count(run_lines, _fragment_form)))
    return found


def _allowed_wait_key_use(line, start, end):
    """True when the key at LINE[START:END] is the env mapping key or a plain $KEY / ${KEY} read."""
    if start == len(line) - len(line.lstrip()) and WAIT_KEY_MAPPING_RE.match(line):
        return True
    if line[start - 1:start] == '$' and (start < 2 or line[start - 2] != '$'):
        return True
    return line[max(0, start - 2):start] == '${' and line[end:end + 1] == '}'


def _bad_wait_key_uses(lines):
    """The number of uses of the wait key in LINES that are neither its env mapping key nor a plain read."""
    return sum(1 for line in lines for use in WAIT_KEY_USE_RE.finditer(line)
               if not _allowed_wait_key_use(line, use.start(), use.end()))


def _decoded_wait_key_uses(node):
    """The bad wait key uses of the parsed document NODE: run values with comments blanked and continuations
    joined (#9847, what the shell runs), every other string value by line, and every key other than the key."""
    count = 0
    stack = [node]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and key != WAIT_KEY:
                    count += _bad_wait_key_uses(key.split('\n'))
                if key == 'run' and isinstance(value, str):
                    count += _bad_wait_key_uses(_code_lines(value))
                else:
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            count += _bad_wait_key_uses(node.split('\n'))
    return count


def wait_key_violations(texts):
    """One line per use of the wait key in run text that is neither its env mapping key nor a plain read.

    The raw lines are scanned; a file with a backslash (an escape or a continuation, the only spellings whose
    decoded text differs from the raw text) is also parsed, and each decoded use beyond the raw count is one more
    line. A file the parser cannot read keeps the raw count: bound_violations parses it too and main exits 2."""
    found = []
    reason = '%s: %s is used other than as its env mapping key or a plain $ read; set it only in the one env mapping'
    for rel, text in sorted(texts.items()):
        count = _bad_wait_key_uses(_code_lines(text))
        if CONTINUATION in text and rel.endswith(YAML_SUFFIXES):
            try:
                count = max(count, _decoded_wait_key_uses(taint_boundary.parse_yaml(text, rel)))
            except (taint_boundary.Unclassifiable, RecursionError, ValueError):
                pass  # the raw count stands; the unreadable file is refused by bound_violations
        found.extend([reason % (rel, WAIT_KEY)] * count)
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
        all_texts = github_all_texts()
        problems = (config_violations(cfg) + call_site_violations(cfg, all_texts)
                    + gated_step_violations(cfg, all_texts)
                    + bound_violations(cfg, texts) + wait_key_violations(texts))
    except (ConfigError, taint_boundary.YamlError) as exc:
        print('host_slots_check: malformed: %s' % exc)
        return EXIT_MALFORMED
    for line in problems:
        print('host_slots_check: %s' % line)
    return EXIT_VIOLATION if problems else EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
