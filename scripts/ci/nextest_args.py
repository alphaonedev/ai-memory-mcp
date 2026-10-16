#!/usr/bin/env python3
"""Translate ``cargo test`` shaped arguments into ``cargo nextest run`` arguments (#7259).

The CI helpers build one argument list in the ``cargo test`` shape
(``--features X --lib -- --test-threads=3 --skip prefix``) and use it for both
the ``cargo test --no-run`` prebuild and the timed run. ``cargo nextest run``
accepts most of that list unchanged, but it rejects libtest's
``--test-threads`` after the ``--`` separator and has its own spelling for the
ignored-test flags. This module is the single translation, shared by
``ci.yml`` (through the CLI) and ``scripts/test/pg_isolated_binary.py``.

CLI: ``nextest_args.py -- <cargo test shaped args...>`` prints the translated
arguments, one per line. Exit 0 on success, 2 when an argument cannot be
translated (fail closed: a flag nextest would silently ignore or reject is an
error here, never a pass-through guess).

Doc tests are refused: nextest does not run them, so they stay on
``cargo test --doc``. Standard library only, Python 3.9+.
"""
import sys
from typing import List, Optional, Tuple

EXIT_OK = 0
EXIT_USAGE = 2
SEPARATOR = '--'
DOC_FLAG = '--doc'
THREADS_FLAG = '--test-threads'
SKIP_FLAG = '--skip'
NEXTEST_RUN = ('cargo', 'nextest', 'run')
# libtest flag -> nextest arguments placed BEFORE the separator.
HEAD_MAPPED = {
    '--ignored': ['--run-ignored', 'only'],
    '--include-ignored': ['--run-ignored', 'all'],
    '--nocapture': ['--no-capture'],
}
# libtest flags nextest accepts verbatim after the separator.
TAIL_PASSTHROUGH = ('--exact',)


class ArgError(Exception):
    """An argument that has no faithful nextest equivalent (fail closed)."""


def is_nextest(cargo: List[str]) -> bool:
    """True when ``cargo`` starts with ``cargo nextest run``."""
    return tuple(cargo[:3]) == NEXTEST_RUN


def _threads(value: Optional[str]) -> str:
    if value is None or not value.isdigit() or int(value) < 1:
        raise ArgError('nextest: %s needs a positive integer, got %r' % (THREADS_FLAG, value))
    return str(int(value))


def split_libtest(tail: List[str]) -> Tuple[List[str], List[str]]:
    """Split libtest arguments into (before-separator, after-separator) nextest arguments."""
    head: List[str] = []
    after: List[str] = []
    i = 0
    while i < len(tail):
        arg = tail[i]
        if arg == THREADS_FLAG:
            i += 1
            head += [THREADS_FLAG, _threads(tail[i] if i < len(tail) else None)]
        elif arg.startswith(THREADS_FLAG + '='):
            head += [THREADS_FLAG, _threads(arg.split('=', 1)[1])]
        elif arg == SKIP_FLAG:
            i += 1
            if i >= len(tail) or not tail[i]:
                raise ArgError('nextest: %s needs a test name filter' % SKIP_FLAG)
            after += [SKIP_FLAG, tail[i]]
        elif arg.startswith(SKIP_FLAG + '='):
            value = arg.split('=', 1)[1]
            if not value:
                raise ArgError('nextest: %s needs a test name filter' % SKIP_FLAG)
            after += [SKIP_FLAG, value]
        elif arg in HEAD_MAPPED:
            head += HEAD_MAPPED[arg]
        elif arg in TAIL_PASSTHROUGH:
            after.append(arg)
        elif arg.startswith('-'):
            raise ArgError('nextest: libtest argument %r has no nextest equivalent' % arg)
        else:
            after.append(arg)  # a positional test-name filter
        i += 1
    return head, after


def translate(args: List[str]) -> List[str]:
    """``cargo test`` shaped arguments -> arguments for ``cargo nextest run``."""
    if SEPARATOR in args:
        at = args.index(SEPARATOR)
        cargo_part, libtest = list(args[:at]), args[at + 1:]
    else:
        cargo_part, libtest = list(args), []
    if DOC_FLAG in cargo_part:
        raise ArgError('nextest does not run doc tests; keep them on `cargo test --doc`')
    head, after = split_libtest(libtest)
    out = cargo_part + head
    if after:
        out += [SEPARATOR] + after
    return out


def command_for(cargo: List[str], target: List[str], test_args: List[str]) -> List[str]:
    """Full child command: ``cargo`` runner + one ``--test NAME`` target + libtest arguments."""
    if not is_nextest(cargo):
        argv = list(cargo) + list(target)
        if test_args:
            argv += [SEPARATOR] + list(test_args)
        return argv
    return list(cargo) + translate(list(target) + ([SEPARATOR] + list(test_args) if test_args else []))


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == [SEPARATOR]:
        args = args[1:]
    try:
        translated = translate(args)
    except ArgError as exc:
        print('nextest_args: %s' % exc, file=sys.stderr)
        return EXIT_USAGE
    for arg in translated:
        print(arg)
    return EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
