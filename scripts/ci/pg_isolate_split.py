#!/usr/bin/env python3
"""Split the serial shard into pooled and residual-serial binaries (#6383 / #6386).

Reads ``serial.txt`` (one cargo selector per line, written by
``partition_test_binaries.py``) and the same build JSON, then writes to
``--out-dir``:

* ``iso_targets.txt``   every ``--test NAME`` / ``--bin NAME`` line of the
                        serial shard, for ``scripts/test/pg_isolated_binary.py run``.
* ``iso_residual.txt``  the names among them that must stay serial on the
                        shared database: unknown source, a fixed loopback port,
                        a shared filesystem path (cross-process state a
                        per-binary database cannot isolate), or named in
                        ``scripts/ci/pg_isolate_serial_residual.txt``.
* ``iso_other.txt``     the remaining selectors (``--example``, ``--bench``;
                        ``--lib`` is left to the existing lib run), which keep
                        the existing single-process path.

Fail closed (exit 2, ``::error::`` on stderr) on an unreadable input or an
unsafe selector. Python 3.9+, standard library only.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import partition_test_binaries as ptb  # noqa: E402


class SplitError(Exception):
    """A fail-closed condition."""


def load_static_residual(path):
    names = set()
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            if not ptb.SAFE_NAME_RE.match(line):
                raise SplitError('unsafe name %r in %s' % (line, path))
            names.add(line)
    return names


def residual_reason(exe, static):
    """Why this binary cannot be pooled, or None when it can."""
    if exe.name in static:
        return 'listed'
    text = ptb.read_sources(exe.src_path)
    if text is None:
        return 'unknown-source'
    if ptb.PORT_RE.search(text):
        return 'port'
    if ptb.SHARED_PATH_RE.search(text):
        return 'shared-path'
    return None


def split(serial_lines, exes, static):
    """Return (targets, residual_names, other) for the serial selector lines."""
    by_selector = {e.selector: e for e in exes}
    targets, residual, other = [], [], []
    for line in serial_lines:
        if line == '--lib':
            continue
        exe = by_selector.get(line)
        if exe is None:
            raise SplitError('serial selector %r is not a built executable' % line)
        if exe.kind in ('test', 'bin'):
            targets.append(line)
            if residual_reason(exe, static) is not None:
                residual.append(exe.name)
        else:
            other.append(line)
    return targets, residual, other


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    ap.add_argument('--build-json', required=True)
    ap.add_argument('--serial-file', required=True)
    ap.add_argument('--static-residual', default=str(Path(__file__).resolve().parent / 'pg_isolate_serial_residual.txt'))
    ap.add_argument('--out-dir', required=True)
    args = ap.parse_args(argv)
    try:
        exes = ptb.parse_build_json(Path(args.build_json).read_text().splitlines())
        serial = [l.strip() for l in Path(args.serial_file).read_text().splitlines() if l.strip()]
        static = load_static_residual(args.static_residual)
        targets, residual, other = split(serial, exes, static)
    except (OSError, ptb.PartitionError, SplitError) as exc:
        print('::error::pg_isolate_split: %s' % exc, file=sys.stderr)
        return 2
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'iso_targets.txt').write_text(''.join(l + '\n' for l in targets))
    (out / 'iso_residual.txt').write_text(''.join(n + '\n' for n in residual))
    (out / 'iso_other.txt').write_text(''.join(l + '\n' for l in other))
    print('pg_isolate_split: %d pooled, %d residual-serial, %d other' % (len(targets) - len(residual), len(residual), len(other)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
