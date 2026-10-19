#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Report suspected run/job IDs when a PR body must satisfy a no-ID claim.

Policy: ASCII decimal tokens of 11 or more digits, not embedded in Unicode
alphanumeric/underscore identifiers. This is a suspicion check, not GitHub ID
verification. The exact SELF_HOSTED_TARGET_CAP_BYTES: 42949672960 assignment
allows only that numeric occurrence; other numbers on the line still count.
Input and output are UTF-8. Exit 0: zero suspects; 1: suspects; 2: I/O or usage
error. Runs entirely locally. Not a blanket gate for every PR body.
"""

import argparse
from pathlib import Path
import re
import sys

MIN_ID_DIGITS = 11
SUSPECT_PATTERN = re.compile(r"(?<!\w)[0-9]{" + str(MIN_ID_DIGITS) + r",}(?!\w)")
CAP_ASSIGNMENT_PATTERN = re.compile(
    r"(?<!\w)SELF_HOSTED_TARGET_CAP_BYTES: (?P<cap>42949672960)(?!\w)"
)
EXIT_OK = 0
EXIT_SUSPECTS = 1
EXIT_ERROR = 2


def scan_body(body):
    """Return numbered offending lines and the number of unallowlisted tokens."""
    offending = []
    hit_count = 0
    for number, line in enumerate(body.splitlines(), start=1):
        allowed = {match.span("cap") for match in CAP_ASSIGNMENT_PATTERN.finditer(line)}
        hits = sum(match.span() not in allowed for match in SUSPECT_PATTERN.finditer(line))
        if hits:
            offending.append(f"{number}: {line}")
            hit_count += hits
    return offending, hit_count


def require_open_stream(stream):
    """Treat absent or caller-closed wrappers as an I/O boundary failure."""
    if stream is None or stream.closed:
        raise OSError("unavailable standard stream")
    return stream


def close_failed_stream(stream):
    """Release a failed CLI stream so shutdown cannot retry pending bytes."""
    if stream is None or stream.closed:
        return
    try:
        # Buffered IO closes the underlying stream even when its flush fails.
        # Closing the wrapper also prevents its finalizer from retrying output.
        stream.close()
    except OSError:
        pass


def report_error(message):
    """Attempt one diagnostic; a broken diagnostic destination is also closed."""
    try:
        print(message, file=require_open_stream(sys.stderr), flush=True)
    except OSError:
        close_failed_stream(sys.stderr)


class OutputParser(argparse.ArgumentParser):
    """Finish every parser write before argparse can terminate parsing."""

    def error(self, message):
        # argparse.print_usage(file=None) defaults to stdout. An absent stderr
        # must instead fail at the intended diagnostic boundary.
        self._print_message(self.format_usage(), sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")

    def _print_message(self, message, file=None):
        if message:
            stream = file
            try:
                require_open_stream(stream)
                stream.write(message)
                stream.flush()
            except OSError:
                close_failed_stream(stream)
                if stream is not sys.stderr:
                    report_error("check_pr_body_ids: output error")
                raise SystemExit(EXIT_ERROR)


def main(argv=None):
    """Read and report a body; failed standard output streams are closed."""
    parser = OutputParser(description=__doc__)
    parser.add_argument("--file", type=Path, help="read UTF-8 body from this file instead of stdin")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_status:
        # Return parser terminal statuses to callers; successful streams remain owned
        # by the caller. Failed wrappers have already been closed before this point.
        return exit_status.code
    try:
        raw = (args.file.read_bytes() if args.file is not None
               else require_open_stream(sys.stdin).buffer.read())
        body = raw.decode("utf-8")
    except (OSError, UnicodeError):
        report_error("check_pr_body_ids: input error (expected readable UTF-8 body)")
        return EXIT_ERROR
    offending, hit_count = scan_body(body)
    report = offending + [f"suspected_ids={hit_count} offending_lines={len(offending)}"]
    try:
        output = require_open_stream(sys.stdout).buffer
        output.write(("\n".join(report) + "\n").encode("utf-8"))
        output.flush()
    except OSError:
        close_failed_stream(sys.stdout)
        report_error("check_pr_body_ids: output error")
        return EXIT_ERROR
    return EXIT_SUSPECTS if hit_count else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
