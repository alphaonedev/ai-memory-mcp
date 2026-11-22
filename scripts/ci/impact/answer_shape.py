"""Judge the three-line answer of the cargo_skip decider, byte-wise (#9263, #9815).

Both classify steps (ci.yml `cls`, coverage.yml `cls`) call this one script on the
file the decider wrote. The reason a step prints for a rejected answer is computed
here, in one place, from the bytes of the file, so the hosted Linux runner (GNU
userland) and macOS (BSD userland) print the same reason for every answer. Before
this script the steps counted lines and keys with grep and found non-printable
bytes with tr and wc; GNU grep reads a NUL as a line end in a file it takes for
binary, so a NUL in the answer was counted as extra lines and labelled
`extra-line` on Linux and `not-printable-ascii` on macOS.

    python3 -I answer_shape.py <answer-file>
    python3 -I cargo_skip.py --judge-answer <answer-file>

The steps use the second form: they already run the trusted `cargo_skip.py`, so the
judge adds no interpreter operand of its own (the taint-boundary ratchet counts one).

Exit 0: the answer is accepted. stdout is the three lines, normalised to the order
docs_only, cargo_skip, cargo_skip_reason, each `key=value`; every byte is printable
ASCII. Exit 1: the answer is rejected. stdout is one fixed token (see the WHY_*
constants) and nothing else; the answer text is never printed. Any other exit
(unreadable file, usage error, an unexpected exception) is a failure of this
script: the step treats it as a rejection with WHY_CHECKER_ERROR.

An answer is accepted only when every test below passes, checked in this order
(the first failure names the reason):

1. extra-line: exactly three lines (a final line feed is optional, an empty
   answer has no line), one `docs_only=` line, one `cargo_skip=` line and one
   `cargo_skip_reason=` line, each key once.
2. not-printable-ascii: every byte is a printable ASCII byte (0x20 to 0x7e) or a
   line feed. A tab, CR, NUL, DEL, ESC and every byte above 0x7e are rejected;
   nothing is cleaned up and then trusted.
3. empty / over-cap-300 / blank-only: the reason holds 1 to REASON_MAX bytes and
   at least one that is not a space.

The decision stays fail-closed: the step runs every rejected answer as a RUN.
Standard library only; cost is linear in the size of the answer.
"""
import sys
from pathlib import Path

KEY_DOCS = b"docs_only="
KEY_SKIP = b"cargo_skip="
KEY_REASON = b"cargo_skip_reason="
KEYS = (KEY_DOCS, KEY_SKIP, KEY_REASON)
EXPECTED_LINES = 3
LF = 0x0A
PRINTABLE_LOW = 0x20
PRINTABLE_HIGH = 0x7E
SPACE = 0x20
REASON_MAX = 300

WHY_EXTRA = "extra-line"
WHY_NONPRINT = "not-printable-ascii"
WHY_EMPTY = "empty"
WHY_OVER = "over-cap-%d" % REASON_MAX
WHY_BLANK = "blank-only"
WHY_CHECKER_ERROR = "checker-error"

EXIT_ACCEPT = 0
EXIT_REJECT = 1
EXIT_ERROR = 2
USAGE = "usage: answer_shape.py <answer-file>"
# A byte is allowed when it is a line feed or a printable ASCII byte.
ALLOWED_BYTES = frozenset(range(PRINTABLE_LOW, PRINTABLE_HIGH + 1)) | {LF}


def split_lines(data: bytes) -> list:
    """The lines of data as a line-oriented reader counts them (no empty tail line)."""
    lines = data.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    return lines


def judge(data: bytes):
    """(None, (docs_only, cargo_skip, reason)) for an accepted answer, else (why, None)."""
    lines = split_lines(data)
    if len(lines) != EXPECTED_LINES:
        return WHY_EXTRA, None
    values = {}
    for key in KEYS:
        found = [line[len(key):] for line in lines if line.startswith(key)]
        if len(found) != 1:
            return WHY_EXTRA, None
        values[key] = found[0]
    if not ALLOWED_BYTES.issuperset(data):
        return WHY_NONPRINT, None
    reason = values[KEY_REASON]
    if not reason:
        return WHY_EMPTY, None
    if len(reason) > REASON_MAX:
        return WHY_OVER, None
    if reason.strip(bytes([SPACE])) == b"":
        return WHY_BLANK, None
    return None, (values[KEY_DOCS].decode("ascii"), values[KEY_SKIP].decode("ascii"),
                  reason.decode("ascii"))


def main(argv: list) -> int:
    if len(argv) != 2:
        sys.stderr.write(USAGE + "\n")
        return EXIT_ERROR
    try:
        data = Path(argv[1]).read_bytes()
        why, accepted = judge(data)
    except Exception as exc:  # fail closed: the step maps this to a rejection
        sys.stderr.write("answer_shape: %s\n" % type(exc).__name__)
        return EXIT_ERROR
    if why is not None:
        sys.stdout.write(why + "\n")
        return EXIT_REJECT
    docs_only, cargo_skip, reason = accepted
    sys.stdout.write("docs_only=%s\ncargo_skip=%s\ncargo_skip_reason=%s\n"
                     % (docs_only, cargo_skip, reason))
    return EXIT_ACCEPT


if __name__ == "__main__":
    sys.exit(main(sys.argv))
