#!/usr/bin/env python3
"""#3607 re-issue: recapture the four-leg `doctor --posture` evidence.

Recaptures the section 2 four-leg `doctor --posture enterprise-federation`
evidence at the published tip (22 checks: +#3553 synchronous, +#3199 backup
signing), derived from the current release tip (20 checks). Docs/evidence only.

Ported from `scripts/recapture-cert-3607-posture.sh` (python-not-shell standing
rule). The outputs are byte-for-byte those of the shell script, with one
deliberate change (#5038): the first line of `posture-legs-exit-codes.txt` carries
the UTC date of the run, not the fixed template date 2026-09-11, and the script
checks the header it wrote before it exits. The fixture-path sanitizer label is
unchanged on purpose: the cert certifies the sanitized fixtures byte-identical
across re-issues (#5039 part B is a separate, vote-gated decision).

Environment overrides: DEFAULT_BIN (default <repo>/target/release/ai-memory),
SQLCIPHER_BIN (default <repo>/target-sqlcipher/release/ai-memory; leg 4 is
recorded as `missing` when it is absent or a bare name is not on the child PATH;
an empty value takes the default, as `:-` did) and TMPDIR (accepted only when it
resolves, symlinks followed, under <repo-root>/.local-runs; a symlinked
.local-runs is refused). A binary value containing a slash is taken relative to
the repo root, a bare name is looked up on the child PATH, and the one resolved
absolute path is both checked and run. The lookup uses only the absolute,
non-empty entries of the child PATH (relative and empty entries mean the cwd and are
dropped). A binary that cannot start records `exit: 127` for its leg when the file or
its interpreter is missing, as the shell did. A file the kernel refuses to execute
(ENOEXEC, an executable with no shebang) is refused and recorded as `exit: 126`; the
shell ran it through /bin/sh, this script fails closed instead (#7464). When leg 4 is
`missing`, a `posture-sqlcipher-pass.out` left by an earlier run is removed and the
summary says so; the shell left the stale file in the bundle and counted it
(deliberate divergence, #7463; decision: a bundle must never carry a leg-4 capture
that this run did not produce). A symlink anywhere under .local-runs/cert-3607-fixtures (the keys
directory, the operator key pair keygen writes, any fixture file) or at .local-runs itself
is refused before anything is written (#7462, #7508) and again after keygen and before
leg 4 (#7509). Every file the script writes (fixtures, the db passphrase, captures,
evidence) is created fresh with O_NOFOLLOW|O_EXCL, walking the path from the repo root
without following a symlink. A symlink at a replaceable path is removed and replaced,
never followed, and the run goes on (exit 0): the unlink is relative to the parent
directory descriptor and a link planted again before the create fails O_EXCL. A symlinked
parent, a symlink at the passphrase (created 0600 and never replaced) or one found by a
re-check fails closed with exit 1 (#7539). Decision: unlink-then-create-exclusive over
truncating in place, because O_EXCL cannot truncate through a link. The evidence bundle is local
operator evidence, not a published artefact (git records the mode as 100644 whatever the
working-tree mode): every file the script creates is 0600 and every directory it creates
(.local-runs, the evidence directory and each parent it makes) is 0700, passed to
os.open/os.mkdir and then enforced with fchmod, so no umask (not even 0) widens one
(#7568, #7569). A check covers every directory the script reads or writes
through (the repo root and each directory from it down to the evidence directory,
.local-runs, the work, fixtures and key directories, TMPDIR): one that exists and is
world writable or owned by another uid is refused before any write; a sticky world-writable
one is accepted (others cannot rename our entries in it) and so is a group-writable one (a
umask 002 checkout makes every directory 0775) (#7611). The bundle is built in a staging
directory (0700) seeded with a copy of the previous bundle and replaces the evidence
directory only when every leg and the header self-check succeeded (the old directory is
moved aside, the staging directory renamed into place, then the old one removed); a run that
fails leaves the previous bundle untouched and no staging directory behind, so a bundle
never mixes legs of two runs (#7574). The staging directory, the aside directory and every
raw (unsanitized) capture live in <repo-root>/.local-runs/cert-3607-work, on the same
filesystem as the evidence directory (checked: a different st_dev is refused, so the
rename stays atomic); nothing temporary is ever created under docs/ (#7609, #7611). Each
run holds a lock there, so two runs never recover each other's work. At start-up the run
recovers from a killed predecessor (SIGKILL, power loss): a leftover aside is put back when
the evidence directory is missing or incomplete (complete = MANIFEST.sha256 present and every
file it lists matches) and removed when the evidence directory is complete, several asides
are refused, and leftover staging and raw directories are removed, including the
`.cert-3607.*` names an older version left next to the evidence directory (#7610). When the
evidence directory has a MANIFEST.sha256 the run refreshes the lines of the files it wrote, so
a bundle it publishes is complete by that definition. Every child process runs with cwd set
to a fresh, empty 0700 sandbox directory under .local-runs, with HOME inside the sandbox and
AI_MEMORY_NO_CONFIG=1, so no leg can open a database it did not create (`doctor --posture`
opens a relative ai-memory.db in its cwd); the sandbox home is labelled `<home>` in the
evidence and the sandbox is removed at exit (#7608). HOME must be an absolute path that is
already in normal form (os.path.normpath(HOME) == HOME, so no `.`, `..`, `//` or trailing `/`
component), not `/`, without a `:`, not starting with `//` and without a control byte
(0x00-0x1f, 0x7f) or any non-ASCII character: a relative or empty HOME would turn the HOME
sanitizer pattern into a substring rewrite of the evidence, a colon would add a cwd entry to
the child PATH, and a control byte would split a captured line (#7510, #7540, #7570). The
character rule is "printable ASCII only", chosen over a category list: it refuses every
character str.splitlines splits on (U+0085, U+2028, U+2029 and the C0 separators) and every
unicodedata category Cc, Cf, Zl and Zp character in one test, the sanitizer and the evidence
are byte-oriented, and a category list can lag Unicode (#7613); the run is refused with
exit 1 before any write. The sanitizer replaces whole path components only (#7538). The shell script's
defaults named build directories of one build host; they are replaced by
repo-relative ones. Exit codes: 0 success; 1 DEFAULT_BIN is not an executable
file, TMPDIR (or the default scratch directory) is outside <repo-root>/.local-runs, HOME is
not a usable absolute path, a fixture path is or became a symlink, operator keygen failed,
the git sha could not be read, or the transcript header date disagrees with the run
date; 2 unknown arguments.
"""
import argparse
import base64
import contextlib
import datetime
import errno
import fcntl
import hashlib
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.path.abspath(__file__)).parent.parent  # logical path, like `cd .. && pwd`
OUT = ROOT / "docs" / "compliance" / "evidence" / "cert-3607"
FIX = ROOT / ".local-runs" / "cert-3607-fixtures"
DEFAULT_BIN_FALLBACK = str(ROOT / "target" / "release" / "ai-memory")
SQLCIPHER_BIN_FALLBACK = str(ROOT / "target-sqlcipher" / "release" / "ai-memory")
HOME = os.environ.get("HOME", "")
CHILD_PATH = "/usr/bin:/bin:" + HOME + "/.cargo/bin"
SANITIZED_FIXTURE_LABEL = "<repo-root>/.local-runs/cert-3607-fixtures"
EXEC_NOT_FOUND = 127
EXEC_FAILED = 126
EXIT_CODES_FILE = "posture-legs-exit-codes.txt"
HEADER_TEMPLATE = (
    "# posture-legs transcript — recorded exit codes "
    "({date} #3607 re-issue recapture (22 checks) @ {sha})"
)
HEADER_RE = re.compile(r"^# posture-legs transcript — recorded exit codes \((\d{4}-\d{2}-\d{2}) ")
POSTURE_ARGS = ["doctor", "--posture", "enterprise-federation"]
PEER_FINGERPRINT = "1111111111111111111111111111111111111111111111111111111111111111"
PEER_ATTESTATION = (
    '{"peer-a":{"allowed_sender_agent_ids":["agent-a"],'
    '"allowed_namespaces":["team-x/ops","team-x/shared"]}}\n'
)
SQLCIPHER_OUT_FILE = "posture-sqlcipher-pass.out"
SUMMARY_FILES = ("posture-bare-env.out", "posture-hardened-env.out", "posture-sqlcipher-pass.out")
PASSPHRASE_BYTES = 32
LOCAL_RUNS = ROOT / ".local-runs"
# Work directories live under .local-runs, never under docs/ (#7609 #7610 #7611).
WORK = LOCAL_RUNS / "cert-3607-work"
SANDBOX = LOCAL_RUNS / "cert-3607-sandbox"  # the cwd and HOME of every child (#7608)
SANDBOX_CWD = SANDBOX / "cwd"
SANDBOX_HOME = SANDBOX / "home"
LOCK_NAME = ".lock"
MANIFEST_NAME = "MANIFEST.sha256"
STAGING_PREFIX = "staging-"
ASIDE_PREFIX = "old-"
RAW_PREFIX = "raw-"
BUNDLE_FILES = ("posture-bare-env.out", "posture-hardened-env.out",
                "posture-hardened-boot-refusal.out", "posture-sqlcipher-pass.out",
                "posture-legs-exit-codes.txt", "peer-fingerprints.txt", "peer-attestation.json")
MANIFEST_LINE_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")
DIR_MODE = 0o700
FILE_MODE = 0o600  # every file the script creates: local operator evidence (#7568)
# Explicit allowlists of delimiter characters (#7538, #7571-#7573). They are the
# characters that, in the captured output, separate a path from the text around it. They
# are not a list of illegal filename bytes: a path that continues with any other byte is a
# different path and is left alone.
# A path starts at the start of input or after whitespace, a quote or backtick, `(`, `[`,
# `<`, `=`, `:`, `,` or `{`. The comma and the brace are start delimiters (#7612): in a list
# (`a,/home/a`), a mapping (`{k: /home/a}`) or a shell-style expansion (`${/home/a}`) they
# are what precedes the exact path, and leaving it would leak it.
PATH_START = rb"(?:\A|(?<=[\s'\"`(\[<=:,{]))"
# A path ends at the end of input, `/`, whitespace, a quote or backtick, `)`, `]`, `>`,
# `:`, `;`, `,` or `}`, or at a `.` that is itself the end of input or is followed by
# whitespace (a sentence full stop); `/home/a./x` and `/home/a..b` are other paths.
PATH_END = rb"(?=\Z|/|[\s'\"`)\]>:;,}]|\.(?:\Z|\s))"
USAGE_EPILOG = (
    "Environment overrides: DEFAULT_BIN (default <repo>/target/release/ai-memory, must be "
    "an executable file; a value with a slash is relative to the repo root, a bare name is "
    "looked up on the child PATH), SQLCIPHER_BIN (default <repo>/target-sqlcipher/release/ai-memory; "
    "leg 4 is recorded as `missing` when absent), TMPDIR (must resolve under "
    "<repo>/.local-runs, which must not be a symlink). HOME must be an absolute path in normal form (not /, no ':', not starting with '//', no control byte, no . or .. components) "
    "of printable ASCII only (any non-ASCII character is refused). Every child runs in a fresh empty sandbox "
    "directory under <repo>/.local-runs with HOME inside it; staging, aside and raw capture directories also "
    "live under <repo>/.local-runs (cert-3607-work), never under docs/. "
    "Fixtures and evidence are never written through a symlink. Exit codes: 0 success; "
    "1 preflight or capture failure; 2 unknown arguments."
)


def utc_run_date():
    """The UTC calendar date of this run, as YYYY-MM-DD."""
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def header_line(run_date, sha):
    """First line of the exit-code transcript."""
    return HEADER_TEMPLATE.format(date=run_date, sha=sha)


def check_header_date(transcript_path, run_date):
    """Return None when the transcript header carries run_date, else a message."""
    first = Path(transcript_path).read_text(encoding="utf-8").split("\n", 1)[0]
    match = HEADER_RE.match(first)
    if match is None:
        return "transcript header is not in the expected shape: " + first
    if match.group(1) != run_date:
        return "transcript header date %s is not the run date %s" % (match.group(1), run_date)
    return None


def sanitize(raw):
    """Collapse absolute repo, fixture and home paths, in the order of the shell sed.

    The replacement is literal. The shell sed read each path as a regular expression and
    fixture and worktree paths do contain a `.` (for example `.local-runs`). For every
    literal occurrence of a path the two agree; they differ only where the sed also
    rewrote a regex near-miss (a different character where the path has a `.`), which
    real output does not produce. Line endings, including CRLF and a missing final
    newline, are preserved exactly.

    A path is replaced only as a whole run of path components, and only when BOTH ends are
    a boundary, each an explicit allowlist of delimiter characters (not a list of illegal
    filename bytes). Start boundary: start of input, or the previous byte is whitespace, a
    quote or backtick, `(`, `[`, `<`, `=`, `:`, `,` or `{`. End boundary: end of input, `/`,
    or the next byte is whitespace, a quote or backtick, `)`, `]`, `>`, `:`, `;`, `,` or `}`;
    a `.` counts as an end only when it is itself at end of input or followed by whitespace.
    The comma is both a start and an end delimiter (a list separator), `{` is a start and
    `}` an end delimiter (a mapping or a `${...}` expansion). So `/home/a` never rewrites
    `/home/ab`, `/home/a.txt`, `/home/a./x`, `/home/a+b`, `/home/a..b`, `~/home/a/x`,
    `x+/home/a/x`, `@/home/a`, `%/home/a` or `$/home/a`, and `{k: /home/a}`, `${/home/a}`,
    `x,/home/a` and `/home/a,/home/a` are rewritten (#7510, #7538, #7571, #7572, #7573,
    #7612). The sandbox home every child runs with is labelled `<home>` first."""
    out = _replace_component(raw, str(SANDBOX_HOME), b"<home>")
    out = _replace_component(out, str(ROOT), b"<repo-root>")
    out = _replace_component(out, str(FIX), SANITIZED_FIXTURE_LABEL.encode())
    if HOME:
        out = _replace_component(out, HOME, b"<home>")
    return out


def _replace_component(raw, path, label):
    """Replace path in raw by label where it is a whole run of path components."""
    path = path.rstrip("/")
    if not path:
        return raw
    pattern = re.compile(PATH_START + re.escape(path.encode()) + PATH_END)
    return pattern.sub(lambda _match: label, raw)


def home_problem(home):
    """A message when home cannot be a sanitizer pattern or a child PATH entry, else None."""
    if not home:
        return "HOME is empty or unset; set it to an absolute path"
    if (not os.path.isabs(home) or ":" in home or not home.rstrip("/")
            or home.startswith("//") or "//" in home
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in home)
            or not home.isascii()
            or os.path.normpath(home) in ("/", "//") or os.path.normpath(home) != home):
        return ("HOME %r must be an absolute path in normal form (no '.', '..', '//' or trailing "
                "'/' component, no control byte, printable ASCII only) that is not / and has no ':'; "
                "a relative or empty HOME would rewrite substrings of the evidence" % home)
    return None


def shell_status(returncode):
    """Map a subprocess return code to the shell's `$?` (128+n for signals)."""
    return 128 - returncode if returncode < 0 else returncode


def open_parent(path):
    """(directory fd, name) for path, walking from ROOT without following any symlink."""
    relative = Path(os.path.abspath(str(path))).relative_to(ROOT)
    fd = os.open(str(ROOT), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
    except OSError:
        os.close(fd)
        raise
    return fd, relative.name


def open_new(path, replace=True):
    """A write fd for a file created by this call (O_CREAT|O_EXCL|O_NOFOLLOW).

    With replace, an existing entry is unlinked first (a symlink is removed, never
    followed); a path swapped back in between the unlink and the create fails O_EXCL."""
    parent, name = open_parent(path)
    try:
        if replace:
            with contextlib.suppress(FileNotFoundError):  # no entry yet is the first-run case
                os.unlink(name, dir_fd=parent)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILE_MODE,
                     dir_fd=parent)
        try:
            os.fchmod(fd, FILE_MODE)  # whatever the umask (#7568)
        except OSError:
            os.close(fd)
            raise
        return fd
    finally:
        os.close(parent)


def write_file(path, data, replace=True):
    """Write data to a file this call creates; raises OSError instead of following a symlink."""
    with os.fdopen(open_new(path, replace), "wb") as handle:
        handle.write(data)


def read_file(path):
    """The bytes of a regular file; raises OSError (ELOOP) for a symlink in any component."""
    parent, name = open_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as handle:
        return handle.read()


def chmod_dir(path, mode=DIR_MODE):
    """chmod a directory that is not a symlink, through a descriptor (no path swap window)."""
    parent, name = open_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def write_fixtures():
    """Create the keypair, peer fingerprints and attestation fixtures."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat)

    keys = FIX / "keys"
    ensure_dirs(keys)
    chmod_dir(keys)
    signing_key = Ed25519PrivateKey.generate()
    priv = signing_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    write_file(keys / "ai-memory.priv", priv)
    write_file(keys / "ai-memory.pub", pub)
    write_file(FIX / "operator.pub.b64", (base64.b64encode(pub).decode() + "\n").encode())
    write_file(FIX / "peer-fingerprints.txt",
               ("peer-a.fleet.example " + PEER_FINGERPRINT + "\n").encode())
    write_file(FIX / "peer-attestation.json", PEER_ATTESTATION.encode())
    print("fixtures ok", keys)


def child_env(tmpdir, extra):
    """The scrubbed environment every binary invocation runs in (env -i). HOME is the sandbox
    home and AI_MEMORY_NO_CONFIG=1 is set, with the sandbox cwd, so no leg opens a store it
    did not create (#7608)."""
    env = {
        "PATH": CHILD_PATH,
        "HOME": str(SANDBOX_HOME),
        "TMPDIR": str(tmpdir),
        "AI_MEMORY_NO_CONFIG": "1",
        "AI_MEMORY_AGENT_ID": "ai-memory",
        "AI_MEMORY_KEY_DIR": str(FIX / "keys"),
    }
    env.update(extra)
    return env


def exec_status(error):
    """The shell status for a binary that could not start: 127 not found, else 126."""
    return EXEC_NOT_FOUND if isinstance(error, FileNotFoundError) else EXEC_FAILED


def run_capture(binary, args, env, raw_path, sanitized_path):
    """Run one leg, sanitize its combined output, drop the raw file, return `$?`.

    A binary that cannot start has its error text as the leg output and status 127 when
    the file or its interpreter is missing (as the shell did), 126 for other exec errors
    such as ENOEXEC (the shell ran those through /bin/sh; this script refuses them)."""
    try:
        with os.fdopen(open_new(raw_path), "wb") as raw:
            try:
                status = shell_status(subprocess.run(
                    [str(binary)] + args, env=env, stdout=raw, cwd=str(SANDBOX_CWD),
                    stderr=subprocess.STDOUT, check=False).returncode)
            except OSError as error:
                raw.write(("%s: %s\n" % (binary, error.strerror or error)).encode())
                status = exec_status(error)
        write_file(sanitized_path, sanitize(read_file(raw_path)))
    finally:
        if raw_path.exists():
            raw_path.unlink()  # the unsanitized capture never outlives this call
    return status


def count_rows(path, marker):
    """grep -c: the number of lines containing marker."""
    return sum(1 for line in path.read_text(errors="replace").splitlines() if marker in line)


def parse_args(argv):
    """Parse the command line; --help and unknown arguments have no side effects."""
    parser = argparse.ArgumentParser(
        prog="recapture-cert-3607-posture.py",
        description="Recapture the #3607 four-leg `doctor --posture enterprise-federation` "
                    "evidence into docs/compliance/evidence/cert-3607 (docs/evidence only).",
        epilog=USAGE_EPILOG)
    return parser.parse_args(argv)


def resolve_tmpdir(raw):
    """Return (resolved TMPDIR, None) when it lies under <repo-root>/.local-runs, else
    (None, message). A symlinked .local-runs is refused: the anchor is the lexical
    <real repo root>/.local-runs, never a resolved symlink target."""
    label = "TMPDIR %s" % raw if raw else "default scratch directory (TMPDIR unset) %s" % (
        LOCAL_RUNS / "tmp")
    candidate = Path(raw) if raw else LOCAL_RUNS / "tmp"
    if LOCAL_RUNS.is_symlink():
        return None, "%s: %s is a symlink; replace it with a real directory" % (label, LOCAL_RUNS)
    resolved = candidate.resolve()
    anchor = ROOT.resolve() / ".local-runs"
    try:
        resolved.relative_to(anchor)
    except ValueError:
        return None, ("%s resolves to %s, which is not under %s; set TMPDIR to a directory "
                      "below it or unset it" % (label, resolved, anchor))
    return resolved, None


def resolve_binary(value):
    """Absolute path of a binary setting, or None when a bare name is not on the child PATH.

    A value containing a slash is relative to the repo root; a bare name is looked up on
    the PATH the legs run with, so the file checked is the file executed. Only absolute,
    non-empty PATH entries are searched: a relative or empty entry (for example from a
    HOME that is relative or contains a colon) would mean the cwd. The legs execute the
    returned absolute path, never a name.
    decision: drop such entries over failing the run, because the remaining entries are
    still a valid, absolute search path and the result is checked to be absolute."""
    if os.sep in value:
        joined = Path(value) if os.path.isabs(value) else ROOT / value
        return os.path.normpath(str(joined))
    found = shutil.which(value, path=os.pathsep.join(child_path_dirs()))
    return found if found and os.path.isabs(found) else None


def child_path_dirs():
    """The absolute, non-empty entries of the child PATH."""
    return [entry for entry in CHILD_PATH.split(os.pathsep) if entry and os.path.isabs(entry)]


def fixture_symlink_problem():
    """A message when .local-runs, the fixtures dir or anything under it is a symlink, else None."""
    anchor = ROOT.resolve() / ".local-runs"
    candidates = [LOCAL_RUNS, FIX]
    if FIX.is_dir() and not FIX.is_symlink():
        # every existing entry, so the key pair keygen writes (#7508) and anything else is covered
        for directory, names, files in os.walk(str(FIX)):
            candidates.extend(Path(directory) / name for name in names + files)
    for candidate in candidates:
        if candidate.is_symlink():
            return "%s is a symlink; fixtures hold keys and must stay inside %s" % (candidate, anchor)
    try:
        FIX.resolve().relative_to(anchor)
    except ValueError:
        return "fixture directory %s resolves outside %s" % (FIX, anchor)
    return None


def ensure_dirs(path):
    """Create every missing directory of path below the repo root, each mode 0700.

    Walks from the root without following a symlink. A level this call creates is made 0700
    by os.mkdir and then fchmod'ed, so no umask widens it (#7569); a level that already
    exists is left as it is."""
    absolute = Path(os.path.abspath(str(path)))
    for base in (ROOT, ROOT.resolve()):
        if absolute == base or base in absolute.parents:
            break
    else:
        raise OSError(errno.EINVAL, "path is not under the repo root", str(path))
    fd = os.open(str(base), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.relative_to(base).parts:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, DIR_MODE, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    os.fchmod(child, DIR_MODE)
                except OSError:
                    os.close(child)
                    raise
            os.close(fd)
            fd = child
    finally:
        os.close(fd)


def dir_problem(path):
    """A message when an existing directory is world writable or owned by another uid, else None.

    Another user could rename a directory they can write to and plant a real one in its
    place, which passes every symlink check (#7569). Group write is accepted: a umask 002
    checkout makes every directory 0775. A sticky world-writable directory is accepted: the
    sticky bit stops others from renaming or removing our entries in it (#7611)."""
    try:
        info = os.lstat(str(path))
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return None  # symlink and non-directory cases have their own refusals
    if info.st_uid != os.geteuid():
        return "%s is owned by uid %d, not by the current uid; refusing to write evidence there" % (
            path, info.st_uid)
    if info.st_mode & stat.S_IWOTH and not info.st_mode & stat.S_ISVTX:
        return "%s is world writable (mode %o); chmod o-w it before recapturing" % (
            path, info.st_mode & 0o777)
    return None


def remove_tree(path):
    """Remove a directory tree (or a lone entry) without following a symlink; ignore a miss."""
    if os.path.islink(path) or os.path.isfile(path):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
    else:
        shutil.rmtree(str(path), ignore_errors=True)


def copy_bundle(source, target):
    """Copy the regular files and directories of source into target (0600 / 0700).

    Symlinks and special files are not copied, and a `.raw` capture left by an interrupted
    run is dropped: the unsanitized capture never ships. Reads do not follow a link."""
    with os.scandir(str(source)) as entries:
        listing = sorted(entries, key=lambda entry: entry.name)
    for entry in listing:
        if entry.is_symlink():
            continue
        if entry.is_dir(follow_symlinks=False):
            ensure_dirs(target / entry.name)
            copy_bundle(source / entry.name, target / entry.name)
        elif entry.is_file(follow_symlinks=False) and not entry.name.endswith(".raw"):
            write_file(target / entry.name, read_file(source / entry.name))


def move(source, target):
    """Rename source to target through directory descriptors (no symlink is followed)."""
    source_parent, source_name = open_parent(source)
    try:
        target_parent, target_name = open_parent(target)
        try:
            os.replace(source_name, target_name, src_dir_fd=source_parent,
                       dst_dir_fd=target_parent)
        finally:
            os.close(target_parent)
    finally:
        os.close(source_parent)


def publish_bundle(stage, suffix):
    """Make stage the evidence directory: the old one is moved aside (into WORK), stage is
    renamed into place, then the old one is removed. When the rename fails the old one is put
    back. A kill between the steps is recovered by recover_leftovers at the next start."""
    aside = WORK / (ASIDE_PREFIX + suffix)
    moved = False
    with contextlib.suppress(FileNotFoundError):  # first run: there is no previous bundle
        move(OUT, aside)
        moved = True
    try:
        move(stage, OUT)
    except OSError:
        if moved:
            move(aside, OUT)
        raise
    if moved:
        remove_tree(aside)


def guarded_dirs(tmpdir):
    """Every directory the script reads or writes through, outermost first."""
    chain = [ROOT]
    chain.extend(ROOT / part for part in
                 _prefixes(OUT.parent.relative_to(ROOT).parts))
    chain.extend([OUT, LOCAL_RUNS, WORK, FIX, FIX / "keys"])
    with contextlib.suppress(ValueError):
        chain.extend(LOCAL_RUNS / part for part in
                     _prefixes(Path(tmpdir).relative_to(LOCAL_RUNS).parts))
    seen, ordered = set(), []
    for candidate in chain:
        if str(candidate) not in seen:
            seen.add(str(candidate))
            ordered.append(candidate)
    return ordered


def _prefixes(parts):
    """The cumulative sub-paths of parts: ('a', 'b') gives 'a', 'a/b'."""
    return [os.path.join(*parts[:count]) for count in range(1, len(parts) + 1)]


def device_problem(first, second):
    """A message when two directories are on different filesystems, else None."""
    if os.stat(str(first)).st_dev != os.stat(str(second)).st_dev:
        return ("%s and %s are not on the same filesystem; the evidence directory could not "
                "be replaced atomically" % (first, second))
    return None


def acquire_lock():
    """An exclusive, non-blocking flock on WORK/.lock: the fd, or None when a run holds it."""
    parent, name = open_parent(WORK / LOCK_NAME)
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, FILE_MODE, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        os.fchmod(fd, FILE_MODE)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    except OSError:
        os.close(fd)
        raise
    return fd


def make_sandbox():
    """A fresh, empty 0700 cwd and home for the children (#7608); an old one is removed."""
    remove_tree(SANDBOX)
    if os.path.lexists(str(SANDBOX)):
        raise OSError(errno.EEXIST, "cannot remove the old sandbox", str(SANDBOX))
    ensure_dirs(SANDBOX_CWD)
    ensure_dirs(SANDBOX_HOME)


def bundle_complete(bundle):
    """True when bundle is a real directory whose MANIFEST.sha256 lists at least one file and
    every listed file is a regular file with the listed sha256."""
    try:
        if not stat.S_ISDIR(os.lstat(str(bundle)).st_mode):
            return False
        lines = read_file(bundle / MANIFEST_NAME).decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return False
    listed = 0
    for line in lines:
        if not line.strip():
            continue
        match = MANIFEST_LINE_RE.match(line)
        if match is None or "/" in match.group(2) or match.group(2) in (".", ".."):
            return False
        try:
            data = read_file(bundle / match.group(2))
        except OSError:
            return False
        if hashlib.sha256(data).hexdigest() != match.group(1):
            return False
        listed += 1
    return listed > 0


def refresh_manifest(bundle):
    """Update the lines of MANIFEST.sha256 for the files this run wrote, when the bundle has
    one: a listed file that is gone is dropped, a written file that is not listed is added."""
    manifest = bundle / MANIFEST_NAME
    try:
        old = read_file(manifest).decode("utf-8").splitlines()
    except FileNotFoundError:
        return
    names = []
    for line in old:
        match = MANIFEST_LINE_RE.match(line)
        if match is not None and match.group(2) not in names:
            names.append(match.group(2))
    names.extend(name for name in BUNDLE_FILES if name not in names)
    lines = []
    for name in names:
        if not (bundle / name).is_file() or (bundle / name).is_symlink():
            continue
        lines.append("%s  %s\n" % (hashlib.sha256(read_file(bundle / name)).hexdigest(), name))
    write_file(manifest, "".join(lines).encode("utf-8"))


def _leftovers(directory, prefix):
    """The entries of directory whose name starts with prefix, sorted; none when it is absent."""
    try:
        with os.scandir(str(directory)) as entries:
            return sorted(directory / entry.name for entry in entries
                          if entry.name.startswith(prefix))
    except FileNotFoundError:
        return []


def recover_leftovers():
    """Recover from a killed run: put back or drop a leftover aside, remove leftover staging
    and raw directories. A message (refusal) when several asides exist, else None."""
    legacy = "." + OUT.name + "."
    asides = _leftovers(WORK, ASIDE_PREFIX) + _leftovers(OUT.parent, legacy + ASIDE_PREFIX)
    if len(asides) > 1:
        return ("several leftover asides of earlier runs exist (%s); keep the complete one as "
                "%s and remove the rest" % (", ".join(str(a) for a in asides), OUT))
    if asides:
        aside = asides[0]
        if not os.path.lexists(str(OUT)):
            move(aside, OUT)
        elif bundle_complete(OUT) or not bundle_complete(aside):
            remove_tree(aside)
        else:
            remove_tree(OUT)
            move(aside, OUT)
    for leftover in (_leftovers(WORK, STAGING_PREFIX) + _leftovers(WORK, RAW_PREFIX)
                     + _leftovers(OUT.parent, legacy + STAGING_PREFIX)):
        remove_tree(leftover)
    return None


def is_executable_file(candidate):
    """True when candidate is a regular file the current user can execute."""
    return os.path.isfile(candidate) and os.access(candidate, os.X_OK)


def main(argv=None):
    """Run the recapture; an OS error from a refused write (a symlink) is exit 1, not a traceback."""
    parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return recapture()
    except OSError as error:
        print("refusing to continue: %s: %s; fixtures and evidence must be regular files, "
              "never reached through a symlink, under %s" % (
                  error.filename or "", error.strerror or error, ROOT), file=sys.stderr)
        return 1


def fixtures_clean():
    """True when no fixture path is a symlink; otherwise the problem is printed."""
    problem = fixture_symlink_problem()
    if problem is not None:
        print(problem, file=sys.stderr)
    return problem is None


def recapture():
    problem = home_problem(HOME)
    if problem is not None:
        print(problem, file=sys.stderr)
        return 1
    run_date = utc_run_date()
    default_setting = os.environ.get("DEFAULT_BIN") or DEFAULT_BIN_FALLBACK
    sqlcipher_setting = os.environ.get("SQLCIPHER_BIN") or SQLCIPHER_BIN_FALLBACK
    tmpdir, problem = resolve_tmpdir(os.environ.get("TMPDIR"))
    if tmpdir is None:
        print(problem, file=sys.stderr)
        return 1
    default_bin = resolve_binary(default_setting)
    if default_bin is None or not is_executable_file(default_bin):
        print("DEFAULT_BIN %s is not an executable file; build it (cargo build --release) "
              "or set DEFAULT_BIN" % (default_bin or default_setting), file=sys.stderr)
        return 1
    sqlcipher_bin = resolve_binary(sqlcipher_setting)
    if not fixtures_clean():
        return 1
    for directory in guarded_dirs(tmpdir):
        problem = dir_problem(directory)
        if problem is not None:
            print(problem, file=sys.stderr)
            return 1
    ensure_dirs(OUT.parent)
    ensure_dirs(WORK)
    problem = device_problem(WORK, OUT.parent)
    if problem is not None:
        print(problem, file=sys.stderr)
        return 1
    lock = acquire_lock()
    if lock is None:
        print("another recapture run holds the lock in %s; wait for it to finish" % WORK,
              file=sys.stderr)
        return 1
    try:
        return recapture_locked(tmpdir, default_bin, sqlcipher_bin, sqlcipher_setting, run_date)
    finally:
        os.close(lock)


def recapture_locked(tmpdir, default_bin, sqlcipher_bin, sqlcipher_setting, run_date):
    """The part of a run that needs the lock: recovery, the sandbox, the staged bundle."""
    problem = recover_leftovers()
    if problem is not None:
        print(problem, file=sys.stderr)
        return 1
    ensure_dirs(FIX)
    chmod_dir(FIX)  # holds the passphrase and keys: tightened on every run
    ensure_dirs(tmpdir)
    # The bundle is built next to the evidence directory's filesystem (WORK is under
    # .local-runs, never under docs/) and replaces the evidence directory only on success, so
    # a failed run never leaves legs of two runs mixed (#7574, #7609).
    suffix = secrets.token_hex(8)
    stage = WORK / (STAGING_PREFIX + suffix)
    raw_dir = WORK / (RAW_PREFIX + suffix)
    ensure_dirs(stage)
    ensure_dirs(raw_dir)
    try:
        make_sandbox()
        if OUT.is_dir() and not OUT.is_symlink():
            copy_bundle(OUT, stage)
        legs = capture_legs(stage, raw_dir, tmpdir, default_bin, sqlcipher_bin,
                            sqlcipher_setting, run_date)
        if isinstance(legs, int):
            return legs
        publish_bundle(stage, suffix)
    finally:
        remove_tree(stage)
        remove_tree(raw_dir)
        remove_tree(SANDBOX)
    report(*legs)
    return 0


def capture_legs(out, raw_dir, tmpdir, default_bin, sqlcipher_bin, sqlcipher_setting,
                 run_date):
    """Write the fixtures and the four legs into out (raw captures in raw_dir, never in out);
    the exit codes (e1, e2, e3, e4), or 1."""
    write_fixtures()

    # #3199 check #22 (backup-manifest signing): the certified configuration
    # carries the operator key pair in the key dir.
    if not (FIX / "keys" / "operator.key").is_file():
        keygen_out = FIX / "keygen.out"
        keygen_env = child_env(tmpdir, {})
        keygen_env.pop("AI_MEMORY_AGENT_ID")
        try:
            with os.fdopen(open_new(keygen_out), "wb") as sink:
                keygen_status = subprocess.run(
                    [default_bin, "rules", "keygen"], env=keygen_env, cwd=str(SANDBOX_CWD),
                    stdout=sink, stderr=subprocess.STDOUT, check=False).returncode
        except OSError as error:
            print("operator keygen failed: %s: %s" % (default_bin, error.strerror or error),
                  file=sys.stderr)
            return 1
        if keygen_status != 0:
            print("operator keygen failed: "
                  + read_file(keygen_out).decode(errors="replace").rstrip("\n"), file=sys.stderr)
            return 1
    if not fixtures_clean():  # keygen ran with the key dir: nothing may have been swapped (#7509)
        return 1
    op_pub_file = FIX / "keys" / "operator.key.pub"
    if not op_pub_file.is_file():
        op_pub_file = FIX / "operator.pub.b64"
    op_pub = read_file(op_pub_file).decode().replace("\n", "")
    attest = read_file(FIX / "peer-attestation.json").decode().rstrip("\n")

    posture_env = child_env(tmpdir, {})
    # --- leg 1: bare ---
    e1 = run_capture(default_bin, POSTURE_ARGS, posture_env,
                     raw_dir / "posture-bare-env.out.raw", out / "posture-bare-env.out")

    hard = {
        "AI_MEMORY_SECURITY_PROFILE": "asi-hard",
        "AI_MEMORY_FED_TRUST_DOMAIN": "cert-fleet-01",
        "AI_MEMORY_FED_PEER_FINGERPRINTS": str(FIX / "peer-fingerprints.txt"),
        "AI_MEMORY_FED_PEER_ATTESTATION": attest,
        "AI_MEMORY_ENCRYPT_AT_REST": "1",
        "AI_MEMORY_APPEND_ONLY": "1",
        "AI_MEMORY_OPERATOR_PUBKEY": op_pub,
        "AI_MEMORY_DB_SYNCHRONOUS": "FULL",
    }
    # --- leg 2: hardened non-sqlcipher, boot gate NOT armed ---
    e2 = run_capture(default_bin, POSTURE_ARGS, child_env(tmpdir, hard),
                     raw_dir / "posture-hardened-env.out.raw", out / "posture-hardened-env.out")

    # --- leg 3: hardened non-sqlcipher, boot gate ARMED ---
    # Boot refuse is NOT doctor --posture (that subcommand bypasses the gate):
    # a plain `doctor` goes through main.
    armed = dict(hard)
    armed["AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE"] = "1"
    e3 = run_capture(default_bin, ["doctor"], child_env(tmpdir, armed),
                     raw_dir / "posture-hardened-boot-refusal.out.raw",
                     out / "posture-hardened-boot-refusal.out")

    # --- leg 4: sqlcipher + encrypt + boot gate ---
    if sqlcipher_bin is None or not is_executable_file(sqlcipher_bin):
        print("sqlcipher binary missing: " + (sqlcipher_bin or sqlcipher_setting), file=sys.stderr)
        print("leg4 skipped")
        e4 = "missing"
        stale = out / SQLCIPHER_OUT_FILE
        if stale.is_file() or stale.is_symlink():
            stale.unlink()  # never ship the previous run's leg-4 capture (#7463)
    else:
        if not fixtures_clean():  # the three legs above ran binaries in the fixture tree
            return 1
        # #3553 check #21 observes the LIVE pragma on the store the sqlcipher
        # build can open only with a passphrase.
        passphrase_file = FIX / "db-passphrase"
        try:
            passphrase = read_file(passphrase_file).decode().replace("\n", "")
        except FileNotFoundError:
            passphrase = secrets.token_hex(PASSPHRASE_BYTES)
            write_file(passphrase_file, passphrase.encode(), replace=False)
        store = FIX / "leg4-sqlcipher.db"
        leg4_env = {"AI_MEMORY_DB": str(store), "AI_MEMORY_DB_PASSPHRASE": passphrase}
        if not store.is_file():
            # doctor opens the store read-only and refuses to create it: seed
            # the encrypted fixture store first (schema-init). Failure tolerated.
            seed_env = child_env(tmpdir, leg4_env)
            for name in ("AI_MEMORY_AGENT_ID", "AI_MEMORY_KEY_DIR"):
                seed_env.pop(name)
            try:
                subprocess.run([sqlcipher_bin, "stats", "--json"], env=seed_env,
                               cwd=str(SANDBOX_CWD), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False)
            except OSError:
                pass  # seeding failure is tolerated; the leg records its own exec status
        leg4 = dict(armed)
        leg4.update(leg4_env)
        e4 = run_capture(sqlcipher_bin, POSTURE_ARGS, child_env(tmpdir, leg4),
                         raw_dir / "posture-sqlcipher-pass.out.raw", out / "posture-sqlcipher-pass.out")

    sha_done = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                              cwd=str(SANDBOX_CWD), capture_output=True, text=True, check=False)
    sha = sha_done.stdout.strip()
    if sha_done.returncode != 0 or not sha:
        print("cannot read the git sha of " + str(ROOT), file=sys.stderr)
        return 1
    transcript = "\n".join([
        header_line(run_date, sha),
        "# each leg: the doctor invocation shape, then the observed shell exit status.",
        "",
        "## leg 1: bare (env -i, AI_MEMORY_NO_CONFIG=1 only)",
        "exit: %s" % e1,
        "## leg 2: hardened non-sqlcipher, boot gate NOT armed",
        "exit: %s" % e2,
        "## leg 3: hardened non-sqlcipher, boot gate ARMED (AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1)",
        "exit: %s" % e3,
        "## leg 4: sqlcipher build, ENCRYPT_AT_REST=1, boot gate ARMED",
        "exit: %s" % e4,
        "",
    ])
    write_file(out / EXIT_CODES_FILE, transcript.encode("utf-8"))
    problem = check_header_date(out / EXIT_CODES_FILE, run_date)
    if problem is not None:
        print(problem, file=sys.stderr)
        return 1

    for name in ("peer-fingerprints.txt", "peer-attestation.json"):
        write_file(out / name, read_file(FIX / name))
    refresh_manifest(out)

    return e1, e2, e3, e4


def report(e1, e2, e3, e4):
    """Print the exit codes and the FAIL/PASS counts of the published bundle."""
    print("exits e1=%s e2=%s e3=%s e4=%s" % (e1, e2, e3, e4))
    print("FAIL/PASS counts:")
    if e4 == "missing":
        print("%s MISSING (leg 4 skipped, no capture in the bundle)" % SQLCIPHER_OUT_FILE)
    for name in SUMMARY_FILES:
        path = OUT / name
        if path.is_file():
            sys.stdout.write("%s FAIL=%d PASS=%d " % (name, count_rows(path, "[FAIL]"), count_rows(path, "[PASS]")))
            for line in path.read_text(errors="replace").splitlines():
                if "overall:" in line:
                    print(line)


if __name__ == "__main__":
    sys.exit(main())
