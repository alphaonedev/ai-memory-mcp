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
`.cert-3607.*` names an older version left next to the evidence directory (#7610). Every run
requires a real existing evidence directory and verifies its manifest as committed in git HEAD
(`git show HEAD:docs/compliance/evidence/cert-3607/MANIFEST.sha256`, never the file on disk)
before anything is built or published (#7649, #7696). The run refuses (exit 1, naming every
offender, no binary runs, nothing is published) unless: (a) the manifest exists in git HEAD,
including on a first run, and the bundle root is a real directory (#7813);
(b) the working-tree manifest is byte-identical to the committed one; (c) the set of every
regular file and every directory under the bundle, recursively, equals the manifest set
exactly, so a missing, extra or unlisted file or subdirectory refuses, and so does any
symlink; (d) every listed digest matches. After a recapture the working tree differs from git
HEAD until the evidence is committed; commit it (or `git checkout` the directory) before the
next recapture. A new manifest is computed only over the files this run freshly wrote (the
captures and SANITIZATION.md); every other line is kept verbatim, and the run never re-hashes
a file it did not write, so an edited `test-results.txt` is never blessed by a rerun.
SANITIZATION.md is part of the bundle: the run rewrites its one `Provenance:` line (tip sha,
UTC date) in staging, so the published manifest covers the updated file, and a
SANITIZATION.md with no such line, or with two, is refused (#7699). Every child process (keygen, the store seed,
each leg, git) runs in its own fresh empty 0700 cwd, with HOME in a sibling directory of
the same per-child sandbox under .local-runs and AI_MEMORY_NO_CONFIG=1; there is no shared
cwd. A store a leg needs is passed by explicit path (AI_MEMORY_DB), never found through the
cwd, so a store that keygen makes in its own cwd is never seen by a leg. What holds (#7608,
#7648): two consecutive runs give byte-identical captures (only the sha and date of the exit-code
header and the provenance line differ, because the evidence is committed between the runs). Legs 1 and
2 run with no store in their cwd and no AI_MEMORY_DB, so the real doctor writes
`ai-memory doctor --posture: live PRAGMA synchronous not observed on ai-memory.db: database
does not exist; refusing to create (read-only): ai-memory.db` to stderr, which the capture merges, and the
check row says `live pragma not observed`; the committed captures (posture-bare-env.out:75,
posture-hardened-env.out:68) say `agrees` because the old shared cwd held the store keygen
made (#7648, #7697). This diagnostic is source-derived; the stub regression is not a real
product capture (#7814). The captures carry no host path. The per-child homes are labelled `<home>` in the evidence and the sandbox is removed at exit.
`AI_MEMORY_NO_CONFIG=1` still lets the product write a config.toml under HOME (#7192, a
product issue, not fixed here); the per-child HOME keeps it inside the sandbox. HOME must be an absolute path that is
already in normal form (os.path.normpath(HOME) == HOME, so no `.`, `..`, `//` or trailing `/`
component), not `/`, without a `:`, not starting with `//` and without a control byte
(0x00-0x1f, 0x7f) or any non-ASCII character: a relative or empty HOME would turn the HOME
sanitizer pattern into a substring rewrite of the evidence, a colon would add a cwd entry to
the child PATH, and a control byte would split a captured line (#7510, #7540, #7570). The
character rule is "printable ASCII only", chosen over a category list: it refuses every
character str.splitlines splits on (U+0085, U+2028, U+2029 and the C0 separators) and every
unicodedata category Cc, Cf, Zl and Zp character in one test, the sanitizer and the evidence
are byte-oriented, and a category list can lag Unicode (#7613); the run is refused with
exit 1 before any write. The sanitizer replaces every occurrence of each sensitive value (HOME,
the repo root, the fixtures root and the per-child homes), longest value first, in its raw,
JSON-escaped and percent-encoded forms; there is no delimiter allowlist, so a longer path
that shares the prefix is over-redacted (#7538, #7651). The redaction is
not claimed to be complete: after it a detector builds decoded views of every capture
(repeated case-insensitive percent-decoding, JSON \\u and \\/ unescaping, html.unescape, ANSI
sequences removed, the text joined across line wraps, `//` and `/./` collapsed) and the run
refuses to publish, naming the capture and the form, when a sensitive value shows in any of
these defined decoded views (#7698). Each decoder and the combined-decoder pass have an
eight-round bound, stopping earlier at a fixed point. Unsupported representations, including
base64 and lone-CR splitting, are not guaranteed detected (#7815). Every guarded
path is resolved with os.path.realpath before any containment test (#7650). The shell script's
defaults named build directories of one build host; they are replaced by
repo-relative ones. Exit codes: 0 success; 1 DEFAULT_BIN is not an executable
file, TMPDIR (or the default scratch directory) is outside <repo-root>/.local-runs, HOME is
not a usable absolute path, a fixture path is or became a symlink, operator keygen failed,
the git sha could not be read, the existing bundle does not match the manifest committed in
git HEAD, SANITIZATION.md has no single provenance line, a sensitive value remains in a
sanitized capture, or the transcript header date disagrees with the run date; 2 unknown
arguments.
"""
import argparse
import base64
import contextlib
import datetime
import errno
import fcntl
import hashlib
import html
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import urllib.parse
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
SANDBOX = LOCAL_RUNS / "cert-3607-sandbox"  # one <label>/{cwd,home} pair per child (#7608 #7648)
CHILD_HOMES = []  # the HOME of every child started in this run, labelled <home> in the evidence
LOCK_NAME = ".lock"
MANIFEST_NAME = "MANIFEST.sha256"
MANIFEST_REL = OUT.relative_to(ROOT).as_posix() + "/" + MANIFEST_NAME  # the path in git HEAD
SANITIZATION_NAME = "SANITIZATION.md"
PROVENANCE_PREFIX = "Provenance: posture captures recorded at tip `"
PROVENANCE_SUFFIX = (" (UTC); rewritten by scripts/recapture-cert-3607-posture.py on every "
                     "recapture.")
PROVENANCE_RE = re.compile(
    r"^" + re.escape(PROVENANCE_PREFIX) + r"([0-9a-f]{40})` on (\d{4}-\d{2}-\d{2})"
    + re.escape(PROVENANCE_SUFFIX) + r"$", re.MULTILINE)
STAGING_PREFIX = "staging-"
ASIDE_PREFIX = "old-"
RAW_PREFIX = "raw-"
BUNDLE_FILES = ("posture-bare-env.out", "posture-hardened-env.out",
                "posture-hardened-boot-refusal.out", "posture-sqlcipher-pass.out",
                "posture-legs-exit-codes.txt", "peer-fingerprints.txt", "peer-attestation.json")
MANIFEST_LINE_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")
DIR_MODE = 0o700
FILE_MODE = 0o600  # every file the script creates: local operator evidence (#7568)
USAGE_EPILOG = (
    "Environment overrides: DEFAULT_BIN (default <repo>/target/release/ai-memory, must be "
    "an executable file; a value with a slash is relative to the repo root, a bare name is "
    "looked up on the child PATH), SQLCIPHER_BIN (default <repo>/target-sqlcipher/release/ai-memory; "
    "leg 4 is recorded as `missing` when absent), TMPDIR (must resolve under "
    "<repo>/.local-runs, which must not be a symlink). HOME must be an absolute path in normal form (not /, no ':', not starting with '//', no control byte, no . or .. components) "
    "of printable ASCII only (any non-ASCII character is refused). Every child runs in its own fresh empty 0700 "
    "cwd in a per-child sandbox under <repo>/.local-runs with HOME beside it (no shared cwd; a store is passed by explicit path); staging, aside and raw capture directories also "
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
    """Replace every occurrence of each sensitive value, longest value first.

    The sensitive values are the per-child homes (labelled `<home>`), the fixtures root, the
    repo root and HOME (`<home>`), each as given and as its os.path.realpath. For each one
    exactly these forms are replaced: the raw text, the JSON-escaped text (with and without
    the `\\/` slash escape, once and twice) and the percent-encoded text (upper and lower hex,
    with and without an encoded slash). The replacement is NOT claimed to be complete: a form
    outside that list (mixed-case percent, `\\uXXXX` escapes of every character, HTML
    entities, a value split across a wrapped line, ANSI sequences inside it, `//` or `/./`
    segments) is not replaced here. The detector
    (leak_problem), which runs on every sanitized capture before anything is written and
    refuses the run, naming the capture and the form, when a sensitive value shows in any
    of its defined decoded views, subject to an eight-round bound for each decoder and the
    combined-decoder pass (stopping earlier at a fixed point). Unsupported representations,
    including base64 and lone-CR splitting, are not guaranteed detected (#7815). The listed forms
    of all the values
    are replaced in one pass over the forms sorted by length, longest first, so a value that is
    a prefix of another (HOME inside the repo root) never splits it. The replacement is a plain
    byte replacement of every literal occurrence: there is no delimiter allowlist, so any
    character may precede or follow the path. A longer path that shares the prefix
    (`/home/a` inside `/home/ab`) is over-redacted (`<home>b`); that is the accepted price and
    the evidence can lose detail. A `.` after a path (a sentence full stop) is replaced like any other character,
    and so is a `.` inside it. The sed the shell script used read each path as a regular expression; for every
    literal occurrence the two agree, and real output has no near-miss of a path. Line endings,
    including CRLF and a missing final newline, are preserved exactly (#7510, #7538, #7571,
    #7572, #7573, #7612, #7651, #7698)."""
    replacements = {}
    for value, label in sensitive_values():
        for form in value_forms(value):
            replacements.setdefault(form.encode("utf-8"), label)
    for form in sorted(replacements, key=len, reverse=True):  # longest first; ties keep order
        raw = raw.replace(form, replacements[form])
    return raw


class SensitiveValueRemains(Exception):
    """A sanitized capture still shows a sensitive value in a decoded view: the run refuses."""


ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
WRAP_RE = re.compile(r"\\?\r?\n[ \t]*")
NEWLINE_RE = re.compile(r"\r?\n")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
SLASH_RUN_RE = re.compile(r"/{2,}")
DECODE_ROUNDS = 8  # repeated decoding stops at a fixed point or after this many rounds


def _json_unescape(text):
    """JSON `\\uXXXX` (either hex case), `\\/` and `\\\\` turned back into their characters."""
    text = UNICODE_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 16)), text)
    return text.replace("\\/", "/").replace("\\\\", "\\")


def _collapse_slashes(text):
    """`//` runs and `/./` segments collapsed to one `/`."""
    text = SLASH_RUN_RE.sub("/", text)
    while "/./" in text:
        text = text.replace("/./", "/")
    return text


DECODERS = (
    ("percent-encoded", urllib.parse.unquote),
    ("JSON-escaped", _json_unescape),
    ("HTML-entity", html.unescape),
    ("ANSI-split", lambda text: ANSI_RE.sub("", text)),
    ("line-wrapped", lambda text: WRAP_RE.sub("", text)),
    ("line-wrapped (indentation kept)", lambda text: NEWLINE_RE.sub("", text)),
    ("doubled-slash", _collapse_slashes),
)


def decoded_views(text):
    """(form, text) of the capture as it is and under each decoding: repeated, case-insensitive
    percent-decoding; JSON `\\u` and `\\/` unescaping; html.unescape; ANSI sequences removed; the
    text joined across line wraps with the wrap characters removed; `//` and `/./` collapsed.
    Each decoding stops at a fixed point or after DECODE_ROUNDS (eight rounds); a last view
    applies all decoders in order, with the same round bound. Combined encodings are detected
    only when a sensitive value becomes visible within those decoded views."""
    views = [("raw", text)]
    for form, decode in DECODERS:
        view = text
        for _ in range(DECODE_ROUNDS):
            decoded = decode(view)
            if decoded == view:
                break
            view = decoded
        views.append((form, view))
    view = text
    for _ in range(DECODE_ROUNDS):
        before = view
        for _, decode in DECODERS:
            view = decode(view)
        if view == before:
            break
    views.append(("combined decodings", view))
    return views


def leak_problem(name, data):
    """A message naming the capture and the form when a sensitive value is still visible in any
    decoded view of the sanitized bytes data, else None. The value itself is never printed."""
    text = data.decode("utf-8", errors="replace")
    values = sensitive_values()
    for form, view in decoded_views(text):
        for value, label in values:
            if value in view:
                return ("%s still shows a sensitive value (%s) in its %s form after redaction"
                        % (name, label.decode(), form))
    return None


def sensitive_values():
    """(text, label) of every sensitive value: the per-child homes, the fixtures root, the repo
    root and HOME, each as given and as its realpath. Trailing slashes are dropped; an empty
    value is skipped."""
    pairs = [(home, b"<home>") for home in CHILD_HOMES]
    pairs.append((FIX, SANITIZED_FIXTURE_LABEL.encode()))
    pairs.append((ROOT, b"<repo-root>"))
    if HOME:
        pairs.append((HOME, b"<home>"))
    result = []
    for value, label in pairs:
        for text in (str(value), os.path.realpath(str(value))):
            text = text.rstrip("/")
            if text:
                result.append((text, label))
    return result


def value_forms(value):
    """The literal forms selected for replacement: raw, JSON-escaped (with and without the
    `\\/` slash escape, once and twice) and percent-encoded (upper and lower hex, with and
    without an encoded slash)."""
    forms = {value, value.replace("/", "\\/")}
    once = json.dumps(value)[1:-1]
    twice = json.dumps(once)[1:-1]
    for text in (once, twice):
        forms.update({text, text.replace("/", "\\/")})
    for safe in ("", "/"):
        quoted = urllib.parse.quote(value, safe=safe)
        forms.update({quoted, re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), quoted)})
    forms.discard("")
    return forms


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


def is_under(path, base):
    """True when path is base or lies below it (a string test on normalised paths; nothing is
    resolved here, so callers pass paths that already went through os.path.realpath)."""
    return path == base or base in path.parents


def real(path):
    """os.path.realpath of path as a Path: every symlink in it followed."""
    return Path(os.path.realpath(str(path)))


def open_parent(path):
    """(directory fd, name) for path, walking from ROOT without following any symlink."""
    absolute = Path(os.path.abspath(str(path)))
    if not is_under(absolute, ROOT):
        raise OSError(errno.EINVAL, "path is not under the repo root", str(path))
    relative = absolute.relative_to(ROOT)
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


def child_env(tmpdir, extra, home):
    """The scrubbed environment every binary invocation runs in (env -i). HOME is the child's
    own home (beside its cwd) and AI_MEMORY_NO_CONFIG=1 is set, so no leg opens a store it
    did not create (#7608, #7648)."""
    env = {
        "PATH": CHILD_PATH,
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "AI_MEMORY_NO_CONFIG": "1",
        "AI_MEMORY_AGENT_ID": "ai-memory",
        "AI_MEMORY_KEY_DIR": str(FIX / "keys"),
    }
    env.update(extra)
    return env


def child_dir(label):
    """A fresh empty 0700 cwd and a home beside it for one child: (cwd, home). Nothing is shared
    between children and a store a child makes dies with its directory (#7648). The home is
    registered so the sanitizer labels it `<home>`."""
    base = SANDBOX / label
    remove_tree(base)
    if os.path.lexists(str(base)):
        raise OSError(errno.EEXIST, "cannot remove the old child directory", str(base))
    ensure_dirs(base / "cwd")
    ensure_dirs(base / "home")
    CHILD_HOMES.append(base / "home")
    return base / "cwd", base / "home"


def exec_status(error):
    """The shell status for a binary that could not start: 127 not found, else 126."""
    return EXEC_NOT_FOUND if isinstance(error, FileNotFoundError) else EXEC_FAILED


def run_capture(binary, args, env, raw_path, sanitized_path, cwd):
    """Run one leg in cwd, sanitize its combined output, drop the raw file, return `$?`.

    A binary that cannot start has its error text as the leg output and status 127 when
    the file or its interpreter is missing (as the shell did), 126 for other exec errors
    such as ENOEXEC (the shell ran those through /bin/sh; this script refuses them)."""
    try:
        with os.fdopen(open_new(raw_path), "wb") as raw:
            try:
                status = shell_status(subprocess.run(
                    [str(binary)] + args, env=env, stdout=raw, cwd=str(cwd),
                    stderr=subprocess.STDOUT, check=False).returncode)
            except OSError as error:
                raw.write(("%s: %s\n" % (binary, error.strerror or error)).encode())
                status = exec_status(error)
        clean = sanitize(read_file(raw_path))
        leak = leak_problem(sanitized_path.name, clean)
        if leak is not None:
            raise SensitiveValueRemains(leak)  # nothing is written; the staging dir is dropped
        write_file(sanitized_path, clean)
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
    resolved = real(candidate)
    anchor = real(ROOT) / ".local-runs"
    if not is_under(resolved, anchor):
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
    anchor = real(ROOT) / ".local-runs"
    candidates = [LOCAL_RUNS, FIX]
    if FIX.is_dir() and not FIX.is_symlink():
        # every existing entry, so the key pair keygen writes (#7508) and anything else is covered
        for directory, names, files in os.walk(str(FIX)):
            candidates.extend(Path(directory) / name for name in names + files)
    for candidate in candidates:
        if candidate.is_symlink():
            return "%s is a symlink; fixtures hold keys and must stay inside %s" % (candidate, anchor)
    if not is_under(real(FIX), anchor):
        return "fixture directory %s resolves outside %s" % (FIX, anchor)
    return None


def ensure_dirs(path):
    """Create every missing directory of path below the repo root, each mode 0700.

    Walks from the root without following a symlink. A level this call creates is made 0700
    by os.mkdir and then fchmod'ed, so no umask widens it (#7569); a level that already
    exists is left as it is."""
    absolute = Path(os.path.abspath(str(path)))
    for base in (ROOT, real(ROOT)):
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
    """Every directory the script reads or writes through, outermost first.

    Each path is placed with os.path.realpath (its parent resolved, its last component kept so
    a symlink there is still seen as one) and must lie under the real repo root; one that
    cannot be placed raises OSError (fails closed). The TMPDIR chain is walked from the real
    .local-runs, so a symlinked repo root or a symlinked TMPDIR parent cannot hide a directory
    (#7650)."""
    root = real(ROOT)

    def place(path):
        path = Path(os.path.abspath(str(path)))
        placed = real(path.parent) / path.name if path != path.parent else path
        if not is_under(placed, root):
            raise OSError(errno.EINVAL, "guarded path is not under the real repo root", str(path))
        return placed

    out_parent = place(OUT.parent)
    chain = [root]
    chain.extend(root / part for part in _prefixes(out_parent.relative_to(root).parts))
    chain.extend(place(path) for path in (OUT, LOCAL_RUNS, WORK, FIX, FIX / "keys"))
    runs = place(LOCAL_RUNS)
    tmp = real(tmpdir)
    if not is_under(tmp, runs):
        raise OSError(errno.EINVAL, "TMPDIR is not under the real .local-runs", str(tmpdir))
    chain.extend(runs / part for part in _prefixes(tmp.relative_to(runs).parts))
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
    """An empty sandbox root for the per-child directories (#7608, #7648); an old one is removed."""
    remove_tree(SANDBOX)
    if os.path.lexists(str(SANDBOX)):
        raise OSError(errno.EEXIST, "cannot remove the old sandbox", str(SANDBOX))
    del CHILD_HOMES[:]
    ensure_dirs(SANDBOX)


def read_manifest(bundle):
    """(entries, problem) of bundle's MANIFEST.sha256: entries is a list of (sha256, name), or
    None when the bundle has no manifest; problem is a message naming the manifest line when it
    cannot be read or a line does not parse (a name with a slash is refused)."""
    try:
        text = read_file(bundle / MANIFEST_NAME).decode("utf-8")
    except FileNotFoundError:
        return None, None
    except (OSError, UnicodeDecodeError) as error:
        return None, "%s cannot be read: %s" % (MANIFEST_NAME, error)
    return parse_manifest(text)


def parse_manifest(text):
    """(entries, problem) of manifest text: entries is a list of (sha256, name)."""
    entries = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = MANIFEST_LINE_RE.match(line)
        if match is None:
            return None, "%s line %d does not parse: %r" % (MANIFEST_NAME, number, line)
        if "/" in match.group(2) or match.group(2) in (".", ".."):
            return None, "%s line %d lists %r, which is not a plain file name" % (
                MANIFEST_NAME, number, match.group(2))
        entries.append((match.group(1), match.group(2)))
    return entries, None


def manifest_problem(bundle):
    """A message naming the file when bundle does not match the MANIFEST.sha256 on disk in it,
    else None (also None when the bundle has no manifest). This is a COMPLETENESS test for the
    recovery of a killed run (bundle_complete); it trusts the file on disk and is not the
    integrity check: committed_bundle_problem is, against the manifest as committed in git.
    A listed file that is missing, is not a regular file or has another digest is a mismatch,
    and so is a manifest that lists nothing."""
    entries, problem = read_manifest(bundle)
    if problem is not None or entries is None:
        return problem
    if not entries:
        return "%s lists no file" % MANIFEST_NAME
    for digest, name in entries:
        try:
            data = read_file(bundle / name)
        except OSError as error:
            return "%s is listed in %s but cannot be read: %s" % (
                name, MANIFEST_NAME, error.strerror or error)
        if hashlib.sha256(data).hexdigest() != digest:
            return "%s does not match its digest in %s" % (name, MANIFEST_NAME)
    return None


def git_env(home):
    """The environment for a git child: the caller's, without any GIT_* variable (GIT_DIR,
    GIT_WORK_TREE and friends could point git at another repository), HOME in the child's home."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["HOME"] = str(home)
    return env


def committed_manifest():
    """(bytes, None) of MANIFEST.sha256 as committed at git HEAD (`git show HEAD:<path>`), or
    (None, message) when git cannot give it: this is the trust anchor, never the file on disk."""
    cwd, home = child_dir("manifest-git")
    try:
        done = subprocess.run(["git", "-C", str(ROOT), "show", "HEAD:./" + MANIFEST_REL],
                              env=git_env(home), cwd=str(cwd), capture_output=True, check=False)
    except OSError as error:
        return None, "git cannot be run to read the committed %s: %s" % (
            MANIFEST_REL, error.strerror or error)
    if done.returncode != 0:
        return None, "%s is not committed in git HEAD (%s)" % (
            MANIFEST_REL, done.stderr.decode(errors="replace").strip())
    return done.stdout, None


def bundle_tree(bundle):
    """(found, problems) for every entry under bundle, recursively and without following a
    link: found maps a relative name (a directory ends in `/`) to its kind; problems names each
    symlink and each entry that is neither a regular file nor a directory."""
    found, problems = {}, []

    def walk(directory, prefix):
        try:
            with os.scandir(str(directory)) as entries:
                listing = sorted(entries, key=lambda entry: entry.name)
        except OSError as error:
            problems.append("%s cannot be listed: %s" % (prefix or ".", error.strerror or error))
            return
        for entry in listing:
            name = prefix + entry.name
            if entry.is_symlink():
                problems.append("%s is a symlink" % name)
            elif entry.is_dir(follow_symlinks=False):
                found[name + "/"] = "directory"
                walk(directory / entry.name, name + "/")
            elif entry.is_file(follow_symlinks=False):
                found[name] = "file"
            else:
                problems.append("%s is neither a regular file nor a directory" % name)

    walk(Path(bundle), "")
    return found, problems


def committed_bundle_problem(bundle, committed):
    """A message naming every offender when bundle is not exactly what the manifest as committed
    in git HEAD (the bytes in committed) attests, else None (#7696). Required: the working-tree
    MANIFEST.sha256 is byte-identical to the committed one; the entries under the bundle,
    every regular file and every directory, recursively, equal the listed names exactly (a
    missing, extra or unlisted file or subdirectory refuses, and so does any symlink); every
    listed digest matches."""
    try:
        entries, problem = parse_manifest(committed.decode("utf-8"))
    except UnicodeDecodeError as error:
        return "the committed %s is not UTF-8: %s" % (MANIFEST_NAME, error)
    if problem is not None:
        return "the committed " + problem
    if not entries:
        return "the committed %s lists no file" % MANIFEST_NAME
    names = [name for _, name in entries]
    problems = ["%s is listed twice in the committed %s" % (name, MANIFEST_NAME)
                for name in sorted({n for n in names if names.count(n) > 1})]
    try:
        working = read_file(bundle / MANIFEST_NAME)
    except FileNotFoundError:
        problems.append("%s is deleted from the working tree but committed in git HEAD"
                        % MANIFEST_NAME)
    except OSError as error:
        problems.append("%s cannot be read: %s" % (MANIFEST_NAME, error.strerror or error))
    else:
        if working != committed:
            old, new = set(committed.splitlines()), set(working.splitlines())
            changed = sorted({line.decode(errors="replace").split("  ", 1)[-1]
                              for line in old ^ new})
            problems.append("the working-tree %s differs from the one committed in git HEAD "
                            "(changed lines: %s)" % (MANIFEST_NAME, ", ".join(changed) or "bytes"))
    found, tree_problems = bundle_tree(bundle)
    problems.extend(tree_problems)
    listed = set(names)
    for name in sorted(found):
        if name != MANIFEST_NAME and name not in listed:
            problems.append("%s is not listed in the committed %s" % (name, MANIFEST_NAME))
    for digest, name in entries:
        if found.get(name) != "file":
            problems.append("%s is listed in the committed %s but is missing or not a regular "
                            "file" % (name, MANIFEST_NAME))
            continue
        try:
            data = read_file(bundle / name)
        except OSError as error:
            problems.append("%s cannot be read: %s" % (name, error.strerror or error))
            continue
        if hashlib.sha256(data).hexdigest() != digest:
            problems.append("%s does not match its digest in the committed %s"
                            % (name, MANIFEST_NAME))
    return "; ".join(problems) or None


def bundle_complete(bundle):
    """True when bundle is a real directory whose MANIFEST.sha256 lists at least one file and
    every listed file is a regular file with the listed sha256."""
    try:
        if not stat.S_ISDIR(os.lstat(str(bundle)).st_mode):
            return False
    except OSError:
        return False
    entries, problem = read_manifest(bundle)
    return entries is not None and problem is None and manifest_problem(bundle) is None


def refresh_manifest(bundle, written):
    """Update MANIFEST.sha256 for the files this run freshly wrote, when the bundle has one.

    Only the names in written are hashed. Every other listed line is kept verbatim: this
    never re-hashes a file it did not write (#7649). A listed or written file that is gone is
    dropped, a written file that is not listed is added."""
    entries, problem = read_manifest(bundle)
    if problem is not None:
        raise OSError(errno.EINVAL, problem, str(bundle / MANIFEST_NAME))
    if entries is None:
        return
    digests = {}
    for digest, name in entries:
        digests.setdefault(name, digest)
    names = list(digests)
    names.extend(name for name in BUNDLE_FILES if name in written and name not in digests)
    names.extend(sorted(name for name in written if name not in digests and name not in BUNDLE_FILES))
    lines = []
    for name in names:
        path = bundle / name
        if not path.is_file() or path.is_symlink():
            continue
        digest = (hashlib.sha256(read_file(path)).hexdigest() if name in written
                  else digests[name])
        lines.append("%s  %s\n" % (digest, name))
    write_file(bundle / MANIFEST_NAME, "".join(lines).encode("utf-8"))


def provenance_line(full_sha, run_date):
    """The one provenance line of SANITIZATION.md for a recapture at full_sha on run_date."""
    return "%s%s` on %s%s" % (PROVENANCE_PREFIX, full_sha, run_date, PROVENANCE_SUFFIX)


def refresh_provenance(bundle, full_sha, run_date, written):
    """Rewrite the provenance line (tip sha, UTC date) of the staged SANITIZATION.md to this run
    and add the file to written, so the published manifest covers the updated file (#7699).
    A bundle without SANITIZATION.md is left alone; one whose file has no, or more than one,
    provenance line is refused: a message, else None."""
    path = bundle / SANITIZATION_NAME
    if not os.path.lexists(str(path)):
        return None
    try:
        text = read_file(path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return "%s cannot be read: %s" % (SANITIZATION_NAME, error)
    if len(PROVENANCE_RE.findall(text)) != 1:
        return ("%s must hold exactly one line of the form %r (tip sha and date); it holds %d"
                % (SANITIZATION_NAME, provenance_line("<40 hex>", "YYYY-MM-DD"),
                   len(PROVENANCE_RE.findall(text))))
    line = provenance_line(full_sha, run_date)
    write_file(path, PROVENANCE_RE.sub(lambda _match: line, text).encode("utf-8"))
    written.add(SANITIZATION_NAME)
    return None


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
    except SensitiveValueRemains as error:
        print("refusing to publish: %s; nothing was published" % error, file=sys.stderr)
        return 1
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
    try:
        make_sandbox()
        # HEAD is required even on a first run; an invalid root must never skip the anchor.
        committed, problem = committed_manifest()
        if problem is None:
            try:
                root_mode = os.lstat(str(OUT)).st_mode
            except FileNotFoundError:
                problem = "the bundle root must exist as a real directory"
            else:
                if not stat.S_ISDIR(root_mode):
                    problem = "the bundle root must be a real directory, never a symlink or file"
        if problem is None:
            problem = committed_bundle_problem(OUT, committed)
        if problem is not None:
            print("refusing to publish over a bundle that does not match its manifest as "
                  "committed in git HEAD: %s (%s); commit the evidence directory, or "
                  "restore it with git checkout, before recapturing" % (problem, OUT),
                  file=sys.stderr)
            return 1
        return build_and_publish(tmpdir, default_bin, sqlcipher_bin, sqlcipher_setting,
                                 run_date, committed)
    finally:
        remove_tree(SANDBOX)


def build_and_publish(tmpdir, default_bin, sqlcipher_bin, sqlcipher_setting, run_date,
                      committed):
    """Build the bundle in a staging directory and publish it when every leg succeeded."""
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
        copy_bundle(OUT, stage)
        problem = committed_bundle_problem(stage, committed)  # nothing changed since
        if problem is not None:
            print("refusing to publish: the staged copy of the bundle does not match its "
                  "manifest as committed in git HEAD: %s (%s)" % (problem, OUT),
                  file=sys.stderr)
            return 1
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
        keygen_cwd, keygen_home = child_dir("keygen")
        keygen_env = child_env(tmpdir, {}, keygen_home)
        keygen_env.pop("AI_MEMORY_AGENT_ID")
        try:
            with os.fdopen(open_new(keygen_out), "wb") as sink:
                keygen_status = subprocess.run(
                    [default_bin, "rules", "keygen"], env=keygen_env, cwd=str(keygen_cwd),
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

    written = {"posture-bare-env.out", "posture-hardened-env.out",
               "posture-hardened-boot-refusal.out", EXIT_CODES_FILE, "peer-fingerprints.txt",
               "peer-attestation.json"}
    # --- leg 1: bare ---
    cwd, home = child_dir("leg1")
    e1 = run_capture(default_bin, POSTURE_ARGS, child_env(tmpdir, {}, home),
                     raw_dir / "posture-bare-env.out.raw", out / "posture-bare-env.out", cwd)

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
    cwd, home = child_dir("leg2")
    e2 = run_capture(default_bin, POSTURE_ARGS, child_env(tmpdir, hard, home),
                     raw_dir / "posture-hardened-env.out.raw", out / "posture-hardened-env.out",
                     cwd)

    # --- leg 3: hardened non-sqlcipher, boot gate ARMED ---
    # Boot refuse is NOT doctor --posture (that subcommand bypasses the gate):
    # a plain `doctor` goes through main.
    armed = dict(hard)
    armed["AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE"] = "1"
    cwd, home = child_dir("leg3")
    e3 = run_capture(default_bin, ["doctor"], child_env(tmpdir, armed, home),
                     raw_dir / "posture-hardened-boot-refusal.out.raw",
                     out / "posture-hardened-boot-refusal.out", cwd)

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
            seed_cwd, seed_home = child_dir("seed")
            seed_env = child_env(tmpdir, leg4_env, seed_home)
            for name in ("AI_MEMORY_AGENT_ID", "AI_MEMORY_KEY_DIR"):
                seed_env.pop(name)
            try:
                subprocess.run([sqlcipher_bin, "stats", "--json"], env=seed_env,
                               cwd=str(seed_cwd), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False)
            except OSError:
                pass  # seeding failure is tolerated; the leg records its own exec status
        leg4 = dict(armed)
        leg4.update(leg4_env)
        cwd, home = child_dir("leg4")
        e4 = run_capture(sqlcipher_bin, POSTURE_ARGS, child_env(tmpdir, leg4, home),
                         raw_dir / "posture-sqlcipher-pass.out.raw",
                         out / "posture-sqlcipher-pass.out", cwd)
        written.add(SQLCIPHER_OUT_FILE)

    git_cwd, git_home = child_dir("git")
    sha_done = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                              env=git_env(git_home), cwd=str(git_cwd), capture_output=True,
                              text=True, check=False)
    sha = sha_done.stdout.strip()
    full_done = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                               env=git_env(git_home), cwd=str(git_cwd), capture_output=True,
                               text=True, check=False)
    full_sha = full_done.stdout.strip()
    if (sha_done.returncode != 0 or not sha or full_done.returncode != 0
            or not re.fullmatch(r"[0-9a-f]{40}", full_sha) or not full_sha.startswith(sha)):
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
    problem = refresh_provenance(out, full_sha, run_date, written)
    if problem is not None:
        print(problem, file=sys.stderr)
        return 1
    refresh_manifest(out, written)

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
