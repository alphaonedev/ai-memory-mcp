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
that this run did not produce). A symlinked .local-runs, fixtures directory, keys
directory or fixture file is refused before anything is written (#7462). The shell script's
defaults named build directories of one build host; they are replaced by
repo-relative ones. Exit codes: 0 success; 1 DEFAULT_BIN is not an executable
file, TMPDIR (or the default scratch directory) is outside <repo-root>/.local-runs, operator keygen failed, the git
sha could not be read, or the transcript header date disagrees with the run
date; 2 unknown arguments.
"""
import argparse
import base64
import datetime
import os
import re
import secrets
import shutil
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
DIR_MODE = 0o700
KEY_FILE_MODE = 0o600
USAGE_EPILOG = (
    "Environment overrides: DEFAULT_BIN (default <repo>/target/release/ai-memory, must be "
    "an executable file; a value with a slash is relative to the repo root, a bare name is "
    "looked up on the child PATH), SQLCIPHER_BIN (default <repo>/target-sqlcipher/release/ai-memory; "
    "leg 4 is recorded as `missing` when absent), TMPDIR (must resolve under "
    "<repo>/.local-runs, which must not be a symlink). Exit codes: 0 success; 1 preflight or capture failure; "
    "2 unknown arguments."
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
    newline, are preserved exactly."""
    out = raw.replace(str(ROOT).encode(), b"<repo-root>")
    out = out.replace(str(FIX).encode(), SANITIZED_FIXTURE_LABEL.encode())
    if HOME:
        out = out.replace(HOME.encode(), b"<home>")
    return out


def shell_status(returncode):
    """Map a subprocess return code to the shell's `$?` (128+n for signals)."""
    return 128 - returncode if returncode < 0 else returncode


def write_fixtures():
    """Create the keypair, peer fingerprints and attestation fixtures."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat)

    keys = FIX / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    os.chmod(keys, DIR_MODE)
    signing_key = Ed25519PrivateKey.generate()
    priv = signing_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    (keys / "ai-memory.priv").write_bytes(priv)
    (keys / "ai-memory.pub").write_bytes(pub)
    os.chmod(keys / "ai-memory.priv", KEY_FILE_MODE)
    os.chmod(keys / "ai-memory.pub", KEY_FILE_MODE)
    (FIX / "operator.pub.b64").write_text(base64.b64encode(pub).decode() + "\n")
    (FIX / "peer-fingerprints.txt").write_text("peer-a.fleet.example " + PEER_FINGERPRINT + "\n")
    (FIX / "peer-attestation.json").write_text(PEER_ATTESTATION)
    print("fixtures ok", keys)


def child_env(tmpdir, extra):
    """The scrubbed environment every binary invocation runs in (env -i)."""
    env = {
        "PATH": CHILD_PATH,
        "HOME": HOME,
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
        with open(str(raw_path), "wb") as raw:
            try:
                status = shell_status(subprocess.run(
                    [str(binary)] + args, env=env, stdout=raw,
                    stderr=subprocess.STDOUT, check=False).returncode)
            except OSError as error:
                raw.write(("%s: %s\n" % (binary, error.strerror or error)).encode())
                status = exec_status(error)
        sanitized_path.write_bytes(sanitize(raw_path.read_bytes()))
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
    """A message when the fixture tree has a symlink between ROOT and a fixture file, else None."""
    anchor = ROOT.resolve() / ".local-runs"
    candidates = [LOCAL_RUNS, FIX, FIX / "keys"] + [
        FIX / "keys" / "ai-memory.priv", FIX / "keys" / "ai-memory.pub",
        FIX / "operator.pub.b64", FIX / "peer-fingerprints.txt", FIX / "peer-attestation.json",
        FIX / "keygen.out", FIX / "db-passphrase", FIX / "leg4-sqlcipher.db"]
    for candidate in candidates:
        if candidate.is_symlink():
            return "%s is a symlink; fixtures hold keys and must stay inside %s" % (candidate, anchor)
    try:
        FIX.resolve().relative_to(anchor)
    except ValueError:
        return "fixture directory %s resolves outside %s" % (FIX, anchor)
    return None


def ensure_private_dir(directory):
    """Create directory (and parents) and chmod 0700 it only when this call created it."""
    existed = directory.exists()
    directory.mkdir(parents=True, exist_ok=True)
    if not existed:
        os.chmod(directory, DIR_MODE)


def is_executable_file(candidate):
    """True when candidate is a regular file the current user can execute."""
    return os.path.isfile(candidate) and os.access(candidate, os.X_OK)


def main(argv=None):
    parse_args(sys.argv[1:] if argv is None else argv)
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
    problem = fixture_symlink_problem()
    if problem is not None:
        print(problem, file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    FIX.mkdir(parents=True, exist_ok=True)
    os.chmod(FIX, DIR_MODE)  # holds the passphrase and keys: tightened on every run
    ensure_private_dir(tmpdir)

    write_fixtures()

    # #3199 check #22 (backup-manifest signing): the certified configuration
    # carries the operator key pair in the key dir.
    if not (FIX / "keys" / "operator.key").is_file():
        keygen_out = FIX / "keygen.out"
        keygen_env = child_env(tmpdir, {})
        keygen_env.pop("AI_MEMORY_AGENT_ID")
        try:
            with open(str(keygen_out), "wb") as sink:
                keygen_status = subprocess.run(
                    [default_bin, "rules", "keygen"], env=keygen_env,
                    stdout=sink, stderr=subprocess.STDOUT, check=False).returncode
        except OSError as error:
            print("operator keygen failed: %s: %s" % (default_bin, error.strerror or error),
                  file=sys.stderr)
            return 1
        if keygen_status != 0:
            print("operator keygen failed: " + keygen_out.read_text(errors="replace").rstrip("\n"),
                  file=sys.stderr)
            return 1
    op_pub_file = FIX / "keys" / "operator.key.pub"
    if not op_pub_file.is_file():
        op_pub_file = FIX / "operator.pub.b64"
    op_pub = op_pub_file.read_text().replace("\n", "")
    attest = (FIX / "peer-attestation.json").read_text().rstrip("\n")

    posture_env = child_env(tmpdir, {})
    # --- leg 1: bare ---
    e1 = run_capture(default_bin, POSTURE_ARGS, posture_env,
                     OUT / "posture-bare-env.out.raw", OUT / "posture-bare-env.out")

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
                     OUT / "posture-hardened-env.out.raw", OUT / "posture-hardened-env.out")

    # --- leg 3: hardened non-sqlcipher, boot gate ARMED ---
    # Boot refuse is NOT doctor --posture (that subcommand bypasses the gate):
    # a plain `doctor` goes through main.
    armed = dict(hard)
    armed["AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE"] = "1"
    e3 = run_capture(default_bin, ["doctor"], child_env(tmpdir, armed),
                     OUT / "posture-hardened-boot-refusal.out.raw",
                     OUT / "posture-hardened-boot-refusal.out")

    # --- leg 4: sqlcipher + encrypt + boot gate ---
    if sqlcipher_bin is None or not is_executable_file(sqlcipher_bin):
        print("sqlcipher binary missing: " + (sqlcipher_bin or sqlcipher_setting), file=sys.stderr)
        print("leg4 skipped")
        e4 = "missing"
        stale = OUT / SQLCIPHER_OUT_FILE
        if stale.is_file() or stale.is_symlink():
            stale.unlink()  # never ship the previous run's leg-4 capture (#7463)
    else:
        # #3553 check #21 observes the LIVE pragma on the store the sqlcipher
        # build can open only with a passphrase.
        passphrase_file = FIX / "db-passphrase"
        if not passphrase_file.is_file():
            fd = os.open(str(passphrase_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(secrets.token_hex(PASSPHRASE_BYTES))
        passphrase = passphrase_file.read_text().replace("\n", "")
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
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            except OSError:
                pass  # seeding failure is tolerated; the leg records its own exec status
        leg4 = dict(armed)
        leg4.update(leg4_env)
        e4 = run_capture(sqlcipher_bin, POSTURE_ARGS, child_env(tmpdir, leg4),
                         OUT / "posture-sqlcipher-pass.out.raw", OUT / "posture-sqlcipher-pass.out")

    sha_done = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, check=False)
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
    (OUT / EXIT_CODES_FILE).write_text(transcript, encoding="utf-8")
    problem = check_header_date(OUT / EXIT_CODES_FILE, run_date)
    if problem is not None:
        print(problem, file=sys.stderr)
        return 1

    for name in ("peer-fingerprints.txt", "peer-attestation.json"):
        (OUT / name).write_bytes((FIX / name).read_bytes())

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
    return 0


if __name__ == "__main__":
    sys.exit(main())
