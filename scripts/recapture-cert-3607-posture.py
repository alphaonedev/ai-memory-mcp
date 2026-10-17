#!/usr/bin/env python3
"""Recapture the four-leg `doctor --posture enterprise-federation` evidence of a cert.

Recaptures the section 2 four-leg evidence of one certification bundle. `--cert`
picks the bundle (default `3607`); the 22-check certs are the #3607 re-issue
(+#3553 synchronous, +#3199 backup signing) and the 20-check cert is `55`.
Docs/evidence only.

Ported from `scripts/recapture-cert-3607-posture.sh` (python-not-shell standing
rule) and, for #4829 #4830 #4882 #4886, from the sibling shell scripts
`recapture-cert-55-posture.sh`, `recapture-cert-9220-posture.sh`,
`recapture-cert-eba96b307-posture.sh` and `recapture-cert-f32c-posture.sh`, which
were copies of it. The outputs of each cert are byte-for-byte those of its shell
script, with these deliberate changes:
- #5038: the first line of `posture-legs-exit-codes.txt` carries the UTC date of
  the run, not a fixed template date, and the script checks the header it wrote.
- #4829: the fixture directory is derived from the repository root. There is no
  `FIX` variable and no working-directory fallback, so the script runs from any
  directory.
- The leg-4 database passphrase reaches the child through its environment only;
  it is on no argv. A passphrase file that cannot be read or is empty exits 70
  before the child runs.
- #5039 part B (3-agent vote 6def5ab6, memory 94ac022e): the fixture path in the
  sanitized output is the generic SANITIZED_FIXTURE_LABEL, not a label derived
  from the fixture directory name. The fixture directory is collapsed BEFORE the
  repository root (the old order made that replacement a no-op, so the label was
  the directory name). No existing bundle byte changes; the new label first
  appears in the next re-issue, whose 12/12 sanitized-fixture check runs as
  relabel_fixture_label (new label back to previous_fixture_label) then compare.

Environment overrides: DEFAULT_BIN (default <repo>/target/release/ai-memory),
SQLCIPHER_BIN (default <repo>/target-sqlcipher/release/ai-memory; leg 4 is
recorded as `missing` when it is absent) and TMPDIR. The shell scripts' defaults
named build directories of one build host; they are replaced by repo-relative ones.

The 22-check certs end by asserting the recorded ladder through
scripts/check-posture-ladder.py (#5036): legs 2/2/1/0, the exact PASS/FAIL
counts, a strictly falling FAIL count, a named leg-3 refusal and distinct
default/sqlcipher binaries. A skipped leg 4 (no sqlcipher binary) therefore exits
non-zero. The gate pins the 22-check counts, so the 20-check cert `55` does not
run it.

Exit codes: 0 success and ladder asserted green; 1 operator keygen failed, the git
sha could not be read, the transcript header date disagrees with the run date, or
the ladder gate found a violation; 2 an unknown --cert, or the ladder gate could
not read the evidence; 70 the leg-4 passphrase file is unreadable or empty.
"""
import argparse
import base64
import collections
import datetime
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.path.abspath(__file__)).parent.parent  # logical path, like `cd .. && pwd`
EVIDENCE_DIR = ROOT / "docs" / "compliance" / "evidence"
FIXTURE_PARENT = ROOT / ".local-runs"
DEFAULT_BIN_FALLBACK = str(ROOT / "target" / "release" / "ai-memory")
SQLCIPHER_BIN_FALLBACK = str(ROOT / "target-sqlcipher" / "release" / "ai-memory")
HOME = os.environ.get("HOME", "")
CHILD_PATH = "/usr/bin:/bin:" + HOME + "/.cargo/bin"
LADDER_GATE = "check-posture-ladder.py"
EXIT_CODES_FILE = "posture-legs-exit-codes.txt"
SANITIZED_FIXTURE_LABEL = "<repo-root>/.local-runs/<cert-fixtures>"
HEADER_TEMPLATE = (
    "# posture-legs transcript — recorded exit codes "
    "({date} {label} @ {sha})"
)
HEADER_RE = re.compile(r"^# posture-legs transcript — recorded exit codes \((\d{4}-\d{2}-\d{2}) ")
POSTURE_ARGS = ["doctor", "--posture", "enterprise-federation"]
PEER_FINGERPRINT = "1111111111111111111111111111111111111111111111111111111111111111"
PEER_ATTESTATION = (
    '{"peer-a":{"allowed_sender_agent_ids":["agent-a"],'
    '"allowed_namespaces":["team-x/ops","team-x/shared"]}}\n'
)
SUMMARY_FILES = ("posture-bare-env.out", "posture-hardened-env.out", "posture-sqlcipher-pass.out")
PASSPHRASE_BYTES = 32
EXIT_PASSPHRASE = 70  # EX_SOFTWARE: the secret could not be read, the child never ran
DEFAULT_CERT = "3607"

# Per-cert facts. `rev22` marks the 22-check generation: keygen for check #22
# (#3199), DB_SYNCHRONOUS for check #21 (#3553), the encrypted leg-4 store with its
# passphrase, and the ladder assertion (#5036).
CertProfile = collections.namedtuple("CertProfile", "cert_dir header_label rev22")
CERT_PROFILES = {
    "3607": CertProfile("cert-3607", "#3607 re-issue recapture (22 checks)", True),
    "92209ad91": CertProfile("cert-92209ad91", "92209ad91 re-issue recapture (22 checks)", True),
    "eba96b307": CertProfile("cert-eba96b307", "#3607 re-issue recapture (22 checks)", True),
    "f32c18dad": CertProfile("cert-f32c18dad", "f32c18dad re-issue recapture (22 checks)", True),
    "55": CertProfile("cert-55", "recapture", False),
}
# The shell scripts' file-name tokens, accepted so old commands keep working.
CERT_ALIASES = {"9220": "92209ad91", "f32c": "f32c18dad"}


class CertRun(object):
    """The paths and flags of one cert recapture, derived from the repository root."""

    def __init__(self, cert_id):
        profile = CERT_PROFILES[CERT_ALIASES.get(cert_id, cert_id)]
        self.out = EVIDENCE_DIR / profile.cert_dir
        self.fix = FIXTURE_PARENT / (profile.cert_dir + "-fixtures")
        self.header_label = profile.header_label
        self.rev22 = profile.rev22


def utc_run_date():
    """The UTC calendar date of this run, as YYYY-MM-DD."""
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def header_line(run_date, sha, label=CERT_PROFILES[DEFAULT_CERT].header_label):
    """First line of the exit-code transcript."""
    return HEADER_TEMPLATE.format(date=run_date, label=label, sha=sha)


def check_header_date(transcript_path, run_date):
    """Return None when the transcript header carries run_date, else a message."""
    first = Path(transcript_path).read_text(encoding="utf-8").split("\n", 1)[0]
    match = HEADER_RE.match(first)
    if match is None:
        return "transcript header is not in the expected shape: " + first
    if match.group(1) != run_date:
        return "transcript header date %s is not the run date %s" % (match.group(1), run_date)
    return None


def previous_fixture_label(cert_dir):
    """The label the existing bundles carry: it was the fixture directory name."""
    return "<repo-root>/.local-runs/" + cert_dir + "-fixtures"


def relabel_fixture_label(data, old_label, new_label):
    """Swap one fixture label for another in sanitized bytes (re-issue byte-identity check)."""
    return data.replace(old_label.encode(), new_label.encode())


def sanitize(raw, run):
    """Collapse absolute fixture, repo and home paths, the fixture directory first.

    The fixture directory lives under the repository root, so replacing the root
    first would leave nothing for the generic fixture label to replace.
    """
    out = raw.replace(str(run.fix).encode(), SANITIZED_FIXTURE_LABEL.encode())
    out = out.replace(str(ROOT).encode(), b"<repo-root>")
    if HOME:
        out = out.replace(HOME.encode(), b"<home>")
    if out and not out.endswith(b"\n"):
        out += b"\n"  # sed terminates the final line
    return out


def shell_status(returncode):
    """Map a subprocess return code to the shell's `$?` (128+n for signals)."""
    return 128 - returncode if returncode < 0 else returncode


def write_fixtures(run):
    """Create the keypair, peer fingerprints and attestation fixtures."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat)

    keys = run.fix / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    os.chmod(keys, 0o700)
    signing_key = Ed25519PrivateKey.generate()
    priv = signing_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    (keys / "ai-memory.priv").write_bytes(priv)
    (keys / "ai-memory.pub").write_bytes(pub)
    os.chmod(keys / "ai-memory.priv", 0o600)
    os.chmod(keys / "ai-memory.pub", 0o644)
    (run.fix / "operator.pub.b64").write_text(base64.b64encode(pub).decode() + "\n")
    (run.fix / "peer-fingerprints.txt").write_text("peer-a.fleet.example " + PEER_FINGERPRINT + "\n")
    (run.fix / "peer-attestation.json").write_text(PEER_ATTESTATION)
    print("fixtures ok", keys)


def child_env(run, tmpdir, extra):
    """The scrubbed environment every binary invocation runs in (env -i)."""
    env = {
        "PATH": CHILD_PATH,
        "HOME": HOME,
        "TMPDIR": str(tmpdir),
        "AI_MEMORY_NO_CONFIG": "1",
        "AI_MEMORY_AGENT_ID": "ai-memory",
        "AI_MEMORY_KEY_DIR": str(run.fix / "keys"),
    }
    env.update(extra)
    return env


def run_capture(run, binary, args, env, raw_path, sanitized_path):
    """Run one leg, sanitize its combined output, drop the raw file, return `$?`."""
    with open(str(raw_path), "wb") as raw:
        done = subprocess.run([str(binary)] + args, env=env, stdout=raw,
                              stderr=subprocess.STDOUT, check=False)
    sanitized_path.write_bytes(sanitize(raw_path.read_bytes(), run))
    raw_path.unlink()
    return shell_status(done.returncode)


def count_rows(path, marker):
    """grep -c: the number of lines containing marker."""
    return sum(1 for line in path.read_text(errors="replace").splitlines() if marker in line)


def assert_ladder(run, default_bin, sqlcipher_bin):
    """Assert the recorded ladder (#5036); return the gate's exit status.

    The evidence written above is kept whatever the verdict, so a red run can be
    diagnosed. Both binaries are handed to the gate only when leg 4 could run: a
    skipped leg 4 (`missing` in the transcript) is itself a violation.
    """
    sys.stdout.flush()  # the gate writes to the same stream: keep the order when piped
    gate_args = [sys.executable, str(ROOT / "scripts" / LADDER_GATE), str(run.out)]
    if os.path.isfile(sqlcipher_bin) and os.access(sqlcipher_bin, os.X_OK):
        gate_args += ["--default-bin", default_bin, "--sqlcipher-bin", sqlcipher_bin]
    return subprocess.run(gate_args, check=False).returncode


def read_secret(path):
    """The contents of a secret file with newlines removed, or None when unusable."""
    try:
        value = path.read_text().replace("\n", "")
    except OSError:
        return None
    return value or None


def leg4_environment(run, tmpdir, armed, sqlcipher_bin):
    """The leg-4 variables, or None when the passphrase is unusable.

    The 22-check generation also seeds the encrypted fixture store. The passphrase
    travels in the child's environment only, never on an argv.
    """
    if not run.rev22:
        return dict(armed)
    # #3553 check #21 observes the LIVE pragma on the store the sqlcipher
    # build can open only with a passphrase.
    passphrase_file = run.fix / "db-passphrase"
    if not passphrase_file.is_file():
        fd = os.open(str(passphrase_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(secrets.token_hex(PASSPHRASE_BYTES))
    passphrase = read_secret(passphrase_file)
    if passphrase is None:
        print("cannot read the leg-4 passphrase file: " + str(passphrase_file), file=sys.stderr)
        return None
    store = run.fix / "leg4-sqlcipher.db"
    store_env = {"AI_MEMORY_DB": str(store), "AI_MEMORY_DB_PASSPHRASE": passphrase}
    if not store.is_file():
        # doctor opens the store read-only and refuses to create it: seed
        # the encrypted fixture store first (schema-init). Failure tolerated.
        seed_env = child_env(run, tmpdir, store_env)
        for name in ("AI_MEMORY_AGENT_ID", "AI_MEMORY_KEY_DIR"):
            seed_env.pop(name)
        subprocess.run([sqlcipher_bin, "stats", "--json"], env=seed_env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    leg4 = dict(armed)
    leg4.update(store_env)
    return leg4


def parse_args(argv):
    """The command line: which cert bundle to recapture."""
    parser = argparse.ArgumentParser(
        description="Recapture the four-leg doctor --posture evidence of one cert bundle.")
    parser.add_argument("--cert", default=DEFAULT_CERT,
                        choices=sorted(CERT_PROFILES) + sorted(CERT_ALIASES),
                        help="cert bundle to recapture (default %(default)s)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    run = CertRun(args.cert)
    run_date = utc_run_date()
    default_bin = os.environ.get("DEFAULT_BIN", DEFAULT_BIN_FALLBACK)
    sqlcipher_bin = os.environ.get("SQLCIPHER_BIN", SQLCIPHER_BIN_FALLBACK)
    tmpdir = Path(os.environ.get("TMPDIR") or str(ROOT / ".local-runs" / "tmp"))
    for directory in (run.out, run.fix, tmpdir):
        directory.mkdir(parents=True, exist_ok=True)
    os.chmod(run.fix, 0o700)
    os.chmod(tmpdir, 0o700)

    write_fixtures(run)

    op_pub_file = run.fix / "operator.pub.b64"
    if run.rev22:
        # #3199 check #22 (backup-manifest signing): the certified configuration
        # carries the operator key pair in the key dir.
        if not (run.fix / "keys" / "operator.key").is_file():
            keygen_out = run.fix / "keygen.out"
            with open(str(keygen_out), "wb") as sink:
                keygen_env = child_env(run, tmpdir, {})
                keygen_env.pop("AI_MEMORY_AGENT_ID")
                done = subprocess.run([default_bin, "rules", "keygen"], env=keygen_env,
                                      stdout=sink, stderr=subprocess.STDOUT, check=False)
            if done.returncode != 0:
                print("operator keygen failed: " + keygen_out.read_text(errors="replace"), file=sys.stderr)
                return 1
        if (run.fix / "keys" / "operator.key.pub").is_file():
            op_pub_file = run.fix / "keys" / "operator.key.pub"
    op_pub = op_pub_file.read_text().replace("\n", "")
    attest = (run.fix / "peer-attestation.json").read_text().rstrip("\n")

    posture_env = child_env(run, tmpdir, {})
    # --- leg 1: bare ---
    e1 = run_capture(run, default_bin, POSTURE_ARGS, posture_env,
                     run.out / "posture-bare-env.out.raw", run.out / "posture-bare-env.out")

    hard = {
        "AI_MEMORY_SECURITY_PROFILE": "asi-hard",
        "AI_MEMORY_FED_TRUST_DOMAIN": "cert-fleet-01",
        "AI_MEMORY_FED_PEER_FINGERPRINTS": str(run.fix / "peer-fingerprints.txt"),
        "AI_MEMORY_FED_PEER_ATTESTATION": attest,
        "AI_MEMORY_ENCRYPT_AT_REST": "1",
        "AI_MEMORY_APPEND_ONLY": "1",
        "AI_MEMORY_OPERATOR_PUBKEY": op_pub,
    }
    if run.rev22:
        hard["AI_MEMORY_DB_SYNCHRONOUS"] = "FULL"
    # --- leg 2: hardened non-sqlcipher, boot gate NOT armed ---
    e2 = run_capture(run, default_bin, POSTURE_ARGS, child_env(run, tmpdir, hard),
                     run.out / "posture-hardened-env.out.raw", run.out / "posture-hardened-env.out")

    # --- leg 3: hardened non-sqlcipher, boot gate ARMED ---
    # Boot refuse is NOT doctor --posture (that subcommand bypasses the gate):
    # a plain `doctor` goes through main.
    armed = dict(hard)
    armed["AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE"] = "1"
    e3 = run_capture(run, default_bin, ["doctor"], child_env(run, tmpdir, armed),
                     run.out / "posture-hardened-boot-refusal.out.raw",
                     run.out / "posture-hardened-boot-refusal.out")

    # --- leg 4: sqlcipher + encrypt + boot gate ---
    if not (os.path.isfile(sqlcipher_bin) and os.access(sqlcipher_bin, os.X_OK)):
        print("sqlcipher binary missing: " + sqlcipher_bin, file=sys.stderr)
        print("leg4 skipped")
        e4 = "missing"
    else:
        leg4 = leg4_environment(run, tmpdir, armed, sqlcipher_bin)
        if leg4 is None:
            return EXIT_PASSPHRASE
        e4 = run_capture(run, sqlcipher_bin, POSTURE_ARGS, child_env(run, tmpdir, leg4),
                         run.out / "posture-sqlcipher-pass.out.raw", run.out / "posture-sqlcipher-pass.out")

    sha_done = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, check=False)
    sha = sha_done.stdout.strip()
    if sha_done.returncode != 0 or not sha:
        print("cannot read the git sha of " + str(ROOT), file=sys.stderr)
        return 1
    transcript = "\n".join([
        header_line(run_date, sha, run.header_label),
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
    (run.out / EXIT_CODES_FILE).write_text(transcript, encoding="utf-8")
    problem = check_header_date(run.out / EXIT_CODES_FILE, run_date)
    if problem is not None:
        print(problem, file=sys.stderr)
        return 1

    for name in ("peer-fingerprints.txt", "peer-attestation.json"):
        (run.out / name).write_bytes((run.fix / name).read_bytes())

    print("exits e1=%s e2=%s e3=%s e4=%s" % (e1, e2, e3, e4))
    print("FAIL/PASS counts:")
    for name in SUMMARY_FILES:
        path = run.out / name
        if path.is_file():
            sys.stdout.write("%s FAIL=%d PASS=%d " % (name, count_rows(path, "[FAIL]"), count_rows(path, "[PASS]")))
            for line in path.read_text(errors="replace").splitlines():
                if "overall:" in line:
                    print(line)
    if not run.rev22:
        return 0
    return assert_ladder(run, default_bin, sqlcipher_bin)


if __name__ == "__main__":
    sys.exit(main())
