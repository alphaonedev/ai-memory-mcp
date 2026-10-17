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
recorded as `missing` when it is absent) and TMPDIR. The shell script's defaults
named build directories of one build host; they are replaced by repo-relative ones. Exit codes: 0 success; 1 operator keygen failed, the git sha could
not be read, or the transcript header date disagrees with the run date.
"""
import base64
import datetime
import os
import re
import secrets
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
SUMMARY_FILES = ("posture-bare-env.out", "posture-hardened-env.out", "posture-sqlcipher-pass.out")
PASSPHRASE_BYTES = 32


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
    """Collapse absolute repo, fixture and home paths (same order as the shell sed)."""
    out = raw.replace(str(ROOT).encode(), b"<repo-root>")
    out = out.replace(str(FIX).encode(), SANITIZED_FIXTURE_LABEL.encode())
    if HOME:
        out = out.replace(HOME.encode(), b"<home>")
    if out and not out.endswith(b"\n"):
        out += b"\n"  # sed terminates the final line
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
    os.chmod(keys, 0o700)
    signing_key = Ed25519PrivateKey.generate()
    priv = signing_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    (keys / "ai-memory.priv").write_bytes(priv)
    (keys / "ai-memory.pub").write_bytes(pub)
    os.chmod(keys / "ai-memory.priv", 0o600)
    os.chmod(keys / "ai-memory.pub", 0o644)
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


def run_capture(binary, args, env, raw_path, sanitized_path):
    """Run one leg, sanitize its combined output, drop the raw file, return `$?`."""
    with open(str(raw_path), "wb") as raw:
        done = subprocess.run([str(binary)] + args, env=env, stdout=raw,
                              stderr=subprocess.STDOUT, check=False)
    sanitized_path.write_bytes(sanitize(raw_path.read_bytes()))
    raw_path.unlink()
    return shell_status(done.returncode)


def count_rows(path, marker):
    """grep -c: the number of lines containing marker."""
    return sum(1 for line in path.read_text(errors="replace").splitlines() if marker in line)


def main():
    run_date = utc_run_date()
    default_bin = os.environ.get("DEFAULT_BIN", DEFAULT_BIN_FALLBACK)
    sqlcipher_bin = os.environ.get("SQLCIPHER_BIN", SQLCIPHER_BIN_FALLBACK)
    tmpdir = Path(os.environ.get("TMPDIR") or str(ROOT / ".local-runs" / "tmp"))
    for directory in (OUT, FIX, tmpdir):
        directory.mkdir(parents=True, exist_ok=True)
    os.chmod(FIX, 0o700)
    os.chmod(tmpdir, 0o700)

    write_fixtures()

    # #3199 check #22 (backup-manifest signing): the certified configuration
    # carries the operator key pair in the key dir.
    if not (FIX / "keys" / "operator.key").is_file():
        keygen_out = FIX / "keygen.out"
        with open(str(keygen_out), "wb") as sink:
            keygen_env = child_env(tmpdir, {})
            keygen_env.pop("AI_MEMORY_AGENT_ID")
            done = subprocess.run([default_bin, "rules", "keygen"], env=keygen_env,
                                  stdout=sink, stderr=subprocess.STDOUT, check=False)
        if done.returncode != 0:
            print("operator keygen failed: " + keygen_out.read_text(errors="replace"), file=sys.stderr)
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
    if not (os.path.isfile(sqlcipher_bin) and os.access(sqlcipher_bin, os.X_OK)):
        print("sqlcipher binary missing: " + sqlcipher_bin, file=sys.stderr)
        print("leg4 skipped")
        e4 = "missing"
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
            subprocess.run([sqlcipher_bin, "stats", "--json"], env=seed_env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
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
