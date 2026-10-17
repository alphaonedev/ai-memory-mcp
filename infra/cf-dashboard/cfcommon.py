"""cfcommon.py - shared credential lookup and wrangler runner for deploy.py and push-state.py (#7313).

Credential precedence (one rule for both scripts): the process environment first, then the FIRST
matching line of the home env file (cfcommon.ENV_FILE; the file is never sourced).
A line may start with an optional `export ` and the value may carry one matching quote pair.
The account id must be 32 lowercase hex characters before it is placed in any URL. Failure
messages are fixed strings and never echo a credential value.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

TOKEN_VAR = "CLOUDFLARE_API_TOKEN"
ACCOUNT_VAR = "CLOUDFLARE_ACCOUNT_ID"
ENV_FILE = ".env"
ACCOUNT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
PROJECT = "agenticmem-test"
WRANGLER_TIMEOUT_S = 600
EXPORT_PREFIX = "export "
QUOTES = "\"'"


class CredentialError(Exception):
    """Raised with a fixed message that never contains a credential value."""


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in QUOTES:
        return value[1:-1]
    return value


def credential(name):
    """Process env value, else the first `name=` line of the home env file; empty string when absent."""
    if os.environ.get(name):
        return os.environ[name]
    try:
        for ln in (Path.home() / ENV_FILE).read_text().splitlines():
            ln = ln.strip()
            if ln.startswith(EXPORT_PREFIX):
                ln = ln[len(EXPORT_PREFIX):].lstrip()
            key, sep, rest = ln.partition("=")
            if sep and key.strip() == name:
                return _unquote(rest)
    except FileNotFoundError:
        return ""  # no env file is the normal case
    except OSError as exc:
        # fixed message: the exception type only, never a path or a credential value
        print("warning: home env file is unreadable (%s)" % type(exc).__name__, file=sys.stderr)
    return ""


def valid_account_id(value):
    """True only for a 32-character lowercase hex account id."""
    return bool(ACCOUNT_ID_RE.match(value or ""))


def load_credentials(require_account):
    """Return (token, account_id); raise CredentialError (fixed message) on a missing/invalid value."""
    token = credential(TOKEN_VAR)
    if not token:
        raise CredentialError("%s is missing (process env or the home env file)" % TOKEN_VAR)
    acct = credential(ACCOUNT_VAR)
    if require_account and not acct:
        raise CredentialError("%s is missing (process env or the home env file)" % ACCOUNT_VAR)
    if acct and not valid_account_id(acct):
        raise CredentialError("%s is not a 32-character lowercase hex id" % ACCOUNT_VAR)
    return token, acct


def run_wrangler(env, cwd):
    """Run `wrangler pages deploy public`; return the CompletedProcess, or None on timeout."""
    try:
        return subprocess.run(["wrangler", "pages", "deploy", "public", "--project-name", PROJECT,
                               "--branch", "main", "--commit-dirty=true"], cwd=cwd, env=env,
                              capture_output=True, text=True, timeout=WRANGLER_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return None
