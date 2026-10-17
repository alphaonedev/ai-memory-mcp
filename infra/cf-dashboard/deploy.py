#!/usr/bin/env python3
"""deploy.py - stand up the realtime campaign dashboard on Cloudflare Pages at test.agenticmem.co.

Port of the former deploy.sh (#7313). Pages-only (no KV/Workers scope needed). Idempotent-ish.

Credentials (never committed; wrangler.toml carries no account id): see cfcommon.py. Process env
first, then the FIRST matching line of the home env file (cfcommon.ENV_FILE); the account id must be 32 lowercase hex characters.

Exit codes: 0 ok, 1 missing credentials or an API/deploy failure.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cfcommon  # noqa: E402

HERE = Path(__file__).resolve().parent
PROJECT = cfcommon.PROJECT
DOMAIN = "test.agenticmem.co"
API = "https://api.cloudflare.com/client/v4"
ALREADY_EXISTS = "already exists"

def api(token, method, path, body=None):
    """Call the Cloudflare API; return (http_ok, parsed_json_or_None)."""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return True, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return False, json.loads(e.read().decode())
        except ValueError:
            return False, None
    except (urllib.error.URLError, ValueError, OSError):
        return False, None


def attach_domain(token, acct):
    """Attach the custom domain; only the Cloudflare "already exists" error counts as success."""
    ok, d = api(token, "POST", "/accounts/%s/pages/projects/%s/domains" % (acct, PROJECT), {"name": DOMAIN})
    if ok and d:
        r = d.get("result") or {}
        print("  domain:", r.get("name"), "-", r.get("status") or d.get("errors"))
        return 0
    errors = (d or {}).get("errors") or []
    if any(ALREADY_EXISTS in str(e.get("message", "")).lower() for e in errors if isinstance(e, dict)):
        print("  (domain already attached)")
        return 0
    codes = [e.get("code") for e in errors if isinstance(e, dict)]
    print("deploy: custom domain attach failed (error codes: %s)" % (codes or "none"), file=sys.stderr)
    return 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.parse_args()
    try:
        token, acct = cfcommon.load_credentials(require_account=True)
    except cfcommon.CredentialError as e:
        print("deploy: " + str(e), file=sys.stderr)
        return 1

    print("== 0. verify token (account-scoped) ==")
    ok, d = api(token, "GET", "/accounts/" + acct)
    if not (ok and d and d.get("success")):
        print("deploy: token verification failed", file=sys.stderr)
        return 1
    print("  OK - account:", d["result"]["name"])

    print("== 1. Pages project ==")
    ok, _ = api(token, "GET", "/accounts/%s/pages/projects/%s" % (acct, PROJECT))
    if ok:
        print("  (project exists)")
    else:
        ok, d = api(token, "POST", "/accounts/%s/pages/projects" % acct,
                    {"name": PROJECT, "production_branch": "main"})
        if not ok:
            print("deploy: project create failed", file=sys.stderr)
            return 1
        print("  created:", d["result"]["name"] if d and d.get("success") else (d or {}).get("errors"))

    print("== 2. deploy static dashboard + state.json ==")
    env = dict(os.environ, CLOUDFLARE_API_TOKEN=token, CLOUDFLARE_ACCOUNT_ID=acct)
    p = cfcommon.run_wrangler(env, str(HERE))
    if p is None:
        print("deploy: wrangler pages deploy timed out", file=sys.stderr)
        return 1
    keys = ("deploy", "http", "view", "uploaded", "success")
    lines = [ln for ln in (p.stdout + p.stderr).splitlines() if any(k in ln.lower() for k in keys)]
    print("\n".join(lines[-8:]))
    if p.returncode != 0:
        print("deploy: wrangler pages deploy failed", file=sys.stderr)
        return 1

    print("== 3. custom domain %s ==" % DOMAIN)
    rc = attach_domain(token, acct)
    if rc != 0:
        return rc

    print()
    print("DONE - https://" + DOMAIN)
    print("  first cert issuance can take a few minutes; the *.pages.dev URL above is live immediately.")
    print("  harness updates:  ./push-state.py <state.json>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
