#!/usr/bin/env python3
"""deploy.py - stand up the realtime campaign dashboard on Cloudflare Pages at test.agenticmem.co.

Port of the former deploy.sh (#7313). Pages-only (no KV/Workers scope needed). Idempotent-ish.

Credentials (never committed; wrangler.toml carries no account id): CLOUDFLARE_API_TOKEN and
CLOUDFLARE_ACCOUNT_ID are read from the process environment, falling back to the FIRST matching
line of ~/.env (the file may carry a second, unrelated token line, so it is never sourced).

Exit codes: 0 ok, 1 missing credentials or an API/deploy failure.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = "agenticmem-test"
DOMAIN = "test.agenticmem.co"
API = "https://api.cloudflare.com/client/v4"

# Per-page state files the external publisher pushes next to the live public/state.json.
PAGE_STATE_FILES = (
    "northstar-state.json",
    "security-state.json",
    "mcp-tools-state.json",
    "swarm-tools-state.json",
    "datatier-state.json",
    "federation-state.json",
)


def env_first(name):
    """Process env value, else the first `name=` line of ~/.env; empty string when absent."""
    if os.environ.get(name):
        return os.environ[name]
    try:
        for ln in (Path.home() / ".env").read_text().splitlines():
            if ln.startswith(name + "="):
                return ln.split("=", 1)[1].strip().strip("\"' ")
    except OSError:
        pass
    return ""


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


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.parse_args()
    token = env_first("CLOUDFLARE_API_TOKEN")
    acct = env_first("CLOUDFLARE_ACCOUNT_ID")
    if not token or not acct:
        print("deploy: CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID are required", file=sys.stderr)
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
    p = subprocess.run(["wrangler", "pages", "deploy", "public", "--project-name", PROJECT, "--branch", "main",
                        "--commit-dirty=true"], cwd=str(HERE), env=env, capture_output=True, text=True)
    keys = ("deploy", "http", "view", "uploaded", "success")
    lines = [ln for ln in (p.stdout + p.stderr).splitlines() if any(k in ln.lower() for k in keys)]
    print("\n".join(lines[-8:]))
    if p.returncode != 0:
        print("deploy: wrangler pages deploy failed", file=sys.stderr)
        return 1

    print("== 3. custom domain %s ==" % DOMAIN)
    ok, d = api(token, "POST", "/accounts/%s/pages/projects/%s/domains" % (acct, PROJECT), {"name": DOMAIN})
    if ok and d:
        r = d.get("result") or {}
        print("  domain:", r.get("name"), "-", r.get("status") or d.get("errors"))
    else:
        print("  (domain may already be attached)")

    print()
    print("DONE - https://" + DOMAIN)
    print("  first cert issuance can take a few minutes; the *.pages.dev URL above is live immediately.")
    print("  harness updates:  ./push-state.py <state.json>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
