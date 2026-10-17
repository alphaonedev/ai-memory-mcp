#!/usr/bin/env python3
"""push-state.py - update the live dashboard at test.agenticmem.co (port of push-state.sh).

Pages-only model: writes public/state.json next to this file and redeploys the Pages project
(agenticmem-test). The open dashboard polls /state.json and picks up the new deploy in seconds.

  push-state.py path/to/state.json      # update from a file
  push-state.py -                       # read state JSON from stdin

~/.env carries TWO CLOUDFLARE_API_TOKEN lines; the SECOND is a Workers AI token with no Pages edit
permission, so the FIRST line is taken explicitly (never `source` the file).
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = "agenticmem-test"


def env_first(name):
    """First `name=` line of ~/.env, quotes and spaces stripped; empty string when absent."""
    try:
        for ln in (Path.home() / ".env").read_text().splitlines():
            if ln.startswith(name + "="):
                return ln.split("=", 1)[1].strip().strip("\"' ")
    except OSError:
        pass
    return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("src", nargs="?", default="-", help="state JSON file, or - for stdin (default)")
    args = ap.parse_args()

    raw = sys.stdin.read() if args.src == "-" else Path(args.src).read_text()
    try:
        body = json.loads(raw)
    except ValueError as e:
        print(f"push-state: state is not valid JSON: {e}", file=sys.stderr)
        return 2
    if not isinstance(body, dict):
        print("push-state: state must be a JSON object", file=sys.stderr)
        return 2
    # stamp lastUpdated (ISO-8601 UTC) so the "updated Xs ago" clock is authoritative
    body["lastUpdated"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = json.dumps(body)
    (HERE / "public").mkdir(exist_ok=True)
    (HERE / "public" / "state.json").write_text(text + "\n")

    token = env_first("CLOUDFLARE_API_TOKEN")
    if not token:
        print("push-state: CLOUDFLARE_API_TOKEN missing from ~/.env", file=sys.stderr)
        return 1
    env = dict(os.environ, CLOUDFLARE_API_TOKEN=token)
    acct = env_first("CLOUDFLARE_ACCOUNT_ID")
    if acct:
        env["CLOUDFLARE_ACCOUNT_ID"] = acct
    p = subprocess.run(["wrangler", "pages", "deploy", "public", "--project-name", PROJECT, "--branch", "main",
                        "--commit-dirty=true"], cwd=str(HERE), env=env, capture_output=True, text=True)
    lines = [ln for ln in (p.stdout + p.stderr).splitlines()
             if any(k in ln.lower() for k in ("deploy", "http", "view", "uploaded"))]
    print("\n".join(lines[-5:]))
    if p.returncode == 0:
        print(f"  -> state pushed + redeployed ({len(text)} bytes)")
    return p.returncode


if __name__ == "__main__":
    sys.exit(main())
