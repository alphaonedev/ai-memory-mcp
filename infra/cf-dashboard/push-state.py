#!/usr/bin/env python3
"""push-state.py - update the live dashboard at test.agenticmem.co (port of push-state.sh).

Pages-only model: writes public/state.json next to this file and redeploys the Pages project
(agenticmem-test). The open dashboard polls /state.json and picks up the new deploy in seconds.

  push-state.py path/to/state.json      # update from a file
  push-state.py -                       # read state JSON from stdin

Credentials follow cfcommon.py (same precedence as deploy.py): process env first, then the FIRST
~/.env line. ~/.env carries TWO CLOUDFLARE_API_TOKEN lines; the SECOND is a Workers AI token with no
Pages edit permission, so the file is never sourced.
"""
import argparse
import datetime
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cfcommon  # noqa: E402
import hostscrub  # noqa: E402

HERE = Path(__file__).resolve().parent


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
    try:
        text = hostscrub.dump_clean(body)  # the state is published: no internal hostname or local path (#7518)
    except hostscrub.LeakError as e:
        print(f"push-state: {e}", file=sys.stderr)
        return 2
    (HERE / "public").mkdir(exist_ok=True)
    (HERE / "public" / "state.json").write_text(text + "\n")

    try:
        token, acct = cfcommon.load_credentials(require_account=False)
    except cfcommon.CredentialError as e:
        print("push-state: " + str(e), file=sys.stderr)
        return 1
    env = dict(os.environ, CLOUDFLARE_API_TOKEN=token)
    if acct:
        env["CLOUDFLARE_ACCOUNT_ID"] = acct
    p = cfcommon.run_wrangler(env, str(HERE))
    if p is None:
        print("push-state: wrangler pages deploy timed out", file=sys.stderr)
        return 1
    lines = [ln for ln in (p.stdout + p.stderr).splitlines()
             if any(k in ln.lower() for k in ("deploy", "http", "view", "uploaded"))]
    print("\n".join(lines[-5:]))
    if p.returncode == 0:
        print(f"  -> state pushed + redeployed ({len(text)} bytes)")
    return p.returncode


if __name__ == "__main__":
    sys.exit(main())
