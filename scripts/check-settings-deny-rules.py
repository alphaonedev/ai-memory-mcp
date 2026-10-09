#!/usr/bin/env python3
"""check-settings-deny-rules.py - issue #6165: no dead `Write(...)` permission deny rules.

Claude Code does not match a `Write(path)` entry in `permissions.deny` against file-editing
tools; it prints "Permission deny rule ... is not matched by file permission checks - only
Edit(path) rules are" and the rule is a no-op. Only `Edit(path)` covers every file-editing
tool (Write, Edit, NotebookEdit). The tracked .claude/settings.json enforces the project
hard rule "no agent-created files under /tmp" through such deny rules, so a `Write(` entry
silently turns the rule off.

What this gate enforces:
  1. The settings file is a regular, readable UTF-8 JSON object (fail closed otherwise).
  2. `permissions.deny`, when present, is a list of strings.
  3. No `permissions.deny` entry starts with `Write(`.

Usage: check-settings-deny-rules.py [--settings PATH] [--self-test]
Exit 0 = clean, 1 = violation or unreadable input, 2 = usage error.
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

DEFAULT_SETTINGS = Path(__file__).resolve().parent.parent / ".claude" / "settings.json"
DEAD_PREFIX = "Write("


def check(path):
    """Return a list of FAIL strings for the settings file at `path`."""
    if path.is_symlink() or not path.is_file():
        return [f"FAIL: {path} is not a regular file"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return [f"FAIL: cannot parse {path} as JSON: {exc}"]
    if not isinstance(data, dict):
        return [f"FAIL: {path} top level is not a JSON object"]
    perms = data.get("permissions", {})
    if not isinstance(perms, dict):
        return [f"FAIL: {path} `permissions` is not an object"]
    deny = perms.get("deny", [])
    if not isinstance(deny, list) or not all(isinstance(e, str) for e in deny):
        return [f"FAIL: {path} `permissions.deny` is not a list of strings"]
    return [
        f"FAIL: {path} permissions.deny entry {entry!r} uses the dead Write(...) form; "
        f"use Edit({entry[len(DEAD_PREFIX):]} (Edit rules cover all file-editing tools) (#6165)"
        for entry in deny
        if entry.startswith(DEAD_PREFIX)
    ]


def self_test():
    """The gate must reject a Write( entry and accept the Edit( form."""
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
        bad = Path(tmp) / "bad.json"
        good = Path(tmp) / "good.json"
        bad.write_text(json.dumps({"permissions": {"deny": ["Write(/tmp/**)"]}}), encoding="utf-8")
        good.write_text(json.dumps({"permissions": {"deny": ["Edit(/tmp/**)"]}}), encoding="utf-8")
        if not check(bad):
            print("self-test FAIL: Write( entry was accepted", file=sys.stderr)
            return 1
        if check(good):
            print("self-test FAIL: Edit( entry was rejected", file=sys.stderr)
            return 1
    print("self-test ok")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--settings", type=Path, default=DEFAULT_SETTINGS)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    errors = check(args.settings)
    for line in errors:
        print(line, file=sys.stderr)
    if errors:
        return 1
    print("settings deny rules ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
