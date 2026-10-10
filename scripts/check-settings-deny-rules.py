#!/usr/bin/env python3
"""check-settings-deny-rules.py - issue #6165: the /tmp permission deny rules must really deny.

Claude Code matches `Write(path)` entries in permissions rules against nothing (it prints
"Permission deny rule ... is not matched by file permission checks - only Edit(path) rules
are"); only `Edit(path)` covers every file-editing tool (Write, Edit, NotebookEdit). In a
permission rule path a single leading slash is relative to the project root, so
`Edit(/tmp/**)` denies <repo>/tmp/**, NOT /tmp. An absolute filesystem path needs the double
slash form `Edit(//tmp/**)`. The tracked .claude/settings.json enforces the project hard rule
"no agent-created files under /tmp" with such deny rules, so a dead or repo-relative entry
silently turns the rule off.

What this gate enforces:
  1. The settings file is a regular, readable UTF-8 (no BOM) JSON object (fail closed).
  2. `permissions` is an object; `deny`, `ask` and `allow`, when present, are lists of strings.
  3. `permissions.deny` contains each of REQUIRED_DENY: Edit(//tmp/**), Edit(//var/tmp/**),
     Edit(//private/tmp/**).
  4. No entry in deny, ask or allow differs from its whitespace-trimmed form (Claude Code does
     not trim rules, so a padded rule matches nothing), and none starts with `Write(`,
     `NotebookEdit(` or `MultiEdit(`: those forms are never matched.
  5. No deny entry uses the single-slash absolute form Edit(/tmp...), Edit(/var/tmp...) or
     Edit(/private/tmp...), which is repo-relative and does not protect the absolute path.

Usage: check-settings-deny-rules.py [--settings PATH] [--self-test]
Exit 0 = clean, 1 = violation or unreadable input, 2 = usage error.
"""
import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

DEFAULT_SETTINGS = Path(__file__).resolve().parent.parent / ".claude" / "settings.json"
DEAD_PREFIXES = ("Write(", "NotebookEdit(", "MultiEdit(")
LISTS = ("deny", "ask", "allow")
REQUIRED_DENY = ("Edit(//tmp/**)", "Edit(//var/tmp/**)", "Edit(//private/tmp/**)")
SINGLE_SLASH_ABS = re.compile(r"^Edit\(/(tmp|var/tmp|private/tmp)(/|\)|$)")


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
    errors = []
    entries = {}
    for key in LISTS:
        value = perms.get(key, [])
        if not isinstance(value, list) or not all(isinstance(e, str) for e in value):
            errors.append(f"FAIL: {path} `permissions.{key}` is not a list of strings")
            value = []
        entries[key] = list(value)
    for key in LISTS:
        for entry in entries[key]:
            if entry != entry.strip():
                errors.append(
                    f"FAIL: {path} permissions.{key} entry {entry!r} has leading or trailing whitespace; "
                    f"Claude Code does not trim rules, so it matches no tool and denies nothing (#6165)")
            if entry.startswith(DEAD_PREFIXES):
                errors.append(
                    f"FAIL: {path} permissions.{key} entry {entry!r} uses a form Claude Code never "
                    f"matches; use Edit(//abs/path/**) (Edit rules cover all file-editing tools) (#6165)")
    for entry in entries["deny"]:
        if SINGLE_SLASH_ABS.match(entry):
            errors.append(
                f"FAIL: {path} permissions.deny entry {entry!r} is repo-relative (single leading slash); "
                f"use the absolute double-slash form, e.g. Edit(/{entry[5:]} (#6165)")
    for required in REQUIRED_DENY:
        if required not in entries["deny"]:
            errors.append(f"FAIL: {path} permissions.deny is missing required entry {required} (#6165)")
    return errors


def self_test():
    """The gate must accept the correct file and reject each broken shape."""
    good = {"permissions": {"deny": list(REQUIRED_DENY)}}
    cases = [
        ("good", json.dumps(good), True),
        ("write-form", json.dumps({"permissions": {"deny": list(REQUIRED_DENY) + ["Write(/tmp/**)"]}}), False),
        ("write-form-leading-space", json.dumps({"permissions": {"deny": list(REQUIRED_DENY) + [" Write(//tmp/**)"]}}), False),
        ("notebook-form", json.dumps({"permissions": {"deny": list(REQUIRED_DENY) + ["NotebookEdit(//tmp/**)"]}}), False),
        ("multiedit-form", json.dumps({"permissions": {"deny": list(REQUIRED_DENY) + ["MultiEdit(//tmp/**)"]}}), False),
        ("write-in-ask", json.dumps({"permissions": {"deny": list(REQUIRED_DENY), "ask": ["Write(//tmp/**)"]}}), False),
        ("write-in-allow", json.dumps({"permissions": {"deny": list(REQUIRED_DENY), "allow": ["Write(//tmp/**)"]}}), False),
        ("single-slash", json.dumps({"permissions": {"deny": ["Edit(/tmp/**)", "Edit(/var/tmp/**)", "Edit(/private/tmp/**)"]}}), False),
        ("missing-one", json.dumps({"permissions": {"deny": list(REQUIRED_DENY[:2])}}), False),
        ("padded-leading", json.dumps({"permissions": {"deny": [" Edit(//tmp/**)"] + list(REQUIRED_DENY[1:])}}), False),
        ("padded-trailing", json.dumps({"permissions": {"deny": ["Edit(//tmp/**) "] + list(REQUIRED_DENY[1:])}}), False),
        ("padded-extra", json.dumps({"permissions": {"deny": list(REQUIRED_DENY) + ["Edit(//tmp/**) "]}}), False),
        ("padded-ask", json.dumps({"permissions": {"deny": list(REQUIRED_DENY), "ask": [" Edit(//x/**)"]}}), False),
        ("no-permissions", json.dumps({}), False),
        ("malformed-json", "{not json", False),
        ("top-level-array", "[]", False),
        ("deny-as-string", json.dumps({"permissions": {"deny": "Edit(//tmp/**)"}}), False),
        ("permissions-null", json.dumps({"permissions": None}), False),
        ("utf8-bom", "\ufeff" + json.dumps(good), False),
    ]
    failed = 0
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
        base = Path(tmp)
        for name, text, want_clean in cases:
            target = base / f"{name}.json"
            target.write_text(text, encoding="utf-8")
            if bool(not check(target)) != want_clean:
                print(f"self-test FAIL: {name} (want clean={want_clean})", file=sys.stderr)
                failed += 1
        link = base / "link.json"
        link.symlink_to(base / "good.json")
        if not check(link):
            print("self-test FAIL: symlink accepted", file=sys.stderr)
            failed += 1
        if not check(base / "absent.json"):
            print("self-test FAIL: missing file accepted", file=sys.stderr)
            failed += 1
    if failed:
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
