# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pins for umbrella #8172: workflow permissions and job-token posture.

One test per checklist item (#3138, #6453, #6813, #7022, #7024, #7057). The
workflow files are read as text (standard library only, Python 3.9): each
helper is also exercised against a mutated copy so the pin is proven to fail
when the guarded property is removed.

Run: python3 -I -m unittest discover -s scripts/ci/tests -p 'test_workflow_permissions_8172.py'
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORKFLOWS = REPO / ".github" / "workflows"

CI_YML = "ci.yml"
COVERAGE_YML = "coverage.yml"
C8_YML = "c8-precheck.yml"
CLIENTS_YML = "clients-ci.yml"

CHECKOUT_RE = re.compile(r"uses:\s*actions/checkout@")
PERSIST_OFF_RE = re.compile(r"persist-credentials:\s*false\b")
FORBIDDEN_TRIGGERS = ("pull_request_target", "workflow_run")

# Top-level permissions every pinned workflow may carry. Nothing else is
# provably needed at workflow level: jobs that need more declare it per job.
ALLOWED_TOP_LEVEL_PERMISSIONS = {"contents": "read"}

# Checkout steps that MUST keep the job token because the job pushes with it.
# Key: (workflow file, text that appears inside the step). Value: why.
PUSHING_CHECKOUTS = {
    (
        "release.yml",
        "repository: alphaonedev/homebrew-tap",
    ): "release.yml pushes the formula update to the Homebrew tap repository "
    "with the tap token (git commit + git push in the next step)",
}

CARGO_AUDIT_PIN = "CARGO_AUDIT_VERSION"
LOW_PORT_SYSCTL = "ip_unprivileged_port_start"


def read(name):
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def checkout_steps(text):
    """Yield (line number, step text) for every actions/checkout step."""
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if not CHECKOUT_RE.search(line):
            continue
        start = idx
        while start > 0 and not lines[start].lstrip().startswith("- "):
            start -= 1
        dash_indent = indent_of(lines[start])
        end = idx + 1
        while end < len(lines):
            nxt = lines[end]
            if nxt.strip() and indent_of(nxt) <= dash_indent:
                break
            end += 1
        yield idx + 1, "\n".join(lines[start:end])


def unprotected_checkouts(name, text):
    """Checkout steps that keep the token and are not allow-listed."""
    bad = []
    for lineno, step in checkout_steps(text):
        if PERSIST_OFF_RE.search(step):
            continue
        allowed = any(
            wf == name and marker in step for (wf, marker) in PUSHING_CHECKOUTS
        )
        if not allowed:
            bad.append("%s:%d" % (name, lineno))
    return bad


def top_level_block(text, key):
    """Return {child: value} of a top-level `key:` mapping, or None."""
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if line == key + ":":
            out = {}
            for body in lines[idx + 1:]:
                if not body.strip() or body.lstrip().startswith("#"):
                    continue
                if indent_of(body) == 0:
                    break
                child, _, value = body.strip().partition(":")
                out[child.strip()] = value.strip()
            return out
    return None


def permissions_problems(text):
    perms = top_level_block(text, "permissions")
    if perms is None:
        return ["top-level permissions block is missing"]
    if perms != ALLOWED_TOP_LEVEL_PERMISSIONS:
        return ["top-level permissions is %r, expected %r" % (perms, ALLOWED_TOP_LEVEL_PERMISSIONS)]
    return []


def trigger_problems(text):
    # `on:` is the only top-level key whose body can name the triggers.
    block = top_level_block(text, "on")
    if block is None:
        return ["no top-level on: block"]
    return [t for t in FORBIDDEN_TRIGGERS if t in block]


def security_audit_step(text):
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if line.strip() == "- name: Security audit":
            dash_indent = indent_of(line)
            end = idx + 1
            while end < len(lines) and not (
                lines[end].strip() and indent_of(lines[end]) <= dash_indent
            ):
                end += 1
            return "\n".join(lines[idx:end])
    return ""


class WorkflowPermissions8172(unittest.TestCase):
    def test_3138_security_audit_guards_and_pins_cargo_audit(self):
        step = security_audit_step(read(CI_YML))
        self.assertTrue(step, "Security audit step not found in ci.yml")
        self.assertIn("command -v cargo-audit", step)
        self.assertIn(CARGO_AUDIT_PIN, step)
        install = [l for l in step.splitlines() if "cargo install cargo-audit" in l]
        self.assertTrue(install)
        for l in install:
            self.assertIn("--version", l, "cargo install must pin the version")

    def test_3138_stale_installed_cargo_audit_is_replaced_or_fails(self):
        step = security_audit_step(read(CI_YML))
        self.assertTrue(step, "Security audit step not found in ci.yml")
        # The installed version is compared with the pin, not just presence.
        self.assertIn('cargo audit --version', step)
        self.assertIn('grep -Fqw -- "${CARGO_AUDIT_VERSION}"', step)
        # A mismatch reinstalls the pinned version over the stale one.
        install = [l for l in step.splitlines() if "cargo install cargo-audit" in l]
        self.assertTrue(install)
        for l in install:
            self.assertIn("--force", l)
            self.assertIn('--version "${CARGO_AUDIT_VERSION}"', l)
        # After the install the job fails unless the pinned version is what runs.
        self.assertIn("exit 1", step)
        self.assertLess(step.index("exit 1"), step.index("cargo audit\n") if "cargo audit\n" in step else len(step))
        # The pin bites: the old presence-only guard is rejected.
        presence_only = step.replace(
            ' \\\n             || ! cargo audit --version 2>/dev/null | grep -Fqw -- "${CARGO_AUDIT_VERSION}"', "", 1)
        self.assertNotEqual(presence_only, step)
        self.assertNotIn("|| ! cargo audit --version", presence_only)

    def test_8172_release_yml_has_no_top_level_contents_write(self):
        text = read("release.yml")
        self.assertEqual(top_level_block(text, "permissions"), {"contents": "read"})
        # The pin bites: a regained top-level write is detected.
        regained = text.replace("\npermissions:\n  contents: read\n", "\npermissions:\n  contents: write\n", 1)
        self.assertNotEqual(top_level_block(regained, "permissions"), {"contents": "read"})
        # Jobs that publish release assets keep their own job-level write.
        self.assertIn("      contents: write\n", text)

    def test_6453_c8_precheck_never_uses_privileged_triggers(self):
        text = read(C8_YML)
        self.assertEqual(trigger_problems(text), [])
        # The pin must bite: a mutated trigger block is rejected.
        mutated = text.replace("\non:\n", "\non:\n  workflow_run:\n    workflows: [x]\n", 1)
        self.assertEqual(trigger_problems(mutated), ["workflow_run"])
        mutated = text.replace("\non:\n", "\non:\n  pull_request_target:\n", 1)
        self.assertEqual(trigger_problems(mutated), ["pull_request_target"])

    def test_6813_clients_ci_checkouts_drop_the_job_token(self):
        # Covers the sdk-python-live checkout (and every sibling job) in clients-ci.
        text = read(CLIENTS_YML)
        steps = list(checkout_steps(text))
        self.assertTrue(steps, "clients-ci.yml has no checkout step")
        for lineno, step in steps:
            self.assertRegex(step, PERSIST_OFF_RE, "clients-ci.yml:%d" % lineno)

    def test_7022_top_level_permissions_pinned_to_contents_read(self):
        for name in (CI_YML, COVERAGE_YML):
            text = read(name)
            self.assertEqual(permissions_problems(text), [], name)
            dropped = text.replace("\npermissions:\n  contents: read\n", "\n", 1)
            self.assertNotEqual(permissions_problems(dropped), [], name + " dropped")
            widened = text.replace(
                "\npermissions:\n  contents: read\n",
                "\npermissions:\n  contents: write\n",
                1,
            )
            self.assertNotEqual(permissions_problems(widened), [], name + " widened")
            extra = text.replace(
                "\npermissions:\n  contents: read\n",
                "\npermissions:\n  contents: read\n  checks: write\n",
                1,
            )
            self.assertNotEqual(permissions_problems(extra), [], name + " extra grant")

    def test_7024_no_workflow_lowers_the_unprivileged_port_floor(self):
        offenders = [
            p.name for p in sorted(WORKFLOWS.glob("*.y*ml"))
            if LOW_PORT_SYSCTL in p.read_text(encoding="utf-8")
        ]
        self.assertEqual(offenders, [], "host sysctl mutation in workflows")
        offenders = []
        for base in (REPO / "tests", REPO / "scripts"):
            for path in sorted(base.rglob("*")):
                if path.is_file() and path.suffix in (".rs", ".sh", ".py", ".yml", ".yaml"):
                    if path == Path(__file__).resolve():
                        continue
                    if LOW_PORT_SYSCTL in path.read_text(encoding="utf-8", errors="ignore"):
                        offenders.append(str(path.relative_to(REPO)))
        self.assertEqual(offenders, [], "host sysctl mutation in tests or scripts")

    def test_7057_every_checkout_drops_the_job_token_unless_it_pushes(self):
        problems = []
        for path in sorted(WORKFLOWS.glob("*.y*ml")):
            problems.extend(unprotected_checkouts(path.name, path.read_text(encoding="utf-8")))
        self.assertEqual(problems, [], "checkout steps that persist the job token")
        # Every allow-list entry must still match a real step.
        for (wf, marker), why in PUSHING_CHECKOUTS.items():
            self.assertTrue(why)
            self.assertTrue(
                any(marker in step for _, step in checkout_steps(read(wf))),
                "stale allow-list entry %s %s" % (wf, marker),
            )
        # The scanner must flag a bare checkout.
        bare = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@abc # v4\n      - run: x\n"
        self.assertEqual(unprotected_checkouts("x.yml", bare), ["x.yml:4"])


if __name__ == "__main__":
    unittest.main()
