#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Execute the hive-1461 pg-age docker build line against a fixture tree (#5401).

deploy/hive-1461/provision/20_pg_age.sh builds the PG/AGE image on each peer.
/opt/hive/pg-age on a peer also holds tls-ca/ca.key (the peer-local CA key) and
.secrets/ (password files) on a rerun, and the docker CLI tars the whole build
context to the daemon. This test takes the real docker build line from the
script, runs it with bash against a fixture copy of /opt/hive/pg-age that holds
those files, with a stub ssh_node (the remote command runs locally, /opt/hive
rewritten to the fixture) and a stub docker on PATH that records every path in
the build context directory it is given.

Cases:
  - the build context holds no file at all, so neither the CA key nor a
    secret file is sent, and the Dockerfile comes in through -f;
  - a build context directory that is not empty is refused before docker runs;
  - one that holds only a dotfile or only a dot directory is refused too (#5728).

Scratch lives under <repo>/.local-runs (the repository forbids /tmp).
"""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy/hive-1461/provision/20_pg_age.sh"

DOCKER_STUB = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
ctx = args[-1]
listing = []
for base, dirs, files in os.walk(ctx):
    for name in dirs + files:
        listing.append(os.path.relpath(os.path.join(base, name), ctx))
with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps({"argv": args, "context": ctx, "listing": sorted(listing)}) + "\n")
'''


def build_line(text):
    lines = [
        line for line in text.splitlines()
        if "docker build" in line and not line.lstrip().startswith("#")
    ]
    if len(lines) != 1:
        raise AssertionError("expected one docker build line, got %r" % (lines,))
    return lines[0].strip()


class TestHivePgAgeBuildContext5401(unittest.TestCase):
    def setUp(self):
        local_runs = ROOT / ".local-runs"
        local_runs.mkdir(exist_ok=True)
        self.dir = Path(tempfile.mkdtemp(prefix="pg-age-ctx-", dir=str(local_runs)))
        self.addCleanup(shutil.rmtree, str(self.dir), True)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(DOCKER_STUB, encoding="utf-8")
        docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
        self.hive = self.dir / "opt-hive"
        pg_age = self.hive / "pg-age"
        (pg_age / "tls-ca").mkdir(parents=True)
        (pg_age / ".secrets").mkdir()
        shutil.copy(str(ROOT / "deploy/hive-1461/provision/pg-age/Dockerfile"), str(pg_age / "Dockerfile"))
        (pg_age / "bootstrap.sql").write_text("-- fixture\n", encoding="utf-8")
        (pg_age / "tls-ca/ca.key").write_text("fixture CA key\n", encoding="utf-8")
        (pg_age / ".secrets/su-init.env").write_text("fixture\n", encoding="utf-8")
        (pg_age / ".secrets/store-url").write_text("fixture\n", encoding="utf-8")
        self.log = self.dir / "docker.jsonl"

    def run_line(self, script_text):
        line = build_line(script_text)
        harness = (
            'ssh_node() { local ip="$1"; shift; local cmd="$*"; '
            'bash -c "${cmd//\\/opt\\/hive/$FIX_HIVE}"; }\n'
            "set -euo pipefail\n" + line + "\n"
        )
        env = {
            "PATH": str(self.bin) + ":/usr/bin:/bin",
            "STUB_LOG": str(self.log),
            "FIX_HIVE": str(self.hive),
            "AGE_IMAGE": "apache/age@sha256:" + "0" * 64,
            "ip": "10.0.0.9",
        }
        return subprocess.run(
            ["bash", "-c", harness], env=env, capture_output=True, text=True, timeout=60
        )

    def docker_calls(self):
        if not self.log.exists():
            return []
        return [json.loads(l) for l in self.log.read_text(encoding="utf-8").splitlines()]

    def test_build_context_sends_no_ca_key_and_no_secret_5401(self):
        proc = self.run_line(SCRIPT.read_text(encoding="utf-8"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        calls = self.docker_calls()
        self.assertEqual(len(calls), 1, calls)
        call = calls[0]
        self.assertEqual(call["listing"], [], "the build context must hold nothing")
        argv = call["argv"]
        self.assertEqual(argv[0], "build")
        self.assertEqual(argv[argv.index("-f") + 1], str(self.hive / "pg-age/Dockerfile"))
        ctx = Path(call["context"]).resolve()
        for secret in ("pg-age/tls-ca/ca.key", "pg-age/.secrets/su-init.env", "pg-age/.secrets/store-url"):
            self.assertFalse(
                (self.hive / secret).resolve().is_relative_to(ctx),
                "a secret lies inside the build context: " + secret,
            )

    def test_non_empty_build_context_is_refused_before_docker_5401(self):
        ctx = self.hive / "pg-age/build-ctx"
        ctx.mkdir()
        (ctx / "stray").write_text("x\n", encoding="utf-8")
        proc = self.run_line(SCRIPT.read_text(encoding="utf-8"))
        self.assertNotEqual(proc.returncode, 0, "a non-empty build context must be refused")
        self.assertIn("#5401", proc.stderr)
        self.assertEqual(self.docker_calls(), [], "docker must not run")

    def test_build_context_holding_only_a_dot_entry_is_refused_5728(self):
        # #5728: a context that holds only a dotfile or a dot directory is not empty either;
        # ls without -A lists neither, so this case pins the -A of the emptiness check.
        for name, is_dir in ((".env", False), (".secrets", True)):
            with self.subTest(entry=name):
                ctx = self.hive / "pg-age/build-ctx"
                shutil.rmtree(str(ctx), True)
                ctx.mkdir()
                if is_dir:
                    (ctx / name).mkdir()
                else:
                    (ctx / name).write_text("x\n", encoding="utf-8")
                if self.log.exists():
                    self.log.unlink()
                proc = self.run_line(SCRIPT.read_text(encoding="utf-8"))
                self.assertNotEqual(proc.returncode, 0, "a context holding only %s must be refused" % name)
                self.assertIn("#5401", proc.stderr)
                self.assertEqual(self.docker_calls(), [], "docker must not run")


if __name__ == "__main__":
    unittest.main(verbosity=2)
