#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""ai-memory PgBouncer pooler infra smoke test (v0.8.0 Pillar-4 4.B, #1736; #4667).

Ported from the earlier smoke-test.sh (#4739: the shell version read the pool
mode with an admin command PgBouncer rejects, so it could never pass).

Brings up postgres+AGE behind PgBouncer (docker-compose.yml), TLS on both hops
with certificate verification, SCRAM authentication, and proves:

  1. A multi-statement AGE cypher transaction (LOAD 'age' + SET LOCAL
     search_path + create_graph + cypher MERGE + cypher MATCH) routed THROUGH
     the pooler succeeds.
  2. The role-default statement_timeout and search_path (role-defaults.sql) are
     visible through the pooler.
  3. The pooler reports pool_mode = session, read with SHOW CONFIG as the
     stats role (#4739, #4731). #4667: session is the only supported mode
     (docs/enterprise-deployment.md section 5.6); see
     scripts/probe-pgbouncer-pool-mode.py for the executed proof.
  4. Both hops are TLS: the client hop refuses a plaintext connection and the
     pooler-to-Postgres hop reports ssl = true in pg_stat_ssl (#4733).
  5. The application role cannot use the pooler's admin console (#4731).

Everything secret is generated per run under ./.smoke/ (private keys and the
userlist 0600): a throwaway
CA, certificates, the SCRAM userlist (written 0600, #4735) and random passwords
(#4734). Passwords reach child processes through the environment only, never
argv.

Requires docker + docker compose, psql and openssl. Run from anywhere:

    ./smoke-test.py                      # bridge network
    ./smoke-test.py --network host       # where docker cannot create bridges

The same stack backs infra/pillar4-envelope/measure-envelope.sh, which needs it
left running with a verified-TLS store URL for the daemon:

    ./smoke-test.py up --url-file PATH   # up, write the 0600 store URL, keep running
    ./smoke-test.py down                 # tear it down and delete ./.smoke/

Exit 0 = pooler config validated; non-zero = a property failed (see output).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent
SMOKE = HERE / ".smoke"
# One compose project per checkout: two trees running the smoke test at once
# must not recreate, answer for or tear down each other's stack (#4710 round 2).
PROJECT = "ai-memory-pgbouncer-smoke-" + hashlib.sha256(str(Path(__file__).resolve().parent).encode("utf-8")).hexdigest()[:10]
APP_ROLE = "ai_memory"
ADMIN_ROLE = "pgbouncer_admin"
STATS_ROLE = "pgbouncer_stats"
SCRAM_ITERATIONS = 4096


class Failure(Exception):
    """A smoke-test property did not hold."""


def scram_verifier(password: str) -> str:
    """A PostgreSQL / PgBouncer SCRAM-SHA-256 secret for the password."""
    salt = os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, SCRAM_ITERATIONS)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    enc = lambda raw: base64.b64encode(raw).decode("ascii")  # noqa: E731
    return "SCRAM-SHA-256$%d:%s$%s:%s" % (SCRAM_ITERATIONS, enc(salt), enc(stored_key), enc(server_key))


def run(argv: List[str], env: Optional[Dict[str, str]] = None, input_text: Optional[str] = None,
        check: bool = True) -> subprocess.CompletedProcess:
    done = subprocess.run(argv, env=env, input=input_text, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, universal_newlines=True)
    if check and done.returncode != 0:
        raise Failure("%s failed (rc=%d): %s" % (" ".join(argv[:4]), done.returncode, done.stdout.strip()))
    return done


class Stack:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.host = args.network == "host"
        self.pg_port = args.pg_port
        self.pgb_port = args.pgb_port if self.host else 6432
        self.pw = os.environ.get("POSTGRES_PASSWORD") or secrets.token_urlsafe(18)
        self.admin_pw = secrets.token_urlsafe(18)
        self.stats_pw = secrets.token_urlsafe(18)
        self.compose_env = {
            "POSTGRES_PASSWORD": self.pw,
            "PGB_UID": str(os.getuid()),
            "PGB_GID": str(os.getgid()),
            "PGB_PORT": str(self.pgb_port),
            "PG_PORT": str(self.pg_port),
        }
        self.sudo = run(["docker", "info"], check=False).returncode != 0

    # -- docker ---------------------------------------------------------
    def docker(self, *a: str, check: bool = True) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env.update(self.compose_env)
        argv = ["docker"] + list(a)
        if self.sudo:
            argv = ["sudo", "-n", "--preserve-env=" + ",".join(self.compose_env)] + argv
        return run(argv, env=env, check=check)

    def compose(self, *a: str, check: bool = True) -> subprocess.CompletedProcess:
        files = ["-f", str(HERE / "docker-compose.yml")]
        if self.host:
            files += ["-f", str(HERE / "docker-compose.host.yml")]
        return self.docker("compose", "-p", self.args.project, *files, *a, check=check)

    # -- generated material --------------------------------------------
    def write_secret(self, path: Path, text: str) -> None:
        """Write a secret file that is 0600 whatever existed at the path before.

        A fresh 0600 file is created beside the target (O_EXCL, O_NOFOLLOW) and
        renamed over it, so a pre-existing wider-mode file or a symlink at the
        path never receives the secret.
        """
        path = Path(path)
        tmp = path.with_name(".%s.%d.tmp" % (path.name, os.getpid()))
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(str(tmp), str(path))
        except BaseException:
            try:
                os.unlink(str(tmp))
            except OSError:
                pass
            raise

    def make_tls(self) -> None:
        tls = SMOKE / "tls"
        # 0755: the postgres server process (another uid) reads the public
        # certificates; every private key is 0600 and owned by the caller.
        tls.mkdir()
        tls.chmod(0o755)
        san = tls / "san.ext"
        san.write_text("subjectAltName=DNS:postgres,DNS:pgbouncer,DNS:localhost,IP:127.0.0.1\n")
        ossl = ["openssl"]
        run(ossl + ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=pgbouncer-smoke-ca",
                    "-keyout", str(tls / "ca.key"), "-out", str(tls / "ca.crt")])
        for name, cn in (("server", "pgbouncer"), ("client", APP_ROLE)):
            run(ossl + ["req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + cn,
                        "-keyout", str(tls / (name + ".key")), "-out", str(tls / (name + ".csr"))])
            run(ossl + ["x509", "-req", "-in", str(tls / (name + ".csr")), "-CA", str(tls / "ca.crt"),
                        "-CAkey", str(tls / "ca.key"), "-CAcreateserial", "-days", "2", "-extfile", str(san),
                        "-out", str(tls / (name + ".crt"))])
        for key in tls.glob("*.key"):
            key.chmod(0o600)

    def render_host_ini(self) -> None:
        import re
        text = (HERE / "pgbouncer.ini").read_text()
        for pattern, repl in (
            (r"(?m)^(ai_memory = host=)postgres( port=)5432", r"\g<1>127.0.0.1\g<2>%d" % self.pg_port),
            (r"(?m)^listen_addr = .*$", "listen_addr = 127.0.0.1"),
            (r"(?m)^listen_port = .*$", "listen_port = %d" % self.pgb_port),
        ):
            text, n = re.subn(pattern, repl, text)
            if n != 1:
                raise Failure("pgbouncer.ini: expected exactly one match for %r, got %d" % (pattern, n))
        (SMOKE / "pgbouncer.host.ini").write_text(text)

    # -- psql ----------------------------------------------------------
    def psql(self, user: str, password: str, dbname: str, sql: str, port: Optional[int] = None,
             tls: bool = True, check: bool = True) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PGPASSWORD"] = password
        env["PGSSLMODE"] = "verify-full" if tls else "disable"
        env["PGSSLROOTCERT"] = str(SMOKE / "tls" / "ca.crt")
        env["PGSSLCERT"] = str(SMOKE / "tls" / "client.crt")
        env["PGSSLKEY"] = str(SMOKE / "tls" / "client.key")
        argv = ["psql", "-X", "-q", "-tA", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1",
                "-p", str(port or self.pgb_port), "-U", user, "-d", dbname]
        return run(argv, env=env, input_text=sql, check=check)

    def admin_rows(self, what: str) -> list:
        """Rows of a PgBouncer admin SHOW command as dicts keyed by column header (stats role)."""
        out = self.psql(STATS_ROLE, self.stats_pw, "pgbouncer",
                        "\\pset tuples_only off\n\\pset footer off\nSHOW %s;" % what).stdout
        lines = [line for line in out.splitlines() if line]
        if not lines:
            return []
        header = lines[0].split("|")
        return [dict(zip(header, line.split("|"))) for line in lines[1:]]

    # -- lifecycle -----------------------------------------------------
    def up(self) -> None:
        if SMOKE.exists():
            shutil.rmtree(str(SMOKE))
        SMOKE.mkdir(mode=0o700)
        self.make_tls()
        if self.host:
            self.render_host_ini()
        print("[1/6] bringing up postgres+AGE ...")
        self.compose("up", "-d", "--wait", "postgres")
        verifier = self.compose("exec", "-T", "postgres", "psql", "-p", str(self.pg_port if self.host else 5432),
                                "-U", APP_ROLE, "-d", "ai_memory", "-At", "-c",
                                "SELECT rolpassword FROM pg_authid WHERE rolname = '%s'" % APP_ROLE).stdout.strip()
        if not verifier.startswith("SCRAM-SHA-256$"):
            raise Failure("the %s role is not stored as a SCRAM verifier (got %r...)" % (APP_ROLE, verifier[:14]))
        self.write_secret(SMOKE / "userlist.txt", "".join(
            '"%s" "%s"\n' % (user, secret) for user, secret in (
                (APP_ROLE, verifier),
                (ADMIN_ROLE, scram_verifier(self.admin_pw)),
                (STATS_ROLE, scram_verifier(self.stats_pw)),
            )))
        print("      bringing up pgbouncer ...")
        self.compose("up", "-d", "--wait", "pgbouncer")
        deadline = time.monotonic() + 60
        while True:
            probe = self.psql(APP_ROLE, self.pw, "ai_memory", "SELECT 1;", check=False)
            if probe.returncode == 0:
                return
            if time.monotonic() > deadline:
                raise Failure("pooler did not accept a verified-TLS connection in 60 s: %s" % probe.stdout.strip())
            time.sleep(1)

    def logs(self) -> str:
        return self.compose("logs", "--no-color", "--tail", "30", check=False).stdout

    def down(self) -> None:
        self.compose("down", "-v", check=False)
        if SMOKE.exists() and not self.args.keep:
            shutil.rmtree(str(SMOKE), ignore_errors=True)

    # -- checks --------------------------------------------------------
    def check(self) -> None:
        print("[2/6] AGE cypher transaction through the pooler ...")
        # ONE transaction => one BEGIN/COMMIT (statement pool mode refuses a block: #4667).
        self.psql(APP_ROLE, self.pw, "ai_memory", """BEGIN;
LOAD 'age';
SET LOCAL search_path = ag_catalog, "$user", public;
SELECT create_graph('pgbouncer_smoke');
SELECT * FROM cypher('pgbouncer_smoke', $$ MERGE (a:N {id:'a'}) MERGE (b:N {id:'b'}) MERGE (a)-[:E]->(b) RETURN a $$) AS (a agtype);
COMMIT;
""")
        counted = self.psql(APP_ROLE, self.pw, "ai_memory", """BEGIN;
LOAD 'age';
SET LOCAL search_path = ag_catalog, "$user", public;
SELECT count(*) FROM cypher('pgbouncer_smoke', $$ MATCH (a:N {id:'a'})-[:E]->(b:N {id:'b'}) RETURN a $$) AS (a agtype);
COMMIT;
""").stdout
        digits = "".join(ch for ch in counted if ch.isdigit())
        if int(digits or "0") < 1:
            raise Failure("AGE edge not found through the pooler (output %r)" % counted)
        print("      OK: AGE edge round-tripped through the pooler (count=%s)" % digits)

        print("[3/6] role defaults visible through the pooler ...")
        want = {"statement_timeout": "30s", "lock_timeout": "5s", "search_path": "public, ag_catalog"}
        for name, expected in want.items():
            got = self.psql(APP_ROLE, self.pw, "ai_memory", "SHOW %s;" % name).stdout.strip()
            print("      %s = %s" % (name, got))
            if got != expected:
                raise Failure("role default %s did not survive the pooler (got %r, want %r); is role-defaults.sql "
                              "mounted into initdb.d?" % (name, got, expected))

        print("[4/6] pooler is in session mode (SHOW CONFIG as the stats role) ...")
        config = self.psql(STATS_ROLE, self.stats_pw, "pgbouncer", "SHOW CONFIG;").stdout
        values = {}
        for line in config.splitlines():
            parts = line.split("|")
            if len(parts) >= 2:
                values[parts[0]] = parts[1]
        mode = values.get("pool_mode", "<unreported>")
        print("      pool_mode = %s  server_reset_query = %s  admin_users = %s  stats_users = %s" % (
            mode, values.get("server_reset_query"), values.get("admin_users"), values.get("stats_users")))
        if mode != "session":
            raise Failure("pooler pool_mode is %r, want 'session' (#4667)" % mode)
        # #4742: SHOW CONFIG is the global value only. [databases] and [users]
        # entries override it, so read the effective mode of the pool the
        # daemon uses (SHOW POOLS: a pool exists after steps 2-3) and every
        # override row; fail closed when the row or the column is missing.
        effective = self.admin_rows("POOLS")
        row = [r for r in effective if r.get("database") == "ai_memory" and r.get("user") == APP_ROLE]
        if not row or "pool_mode" not in row[0]:
            raise Failure("SHOW POOLS has no ai_memory/%s row with a pool_mode column (#4742)" % APP_ROLE)
        print("      effective pool_mode for %s@ai_memory = %s" % (APP_ROLE, row[0]["pool_mode"]))
        if row[0]["pool_mode"] != "session":
            raise Failure("the ai_memory pool runs pool_mode %r, want 'session' (#4742)" % row[0]["pool_mode"])
        for what in ("DATABASES", "USERS"):
            for r in self.admin_rows(what):
                # the admin console's own pseudo-database always reports statement
                if what == "DATABASES" and r.get("name") == "pgbouncer":
                    continue
                if r.get("pool_mode") not in (None, "", "session"):
                    raise Failure("SHOW %s: %s overrides pool_mode to %r, want 'session' (#4742)" % (
                        what, r.get("name"), r.get("pool_mode")))
        if values.get("server_reset_query") != "DISCARD ALL":
            raise Failure("server_reset_query is %r, want 'DISCARD ALL' (#4736)" % values.get("server_reset_query"))
        if APP_ROLE in (values.get("admin_users") or "").split(","):
            raise Failure("the application role is an admin_users member (#4731)")
        # #4954: step 5 proves TLS is on, not that it verifies. Assert both hops
        # run verify-full as PgBouncer reports it, so lowering either to
        # `require` turns this test red.
        for key in ("client_tls_sslmode", "server_tls_sslmode"):
            if values.get(key) != "verify-full":
                raise Failure("%s is %r, want 'verify-full' (#4729, #4730, #4954)" % (key, values.get(key)))
        print("      client_tls_sslmode = %s  server_tls_sslmode = %s" % (
            values.get("client_tls_sslmode"), values.get("server_tls_sslmode")))

        print("[5/6] TLS on both hops ...")
        plain = self.psql(APP_ROLE, self.pw, "ai_memory", "SELECT 1;", tls=False, check=False)
        if plain.returncode == 0:
            raise Failure("the pooler accepted a plaintext client connection (#4733)")
        print("      OK: plaintext client connection refused")
        server_ssl = self.psql(APP_ROLE, self.pw, "ai_memory",
                               "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();").stdout.strip()
        print("      pooler-to-postgres hop: pg_stat_ssl.ssl = %s" % server_ssl)
        if server_ssl != "t":
            raise Failure("the pooler-to-Postgres hop is not TLS (pg_stat_ssl.ssl = %r)" % server_ssl)

        print("[6/6] the application role cannot use the admin console ...")
        admin = self.psql(APP_ROLE, self.pw, "pgbouncer", "SHOW CONFIG;", check=False)
        if admin.returncode == 0:
            raise Failure("the application role reached the admin console (#4731)")
        print("      OK: admin console refused the application role")


def serve(stack: "Stack", args: argparse.Namespace) -> int:
    """Leave the stack running and hand the daemon its store URL (envelope harness)."""
    if not args.url_file:
        print("FAIL: `up` needs --url-file", file=sys.stderr)
        return 2
    try:
        stack.up()
        tls = SMOKE / "tls"
        url = ("postgres://%s:%s@127.0.0.1:%d/ai_memory?sslmode=verify-full&sslrootcert=%s&sslcert=%s&sslkey=%s"
               % (APP_ROLE, stack.pw, stack.pgb_port, tls / "ca.crt", tls / "client.crt", tls / "client.key"))
        stack.write_secret(Path(args.url_file), url + "\n")
    except Failure as exc:
        print("FAIL: %s" % exc, file=sys.stderr)
        print("--- container logs ---\n%s" % stack.logs(), file=sys.stderr)
        stack.down()
        return 1
    except (OSError, subprocess.SubprocessError) as exc:
        print("FAIL (could not run): %s" % exc, file=sys.stderr)
        stack.down()
        return 2
    print("UP: pooler on 127.0.0.1:%d, store URL written to %s" % (stack.pgb_port, args.url_file))
    return 0


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--network", choices=("bridge", "host"), default="bridge")
    parser.add_argument("--pg-port", type=int, default=15432, help="host-network mode only")
    parser.add_argument("--pgb-port", type=int, default=16432, help="host-network mode only")
    parser.add_argument("--keep", action="store_true", help="keep ./.smoke/ for inspection")
    parser.add_argument("--project", default=PROJECT,
                        help="compose project name (default: derived from this checkout's path, so two checkouts never "
                             "share containers; container names derive from it, #4955, #4962). Material lives in this "
                             "checkout's ./.smoke/, so concurrent runs need separate checkouts")
    parser.add_argument("command", nargs="?", choices=("test", "up", "down"), default="test")
    parser.add_argument("--url-file", help="up: write the daemon's verified-TLS store URL here (mode 0600)")
    args = parser.parse_args(argv)
    stack = Stack(args)
    if args.command == "down":
        args.keep = False
        stack.down()
        return 0
    if args.command == "up":
        return serve(stack, args)
    try:
        stack.up()
        stack.check()
    except Failure as exc:
        print("FAIL: %s" % exc, file=sys.stderr)
        print("--- container logs ---\n%s" % stack.logs(), file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError) as exc:
        print("FAIL (could not run): %s" % exc, file=sys.stderr)
        return 2
    finally:
        stack.down()
    print("PASS: PgBouncer pooler validated (session mode, SCRAM, TLS on both hops, AGE cypher through the pooler).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
