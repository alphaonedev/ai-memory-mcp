#!/usr/bin/env python3
"""Run the opt-in live tests of sdk/python against a real daemon and a real wake hub (#6746).

Five sdk/python tests prove the SDK against the Rust binary itself and skip
without it: four in ``tests/test_client.py`` need a daemon at
``AI_MEMORY_TEST_BASE_URL`` (``AI_MEMORY_TEST_DAEMON=1``; this harness sets
the URL to the free loopback port it picks, #6831) and one in
``tests/test_wake_client.py`` needs a live ``ai-memory wake-hub`` and a
delegation bundle. Before #6746 no CI job started either, so the five never ran.

This harness, run by the clients-ci job ``sdk-python-live``:

1. mints a throwaway CA and a leaf for ``localhost`` / ``127.0.0.1`` with
   ``cryptography`` (a dev-extra dependency), all under ``--run-dir``;
2. starts ``ai-memory serve`` with TLS on the port, with an isolated HOME;
3. enrolls one agent (generate, register, bind-key, delegate ``a2a-hub``),
   publishes the hub allowlist, keeps it fresh (the hub refuses a snapshot
   older than 60 s) and starts ``ai-memory wake-hub``;
4. runs pytest on exactly the live tests, with ``SSL_CERT_FILE`` naming the CA,
   and FAILS unless every one of them ran and passed: a skip is a failure here,
   because a skipped live test is the defect #6746 closes.

The daemon listens on a free loopback port the harness picks, unless
``--port`` names one (#6831). The daemon and the hub are stopped on every
exit: normal, a startup error of any kind, SIGINT, SIGTERM or SIGHUP (#6812).

Usage: sdk-python-live.py --binary PATH --sdk sdk/python --run-dir DIR [--port N]
Exit codes: 0 all live tests passed; 1 a live test failed, skipped or was not
collected; 2 the daemon or hub could not be started; 128+N stopped by signal N.
"""

import argparse
import base64
import binascii
import codecs
import datetime
import functools
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

HUB_ID = "ai-memory-wake-hub"
AGENT_ID = "ai:sdk-live-6746"

# The live tests, by pytest node id. The harness fails unless each one passed.
LIVE_TESTS = (
    "tests/test_client.py::test_health_ok",
    "tests/test_client.py::test_store_and_get_roundtrip",
    "tests/test_client.py::test_recall_returns_wrapper",
    "tests/test_client.py::test_not_found_raises",
    "tests/test_wake_client.py::test_a_real_hub_admits_this_client_over_a_real_socket",
)


def junit_outcomes(report):
    """Map ``file::name`` to passed / failed / skipped from a pytest junit XML report."""
    outcomes = {}
    for case in ET.parse(str(report)).getroot().iter("testcase"):
        classname = case.get("classname", "")
        name = case.get("name", "")
        node = classname.replace(".", "/") + ".py::" + name
        if case.find("skipped") is not None:
            outcomes[node] = "skipped"
        elif case.find("failure") is not None or case.find("error") is not None:
            outcomes[node] = "failed"
        else:
            outcomes[node] = "passed"
    return outcomes


def verdict(outcomes, expected=LIVE_TESTS):
    """Return the problems with a run: every expected test must have passed."""
    problems = []
    for node in expected:
        got = outcomes.get(node)
        if got is None:
            problems.append(f"{node}: not collected")
        elif got != "passed":
            problems.append(f"{node}: {got}")
    return problems


def free_port():
    """A TCP port free on 127.0.0.1 now, chosen by the kernel (#6831)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Stopped(BaseException):
    """A termination signal arrived; ``main`` tears the stack down and exits 128+N.

    A ``BaseException``, so the startup ``except Exception`` cannot swallow it.
    """

    def __init__(self, signum):
        super().__init__(f"stopped by signal {signum}")
        self.signum = signum


#: Set while ``Stack.spawn`` forks a child: a stop signal then waits until the child is tracked (#6960).
_spawn_guard = {"active": False, "pending": None}


def _stop(signum, _frame):
    if _spawn_guard["active"]:
        _spawn_guard["pending"] = signum  # delivered by spawn() once the child is in Stack.procs
        return
    raise Stopped(signum)


#: Signals that end the run with the stack torn down (#6812).
STOP_SIGNALS = tuple(getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGHUP") if hasattr(signal, name))


def mint_tls(tls_dir):
    """Write ca.pem, cert.pem and key.pem (leaf for localhost and 127.0.0.1) into tls_dir."""
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)  # noqa: UP017 - Python 3.9 has no datetime.UTC
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ai-memory sdk-live CA (#6746)")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    tls_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    pem = serialization.Encoding.PEM
    (tls_dir / "ca.pem").write_bytes(ca.public_bytes(pem))
    (tls_dir / "cert.pem").write_bytes(leaf.public_bytes(pem))
    key = tls_dir / "key.pem"
    key.write_bytes(leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(key, 0o600)
    return tls_dir / "ca.pem", tls_dir / "cert.pem", key


REDACTED = "<redacted>"
_MIN_SECRET_LEN = 8  # a shorter value would turn the filter into a wildcard


def secret_forms(data, _der=True):
    """Every text form of ``data`` that a traceback or an assertion could print (#6964).

    Raw (UTF-8 and Latin-1), the ``bytes`` ``repr`` with and without its
    ``b'...'`` wrapper, hex, and both base64 alphabets with and without
    padding, upper-case and colon-separated hex, the decimal byte list, and both
    base32 spellings. A multi-line value (a PEM) also yields each of its body
    lines and the forms of its decoded DER body. :func:`redact` additionally
    removes every ``_WINDOW``-character fragment of any form, so a truncated
    or split form is not a way around the list (#6964, security review F1).
    Longest first, so a form that contains another is replaced whole.
    """
    data = bytes(data)
    stripped = data.strip()
    if len(stripped) < _MIN_SECRET_LEN:
        return []
    forms = set()
    for blob in {data, stripped}:
        forms.add(repr(blob))
        forms.add(repr(blob)[2:-1])
        forms.add(blob.hex())
        forms.add(blob.hex().upper())
        forms.add(blob.hex(":"))
        forms.add(blob.hex(":").upper())
        forms.add(str(list(blob)))
        forms.add(",".join(str(b) for b in blob))
        forms.add(blob.decode("latin-1"))
        try:
            forms.add(blob.decode("utf-8"))
        except UnicodeDecodeError:
            pass
        for encode in (base64.b64encode, base64.urlsafe_b64encode, base64.b32encode):
            text = encode(blob).decode("ascii")
            forms.add(text)
            forms.add(text.rstrip("="))
    if b"\n" in stripped:
        for line in stripped.splitlines():
            if len(line.strip()) >= _MIN_SECRET_LEN and not line.startswith(b"-----"):
                forms.update(secret_forms(line, _der=False))
        if _der:
            try:
                body = b"".join(ln for ln in stripped.splitlines() if not ln.startswith(b"-----"))
                forms.update(secret_forms(base64.b64decode(body, validate=True), _der=False))
            except (binascii.Error, ValueError):
                pass  # not a base64 body: the other forms still apply
    forms.discard("")
    return sorted((f for f in forms if len(f) >= _MIN_SECRET_LEN), key=len, reverse=True)


_WINDOW = 12  # a fragment this long of any secret form is treated as the secret


@functools.lru_cache(maxsize=8)
def _windows(forms):
    return frozenset(form[i : i + _WINDOW] for form in forms for i in range(len(form) - _WINDOW + 1))


def _spans(text, forms):
    """The merged ``(start, end)`` ranges of ``text`` that belong to a secret: every
    occurrence of a form and every ``_WINDOW``-character fragment of one."""
    mask = bytearray(len(text))
    for form in forms:
        start = text.find(form)
        while start != -1:
            mask[start : start + len(form)] = b"\x01" * len(form)
            start = text.find(form, start + 1)
    windows = _windows(forms)
    if windows:
        for i in range(len(text) - _WINDOW + 1):
            if text[i : i + _WINDOW] in windows:
                mask[i : i + _WINDOW] = b"\x01" * _WINDOW
    spans, i = [], 0
    while i < len(text):
        if mask[i]:
            j = i
            while j < len(text) and mask[j]:
                j += 1
            spans.append((i, j))
            i = j
        else:
            i += 1
    return spans


def _replace_spans(text, spans, marker=REDACTED):
    out, last = [], 0
    for start, end in spans:
        out.append(text[last:start])
        out.append(marker)
        last = end
    out.append(text[last:])
    return "".join(out)


def redact(text, forms):
    """``text`` with every one of ``forms`` and every ``_WINDOW``-character fragment of one replaced by ``<redacted>``."""
    forms = tuple(forms)
    return _replace_spans(text, _spans(text, forms))


def redact_stream(buffer, forms, hold):
    """Split raw ``buffer`` into ``(redacted prefix, raw tail)`` for a streaming filter (#7062).

    The tail is the last ``hold`` characters, moved back to the start of any secret
    span that crosses that boundary, and is returned UNREDACTED: it is joined with
    the next read and matched whole, so a form split across two reads is never
    half emitted. The prefix is redacted.
    """
    forms = tuple(forms)
    cut = max(len(buffer) - hold, 0)
    for start, end in _spans(buffer, forms):
        if start < cut < end:
            cut = start
            break
    return redact(buffer[:cut], forms), buffer[cut:]


def scrub_file(path, secrets):
    """Rewrite the junit XML at ``path`` with the same filter as the CI log, mode 0600 (#7048).

    The report is parsed and every text node and attribute value is filtered after
    XML decoding, so an escaped rendering of a secret (``&amp;``, ``&lt;``,
    ``&quot;``, a numeric character reference) is matched like the plain one
    (#7064), and the marker is serialised as escaped text so the file stays
    well-formed (#7063).

    Fail closed: when the file cannot be filtered it is removed.
    """
    forms = [form for secret in secrets for form in secret_forms(secret)]
    forms.sort(key=len, reverse=True)
    try:
        os.chmod(path, 0o600)
        tree = ET.parse(str(path))
        for element in tree.getroot().iter():
            if element.text:
                element.text = redact(element.text, forms)
            if element.tail:
                element.tail = redact(element.tail, forms)
            for key, value in element.attrib.items():
                element.set(key, redact(value, forms))
        tree.write(str(path), encoding="utf-8", xml_declaration=True)
    except (OSError, ET.ParseError):
        path.unlink(missing_ok=True)
        raise


# The environment a child of this harness gets (#7049). Everything else, above all a
# CI secret or token in the parent environment, is not inherited.
CHILD_ENV_ALLOW = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TZ",
    "TERM",
    "USER",
    "LOGNAME",
    "CI",
)


def child_env(**extra):
    env = {k: os.environ[k] for k in CHILD_ENV_ALLOW if k in os.environ}
    env.update(extra)
    return env


def run_redacted(argv, *, cwd, env, secrets):
    """Run ``argv`` with its stdout and stderr filtered through :func:`redact`; return its exit code.

    The output is streamed in chunks and a tail as long as the longest secret
    form is held back until the next chunk, so a form split across two reads or
    spanning a newline is still matched (#6964).
    """
    forms = [form for secret in secrets for form in secret_forms(secret)]
    forms.sort(key=len, reverse=True)
    hold = max((len(f) for f in forms), default=1) - 1
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  # noqa: S603
    pending = ""
    try:
        while True:
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                break
            emit, pending = redact_stream(pending + decoder.decode(chunk), forms, hold)
            sys.stdout.write(emit)
            sys.stdout.flush()
        sys.stdout.write(redact(pending + decoder.decode(b"", final=True), forms))
        sys.stdout.flush()
    except BaseException:
        proc.kill()  # a stop signal or an error here must not leave pytest running
        raise
    finally:
        proc.stdout.close()
        code = proc.wait()
        # pytest writes its own report file; filter it exactly like the log (#7048).
        for arg in argv:
            if isinstance(arg, str) and arg.startswith("--junitxml="):
                try:
                    scrub_file(Path(arg.split("=", 1)[1]), secrets)
                except FileNotFoundError:
                    pass
                except (OSError, ET.ParseError) as exc:
                    print(
                        f"sdk-python-live: the junit report could not be filtered and was removed: {exc}",
                        file=sys.stderr,
                    )
    return code


class Stack:
    """The daemon, the hub and the allowlist refresher, torn down in reverse order."""

    def __init__(self, binary, run_dir, port):
        self.binary = str(binary)
        self.run = run_dir
        self.port = port
        self.home = run_dir / "home"
        self.keys = run_dir / "keys"
        self.hub_dir = run_dir / "hub"
        self.socket = self.hub_dir / "wake-hub.sock"
        self.allowlist = run_dir / "hub-allow.json"
        self.ceremony = run_dir / "ceremony.db"
        self.bundle = run_dir / "bundles" / "agent.a2a-hub.json"
        self.procs = []
        self.stop_refresh = threading.Event()
        self.refresh_error = None

    def env(self):
        return child_env(
            HOME=str(self.home),
            XDG_CONFIG_HOME=str(self.home / ".config"),
            XDG_DATA_HOME=str(self.home / ".local" / "share"),
            AI_MEMORY_NO_CONFIG="1",
            AI_MEMORY_KEY_DIR=str(self.keys),
        )

    def cli(self, *args):
        res = subprocess.run([self.binary, *args], env=self.env(), capture_output=True, text=True, check=False)
        if res.returncode != 0:
            raise RuntimeError(f"`ai-memory {' '.join(args[:2])}` exited {res.returncode}: {res.stderr.strip()[-800:]}")
        return res.stdout

    def spawn(self, name, *args, extra_env=None):
        env = self.env()
        env.update(extra_env or {})
        log = open(self.run / f"{name}.log", "wb")  # noqa: SIM115 - held open for the child, closed in close()
        _spawn_guard["pending"] = None
        _spawn_guard["active"] = True
        try:
            proc = subprocess.Popen([self.binary, *args], env=env, stdout=log, stderr=subprocess.STDOUT)
            self.procs.append((name, proc, log))
        except BaseException as exc:
            # No child owns the log now, so close it here (#7040). A stop signal that
            # arrived while the guard was active outranks the spawn error: the run
            # must end as that signal (128+N), not as a failed start (exit 2).
            log.close()
            _spawn_guard["active"] = False
            pending = _spawn_guard["pending"]
            if pending is not None:
                _spawn_guard["pending"] = None
                raise Stopped(pending) from exc
            raise
        finally:
            _spawn_guard["active"] = False
        pending = _spawn_guard["pending"]
        if pending is not None:
            _spawn_guard["pending"] = None
            raise Stopped(pending)
        return proc

    @property
    def signing_key(self):
        return self.keys / f"{AGENT_ID}.priv"

    def start_daemon(self, cert, key):
        """Start `serve` in its shipped posture: HTTP-direct writes must be signed.

        The test agent's key is bound on the daemon database with the operator
        CLI first, so the SDK's signed store is admitted and an unsigned one is
        not. The agent is NOT an admin: the tests clean up by deleting their own
        memories by id.
        """
        db = str(self.run / "daemon.db")
        pub = self.cli("identity", "export-pub", "--key-dir", str(self.keys), "--agent-id", AGENT_ID).strip()
        self.cli("agents", "register", "--db", db, "--agent-id", AGENT_ID, "--agent-type", "ai:sdk-live", "--json")
        self.cli("agents", "bind-key", "--db", db, "--agent-id", AGENT_ID, f"--pubkey={pub}", "--json")
        self.spawn(
            "daemon",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--tls-cert",
            str(cert),
            "--tls-key",
            str(key),
            "--db",
            db,
        )

    def wait_daemon(self, ca, deadline_secs=120):
        ctx = ssl.create_default_context(cafile=str(ca))
        end = time.monotonic() + deadline_secs
        while time.monotonic() < end:
            self.check_alive()
            try:
                # Nested on purpose: parenthesised multi-context `with` needs Python 3.10.
                with socket.create_connection(("127.0.0.1", self.port), timeout=2) as raw:  # noqa: SIM117
                    with ctx.wrap_socket(raw, server_hostname="localhost"):
                        return
            except OSError:
                time.sleep(1)
        raise RuntimeError(f"the daemon never answered TLS on 127.0.0.1:{self.port}")

    def enroll(self):
        for d in (self.keys, self.hub_dir, self.bundle.parent):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(d, 0o700)
        self.cli("identity", "generate", "--key-dir", str(self.keys), "--agent-id", "daemon", "--json")
        self.cli("identity", "generate", "--key-dir", str(self.keys), "--agent-id", AGENT_ID, "--json")
        pub = self.cli("identity", "export-pub", "--key-dir", str(self.keys), "--agent-id", AGENT_ID).strip()
        db = str(self.ceremony)
        self.cli("agents", "register", "--db", db, "--agent-id", AGENT_ID, "--agent-type", "ai:sdk-live", "--json")
        self.cli("agents", "bind-key", "--db", db, "--agent-id", AGENT_ID, f"--pubkey={pub}", "--json")
        self.cli(
            "identity",
            "delegate",
            "--db",
            db,
            "--agent-id",
            AGENT_ID,
            "--scope",
            "a2a-hub",
            "--hub-id",
            HUB_ID,
            "--ttl-secs",
            "3600",
            "--out",
            str(self.bundle),
            "--json",
        )

    def publish_allowlist(self):
        self.cli(
            "identity",
            "hub-cache",
            "--db",
            str(self.ceremony),
            "--include-agent",
            AGENT_ID,
            "--daemon-producer",
            "--out",
            str(self.allowlist),
            "--json",
        )
        os.chmod(self.allowlist, 0o600)

    def refresher(self):
        while not self.stop_refresh.wait(15):
            try:
                self.publish_allowlist()
            except RuntimeError as exc:
                self.refresh_error = str(exc)

    def start_hub(self, deadline_secs=60):
        self.publish_allowlist()
        threading.Thread(target=self.refresher, daemon=True).start()
        if self.socket.exists():
            self.socket.unlink()
        self.spawn(
            "hub",
            "wake-hub",
            "--socket",
            str(self.socket),
            "--hub-id",
            HUB_ID,
            "--allowlist",
            str(self.allowlist),
        )
        end = time.monotonic() + deadline_secs
        while time.monotonic() < end:
            self.check_alive()
            res = subprocess.run(
                [self.binary, "wake-hub", "--socket", str(self.socket), "--health"],
                env=self.env(),
                capture_output=True,
                check=False,
            )
            if res.returncode == 0:
                return
            time.sleep(1)
        raise RuntimeError(f"the wake hub never became healthy on {self.socket}")

    def check_alive(self):
        for name, proc, _ in self.procs:
            if proc.poll() is not None:
                tail = (self.run / f"{name}.log").read_text(errors="replace")[-2000:]
                raise RuntimeError(f"{name} exited with {proc.returncode}:\n{tail}")

    def close(self):
        """Stop every child, newest first: terminate, wait up to 20 s, then kill.

        Idempotent. Termination signals are ignored meanwhile, so a second
        Ctrl-C cannot cut the teardown short and leave a child running (#6812).
        """
        previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in STOP_SIGNALS}
        try:
            self._close()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)

    def _close(self):
        self.stop_refresh.set()
        for _, proc, log in reversed(self.procs):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            log.close()
        self.procs = []


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", required=True, type=Path)
    ap.add_argument("--sdk", required=True, type=Path)
    ap.add_argument("--run-dir", required=True, type=Path)
    ap.add_argument("--port", type=int, default=0, help="daemon port (default: a free loopback port, #6831)")
    a = ap.parse_args(argv)

    previous = {sig: signal.signal(sig, _stop) for sig in STOP_SIGNALS}
    try:
        return run_live(a)
    except Stopped as stopped:
        print(f"sdk-python-live: stopped by signal {stopped.signum}; the stack was torn down", file=sys.stderr)
        return 128 + stopped.signum
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def run_live(a):
    """Start the stack, run the live tests, and tear the stack down on every exit (#6812)."""
    run = a.run_dir.resolve()
    run.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(run, 0o700)
    port = a.port or free_port()
    stack = Stack(a.binary.resolve(), run, port)
    try:
        return run_stack(stack, a.sdk, port)
    finally:
        stack.close()


def run_secrets(stack, key):
    """The secrets the filter must keep out of the CI log: the signing key and the TLS key."""
    return [stack.signing_key.read_bytes(), key.read_bytes()]


def run_stack(stack, sdk, port):
    run = stack.run
    try:
        ca, cert, key = mint_tls(run / "tls")
        stack.home.mkdir(parents=True, exist_ok=True)
        stack.enroll()
        stack.start_daemon(cert, key)
        stack.start_hub()
        stack.wait_daemon(ca)
    except Exception as exc:  # noqa: BLE001 - any startup error is exit 2; the caller tears down
        print(f"sdk-python-live: could not start the stack: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    report = run / "live-junit.xml"
    env = child_env(
        SSL_CERT_FILE=str(ca),
        AI_MEMORY_NO_CONFIG="1",
        AI_MEMORY_TEST_DAEMON="1",
        AI_MEMORY_TEST_BASE_URL=f"https://localhost:{port}",
        AI_MEMORY_TEST_AGENT_ID=AGENT_ID,
        AI_MEMORY_TEST_SIGNING_KEY=str(stack.signing_key),
        AI_MEMORY_TEST_WAKE_HUB_SOCKET=str(stack.socket),
        AI_MEMORY_TEST_WAKE_HUB_BUNDLE=str(stack.bundle),
        AI_MEMORY_TEST_WAKE_HUB_ID=HUB_ID,
    )
    # pytest's output goes through the redaction filter: a failing live test
    # may print the per-run signing key or the TLS key in an assertion (#6964).
    secrets = run_secrets(stack, key)
    exit_code = run_redacted(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-rs",
            "-p",
            "no:cacheprovider",
            f"--junitxml={report}",
            *LIVE_TESTS,
        ],
        cwd=str(sdk.resolve()),
        env=env,
        secrets=secrets,
    )
    stack.close()
    if stack.refresh_error:
        print(f"sdk-python-live: allowlist refresh failed: {stack.refresh_error}", file=sys.stderr)
    problems = verdict(junit_outcomes(report)) if report.exists() else ["no junit report was written"]
    if problems or exit_code != 0:
        for p in problems:
            print(f"sdk-python-live: {p}", file=sys.stderr)
        print(f"sdk-python-live: FAIL (pytest exit {exit_code})", file=sys.stderr)
        return 1
    print(f"sdk-python-live: PASS, all {len(LIVE_TESTS)} live tests ran and passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
