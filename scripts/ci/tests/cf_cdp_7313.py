"""Standard-library Chrome DevTools Protocol harness for the cf-dashboard browser test (#7634 #7639).

No third-party package: it launches an installed Chrome or Chromium with `--headless=new`, talks to it over a
hand-written WebSocket client, and serves `infra/cf-dashboard/public` from a local http.server with the response
headers of the REAL `_headers` file. Every external host is unresolvable (`--host-resolver-rules`), so a page can
only load what the local server gives it.

`find_browser()` looks at CF_DASH_CHROME, then PATH, then a Playwright browser cache if one exists. Scratch space
(the Chrome profile) lives under the repository's `.local-runs/`, never under a temp directory.
"""
import base64
import glob
import hashlib
import http.server
import json
import mimetypes
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

import cf_origin_7313 as origin_mod

REPO = Path(__file__).resolve().parents[3]
PUBLIC = REPO / "infra" / "cf-dashboard" / "public"
SCRATCH = REPO / ".local-runs"
BROWSER_ENV = "CF_DASH_CHROME"
BROWSER_NAMES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome")
PLAYWRIGHT_GLOBS = ("~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome",
                    "~/Library/Caches/ms-playwright/chromium-*/chrome-mac*/Chromium.app/Contents/MacOS/Chromium")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
LAUNCH_TIMEOUT = 30
CALL_TIMEOUT = 30
READ_STEP = 0.2
FRAME_TIMEOUT = 10


def find_browser():
    """Path of a Chrome / Chromium binary, or None."""
    given = os.environ.get(BROWSER_ENV)
    if given:
        return given if os.access(given, os.X_OK) else None
    for name in BROWSER_NAMES:
        found = shutil.which(name)
        if found:
            return found
    for pattern in PLAYWRIGHT_GLOBS:
        for candidate in sorted(glob.glob(os.path.expanduser(pattern)), reverse=True):
            if os.access(candidate, os.X_OK):
                return candidate
    return None


class WebSocket:
    """A minimal RFC 6455 client: handshake, masked text frames, fragmentation, ping and close."""

    def __init__(self, host, port, path):
        self.sock = socket.create_connection((host, port), timeout=FRAME_TIMEOUT)
        key = base64.b64encode(os.urandom(16)).decode()
        request = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key))
        self.sock.sendall(request.encode("ascii"))
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("websocket handshake: connection closed")
            head += chunk
        head, _, self.buf = head.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        if " 101 " not in lines[0] + " ":
            raise ConnectionError("websocket handshake refused: %s" % lines[0])
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode()
        headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
        if headers.get("sec-websocket-accept") != accept:
            raise ConnectionError("websocket handshake: bad Sec-WebSocket-Accept")

    def _frame(self, opcode, payload):
        header = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def send_text(self, text):
        self._frame(0x1, text.encode("utf-8"))

    def _read(self, n):
        while len(self.buf) < n:
            ready, _, _ = select.select([self.sock], [], [], FRAME_TIMEOUT)
            if not ready:
                raise socket.timeout("websocket: frame read timed out")
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket closed")
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def readable(self, timeout):
        return bool(self.buf) or bool(select.select([self.sock], [], [], timeout)[0])

    def recv_message(self):
        """The next complete text message (blocks once its first byte is readable)."""
        parts, opcode0 = [], None
        while True:
            b0, b1 = self._read(2)
            fin, opcode, masked, n = b0 & 0x80, b0 & 0x0F, b1 & 0x80, b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            mask = self._read(4) if masked else b""
            payload = self._read(n)
            if masked:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x9:
                self._frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x8:
                raise ConnectionError("websocket closed by the browser")
            if opcode in (0x1, 0x2):
                opcode0 = opcode
            parts.append(payload)
            if fin:
                return b"".join(parts).decode("utf-8") if opcode0 == 0x1 else ""

    def close(self):
        try:
            self._frame(0x8, b"")
        except OSError:
            pass
        self.sock.close()


class CdpError(RuntimeError):
    pass


class Cdp:
    def __init__(self, ws):
        self.ws, self.counter, self.events = ws, 0, []

    def send(self, method, params=None, timeout=CALL_TIMEOUT):
        self.counter += 1
        mid = self.counter
        self.ws.send_text(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.ws.readable(READ_STEP):
                continue
            msg = json.loads(self.ws.recv_message())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise CdpError("%s: %s" % (method, msg["error"]))
                return msg.get("result", {})
            self.events.append(msg)
        raise TimeoutError("no answer to %s" % method)

    def pump(self, seconds, until=None):
        """Collect events for `seconds`, or until `until(events)` is true."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            if until is not None and until(self.events):
                return True
            if self.ws.readable(READ_STEP):
                self.events.append(json.loads(self.ws.recv_message()))
        return bool(until is not None and until(self.events))


class Browser:
    def __init__(self, binary):
        SCRATCH.mkdir(exist_ok=True)
        self.profile = tempfile.mkdtemp(prefix="chrome-7634-", dir=str(SCRATCH))
        flags = ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run",
                 "--no-default-browser-check", "--disable-extensions", "--disable-background-networking",
                 "--mute-audio", "--remote-debugging-port=0", "--user-data-dir=" + self.profile,
                 "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1", "about:blank"]
        self.proc = subprocess.Popen([binary] + flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     start_new_session=True)
        port_file = Path(self.profile) / "DevToolsActivePort"
        deadline = time.time() + LAUNCH_TIMEOUT
        while time.time() < deadline and not port_file.exists():
            if self.proc.poll() is not None:
                break
            time.sleep(0.1)
        if not port_file.exists():
            self.close()
            raise RuntimeError("the browser did not publish a DevTools port")
        time.sleep(0.2)
        self.port = int(port_file.read_text().split()[0])

    def new_page(self):
        deadline = time.time() + LAUNCH_TIMEOUT
        while time.time() < deadline:
            with urllib.request.urlopen("http://127.0.0.1:%d/json/list" % self.port, timeout=FRAME_TIMEOUT) as r:
                pages = [t for t in json.load(r) if t.get("type") == "page"]
            if pages:
                parsed = urllib.parse.urlparse(pages[0]["webSocketDebuggerUrl"])
                return Cdp(WebSocket(parsed.hostname, parsed.port, parsed.path))
            time.sleep(0.1)
        raise RuntimeError("the browser has no page target")

    def close(self):
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        shutil.rmtree(self.profile, ignore_errors=True)


def headers_for(headers_text, path):
    """Every (name, value) of every `_headers` rule whose pattern matches the served path, in file order."""
    out, current = [], None
    for line in headers_text.splitlines():
        if not line.strip():
            continue
        if line[0] not in " \t":
            current = origin_mod._pattern_regex(line.strip()).match(path) is not None
        elif current:
            name, _, value = line.strip().partition(":")
            out.append((name.strip(), value.strip()))
    return out


class Site:
    """The dashboard public directory on 127.0.0.1 with the headers of a `_headers` text and per-path overrides."""

    def __init__(self, headers_text, overrides=None):
        self.headers_text = headers_text
        self.overrides = dict(overrides or {})  # path -> (status, content type, bytes)
        self.served = []  # (path, [(header, value)])
        site = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                path = urllib.parse.urlparse(self.path).path
                status, ctype, body = site.lookup(path)
                headers = headers_for(site.headers_text, path)
                site.served.append((path, headers))
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for name, value in headers:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def lookup(self, path):
        if path in self.overrides:
            return self.overrides[path]
        name = "index.html" if path == "/" else path.lstrip("/")
        target = (PUBLIC / name).resolve()
        if PUBLIC.resolve() not in target.parents or not target.is_file():
            return 404, "text/plain", b"not found"
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if target.suffix == ".js":
            ctype = "text/javascript"
        return 200, ctype + ("; charset=utf-8" if ctype.startswith("text/") or ctype == "application/json" else ""), target.read_bytes()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


VIOLATION_COLLECTOR = (
    "window.__v=[];document.addEventListener('securitypolicyviolation',function(e){window.__v.push("
    "{d:e.violatedDirective,eff:e.effectiveDirective,uri:e.blockedURI,sample:e.sample})});")


def load(browser, public_headers, state_text, selectors, js_append="", js_replace=None, init_script="",
         settle=1.8, extra_overrides=None):
    """Load the dashboard in a fresh page and return what the browser saw (a dict)."""
    js_source = (PUBLIC / "index.js").read_text(encoding="utf-8")
    if js_replace:
        for old, new in js_replace:
            if old not in js_source:
                raise AssertionError("mutation target not found in index.js: %r" % old)
            js_source = js_source.replace(old, new)
    overrides = {"/state.json": (200, "application/json; charset=utf-8", state_text.encode("utf-8")),
                 "/index.js": (200, "text/javascript; charset=utf-8", (js_source + "\n" + js_append).encode("utf-8"))}
    overrides.update(extra_overrides or {})
    site = Site(public_headers, overrides)
    page = browser.new_page()
    try:
        for domain in ("Page", "Runtime", "Log"):
            page.send(domain + ".enable")
        page.send("Page.addScriptToEvaluateOnNewDocument", {"source": VIOLATION_COLLECTOR + init_script})
        page.send("Page.navigate", {"url": "http://127.0.0.1:%d/" % site.port})
        if not page.pump(CALL_TIMEOUT, until=lambda ev: any(e.get("method") == "Page.loadEventFired" for e in ev)):
            raise TimeoutError("the page did not finish loading")
        page.pump(settle)
        expression = (
            "(async()=>{const counts={};for(const s of %s){counts[s]=document.querySelectorAll(s).length;}"
            "const r=await fetch('/',{cache:'no-store'});"
            "return JSON.stringify({v:window.__v,pwn:typeof window.__pwn,counts:counts,shapes:window.__shapes||null,forge:window.__forge||null,"
            "csp:r.headers.get('content-security-policy'),live:(document.getElementById('livetext')||{}).textContent||'',"
            "tt:typeof window.trustedTypes});})()" % json.dumps(list(selectors)))
        result = page.send("Runtime.evaluate", {"expression": expression, "returnByValue": True, "awaitPromise": True})
        if "exceptionDetails" in result:
            raise AssertionError("collecting the page state failed: %s" % result["exceptionDetails"])
        seen = json.loads(result["result"]["value"])
        page.pump(0.2)
    finally:
        try:
            page.ws.close()
        finally:
            site.close()
    console, exceptions, log = [], [], []
    for event in page.events:
        method, params = event.get("method"), event.get("params", {})
        if method == "Runtime.consoleAPICalled":
            console.append("%s: %s" % (params.get("type"), " ".join(str(a.get("value", a.get("description", ""))) for a in params.get("args", []))))
        elif method == "Runtime.exceptionThrown":
            details = params.get("exceptionDetails", {})
            exceptions.append((details.get("exception") or {}).get("description") or details.get("text"))
        elif method == "Log.entryAdded":
            entry = params.get("entry", {})
            host = urllib.parse.urlparse(entry.get("url", "")).hostname
            if entry.get("source") == "network" and host not in (None, "127.0.0.1"):
                continue  # an external host the sandbox deliberately cannot resolve
            log.append("%s/%s: %s" % (entry.get("source"), entry.get("level"), entry.get("text")))
    seen.update({"console": console, "exceptions": exceptions, "log": log, "served": site.served})
    return seen
