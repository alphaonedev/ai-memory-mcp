#!/usr/bin/env -S python3 -I -S
"""The ai-memory v1.0.0 laptop federation lab (Python 3.9+, standard library only).

ONE command stands up a two-node ai-memory federation on your laptop with mutual TLS,
fingerprint-pinned peers, required agent attestation and every asi-hard posture knob at its
hard floor; loads a sample of the synthetic corpus; and then PROVES the thing works by
asserting both positives (an attested write replicates across the mesh and is recallable at
the peer) and negatives (an unpinned client, a plaintext client and an unsigned write are all
refused).

    ./run.py

It is idempotent (each run removes and rebuilds run/), it writes nothing outside run/ and
stops every daemon it started on the way out, including on Ctrl-C (exit 130) and SIGTERM
(exit 143). The --posture-selftest legs write only to one scratch directory under $TMPDIR
(the current directory when TMPDIR is unset) and remove it.

EXTENDS, DOES NOT FORK. All cryptographic material comes from
infra/do-hive/crypto/gen-certs.sh, which this program runs with bash.

HONESTY. Read README.md "What this does and does not prove": this is a functional
demonstration on ONE host with TWO nodes. It is not a scale test, not a benchmark, and not
evidence for any capacity claim.

START STATE. Before it imports anything but sys, the program refuses to run (one
"run.py: REFUSED: <reasons>" line on stderr, exit 78) unless the interpreter was started
isolated (-I) on a script file: no -c, -m or stdin entry, no -i, -O, -v, -b, -d, -x, -W or -X
option other than -X frozen_modules=on|off, no trace, profile or monitoring hook, no global,
module or import hook that a plain start does not have, none of 23 builtin functions and 10 core types replaced (the
exception classes, enumerate, range and super are the names it uses that are not checked), and no LD_* or DYLD_*
variable. A start with -I but without -S re-executes itself once with -I -S, so the program
runs in a process where no .pth file or sitecustomize of the installation ran; where that site
code already replaced a sys hook (Ubuntu's apport replaces sys.excepthook) the start is refused
like any other replacement, so start it with -I -S as the first line does. Stated limits: code
that runs inside the interpreter before line 1 (an LD_PRELOAD library already loaded, an audit
hook, a modified installation) can forge any check; the python3 found on PATH and its installation are trusted; on Python 3.9, which has no
sys.orig_argv, the interpreter command line is read through ctypes (Py_GetArgcArgv), and a start where it cannot be read is refused.

EXIT CODES. 0 only when at least one PASS was recorded, no FAIL was, and the summary and every
output stream were written; --help is 0. 1: a preflight failure, a RED run, a missing option
value or an output stream that could not be written. 2: an unknown argument, a bad port, a
bad --corpus-ns or CORPUS_ROWS, --probe-mutation with --no-caveat-probe. 78: the start state
was refused. 130 and 143: interrupted by SIGINT or SIGTERM (daemons stopped first).
"""
import sys

_LAB_REFUSED_RC = 78
_LAB_ALLOWED_OPTION_LETTERS = "IsSEPBq"
_LAB_ALLOWED_XOPTIONS = ("frozen_modules=on", "frozen_modules=off")
_LAB_REQUIRED_FLAGS = (
    ("debug", 0), ("inspect", 0), ("interactive", 0), ("optimize", 0), ("no_user_site", 1),
    ("ignore_environment", 1), ("isolated", 1), ("verbose", 0), ("bytes_warning", 0),
    ("dev_mode", False), ("safe_path", True),
)
_LAB_TOLERATED_FLAGS = (
    "no_site", "dont_write_bytecode", "quiet", "hash_randomization", "utf8_mode",
    "warn_default_encoding", "int_max_str_digits", "gil", "thread_inherit_context",
    "context_aware_warnings",
)
_LAB_STRUCTSEQ_ATTRS = ("count", "index", "n_fields", "n_sequence_fields", "n_unnamed_fields")
_LAB_START_GLOBALS = (
    "__name__", "__doc__", "__package__", "__loader__", "__spec__", "__annotations__",
    "__builtins__", "__file__", "__cached__", "sys", "_LAB_REFUSED_RC",
    "_LAB_ALLOWED_OPTION_LETTERS", "_LAB_ALLOWED_XOPTIONS", "_LAB_REQUIRED_FLAGS",
    "_LAB_TOLERATED_FLAGS", "_LAB_STRUCTSEQ_ATTRS", "_LAB_START_GLOBALS", "_LAB_BUILTIN_NAMES",
    "_LAB_CORE_TYPE_NAMES", "_LAB_UNCHECKED_BUILTINS",
    "_lab_refuse", "_lab_flag_reasons", "_lab_ctypes_argv", "_lab_orig_argv", "_lab_argv_reasons", "_lab_entry_reasons",
    "_lab_hook_reasons", "_lab_world_reasons", "_lab_start_state",
)
_LAB_BUILTIN_NAMES = (
    "open", "__import__", "len", "print", "isinstance", "getattr", "hasattr", "repr", "sorted",
    "compile", "exec", "eval", "dir", "iter", "next", "globals", "setattr", "id", "min", "max", "abs", "all", "any",
)
# The core types, compared by identity with the class of a literal (no name lookup can forge a literal's class).
_LAB_CORE_TYPE_NAMES = ("str", "int", "float", "bool", "bytes", "list", "dict", "set", "tuple", "type")
# Builtins the program names that are NOT identity-checked: exception classes and three constructors.
_LAB_UNCHECKED_BUILTINS = (
    "BaseException", "ConnectionRefusedError", "Exception", "OSError", "ProcessLookupError", "RecursionError",
    "RuntimeError", "SystemExit", "TypeError", "ValueError", "enumerate", "range", "super",
)


def _lab_refuse(reasons):
    """Write one REFUSED line and leave with 78 through posix._exit (no REPL, no atexit)."""
    try:
        sys.stderr.write("run.py: REFUSED: " + "; ".join(reasons) + "\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001 - a refusal must leave even when stderr is gone
        pass
    posix = sys.modules.get("posix")
    if posix is not None and hasattr(posix, "_exit"):
        posix._exit(_LAB_REFUSED_RC)
    raise SystemExit(_LAB_REFUSED_RC)


def _lab_flag_reasons():
    """Every sys.flags field is required, tolerated or refused; an unknown field is refused."""
    reasons = []
    flags = sys.flags
    if type(flags).__flags__ & (1 << 9):
        reasons.append("sys.flags is not the interpreter's own type")
    required = dict(_LAB_REQUIRED_FLAGS)
    for name in dir(flags):
        if name.startswith("_") or name in _LAB_STRUCTSEQ_ATTRS:
            continue
        value = getattr(flags, name)
        if name in required:
            want = required[name]
            if type(value) not in (int, bool) or value != want:
                reasons.append("interpreter flag %s=%r (wanted %r)" % (name, value, want))
        elif name not in _LAB_TOLERATED_FLAGS:
            reasons.append("unknown interpreter flag %s=%r" % (name, value))
    if flags.isolated != 1:
        reasons.append("not started isolated (-I)")
    if sys.warnoptions:
        reasons.append("warning options are set (-W)")
    for key, value in getattr(sys, "_xoptions", {}).items():
        if key != "frozen_modules" or value not in ("on", "off"):
            reasons.append("-X option %s is not allowed" % key)
    return reasons


def _lab_ctypes_argv():
    """The interpreter command line from Py_GetArgcArgv through ctypes; None when it cannot be read."""
    try:
        import ctypes
        argc = ctypes.c_int()
        argv = ctypes.POINTER(ctypes.c_wchar_p)()
        ctypes.pythonapi.Py_GetArgcArgv(ctypes.byref(argc), ctypes.byref(argv))
        return [argv[n] for n in range(argc.value)]
    except Exception:  # noqa: BLE001 - an unreadable command line is a refusal, never a pass
        return None


def _lab_orig_argv():
    """The interpreter command line: sys.orig_argv (3.10+), else the ctypes reader (3.9); None when unreadable."""
    orig = getattr(sys, "orig_argv", None)
    if orig is not None:
        return list(orig)
    return _lab_ctypes_argv()


def _lab_argv_reasons():
    """The interpreter options before the script token (sys.orig_argv, or ctypes on Python 3.9)."""
    orig = _lab_orig_argv()
    if orig is None or len(orig) < 1 or any(type(t) is not str for t in orig):
        return ["the interpreter command line cannot be read (Python 3.9 needs ctypes)"]
    reasons = []
    i = 1
    script = None
    while i < len(orig):
        tok = orig[i]
        if tok == "-X":
            if i + 1 >= len(orig) or orig[i + 1] not in _LAB_ALLOWED_XOPTIONS:
                reasons.append("interpreter option -X %s is not allowed" % (orig[i + 1] if i + 1 < len(orig) else ""))
            i += 2
            continue
        if tok.startswith("-X"):
            if tok[2:] not in _LAB_ALLOWED_XOPTIONS:
                reasons.append("interpreter option %s is not allowed" % tok)
            i += 1
            continue
        if tok == "-":
            reasons.append("entry from stdin is not allowed")
            return reasons
        if tok.startswith("-"):
            bad = [c for c in tok[1:] if c not in _LAB_ALLOWED_OPTION_LETTERS]
            if bad or len(tok) == 1:
                reasons.append("interpreter option %s is not allowed" % tok)
                if "c" in bad or "m" in bad:
                    reasons.append("entry by -c or -m is not allowed")
                    return reasons
            i += 1
            continue
        script = i
        break
    if script is None:
        reasons.append("no script file on the interpreter command line")
    elif list(orig[script + 1:]) != list(sys.argv[1:]):
        reasons.append("the script arguments differ from the interpreter command line")
    return reasons


def _lab_entry_reasons(names):
    """__main__ must be this file run as a script: no spec, an absolute __file__, argv[0] set."""
    reasons = []
    if names.get("__name__") != "__main__":
        reasons.append("not run as the main program")
    if names.get("__spec__") is not None:
        reasons.append("entry by -m or an import is not allowed")
    path = names.get("__file__")
    if type(path) is not str or not path.startswith("/") or not path.endswith(".py"):
        reasons.append("entry is not a script file run directly")
    argv0 = sys.argv[0] if sys.argv else ""
    if type(argv0) is not str or argv0 in ("", "-", "-c", "-m"):
        reasons.append("entry is not a script file run directly (argv[0] %r)" % (argv0,))
    if names.get("__builtins__") is not sys.modules.get("builtins"):
        reasons.append("__builtins__ is not the builtins module")
    extra = sorted(k for k in names if k not in _LAB_START_GLOBALS)
    for k in extra:
        reasons.append("unexpected global %s at start" % k)
    exe = sys.executable
    if type(exe) is not str or not exe.startswith("/"):
        reasons.append("sys.executable is not an absolute path")
    if sys.version_info < (3, 9):
        reasons.append("Python 3.9 or newer is required")
    return reasons


def _lab_hook_reasons():
    """Trace, profile and monitoring hooks, the sys hooks, loader variables, builtin functions and core types."""
    reasons = []
    if sys.gettrace() is not None or sys.getprofile() is not None:
        reasons.append("a trace or profile hook is set")
    mon = getattr(sys, "monitoring", None)
    if mon is not None:
        for tool in range(6):
            if mon.get_tool(tool) is not None:
                reasons.append("a sys.monitoring tool is registered")
                break
    for hook in ("excepthook", "displayhook", "unraisablehook", "breakpointhook"):
        if getattr(sys, hook, None) is not getattr(sys, "__%s__" % hook, None):
            reasons.append("sys.%s is replaced" % hook)
    posix = sys.modules.get("posix")
    if posix is None or "posix" not in sys.builtin_module_names or type(posix) is not type(sys):
        reasons.append("the posix module is not the builtin one")
    else:
        for key in posix.environ:
            if key.startswith(b"LD_") or key.startswith(b"DYLD_"):
                reasons.append("loader variable %s is set" % key.decode("ascii", "replace"))
    bi = sys.modules.get("builtins")
    io_mod = sys.modules.get("_io")
    for name in _LAB_BUILTIN_NAMES:
        obj = getattr(bi, name, None)
        owner = io_mod if name == "open" else bi
        if (type(obj).__name__ != "builtin_function_or_method" or getattr(obj, "__name__", None) != name
                or getattr(obj, "__self__", None) is not owner):
            reasons.append("builtin %s replaced" % name)
    literals = (("str", ""), ("int", 0), ("float", 1.0), ("bool", True), ("bytes", b""), ("list", []),
                ("dict", {}), ("set", {1}), ("tuple", ()), ("type", 0))
    for name, literal in literals:
        want = literal.__class__.__class__ if name == "type" else literal.__class__
        if getattr(bi, name, None) is not want:
            reasons.append("builtin %s replaced" % name)
    return reasons


def _lab_world_reasons(names):
    """Import machinery, sys.path and every loaded module (only meaningful once site is not imported)."""
    reasons = []
    want_meta = [("BuiltinImporter", "_frozen_importlib"), ("FrozenImporter", "_frozen_importlib"),
                 ("PathFinder", "_frozen_importlib_external")]
    meta = [(getattr(f, "__name__", None), getattr(f, "__module__", None)) for f in sys.meta_path]
    if meta != want_meta or not all(type(f) is type for f in sys.meta_path):
        reasons.append("import machinery changed (sys.meta_path)")
    hooks = sys.path_hooks
    if (len(hooks) != 2 or getattr(hooks[0], "__name__", None) != "zipimporter"
            or getattr(hooks[1], "__name__", None) != "path_hook_for_FileFinder"):
        reasons.append("import machinery changed (sys.path_hooks)")
    base = sys.base_prefix.rstrip("/") + "/"
    path = names.get("__file__")
    here = path[:path.rindex("/")] if type(path) is str and "/" in path else ""
    stdlib = []
    for entry in sys.path:
        if (type(entry) is not str or not entry.startswith(base) or entry.rstrip("/") == here
                or entry in ("", ".")):
            reasons.append("sys.path entry outside the standard library: %r" % (entry,))
        else:
            stdlib.append(entry.rstrip("/") + "/")
    for name, mod in list(sys.modules.items()):
        if name == "__main__":
            continue
        if type(mod) is not type(sys):
            reasons.append("module %s is not a module object" % name)
            continue
        spec = getattr(mod, "__spec__", None)
        origin = getattr(spec, "origin", None)
        if origin in ("built-in", "frozen") and getattr(spec, "name", None) == name:
            continue
        mpath = getattr(mod, "__file__", None)
        if type(mpath) is str and any(mpath.startswith(d) for d in stdlib):
            continue
        reasons.append("module %s loaded from outside the standard library" % name)
    return reasons


def _lab_start_state(names):
    """Refuse, re-execute with -I -S, or return so the program may import its modules."""
    core = _lab_flag_reasons() + _lab_argv_reasons() + _lab_entry_reasons(names) + _lab_hook_reasons()
    if not core and sys.flags.no_site == 0:
        posix = sys.modules["posix"]
        argv = [sys.executable, "-I", "-S"]
        frozen = getattr(sys, "_xoptions", {}).get("frozen_modules")
        if frozen in ("on", "off"):
            argv += ["-X", "frozen_modules=" + frozen]
        argv += [names["__file__"]] + list(sys.argv[1:])
        try:
            sys.stdout.flush()
            sys.stderr.flush()
            posix.execve(sys.executable, argv, posix.environ)
        except Exception as exc:  # noqa: BLE001 - any failure to re-execute is a refusal
            _lab_refuse(["re-executing with -I -S failed (%s)" % exc.__class__.__name__])
    if sys.flags.no_site == 0:
        _lab_refuse(core)
    reasons = core + _lab_world_reasons(names)
    if reasons:
        _lab_refuse(reasons)


_lab_start_state(globals())

# ---------------------------------------------------------------------------------------------------------------------
# Stage 1: the start state is proven; the standard library may be imported.
# ---------------------------------------------------------------------------------------------------------------------
import errno  # noqa: E402
import http.client  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import signal  # noqa: E402
import socket  # noqa: E402
import sqlite3  # noqa: E402
import ssl  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
import urllib.parse  # noqa: E402
from collections import Counter  # noqa: E402


def _lab_stage1_reasons(names):
    """After the imports: every module file and the script token resolve inside the standard library or to this file."""
    reasons = []
    stdlib = [os.path.realpath(p) + os.sep for p in sys.path]
    for name, mod in list(sys.modules.items()):
        if name == "__main__":
            continue
        spec = getattr(mod, "__spec__", None)
        if getattr(spec, "origin", None) in ("built-in", "frozen"):
            continue
        path = getattr(mod, "__file__", None)
        if type(path) is not str or not any(os.path.realpath(path).startswith(d) for d in stdlib):
            reasons.append("module %s loaded from outside the standard library" % name)
    me = os.path.realpath(names["__file__"])
    if os.path.realpath(os.path.abspath(sys.argv[0])) != me:
        reasons.append("argv[0] does not resolve to this file")
    orig = _lab_orig_argv()
    if orig is None:
        reasons.append("the interpreter command line cannot be read")
    else:
        tokens = [t for t in orig[1:] if not t.startswith("-") and not t.startswith("frozen_modules=")]
        if not tokens or os.path.realpath(os.path.abspath(tokens[0])) != me:
            reasons.append("the script on the interpreter command line is not this file")
    return reasons


_LAB_STAGE1 = _lab_stage1_reasons(globals())
if _LAB_STAGE1:
    _lab_refuse(_LAB_STAGE1)

# ---------------------------------------------------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------------------------------------------------
LAB = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(LAB))
RUN = os.path.join(LAB, "run")
SAMPLE = os.path.join(LAB, "sample", "lab-corpus.json")

AGENT_A = "ai:lab-node-a"
AGENT_B = "ai:lab-node-b"
AUTHOR = "ai:lab-author"
FED_NS = "fed-lab"
DEFAULT_CORPUS_NS = "lab-corpus"
DEFAULT_CORPUS_ROWS = "2000"
DEFAULT_PORT_A = "19481"
DEFAULT_PORT_B = "19482"
DEFAULT_RUST_LOG = "ai_memory=info,federation=debug"
FIXTURE_QUERY = "ballast scheduling harbour rotation"
CONFIG_TOML = 'schema_version = 2\ntier = "keyword"\n'
PROBE_KNOB = "AI_MEMORY_REQUIRE_ROLLBACK_CHECK"
PROBE_REFUSAL = b"refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK:"
PROBE_INFO = b"INFO"
TIMEOUT_RC = 124
BASH_PATHS = ("/bin/bash", "/usr/bin/bash")

PORT_RE = re.compile(r"[1-9][0-9]{0,4}\Z", re.ASCII)
PORT_MAX = 65533
ROWS_RE = re.compile(r"[1-9][0-9]{0,8}\Z", re.ASCII)
NS_RE = re.compile(r"[A-Za-z0-9_/:.@-]+\Z", re.ASCII)
RUST_LOG_RE = re.compile(r"[A-Za-z0-9_=,.:-]{1,256}\Z", re.ASCII)

# The asi-hard posture: every row of src/security_profile.rs::KNOBS at its hard floor. SET entries are exported to each
# node; UNSET entries are permissive hatches whose hard value is "" (not in force). The drift guard compares both.
LAB_POSTURE_SET = (
    "AI_MEMORY_SECRET_SCREEN_MODE=refuse",
    "AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1",
    "AI_MEMORY_FED_REQUIRE_WRITE_SIG=1",
    "AI_MEMORY_FED_REQUIRE_SIGNAL_SIG=1",
    "AI_MEMORY_FED_REQUIRE_TRANSITION_SIG=1",
    "AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG=1",
    "AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED=1",
    "AI_MEMORY_CID_ENFORCE=1",
    "AI_MEMORY_REQUIRE_ROLLBACK_CHECK=1",
    "AI_MEMORY_REQUIRE_WITNESS=1",
    "AI_MEMORY_REQUIRE_CAUSE_BINDING=1",
    "AI_MEMORY_REQUIRE_ROLE_SEPARATION=1",
    "AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1",
    "AI_MEMORY_FED_REQUIRE_SERVER_VERIFY=1",
    "AI_MEMORY_DB_SYNCHRONOUS=FULL",
    "AI_MEMORY_FED_REQUIRE_SIG=1",
    "AI_MEMORY_FED_REQUIRE_NONCE=1",
    "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1",
    "AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=1",
    "AI_MEMORY_MIGRATION_REQUIRE_CORE_TABLES=1",
    "AI_MEMORY_PERMISSIONS_MODE=enforce",
    "AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=1",
    "AI_MEMORY_FED_CERT_PEER_BINDING=enforce",
    "AI_MEMORY_UNSTAMPED_MUTATION=refuse",
    "AI_MEMORY_REQUIRE_FORENSIC_SINK=1",
)
LAB_POSTURE_UNSET = (
    "AI_MEMORY_ALLOW_SCHEMA_AHEAD",
    "AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS",
    "AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR",
    "AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS",
    "AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS",
    "AI_MEMORY_AGENT_API_KEY_FILE_ALLOW_LAX_PERMS",
)

USAGE = """usage: run.py [options]

  --bin PATH          ai-memory binary (default: repo target/release, then $PATH)
  --signer PATH       attest_sign example binary (default: repo target/release/examples)
  --corpus-db PATH    load this FULL local corpus SQLite DB instead of the committed
                      text-only sample. Recall quality depends on the embedder that
                      produced the corpus matching the one the lab node runs (F-L8a);
                      the lab's default nodes run tier=keyword, i.e. lexical.
  --corpus-ns NS      namespace to slice from --corpus-db (default lab-corpus)
  --corpus-rows N     rows to take from --corpus-db (default 2000)
  --recall-query Q    query for the corpus-recall proof. Defaults to a phrase that
                      matches the committed synthetic fixture; with --corpus-db and
                      no explicit query the lab derives one from your corpus.
  --port-a N          node A port (default 19481)
  --port-b N          node B port (default 19482)
  --keep              keep run/ (daemons are still stopped) for post-mortem
  --no-caveat-probe   skip the asi-hard full-profile cold-boot probe (#2942, #4938)
  --probe-mutation    lower AI_MEMORY_REQUIRE_ROLLBACK_CHECK below its floor inside the probe and
                      require the probe to refuse for that knob (proves the probe can fail)
  --posture-selftest  run only the self-test legs (posture drift guard, matcher, start state,
                      exit paths; no daemons) and exit
  -h, --help          this text
"""


class LabInterrupted(BaseException):
    """Raised by the SIGINT and SIGTERM handlers so cleanup runs before the exit.

    A BaseException, like KeyboardInterrupt: no handler written for ordinary errors can swallow an interrupt
    and let the run continue to a GREEN verdict.
    """

    def __init__(self, signum):
        BaseException.__init__(self, signum)
        self.signum = signum


# ---------------------------------------------------------------------------------------------------------------------
# Output and the PASS/FAIL ledger
# ---------------------------------------------------------------------------------------------------------------------
class Ledger:
    """Every assertion goes through ok/no; an output line that cannot be written marks the ledger broken."""

    def __init__(self, out, color):
        self.out = out
        self.passes = 0
        self.fails = 0
        self.rows = []
        self.broken = False
        if color:
            self.c_ok, self.c_no, self.c_hd, self.c_dim, self.c_0 = "\033[32m", "\033[31m", "\033[1;36m", "\033[2m", "\033[0m"
        else:
            self.c_ok = self.c_no = self.c_hd = self.c_dim = self.c_0 = ""

    def emit(self, text):
        try:
            self.out.write(text)
        except (OSError, ValueError):
            self.broken = True

    def step(self, text):
        self.emit("\n%s══ %s %s\n" % (self.c_hd, text, self.c_0))

    def info(self, text):
        self.emit("   %sinfo%s %s\n" % (self.c_dim, self.c_0, text))

    def warn(self, text):
        self.emit("   %swarn%s %s\n" % (self.c_no, self.c_0, text))

    def ok(self, text):
        self.passes += 1
        self.rows.append(("PASS", text))
        self.emit("   %sPASS%s %s\n" % (self.c_ok, self.c_0, text))

    def no(self, text):
        self.fails += 1
        self.rows.append(("FAIL", text))
        self.emit("   %sFAIL%s %s\n" % (self.c_no, self.c_0, text))

    def summary(self):
        """Print the ledger and the counts; True only when nothing failed."""
        self.step("SUMMARY")
        for kind, text in self.rows:
            color = self.c_ok if kind == "PASS" else self.c_no
            self.emit("   %s%s%s %s\n" % (color, kind, self.c_0, text))
        self.emit("\n   %d PASS / %d FAIL\n" % (self.passes, self.fails))
        return self.fails == 0


def flush_streams(streams):
    """Flush every stream; False when any flush fails (a verdict that was not written is not a verdict)."""
    good = True
    for stream in streams:
        try:
            stream.flush()
        except (OSError, ValueError):
            good = False
    return good


def final_rc(ledger, summarized, streams):
    """0 only for a positive recorded pass: at least one PASS, no FAIL, the summary printed, every stream written."""
    flushed = flush_streams(streams)
    if ledger.passes >= 1 and ledger.fails == 0 and summarized and flushed and not ledger.broken:
        return 0
    return 1


# ---------------------------------------------------------------------------------------------------------------------
# Input parsing (positive forms only)
# ---------------------------------------------------------------------------------------------------------------------
def parse_port(text):
    """A plain decimal port from 1 to 65533 (room for PORT_B + 2), or None."""
    if type(text) is not str or PORT_RE.match(text) is None:
        return None
    value = int(text, 10)
    return value if value <= PORT_MAX else None


def parse_rows(text):
    """A plain decimal row count from 1 to 999999999, or None."""
    if type(text) is not str or ROWS_RE.match(text) is None:
        return None
    return int(text, 10)


def safe_namespace(text):
    """The --corpus-ns charset of tools/make-local-slice.sh: alphanumerics and _ / : . @ -."""
    return type(text) is str and NS_RE.match(text) is not None


def rust_log_value(environ):
    """The caller's RUST_LOG when it is a plain filter, else the lab default; and whether it was replaced."""
    value = environ.get("RUST_LOG")
    if value is None or value == "":
        return DEFAULT_RUST_LOG, False
    if RUST_LOG_RE.match(value) is None:
        return DEFAULT_RUST_LOG, True
    return value, False


VALUE_OPTIONS = {
    "--bin": "bin", "--signer": "signer", "--corpus-db": "corpus_db", "--corpus-ns": "corpus_ns",
    "--corpus-rows": "corpus_rows", "--recall-query": "recall_query", "--port-a": "port_a", "--port-b": "port_b",
}
FLAG_OPTIONS = {
    "--keep": "keep", "--no-caveat-probe": "no_caveat_probe", "--probe-mutation": "probe_mutation",
    "--posture-selftest": "posture_selftest",
}


def parse_args(argv, environ):
    """Return (options, None) or (None, (rc, stdout_text, stderr_text)) for an early exit."""
    opts = {
        "bin": environ.get("BIN", ""), "signer": environ.get("SIGNER", ""), "corpus_db": "", "corpus_ns": "",
        "corpus_rows": environ.get("CORPUS_ROWS", DEFAULT_CORPUS_ROWS), "recall_query": "",
        "port_a": environ.get("PORT_A", DEFAULT_PORT_A), "port_b": environ.get("PORT_B", DEFAULT_PORT_B),
        "keep": False, "no_caveat_probe": False, "probe_mutation": False, "posture_selftest": False,
    }
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in VALUE_OPTIONS:
            if i + 1 >= len(argv):
                return None, (1, "", "run.py: %s needs a value\n" % arg)
            opts[VALUE_OPTIONS[arg]] = argv[i + 1]
            i += 2
        elif arg in FLAG_OPTIONS:
            opts[FLAG_OPTIONS[arg]] = True
            i += 1
        elif arg in ("-h", "--help"):
            return None, (0, USAGE, "")
        else:
            return None, (2, "", "unknown argument: %s\n%s" % (arg, USAGE))
    for label, key in (("PORT_A", "port_a"), ("PORT_B", "port_b")):
        port = parse_port(opts[key])
        if port is None:
            return None, (2, "", "run.py: %s must be a decimal port from 1 to 65533, got [%s] (#5745)\n" % (label, opts[key]))
        opts[key] = port
    if opts["probe_mutation"] and opts["no_caveat_probe"]:
        return None, (2, "", "--probe-mutation needs the cold-boot probe: it cannot be combined with --no-caveat-probe\n")
    ns = opts["corpus_ns"] or DEFAULT_CORPUS_NS
    if not safe_namespace(ns):
        return None, (2, "", "refusing unsafe --corpus-ns: %s\n" % ns)
    opts["corpus_ns"] = ns
    rows = parse_rows(opts["corpus_rows"])
    if rows is None:
        return None, (2, "", "run.py: CORPUS_ROWS must be a decimal row count from 1 to 999999999, got [%s]\n" % opts["corpus_rows"])
    opts["corpus_rows"] = rows
    return opts, None


# ---------------------------------------------------------------------------------------------------------------------
# Posture: render, environment, drift guard (src/security_profile.rs::KNOBS)
# ---------------------------------------------------------------------------------------------------------------------
def posture_count(posture_set=LAB_POSTURE_SET, posture_unset=LAB_POSTURE_UNSET):
    return len(posture_set) + len(posture_unset)


def posture_render(posture_set=LAB_POSTURE_SET, posture_unset=LAB_POSTURE_UNSET):
    lines = list(posture_set) + ["%s=<unset — permissive hatch NOT in force>" % k for k in posture_unset]
    return "".join(line + "\n" for line in lines)


def posture_env(posture_set=LAB_POSTURE_SET):
    env = {}
    for kv in posture_set:
        name, _, value = kv.partition("=")
        env[name] = value
    return env


WS = b"[ \t\n\v\f\r]"
KNOBS_START = re.compile(rb"^const KNOBS: &\[KnobSpec\] = &\[")
KNOBS_END = re.compile(rb"^\];")
ENV_ROW = re.compile(rb"^" + WS + rb"*env:" + WS + rb"*")
VALUE_ROW = re.compile(rb"^" + WS + rb"*hard_value:" + WS + rb"*")
ROW_TAIL = re.compile(rb"," + WS + rb"*\Z")
CNAME = re.compile(r".*::([A-Z0-9_]*)\Z", re.DOTALL)


def knobs_block(data):
    """The lines of every range from the KNOBS start line through the next line starting with '];' (awk range)."""
    out = []
    inside = False
    for line in data.split(b"\n"):
        if not inside and KNOBS_START.search(line):
            inside = True
            out.append(line)
            if KNOBS_END.search(line):
                inside = False
            continue
        if inside:
            out.append(line)
            if KNOBS_END.search(line):
                inside = False
    return out


def knob_pairs(block):
    """(env-expr, hard_value-expr) per row; None when a hard_value has no env row before it."""
    pairs = []
    pending = None
    for line in block:
        if ENV_ROW.search(line):
            pending = ROW_TAIL.sub(b"", ENV_ROW.sub(b"", line, count=1), count=1)
        elif VALUE_ROW.search(line):
            if pending is None:
                return None
            pairs.append((pending.decode("utf-8", "surrogateescape"),
                          ROW_TAIL.sub(b"", VALUE_ROW.sub(b"", line, count=1), count=1).decode("utf-8", "surrogateescape")))
            pending = None
    return pairs


class SourceTree:
    """Reads files under <root>/src once per check (the name-only search walks all of src, following symlinks)."""

    def __init__(self, root):
        self.root = root
        self.cache = {}
        self.all_files = None

    def read(self, path):
        if path not in self.cache:
            try:
                with open(path, "rb") as fh:
                    self.cache[path] = fh.read()
            except OSError:
                self.cache[path] = b""
        return self.cache[path]

    def every_file(self):
        if self.all_files is None:
            found = []
            for dirpath, _dirs, files in os.walk(os.path.join(self.root, "src"), followlinks=True):
                for name in files:
                    path = os.path.join(dirpath, name)
                    if os.path.isfile(path):
                        found.append(path)
            self.all_files = sorted(found)
        return self.all_files

    def const_values(self, name, files):
        pattern = re.compile(rb"pub(\(crate\))? const " + re.escape(name.encode("ascii")) + rb": &str =" + WS + rb'*"([^"]*)"')
        values = set()
        for path in files:
            for match in pattern.finditer(self.read(path)):
                values.add(match.group(2).replace(b"\n", b" ").replace(b"\0", b" ").decode("utf-8", "surrogateescape"))
        return values

    def const(self, name, modp):
        """The single distinct literal of pub [(crate)] const NAME: &str, searched in the named module first; else ''."""
        files = []
        if modp:
            for cand in (os.path.join(self.root, "src", modp + ".rs"), os.path.join(self.root, "src", modp, "mod.rs")):
                if os.path.isfile(cand):
                    files.append(cand)
        values = self.const_values(name, files) if files else set()
        if not values:
            values = self.const_values(name, self.every_file())
        if len(values) != 1:
            return ""
        return next(iter(values))


def knob_expr(tree, expr):
    """A literal "x" gives x; crate::path::CONST gives the const's literal; None when unresolvable."""
    if len(expr) >= 2 and expr.startswith('"') and expr.endswith('"'):
        return expr[1:-1]
    if expr.startswith("crate::"):
        match = CNAME.match(expr)
        cname = match.group(1) if match else ""
        if not cname:
            return None
        modp = re.sub(r"^crate::", "", expr, count=1)
        modp = re.sub(r"::[A-Z0-9_]*\Z", "", modp, count=1)
        modp = re.sub(r"::[A-Z][A-Za-z0-9]*\Z", "", modp, count=1)
        modp = modp.replace("::", "/")
        value = tree.const(cname, modp)
        return value if value else None
    return None


def posture_ssot_check(root, posture_set=LAB_POSTURE_SET, posture_unset=LAB_POSTURE_UNSET):
    """DRIFT GUARD: (0, ok line) on agreement, (1, DRIFT lines) on drift, (2, why) when it cannot check."""
    src = os.path.join(root, "src", "security_profile.rs")
    if not os.path.isfile(src):
        return 2, "skip: no source tree at %s (release-tarball mode)" % root
    tree = SourceTree(root)
    block = knobs_block(tree.read(src))
    if not block:
        return 2, "cannot check: KNOBS table not found in %s" % src
    pairs = knob_pairs(block)
    if pairs is None:
        return 2, "cannot check: a KNOBS hard_value row has no env row before it"
    ssot = []
    for envx, valx in pairs:
        name = knob_expr(tree, envx)
        if not name:
            return 2, "cannot check: could not resolve KNOBS env expression %s" % envx
        value = knob_expr(tree, valx)
        if value is None:
            return 2, "cannot check: could not resolve KNOBS hard_value expression %s (knob %s)" % (valx, name)
        ssot.append((name, value))
    if not ssot:
        return 2, "cannot check: KNOBS table parsed to zero rows"
    lab = [kv.partition("=")[0] for kv in posture_set] + list(posture_unset)
    a = Counter(name for name, _ in ssot)
    b = Counter(lab)
    if a != b:
        only_ssot = sorted((a - b).elements())
        only_lab = sorted((b - a).elements())
        return 1, "\n".join((
            "DRIFT: lab posture list disagrees with src/security_profile.rs::KNOBS",
            "  only in SSOT: " + "".join(n + " " for n in only_ssot),
            "  only in lab:  " + "".join(n + " " for n in only_lab),
        ))
    lines = []
    for kv in posture_set:
        k, _, val = kv.partition("=")
        want = ""
        for name, value in ssot:
            if name == k:
                want = value
        if want == "" or val != want:
            lines.append("DRIFT: %s value '%s' != hard value '%s' in src/security_profile.rs::KNOBS" % (k, val, want))
    for k in posture_unset:
        for name, value in ssot:
            if name == k and value != "":
                lines.append("DRIFT: %s is unset in the lab but its hard value is '%s' in src/security_profile.rs::KNOBS" % (k, value))
    if lines:
        return 1, "\n".join(lines)
    return 0, "ok: lab posture covers all %d SSOT knobs (%d of %d at hard floor, names and values compared)" % (
        len(ssot), posture_count(posture_set, posture_unset), len(ssot))


# ---------------------------------------------------------------------------------------------------------------------
# The probe-mutation matcher: a pure function of the log bytes
# ---------------------------------------------------------------------------------------------------------------------
def probe_verdict(path):
    """detected: a line names the knob with its colon and is not an INFO pin line; not-detected: none does;
    refused: <reason> when the log cannot be read."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return "refused: the probe log could not be read (%s)" % exc.__class__.__name__
    if type(data) is not bytes:
        return "refused: the probe log did not read as bytes"
    for line in data.split(b"\n"):
        if PROBE_REFUSAL in line and PROBE_INFO not in line:
            return "detected"
    return "not-detected"


def probe_report(verdict, rc):
    """(True, line) only for detected; every other verdict is (False, line) naming it."""
    if verdict == "detected":
        return True, "probe mutation detected: the boot refused (exit %s) and the refusal names %s" % (rc, PROBE_KNOB)
    if verdict == "not-detected":
        return False, "probe mutation inconclusive: the boot refused (exit %s) but not for the lowered rollback-check knob" % rc
    return False, "probe mutation inconclusive: the probe matcher %s" % verdict


def probe_count_line(ledger, before):
    """None when the probe block recorded exactly one verdict, else the #5739 FAIL line."""
    if ledger.passes + ledger.fails - before == 1:
        return None
    return ("   FAIL the cold-boot probe did not record exactly one verdict (PASS %s, FAIL %s, %s before it): a verdict "
            "that could not be written fails the run (#5739)\n" % (ledger.passes, ledger.fails, before))


# ---------------------------------------------------------------------------------------------------------------------
# jq-equivalent readers (jq 1.6 semantics: an error anywhere yields the fallback)
# ---------------------------------------------------------------------------------------------------------------------
def json_load(text):
    try:
        return json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None


def _present(value):
    return value is not None and value is not False


def jq_raw(value):
    """What jq -r prints for one value."""
    if type(value) is str:
        return value
    if value is True:
        return "true"
    if type(value) is float and value.is_integer() and abs(value) < 1e17:
        return str(int(value))
    if type(value) in (int, float):
        return json.dumps(value)
    return json.dumps(value, indent=2, ensure_ascii=False)


def seed_rows(text):
    """.count // (.memories|length) // 0 over the seed file; any non-object root gives 0."""
    doc = json_load(text)
    if doc is None:
        return "0"
    if type(doc) is not dict:
        return "0"
    if _present(doc.get("count")):
        return jq_raw(doc["count"])
    mem = doc.get("memories")
    if type(mem) in (list, dict, str):
        return str(len(mem))
    if mem is None:
        return "0"
    return "0"


def recall_list(doc):
    """(.memories // .results // .) for an object root; None for any other root (jq 1.6 errors on it)."""
    if doc is None:
        return []
    if type(doc) is not dict:
        return None
    for key in ("memories", "results"):
        if _present(doc.get(key)):
            return doc[key]
    return doc


def recall_items(seq):
    """.[]? : list elements or object values; nothing for a scalar."""
    if type(seq) is list:
        return list(seq)
    if type(seq) is dict:
        return list(seq.values())
    return []


def recall_hits(text, title):
    """Number of recalled items whose title equals TITLE; any shape jq would error on gives 0."""
    doc = json_load(text)
    seq = recall_list(doc)
    if seq is None:
        return 0
    hits = 0
    for item in recall_items(seq):
        if item is None:
            continue
        if type(item) is not dict:
            return 0
        if item.get("title") == title:
            hits += 1
    return hits


def recall_count(text):
    doc = json_load(text)
    seq = recall_list(doc)
    if seq is None:
        return 0
    return len(recall_items(seq))


def recall_top_title(text):
    """((.memories // .results // .)[0].title) // "?" ; '' where jq errors."""
    doc = json_load(text)
    seq = recall_list(doc)
    if seq is None or type(seq) is dict:
        return ""
    first = None
    if type(seq) is list:
        first = seq[0] if seq else None
    elif seq is not None:
        return ""
    if first is None:
        return "?"
    if type(first) is not dict:
        return ""
    title = first.get("title")
    return jq_raw(title) if _present(title) else "?"


def json_field(text, key):
    """.KEY // empty for an object root; '' otherwise."""
    doc = json_load(text)
    if type(doc) is not dict or not _present(doc.get(key)):
        return ""
    return jq_raw(doc[key])


def derive_query(title):
    """The first four ASCII-alphanumeric words of a title, each followed by one space."""
    if title is None:
        return ""
    data = (title if type(title) is bytes else str(title).encode("utf-8", "surrogateescape")) + b"\n"
    words = re.sub(rb"[^A-Za-z0-9]+", b" ", data).split()
    return "".join(w.decode("ascii") + " " for w in words[:4])


# ---------------------------------------------------------------------------------------------------------------------
# Processes, environments, network and SQLite helpers
# ---------------------------------------------------------------------------------------------------------------------
def search_path(environ):
    """The caller's PATH with only absolute, existing directories kept."""
    dirs = []
    for d in environ.get("PATH", "").split(os.pathsep):
        if d.startswith("/") and os.path.isdir(d) and d not in dirs:
            dirs.append(d)
    return os.pathsep.join(dirs)


def resolve_program(value, path):
    """An absolute, real path to a regular executable file, or None. A bare name is searched on PATH."""
    if not value:
        return None
    found = shutil.which(value, path=path) if os.sep not in value else (value if os.access(value, os.X_OK) else None)
    if found is None:
        return None
    real = os.path.realpath(os.path.abspath(found))
    if os.path.isfile(real) and os.access(real, os.X_OK):
        return real
    return None


def find_bash():
    for cand in BASH_PATHS:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def tool_env(path, home, **extra):
    env = {"PATH": path, "HOME": home, "AI_MEMORY_NO_CONFIG": "1"}
    env.update(extra)
    return env


def daemon_env(path, home, keydir, fedid, peer_attestation, witness_dir, rust_log, posture_set=LAB_POSTURE_SET):
    env = posture_env(posture_set)
    env.update({
        "PATH": path, "HOME": home, "AI_MEMORY_KEY_DIR": keydir, "AI_MEMORY_FED_IDENTITY": fedid,
        "AI_MEMORY_FED_PEER_ATTESTATION": peer_attestation, "AI_MEMORY_WITNESS_KEY_DIR": witness_dir,
        "RUST_LOG": rust_log,
    })
    return env


def probe_env(path, home, keydir, mutation):
    env = {
        "PATH": path, "HOME": home, "AI_MEMORY_SECURITY_PROFILE": "asi-hard", "AI_MEMORY_KEY_DIR": keydir,
        "AI_MEMORY_FED_PEER_ATTESTATION": json.dumps({AGENT_A: {"allowed_namespaces": [FED_NS]}}, separators=(",", ":")),
    }
    if mutation:
        env[PROBE_KNOB] = "0"
    return env


def n4_env(path, home):
    return {"PATH": path, "HOME": home, "AI_MEMORY_SECURITY_PROFILE": "asi-hard", "AI_MEMORY_SECRET_SCREEN_MODE": "off"}


def stop_process(proc, grace=10.0):
    """TERM, wait up to GRACE seconds, KILL, reap."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait()
    except OSError:
        pass


_SPAWN_SIGNALS = (signal.SIGINT, signal.SIGTERM)


def spawn(argv, register=None, **kwargs):
    """Popen with SIGINT and SIGTERM held back until the child is registered (#5527 r8, F2).

    A signal that lands between Popen returning and the child being tracked would otherwise raise with the child
    in no list, so nothing could stop it. While held, the signal is only recorded; afterwards the child is
    registered (daemons) or stopped (short tool), and then LabInterrupted is raised.
    """
    held = []
    saved = []
    for signum in _SPAWN_SIGNALS:
        if signal.getsignal(signum) is _interrupt:
            saved.append((signum, signal.signal(signum, lambda n, _f: held.append(n))))
    proc = None
    try:
        proc = subprocess.Popen(argv, **kwargs)
        if register is not None:
            register(proc)
    finally:
        for signum, old in saved:
            signal.signal(signum, old)
    if held:
        if register is None and proc is not None:
            stop_process(proc, grace=2.0)
        raise LabInterrupted(held[0])
    return proc


def run_bounded(argv, env, timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                cwd=None):
    """Run ARGV (absolute program, argument list, given environment); 124 when TIMEOUT expires (then TERM, KILL)."""
    try:
        proc = spawn(argv, env=env, stdin=stdin, stdout=stdout, stderr=stderr, cwd=cwd, close_fds=True)
    except OSError:
        return 127
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_process(proc)
        return TIMEOUT_RC
    except BaseException:
        stop_process(proc, grace=2.0)
        raise


def run_capture(argv, env, timeout, stderr_path=None):
    """(rc, stdout bytes) for a short tool command; stderr to STDERR_PATH or discarded."""
    err = open(stderr_path, "wb") if stderr_path else subprocess.DEVNULL
    try:
        proc = spawn(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=err, close_fds=True)
    except OSError:
        if stderr_path:
            err.close()
        return 127, b""
    try:
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out
    except subprocess.TimeoutExpired:
        stop_process(proc)
        proc.communicate()
        return TIMEOUT_RC, b""
    finally:
        if stderr_path:
            err.close()


def last_line(data):
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[-1] if lines else ""


def port_free(port):
    """True only when a connect to 127.0.0.1:PORT is refused; anything else reads as busy."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    try:
        sock.connect(("127.0.0.1", port))
    except ConnectionRefusedError:
        return True
    except OSError:
        return False
    finally:
        sock.close()
    return False


def tls_context(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if cert:
        ctx.load_cert_chain(cert, key)
    return ctx


def http_call(method, url, timeout, cert=None, key=None, headers=None, body=None):
    """(status, body bytes) for any HTTP response; (None, b'') when no response arrived."""
    parts = urllib.parse.urlsplit(url)
    target = parts.path + ("?" + parts.query if parts.query else "")
    try:
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=timeout, context=tls_context(cert, key))
        else:
            conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
        try:
            conn.request(method, target, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, data
        finally:
            conn.close()
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None, b""


def recall_url(port, query, namespace, limit):
    qs = urllib.parse.urlencode([("q", query), ("namespace", namespace), ("limit", str(limit))],
                                quote_via=urllib.parse.quote)
    return "https://127.0.0.1:%d/api/v1/recall?%s" % (port, qs)


def wait_https(url, cert, key, tries=120):
    for _ in range(tries):
        status, _body = http_call("GET", url, 3, cert, key)
        if status is not None:
            return True
        time.sleep(0.5)
    return False


def sql_value(db, sql, params, timeout):
    """The first column of the first row as the sqlite3 shell prints it ('' for NULL or no row or any error)."""
    try:
        uri = "file:%s?mode=rw" % urllib.parse.quote(os.path.abspath(db))
        con = sqlite3.connect(uri, uri=True, timeout=timeout)
        try:
            row = con.execute(sql, params).fetchone()
        finally:
            con.close()
    except (sqlite3.Error, OSError, ValueError):
        return ""
    if row is None or row[0] is None:
        return ""
    value = row[0]
    if type(value) is bytes:
        return value.decode("utf-8", "replace")
    return str(value)


def sql_count(db, sql, params):
    text = sql_value(db, sql, params, 5)
    return int(text) if text.isdigit() else 0


def tail_lines(path, count, pattern=None):
    try:
        with open(path, "rb") as fh:
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    if pattern is not None:
        lines = [ln for ln in lines if pattern.search(ln)]
    return lines[-count:] if count else []


def head_bytes(data, count):
    return data[:count].decode("utf-8", "replace")


def utc_now(fmt):
    return time.strftime(fmt, time.gmtime())


def write_text(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def scratch_base(environ, cwd):
    """The directory scratch lives under: $TMPDIR made absolute, or the current directory; never a fixed /tmp."""
    base = environ.get("TMPDIR") or cwd
    return os.path.realpath(os.path.join(cwd, base))


def scratch_dir(prefix, environ=None, cwd=None):
    """The only scratch-directory maker in this file: an absolute directory under scratch_base."""
    environ = os.environ if environ is None else environ
    cwd = os.getcwd() if cwd is None else cwd
    return os.path.realpath(tempfile.mkdtemp(prefix=prefix + ".", dir=scratch_base(environ, cwd)))


# ---------------------------------------------------------------------------------------------------------------------
# The lab run
# ---------------------------------------------------------------------------------------------------------------------
class Lab:
    """One lab run: daemons it started, whether it owns run/, and the ledger."""

    def __init__(self, opts, ledger, environ, run_dir=RUN):
        self.o = opts
        self.rdir = run_dir
        self.summarized = False
        self.out = os.path.join(run_dir, "crypto")
        self.gov = os.path.join(run_dir, "governance")
        self.led = ledger
        self.env = environ
        self.path = search_path(environ)
        self.daemons = []
        self.owned = False
        self.bin = None
        self.signer = None
        self.bin_version = ""
        self.loaded = 0
        self.seed_desc = ""

    def cleanup(self):
        for proc in self.daemons:
            try:
                proc.terminate()
            except OSError:
                pass
        for proc in self.daemons:
            stop_process(proc)
        self.daemons = []
        if self.owned and not self.o["keep"]:
            shutil.rmtree(self.rdir, ignore_errors=True)
        elif self.owned:
            self.led.emit("\n   run dir kept at %s\n" % self.rdir)

    def tool(self, *args, **extra):
        env = tool_env(self.path, os.path.join(self.rdir, "tool-home"), **extra)
        return run_bounded([self.bin] + list(args), env, 300)

    def preflight(self):
        L = self.led
        L.step("0 · preflight")
        missing = [t for t in ("openssl",) if shutil.which(t, path=self.path) is None]
        if self.o["corpus_db"]:
            missing += [t for t in ("sqlite3", "jq") if shutil.which(t, path=self.path) is None]
        if find_bash() is None:
            missing.append("bash")
        if missing:
            L.warn("missing required tool(s): %s" % " ".join(missing))
            L.warn("  Debian/Ubuntu: sudo apt-get install -y openssl sqlite3 jq")
            L.warn("  macOS (brew):  brew install openssl sqlite jq")
            return False
        cand = self.o["bin"]
        if not cand:
            default = os.path.join(ROOT, "target", "release", "ai-memory")
            cand = default if os.access(default, os.X_OK) else "ai-memory"
        self.bin = resolve_program(cand, self.path)
        if self.bin is None:
            L.warn("no ai-memory binary found.")
            L.warn("  build one:  cargo build --release --bin ai-memory --example attest_sign")
            L.warn("  or pass:    ./run.py --bin /path/to/ai-memory")
            return False
        signer = self.o["signer"] or os.path.join(ROOT, "target", "release", "examples", "attest_sign")
        self.signer = resolve_program(signer, self.path)
        if self.signer is None:
            L.warn("no attest_sign example at %s" % signer)
            L.warn("  build it:  cargo build --release --example attest_sign")
            L.warn("  (the lab signs its attested write with the SAME crate code the daemon")
            L.warn("   verifies with, so the canonical CBOR bytes are never re-implemented here)")
            return False
        _rc, out = run_capture([self.bin, "--version"], {"PATH": self.path, "AI_MEMORY_NO_CONFIG": "1"}, 60)
        self.bin_version = last_line(out)
        L.info("binary   %s  (%s)" % (self.bin, self.bin_version))
        L.info("signer   %s" % self.signer)
        L.info("lab dir  %s" % LAB)
        for port in (self.o["port_a"], self.o["port_b"]):
            if not port_free(port):
                L.warn("port %d is already in use — pass --port-a/--port-b to move the lab" % port)
                return False
        rc, text = posture_ssot_check(ROOT)
        if rc == 0:
            L.ok("asi-hard posture list matches src/security_profile.rs::KNOBS — %s" % text)
        elif rc == 1:
            L.no("asi-hard posture DRIFT: %s" % text)
        else:
            L.info("posture SSOT check: %s" % text)
        return True

    def run(self):
        """Run every step; returns the exit code."""
        L = self.led
        if not self.preflight():
            return 1
        L.step("1 · workspace")
        shutil.rmtree(self.rdir, ignore_errors=True)
        if os.path.lexists(self.rdir):
            L.no("could not remove the previous run dir %s" % self.rdir)
            return self.finish_early()
        self.owned = True
        for sub in ("crypto", "evidence", "author-keys", "governance", "tool-home"):
            os.makedirs(os.path.join(self.rdir, sub))
        for node in ("node-a", "node-b"):
            os.makedirs(os.path.join(self.rdir, node, "home", ".config", "ai-memory"))
            os.makedirs(os.path.join(self.rdir, node, "keys"))
        L.info("work dir %s (removed and recreated — this run is idempotent)" % self.rdir)
        L.info("nothing is written outside this directory: no /tmp, no $HOME")
        self.adb, self.bdb = os.path.join(self.rdir, "node-a", "node.db"), os.path.join(self.rdir, "node-b", "node.db")
        self.alog, self.blog = os.path.join(self.rdir, "node-a", "daemon.log"), os.path.join(self.rdir, "node-b", "daemon.log")
        self.ka, self.kb = os.path.join(self.rdir, "node-a", "keys"), os.path.join(self.rdir, "node-b", "keys")
        self.kauth = os.path.join(self.rdir, "author-keys")
        self.gov = os.path.join(self.rdir, "governance")
        for d in (self.ka, self.kb, self.kauth, self.gov):
            os.chmod(d, 0o700)
        for node in ("node-a", "node-b"):
            write_text(os.path.join(self.rdir, node, "home", ".config", "ai-memory", "config.toml"), CONFIG_TOML)
        for stepfn in (self.step_crypto, self.step_identities, self.step_seed, self.step_posture, self.step_launch):
            rc = stepfn()
            if rc is not None:
                return rc
        self.step_negative()
        self.step_positive()
        return self.step_manifest()

    def finish_early(self):
        """summary; exit 1 (the step could not continue)."""
        self.led.summary()
        return 1

    def step_crypto(self):
        L = self.led
        L.step("2 · crypto material (calls infra/do-hive/crypto/gen-certs.sh)")
        gencerts = os.path.join(ROOT, "infra", "do-hive", "crypto", "gen-certs.sh")
        if not os.path.isfile(gencerts):
            L.no("prior-art cert generator not found at %s" % gencerts)
            return self.finish_early()
        self.out = os.path.join(self.rdir, "crypto")
        with open(os.path.join(self.rdir, "evidence", "gen-certs.out"), "wb") as log:
            rc = run_bounded([find_bash(), "--noprofile", "--norc", gencerts],
                             {"OUT_DIR": self.out, "PATH": self.path, "HOME": os.path.join(self.rdir, "tool-home")}, 600,
                             stdout=log, stderr=subprocess.STDOUT)
        if rc == 0:
            L.ok("gen-certs.sh minted the CA + peer/client leaves into run/crypto")
        else:
            L.no("gen-certs.sh failed — see run/evidence/gen-certs.out")
            return self.finish_early()
        fps = {}
        try:
            with open(os.path.join(self.out, "fingerprints.txt"), encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    fields = line.split()
                    for peer in ("peerA", "peerB"):
                        if line.startswith(peer) and len(fields) > 1:
                            fps.setdefault(peer, []).append(fields[1])
        except OSError:
            pass
        L.info("peerA fp %s" % "\n".join(fps.get("peerA", [])))
        L.info("peerB fp %s" % "\n".join(fps.get("peerB", [])))
        L.info("each node's allowlist pins ONLY the other node's client cert (SSH known_hosts model:")
        L.info("the FINGERPRINT is the trust anchor, not the CA — client-bad is signed by the same CA")
        L.info("and is still refused, which is exactly what step 7 asserts)")
        return None

    def step_identities(self):
        L = self.led
        L.step("3 · identities, cross-peer enrollment, agent key binding")
        self.tool("identity", "generate", "--agent-id", AGENT_A, "--key-dir", self.ka)
        self.tool("identity", "generate", "--agent-id", AGENT_B, "--key-dir", self.kb)
        for src, dst in ((os.path.join(self.ka, AGENT_A + ".pub"), os.path.join(self.kb, AGENT_A + ".pub")),
                         (os.path.join(self.kb, AGENT_B + ".pub"), os.path.join(self.ka, AGENT_B + ".pub"))):
            try:
                shutil.copyfile(src, dst)
            except OSError:
                pass
        if all(os.path.isfile(p) and os.path.getsize(p) > 0 for p in (
                os.path.join(self.kb, AGENT_A + ".pub"), os.path.join(self.ka, AGENT_B + ".pub"))):
            L.ok("cross-peer federation identities enrolled (%s ↔ %s)" % (AGENT_A, AGENT_B))
        else:
            L.no("cross-peer federation identity enrollment failed")
        self.tool("identity", "generate", "--agent-id", AUTHOR, "--key-dir", self.kauth)
        _rc, out = run_capture([self.bin, "identity", "export-pub", "--agent-id", AUTHOR, "--key-dir", self.kauth],
                               tool_env(self.path, os.path.join(self.rdir, "tool-home")), 300)
        self.author_pub = last_line(out)
        if not self.author_pub:
            L.no("could not export the author public key")
            return self.finish_early()
        sql = ("SELECT COALESCE(json_extract(metadata,'$.agent_pubkey'),'') FROM memories "
               "WHERE namespace='_agents' AND title=? LIMIT 1")
        for db in (self.adb, self.bdb):
            label = os.path.basename(os.path.dirname(db))
            attempt, bound = 0, ""
            while attempt < 3:
                attempt += 1
                self.tool("agents", "register", "--agent-id", AUTHOR, "--agent-type", "system", "--db", db)
                self.tool("agents", "bind-key", "--agent-id", AUTHOR, "--pubkey", self.author_pub, "--db", db,
                          AI_MEMORY_KEY_DIR=self.kauth)
                bound = sql_value(db, sql, ("agent:" + AUTHOR,), 3)
                if bound == self.author_pub:
                    break
                L.warn("bind-key attempt %d on %s did not persist metadata.agent_pubkey (issue #2941) — retrying" % (attempt, label))
                time.sleep(0.5)
            if bound == self.author_pub:
                L.ok("%s: author pubkey bound AND read back from the _agents registry row (#2941 guard, attempt %d)" % (label, attempt))
            else:
                L.no("%s: agents bind-key silently no-opped — metadata.agent_pubkey is unset after %d attempts." % (label, attempt))
                L.warn("  This is the known intermittent enrollment flake, issue #2941.")
                L.warn("  Every signed write will now 403 ATTESTATION_FAILED. Re-run the lab; if it")
                L.warn("  reproduces, attach run/node-*/daemon.log and the attempt count to #2941.")
        return None

    def step_seed(self):
        L = self.led
        L.step("4 · seed the corpus (bootstrap phase — deliberately NOT hardened)")
        ns = self.o["corpus_ns"]
        cdb = self.o["corpus_db"]
        if cdb:
            if not os.path.isfile(cdb):
                L.no("--corpus-db %s does not exist" % cdb)
                return self.finish_early()
            seed = os.path.join(self.rdir, "node-a", "corpus.json")
            with open(os.path.join(self.rdir, "evidence", "corpus-build.out"), "wb") as log:
                rc = run_bounded([find_bash(), "--noprofile", "--norc", os.path.join(LAB, "tools", "make-local-slice.sh"),
                                  "--bin", self.bin, "--corpus-db", cdb, "--namespace", ns,
                                  "--rows", str(self.o["corpus_rows"]), "--out", seed],
                                 {"PATH": self.path, "HOME": os.path.join(self.rdir, "tool-home")}, 1800,
                                 stdout=log, stderr=subprocess.STDOUT)
            if rc != 0:
                L.no("could not build a corpus slice from %s — see run/evidence/corpus-build.out" % cdb)
                return self.finish_early()
            self.seed_desc = "full local corpus %s (up to %d rows of '%s')" % (cdb, self.o["corpus_rows"], ns)
            L.warn("F-L8a: recall quality over a full corpus depends on the lab node's embedder")
            L.warn("  matching the one that produced its vectors. These nodes run tier=keyword")
            L.warn("  (lexical), so semantic ranking is NOT what is being demonstrated.")
        else:
            seed = SAMPLE
            self.seed_desc = "committed SYNTHETIC fixture %s" % os.path.basename(SAMPLE)
        if not (os.path.isfile(seed) and os.path.getsize(seed) > 0):
            L.no("corpus file %s is missing or empty" % seed)
            return self.finish_early()
        with open(seed, "rb") as fh:
            seed_text = fh.read()
        declared = seed_rows(seed_text)
        with open(seed, "rb") as src, open(os.path.join(self.rdir, "evidence", "import.out"), "wb") as log:
            run_bounded([self.bin, "import", "--db", self.adb],
                        tool_env(self.path, os.path.join(self.rdir, "tool-home"), AI_MEMORY_AGENT_ID=AUTHOR), 1800,
                        stdin=src, stdout=log, stderr=subprocess.STDOUT)
        self.loaded = sql_count(self.adb, "SELECT COUNT(*) FROM memories WHERE namespace=?", (ns,))
        live = sql_count(self.adb, "SELECT COUNT(*) FROM memories WHERE namespace=? "
                                   "AND (expires_at IS NULL OR expires_at > datetime('now'))", (ns,))
        if self.loaded > 0 and live == self.loaded:
            L.ok("node-a seeded with %d rows in namespace '%s', all unexpired (from the %s; file declares %s)"
                 % (self.loaded, ns, self.seed_desc, declared))
        elif self.loaded > 0:
            L.no("node-a seeded %d rows in '%s' but only %d are unexpired — recall will not see the rest, and gc will "
                 "archive them" % (self.loaded, ns, live))
            L.warn("  A corpus fixture must carry no live TTL. Rebuild the slice with tools/make-local-slice.sh,")
            L.warn("  which stamps the slice long-tier (permanent) precisely to avoid this.")
        else:
            L.no("corpus seeding produced 0 rows in '%s' — see run/evidence/import.out" % ns)
        return None

    def step_posture(self):
        L = self.led
        L.step("5 · asi-hard posture")
        rendered = posture_render()
        write_text(os.path.join(self.rdir, "evidence", "posture.env"), rendered)
        for line in rendered.splitlines():
            L.emit("   %s\n" % line)
        L.info("%d pinned knobs at their hard floor." % posture_count())
        L.info("AI_MEMORY_SECURITY_PROFILE is deliberately NOT set (every knob is pinned directly) — see README §asi-hard.")
        if self.o["no_caveat_probe"]:
            return None
        return self.probe_guarded()

    def probe_guarded(self):
        """Run the probe block; None when it recorded exactly one verdict, else the #5739 FAIL line and 1."""
        L = self.led
        before = L.passes + L.fails
        try:
            self.probe_block()
        except LabInterrupted:
            raise
        except Exception as exc:  # noqa: BLE001 - the count check below turns a lost verdict into a failed run
            L.warn("the cold-boot probe block raised %s" % exc.__class__.__name__)
        line = probe_count_line(L, before)
        if line is not None:
            L.emit(line)
            return 1
        return None

    def probe_block(self):
        """PROVE the full profile cold-boots (#2942 fixed, #4938); with --probe-mutation, prove the probe can fail."""
        L = self.led
        probe = os.path.join(self.rdir, "evidence", "caveat-asi-hard-coldboot.txt")
        home = os.path.join(self.rdir, "probe-home")
        os.makedirs(os.path.join(home, ".config", "ai-memory"), exist_ok=True)
        write_text(os.path.join(home, ".config", "ai-memory", "config.toml"), CONFIG_TOML)
        port = self.o["port_b"] + 1
        write_text(probe, "# asi-hard full-profile cold-boot probe on a FRESH database (issue #2942)\n"
                          "# command: AI_MEMORY_SECURITY_PROFILE=asi-hard ai-memory serve --db <fresh> ...\n\n")
        if not port_free(port):
            L.no("cold-boot probe cannot run: port %d is occupied, so a non-zero exit would prove nothing" % port)
            return
        mutation = self.o["probe_mutation"]
        with open(probe, "ab") as log:
            rc = run_bounded([self.bin, "serve", "--host", "127.0.0.1", "--port", str(port), "--db",
                              os.path.join(self.rdir, "probe.db"), "--tls-cert", os.path.join(self.out, "server.crt"),
                              "--tls-key", os.path.join(self.out, "server.key"), "--mtls-allowlist",
                              os.path.join(self.out, "allowlist.txt")],
                             probe_env(self.path, home, self.gov, mutation), 60, stdout=log, stderr=subprocess.STDOUT)
        with open(probe, "ab") as log:
            log.write(("exit_code=%d\n" % rc).encode("ascii"))
        with open(probe, "rb") as fh:
            listened = b"listening on" in fh.read()
        if listened and rc in (TIMEOUT_RC, 0):
            if mutation:
                L.no("probe MUTATION NOT DETECTED: the node listened with %s=0 under the profile (exit %d)" % (PROBE_KNOB, rc))
            else:
                L.ok("full asi-hard cold boot on a fresh DB succeeded (listening, exit %d after the probe timeout) — "
                     "evidence in run/evidence/caveat-asi-hard-coldboot.txt" % rc)
        else:
            if mutation:
                good, line = probe_report(probe_verdict(probe), rc)
                if good:
                    L.ok(line)
                else:
                    L.no(line)
            else:
                L.no("full asi-hard cold boot on a fresh DB did NOT come up (exit %d): the lab runs this posture, so a "
                     "refusal is a failure (#2942 regression or a new refusal)" % rc)
            lines = tail_lines(probe, 2, re.compile(r"rollback|refuse|fatal", re.IGNORECASE))
            L.info("\n".join("     " + ln for ln in lines))
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                os.remove(os.path.join(self.rdir, "probe.db" + suffix))
            except OSError:
                pass

    def launch(self, name, port, db, keydir, fedid, home, peer, sc, sk, al, log, peerfed):
        attestation = json.dumps({peerfed: {"allowed_namespaces": [FED_NS, self.o["corpus_ns"]]}}, separators=(",", ":"))
        env = daemon_env(self.path, home, keydir, fedid, attestation, self.gov, self.rust_log)
        argv = [self.bin, "serve", "--host", "127.0.0.1", "--port", str(port), "--db", db, "--tls-cert", sc,
                "--tls-key", sk, "--mtls-allowlist", al, "--quorum-writes", "2", "--quorum-peers",
                "https://127.0.0.1:%d" % peer, "--quorum-client-cert", sc, "--quorum-client-key", sk,
                "--quorum-ca-cert", os.path.join(self.out, "ca.crt"), "--quorum-timeout-ms", "8000"]
        with open(log, "wb") as fh:
            proc = spawn(argv, self.daemons.append, env=env, stdin=subprocess.DEVNULL, stdout=fh,
                         stderr=subprocess.STDOUT, close_fds=True)
        self.led.info("%s pid %d on https://127.0.0.1:%d" % (name, proc.pid, port))

    def step_launch(self):
        L = self.led
        L.step("6 · launch the two-node mTLS federation")
        self.rust_log, replaced = rust_log_value(self.env)
        if replaced:
            L.warn("RUST_LOG from the environment is not a plain filter; the nodes use %s" % DEFAULT_RUST_LOG)
        o = self.out
        pa, pb = self.o["port_a"], self.o["port_b"]
        self.launch("node-a", pa, self.adb, self.ka, AGENT_A, os.path.join(self.rdir, "node-a", "home"), pb,
                    os.path.join(o, "peerA.crt"), os.path.join(o, "peerA.key"), os.path.join(o, "peerA.allowlist"),
                    self.alog, AGENT_B)
        self.launch("node-b", pb, self.bdb, self.kb, AGENT_B, os.path.join(self.rdir, "node-b", "home"), pa,
                    os.path.join(o, "peerB.crt"), os.path.join(o, "peerB.key"), os.path.join(o, "peerB.allowlist"),
                    self.blog, AGENT_A)
        self.ca_client = (os.path.join(o, "peerB.crt"), os.path.join(o, "peerB.key"))
        self.cb_client = (os.path.join(o, "peerA.crt"), os.path.join(o, "peerA.key"))
        if (wait_https("https://127.0.0.1:%d/api/v1/health" % pa, *self.ca_client)
                and wait_https("https://127.0.0.1:%d/api/v1/health" % pb, *self.cb_client)):
            L.ok("both nodes answer /api/v1/health over mutual TLS with a PINNED client cert")
        else:
            L.no("one or both nodes never became reachable — see run/node-*/daemon.log")
            L.info("\n".join("     A| " + ln for ln in tail_lines(self.alog, 5)))
            L.info("\n".join("     B| " + ln for ln in tail_lines(self.blog, 5)))
            return self.finish_early()
        want = "loaded config from %s" % os.path.join(self.rdir, "node-a", "home", ".config", "ai-memory", "config.toml")
        try:
            with open(self.alog, "rb") as fh:
                loaded = want.encode("utf-8") in fh.read()
        except OSError:
            loaded = False
        if loaded:
            L.ok("node-a loaded its private config (tier=keyword) — no embedder, no network")
        else:
            L.no("node-a did not load its private config; the tier override was inert (#2852 shape)")
        return None

    def post_json(self, port, payload, timeout):
        status, data = http_call("POST", "https://127.0.0.1:%d/api/v1/memories" % port, timeout, *self.ca_client,
                                 headers={"x-agent-id": AUTHOR, "content-type": "application/json"},
                                 body=json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        return ("%03d" % status if status is not None else "000"), data.decode("utf-8", "replace")

    def step_negative(self):
        L = self.led
        L.step("7 · negative lanes — what MUST be refused")
        o, pa, pb = self.out, self.o["port_a"], self.o["port_b"]
        status, _ = http_call("GET", "https://127.0.0.1:%d/api/v1/health" % pb, 8, os.path.join(o, "client-bad.crt"),
                              os.path.join(o, "client-bad.key"))
        if status is not None:
            L.no("N1 unpinned client cert reached node-b (the fingerprint allowlist is NOT enforcing)")
        else:
            L.ok("N1 unpinned client cert refused at node-b's TLS layer (same CA, absent from the allowlist)")
        status, _ = http_call("GET", "http://127.0.0.1:%d/api/v1/health" % pb, 8)
        if status is not None:
            L.no("N2 plaintext http reached node-b")
        else:
            L.ok("N2 plaintext http refused at node-b's mTLS port")
        code, text = self.post_json(pa, {"title": "unsigned-probe-%d" % os.getpid(),
                                         "content": "an unsigned direct write that the hardened posture must refuse",
                                         "namespace": FED_NS, "tier": "mid"}, 20)
        err = json_field(text, "code")
        if code == "403":
            L.ok("N3 unsigned write refused 403%s under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1" % ((" " + err) if err else ""))
        else:
            L.no("N3 unsigned write got '%s' (expected 403) — %s" % (code, text))
        n4log = os.path.join(self.rdir, "evidence", "no-disable-refusal.txt")
        n4home = os.path.join(self.rdir, "n4-home")
        os.makedirs(os.path.join(n4home, ".config", "ai-memory"), exist_ok=True)
        write_text(os.path.join(n4home, ".config", "ai-memory", "config.toml"), CONFIG_TOML)
        n4port = pb + 2
        if not port_free(n4port):
            L.no("N4 cannot run: port %d is occupied, so a refusal would be unattributable" % n4port)
            return
        with open(n4log, "wb") as log:
            rc = run_bounded([self.bin, "serve", "--host", "127.0.0.1", "--port", str(n4port), "--db",
                              os.path.join(self.rdir, "n4.db"), "--tls-cert", os.path.join(o, "server.crt"), "--tls-key",
                              os.path.join(o, "server.key"), "--mtls-allowlist", os.path.join(o, "allowlist.txt")],
                             n4_env(self.path, n4home), 40, stdout=log, stderr=subprocess.STDOUT)
        try:
            with open(n4log, "rb") as fh:
                named = b"SECRET_SCREEN_MODE" in fh.read().upper()
        except OSError:
            named = False
        if rc != 0 and named:
            L.ok("N4 asi-hard REFUSED to boot with a loosened pin (exit %d, names AI_MEMORY_SECRET_SCREEN_MODE) — the "
                 "no-disable contract holds" % rc)
        elif rc != 0:
            L.no("N4 boot failed (exit %d) but the message does not name the loosened knob — unattributable, see "
                 "run/evidence/no-disable-refusal.txt" % rc)
            L.info("\n".join("     " + ln for ln in tail_lines(n4log, 3)))
        else:
            L.no("N4 asi-hard BOOTED with AI_MEMORY_SECRET_SCREEN_MODE=off — the no-disable contract did not hold")
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                os.remove(os.path.join(self.rdir, "n4.db" + suffix))
            except OSError:
                pass

    def step_positive(self):
        L = self.led
        L.step("8 · positive lanes — attested write, replication, federated recall")
        pa, pb, ns = self.o["port_a"], self.o["port_b"], self.o["corpus_ns"]
        title = "fed-lab-attested-%d" % os.getpid()
        content = ("A v1.0.0 laptop federation lab probe: an agent-attested memory authored on node-a that must "
                   "replicate across the mutually authenticated quorum mesh and be recallable at node-b.")
        created = utc_now("%Y-%m-%dT%H:%M:%S+00:00")
        sign_err = os.path.join(self.rdir, "evidence", "sign.err")
        _rc, out = run_capture([self.signer, "--agent-id", AUTHOR, "--namespace", FED_NS, "--title", title, "--kind",
                                "observation", "--created-at", created, "--content", content, "--priv-file",
                                os.path.join(self.kauth, AUTHOR + ".priv")],
                               {"PATH": self.path, "HOME": os.path.join(self.rdir, "tool-home")}, 120, stderr_path=sign_err)
        sig = out.decode("utf-8", "replace").rstrip("\n")
        if not sig:
            L.no("P1 attest_sign produced no signature — %s" % "\n".join(_head_lines(sign_err, 2)))
        else:
            code, text = self.post_json(pa, {"title": title, "content": content, "namespace": FED_NS, "tier": "mid",
                                             "signature": sig, "created_at": created}, 30)
            rid = json_field(text, "id")
            if code in ("201", "202") and rid:
                L.ok("P1 attested write accepted at node-a (HTTP %s, id=%s)" % (code, rid))
            else:
                L.no("P1 attested write got '%s' — %s" % (code, text))
            sql = "SELECT COALESCE(json_extract(metadata,'$.attest_level'),%s) FROM memories WHERE namespace=? AND title=? LIMIT 1"
            alvl = sql_value(self.adb, sql % "''", (FED_NS, title), 3)
            if alvl == "agent_attested":
                L.ok("P2 node-a stored it at attest_level=agent_attested (signature verified against the bound key)")
            else:
                L.no("P2 node-a attest_level='%s' (expected agent_attested)" % (alvl or "<row absent>"))
            blvl = ""
            for _ in range(60):
                blvl = sql_value(self.bdb, sql % "'present-no-level'", (FED_NS, title), 3)
                if blvl:
                    break
                time.sleep(0.5)
            if blvl == "agent_attested":
                L.ok("P3 the write REPLICATED to node-b over the mTLS quorum channel and arrived agent_attested")
            elif blvl:
                L.no("P3 the write reached node-b but at attest_level='%s' (expected agent_attested)" % blvl)
            else:
                lines = tail_lines(self.blog, 2, re.compile(r"quorum|push|write.?sig|enroll", re.IGNORECASE))
                L.no("P3 the write never reached node-b — %s" % "".join(ln + " " for ln in lines))
            _status, data = http_call("GET", recall_url(pb, "agent-attested memory replicate quorum mesh", FED_NS, 10), 30,
                                      *self.cb_client, headers={"x-agent-id": AUTHOR})
            text = data.decode("utf-8", "replace")
            if recall_hits(text, title) >= 1:
                L.ok("P4 federated recall: node-b returns the memory that was written to node-a")
            else:
                L.no("P4 federated recall at node-b returned no match — %s" % head_bytes(data, 300))
        query, kind = self.o["recall_query"], "explicit"
        if not query:
            if self.o["corpus_db"]:
                query = derive_query(sql_value(self.adb, "SELECT title FROM memories WHERE namespace=? ORDER BY id LIMIT 1",
                                               (ns,), 5) or None)
                kind = "derived from the seeded corpus"
            else:
                query, kind = FIXTURE_QUERY, "fixture-authored"
        if query.replace(" ", "") == "":
            L.no("P5 could not resolve a corpus recall query — pass --recall-query")
            query = "__unresolved__"
        L.info("corpus query (%s): %s" % (kind, query))
        _status, data = http_call("GET", recall_url(pa, query, ns, 5), 30, *self.ca_client, headers={"x-agent-id": AUTHOR})
        text = data.decode("utf-8", "replace")
        chits = recall_count(text)
        if chits >= 1:
            L.ok("P5 corpus recall on node-a returned %d result(s) from '%s' (lexical — tier=keyword, query %s)" % (chits, ns, kind))
            L.info("top hit: %s" % recall_top_title(text))
        else:
            L.no("P5 corpus recall on node-a returned nothing — %s" % head_bytes(data, 300))

    def step_manifest(self):
        L = self.led
        L.step("9 · run manifest")
        uname = os.uname()
        manifest = "".join(line + "\n" for line in (
            "ai-memory laptop federation lab",
            "generated_at:   %s" % utc_now("%Y-%m-%dT%H:%M:%SZ"),
            "binary:         %s" % self.bin,
            "binary_version: %s" % self.bin_version,
            "host:           %s %s %s" % (uname.sysname, uname.release, uname.machine),
            "nodes:          node-a https://127.0.0.1:%d , node-b https://127.0.0.1:%d" % (self.o["port_a"], self.o["port_b"]),
            "corpus:         %s (%d rows in %s)" % (self.seed_desc, self.loaded, self.o["corpus_ns"]),
            "posture:        %d asi-hard knobs at hard floor (every KNOBS row)" % posture_count(),
            "result:         %d PASS / %d FAIL" % (L.passes, L.fails),
        ))
        write_text(os.path.join(self.rdir, "evidence", "manifest.txt"), manifest)
        for line in manifest.splitlines():
            L.emit("   %s\n" % line)
        green = L.summary()
        if green and L.passes >= 1:
            L.emit("\n   %sfederation lab GREEN%s — %d assertions passed.\n" % (L.c_ok, L.c_0, L.passes))
        else:
            L.emit("\n   %sfederation lab RED%s — see the FAIL rows above; logs in run/node-*/daemon.log\n" % (L.c_no, L.c_0))
            if not self.o["keep"]:
                L.emit("   re-run with --keep to preserve run/ for a post-mortem.\n")
        self.summarized = green
        return 0 if green else 1


def _head_lines(path, count):
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace").splitlines()[:count]
    except OSError:
        return []


# ---------------------------------------------------------------------------------------------------------------------
# Self-test (--posture-selftest): every leg prints PASS or FAIL; the run passes only when every leg passed
# ---------------------------------------------------------------------------------------------------------------------
class Sink:
    """A write target for in-process ledgers; fail=True makes every write and flush raise OSError."""

    def __init__(self, fail=False):
        self.text = []
        self.fail = fail

    def write(self, text):
        if self.fail:
            raise OSError(errno.ENOSPC, "no space")
        self.text.append(text)

    def flush(self):
        if self.fail:
            raise OSError(errno.ENOSPC, "no space")

    def value(self):
        return "".join(self.text)


class Legs:
    """The self-test ledger: one line per leg."""

    def __init__(self, out):
        self.out = out
        self.passes = 0
        self.fails = 0
        self.broken = False

    def emit(self, text):
        try:
            self.out.write(text)
        except (OSError, ValueError):
            self.broken = True

    def leg(self, name, got, want, detail=""):
        if got == want:
            self.passes += 1
            self.emit("  PASS %s (rc=%s)\n" % (name, got))
        else:
            self.fails += 1
            self.emit("  FAIL %s: rc=%s, wanted %s: %s\n" % (name, got, want, " ".join(str(detail).split())[:400]))


def _write(path, text, mode=0o644):
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, mode)


def _synth_root(base, name, rows, files=None):
    """A source tree whose src/security_profile.rs holds a KNOBS table of (env-expr, hard_value-expr) rows."""
    root = os.path.join(base, name)
    if rows is None:
        text = "// no table\n"
    else:
        text = "const KNOBS: &[KnobSpec] = &[\n" + "".join(
            "    KnobSpec {\n        env: %s,\n        hard_value: %s,\n    },\n" % row for row in rows) + "];\n"
    _write(os.path.join(root, "src", "security_profile.rs"), text)
    for rel, body in (files or {}).items():
        _write(os.path.join(root, "src", rel), body)
    return root


def _shadow_root(base, name, line):
    """A source tree linking every top-level entry of ROOT/src and adding src/aaa_shadow.rs holding LINE."""
    root = os.path.join(base, name)
    os.makedirs(os.path.join(root, "src"))
    for entry in sorted(os.listdir(os.path.join(ROOT, "src"))):
        os.symlink(os.path.join(ROOT, "src", entry), os.path.join(root, "src", entry))
    _write(os.path.join(root, "src", "aaa_shadow.rs"), line + "\n")
    return root


def _replace_kv(posture_set, name, value):
    return tuple(("%s=%s" % (name, value)) if kv.partition("=")[0] == name else kv for kv in posture_set)


def selftest_drift(T, base):
    """Drift-guard legs: the real KNOBS table, lab-list mutations, shadow consts and synthetic tables."""
    if os.path.isfile(os.path.join(ROOT, "src", "security_profile.rs")):
        rc, text = posture_ssot_check(ROOT)
        T.leg("control: lab posture equals the SSOT names and values", rc, 0, text)
        T.leg("control: the ok line counts 31 knobs, 31 of 31 at the hard floor",
              ("covers all 31 SSOT knobs" in text, "31 of 31" in text), (True, True), text)
        for label, mutated in (
                ("weakened value AI_MEMORY_PERMISSIONS_MODE=advisory is refused",
                 _replace_kv(LAB_POSTURE_SET, "AI_MEMORY_PERMISSIONS_MODE", "advisory")),
                ("weakened boolean AI_MEMORY_CID_ENFORCE=0 is refused", _replace_kv(LAB_POSTURE_SET, "AI_MEMORY_CID_ENFORCE", "0")),
                ("weakened const-valued knob AI_MEMORY_UNSTAMPED_MUTATION=warn is refused",
                 _replace_kv(LAB_POSTURE_SET, "AI_MEMORY_UNSTAMPED_MUTATION", "warn"))):
            rc, text = posture_ssot_check(ROOT, mutated)
            T.leg(label, (rc, "value '" in text), (1, True), text)
        dropped = tuple(kv for kv in LAB_POSTURE_SET if not kv.startswith("AI_MEMORY_REQUIRE_FORENSIC_SINK="))
        rc, text = posture_ssot_check(ROOT, dropped)
        T.leg("dropped knob name is refused and named as only in SSOT",
              (rc, "  only in SSOT: AI_MEMORY_REQUIRE_FORENSIC_SINK \n" in text), (1, True), text)
        moved = tuple(kv for kv in LAB_POSTURE_SET if not kv.startswith("AI_MEMORY_CID_ENFORCE="))
        rc, text = posture_ssot_check(ROOT, moved, LAB_POSTURE_UNSET + ("AI_MEMORY_CID_ENFORCE",))
        T.leg("a pinned knob moved to the unset list is refused", (rc, "is unset in the lab" in text), (1, True), text)
        rc, text = posture_ssot_check(ROOT, LAB_POSTURE_SET + ("AI_MEMORY_CID_ENFORCE=1",))
        T.leg("a knob listed twice in the lab is refused (names compared as a multiset)", rc, 1, text)
        for i, (label, line, want) in enumerate((
                ("a shadow duplicate of a path-named const does not change the result",
                 'pub const MODE_REFUSE: &str = "warn";', 0),
                ("a shadow duplicate of a single-module path-named const (crate::tls) does not change the result",
                 'pub const FED_CERT_PEER_BINDING_ENV: &str = "SHADOW_ENV";', 0),
                ("a name-only const with two distinct values is cannot-check, not first-match",
                 'pub const ENV_DB_SYNCHRONOUS: &str = "SHADOW_ENV";', 2))):
            rc, text = posture_ssot_check(_shadow_root(base, "shadow-%d" % i, line))
            T.leg(label, rc, want, text)
    else:
        T.emit("  info: no source tree at %s, the legs over the real KNOBS table need src/\n" % ROOT)
    root = _synth_root(base, "lit", [('"AI_MEMORY_A"', '"1"'), ('"AI_MEMORY_B"', '""')])
    T.leg("synthetic: literal env and hard values agree", posture_ssot_check(root, ("AI_MEMORY_A=1",), ("AI_MEMORY_B",))[0], 0)
    T.leg("synthetic: a set value that differs is drift", posture_ssot_check(root, ("AI_MEMORY_A=2",), ("AI_MEMORY_B",))[0], 1)
    T.leg("synthetic: a knob unset in the lab whose hard value is set is drift",
          posture_ssot_check(root, ("AI_MEMORY_B=",), ("AI_MEMORY_A",))[0], 1)
    T.leg("synthetic: a set knob whose hard value is empty is drift",
          posture_ssot_check(root, ("AI_MEMORY_A=1", "AI_MEMORY_B="), ())[0], 1)
    T.leg("synthetic: a name missing from the lab is drift", posture_ssot_check(root, ("AI_MEMORY_A=1",), ())[0], 1)
    root = _synth_root(base, "path", [("crate::knobs::ENV_A", "crate::knobs::HARD_A")],
                       {"knobs.rs": 'pub const ENV_A: &str = "AI_MEMORY_A";\npub(crate) const HARD_A: &str =\n    "on";\n',
                        "other.rs": 'pub const ENV_A: &str = "AI_MEMORY_OTHER";\n'})
    T.leg("synthetic: a crate:: path resolves in its own module first (src/knobs.rs)",
          posture_ssot_check(root, ("AI_MEMORY_A=on",), ())[0], 0)
    root = _synth_root(base, "modrs", [("crate::knobs::Kind::ENV_A", '"1"')],
                       {"knobs/mod.rs": 'pub const ENV_A: &str = "AI_MEMORY_A";\n',
                        "zz.rs": 'pub const ENV_A: &str = "AI_MEMORY_Z";\n'})
    T.leg("synthetic: a crate::module::Type::CONST path resolves in src/module/mod.rs",
          posture_ssot_check(root, ("AI_MEMORY_A=1",), ())[0], 0)
    root = _synth_root(base, "nameonly", [("crate::gone::ENV_A", '"1"')],
                       {"a.rs": 'pub const ENV_A: &str = "AI_MEMORY_A";\n', "b/c.rs": 'pub const ENV_A: &str = "AI_MEMORY_A";\n'})
    T.leg("synthetic: a name-only const with one distinct value resolves", posture_ssot_check(root, ("AI_MEMORY_A=1",), ())[0], 0)
    root = _synth_root(base, "twovals", [("crate::gone::ENV_A", '"1"')],
                       {"a.rs": 'pub const ENV_A: &str = "AI_MEMORY_A";\n', "b.rs": 'pub const ENV_A: &str = "AI_MEMORY_Z";\n'})
    rc, text = posture_ssot_check(root, ("AI_MEMORY_A=1",), ())
    T.leg("synthetic: a name-only const with two distinct values is cannot-check", (rc, "env expression" in text), (2, True), text)
    root = _synth_root(base, "noenv", [("crate::gone::ENV_A", '"1"')])
    T.leg("synthetic: an unresolvable env expression is cannot-check", posture_ssot_check(root, (), ())[0], 2)
    root = _synth_root(base, "noval", [('"AI_MEMORY_A"', "crate::gone::HARD")])
    rc, text = posture_ssot_check(root, ("AI_MEMORY_A=1",), ())
    T.leg("synthetic: an unresolvable hard_value expression is cannot-check and names the knob",
          (rc, "(knob AI_MEMORY_A)" in text), (2, True), text)
    root = _synth_root(base, "lower", [("crate::knobs::env_a", '"1"')], {"knobs.rs": 'pub const env_a: &str = "AI_MEMORY_A";\n'})
    T.leg("synthetic: a crate:: path whose last segment is not an upper-case const is cannot-check",
          posture_ssot_check(root, ("AI_MEMORY_A=1",), ())[0], 2)
    root = _synth_root(base, "orphan", [])
    _write(os.path.join(root, "src", "security_profile.rs"),
           "const KNOBS: &[KnobSpec] = &[\n    KnobSpec {\n        hard_value: \"1\",\n    },\n];\n")
    T.leg("synthetic: a hard_value row with no env row before it is cannot-check", posture_ssot_check(root, (), ())[0], 2)
    root = _synth_root(base, "empty", [])
    rc, text = posture_ssot_check(root, (), ())
    T.leg("synthetic: a KNOBS table with zero rows is cannot-check", (rc, "zero rows" in text), (2, True), text)
    root = _synth_root(base, "notable", None)
    rc, text = posture_ssot_check(root, (), ())
    T.leg("synthetic: a source file with no KNOBS table is cannot-check", (rc, "KNOBS table not found" in text), (2, True), text)
    rc, text = posture_ssot_check(os.path.join(base, "no-such-root"))
    T.leg("synthetic: no source tree is a skip (release-tarball mode)", (rc, text.startswith("skip: no source tree")), (2, True), text)


def selftest_render(T):
    """Render, count and environment legs for the posture lists."""
    T.leg("posture: 25 set knobs plus 6 unset hatches count 31", posture_count(), 31)
    lines = posture_render().splitlines()
    T.leg("posture: the render has one line per knob", len(lines), 31)
    T.leg("posture: the unset hatches render as not in force",
          all(ln.endswith("=<unset — permissive hatch NOT in force>") for ln in lines[25:]), True)
    env = posture_env()
    T.leg("posture: the node environment holds every set knob and no unset hatch",
          (len(env), any(k in env for k in LAB_POSTURE_UNSET)), (25, False))
    T.leg("posture: the knob names are distinct",
          len(set(kv.partition("=")[0] for kv in LAB_POSTURE_SET) | set(LAB_POSTURE_UNSET)), 31)


MATCHER_LOGS = (
    ("a refusal naming the knob is detected", "fatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: floor 1\n", "detected"),
    ("a refusal for a longer knob name is not counted",
     "fatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK_STRICT: nope\n", "not-detected"),
    ("an INFO pin line is not counted", "boot\nINFO refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: pinned\n", "not-detected"),
    ("an INFO pin line with a timestamp prefix is not counted",
     "2026-01-01T00:00:00Z INFO refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: pinned\n", "not-detected"),
    ("a refusal after an INFO line naming the knob is detected",
     "INFO refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: pinned\nfatal: refuses to disable "
     "AI_MEMORY_REQUIRE_ROLLBACK_CHECK: floor 1\n", "detected"),
    ("a refusal followed by an INFO line naming the knob is detected",
     "fatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: floor 1\nINFO refuses to disable "
     "AI_MEMORY_REQUIRE_ROLLBACK_CHECK: pinned\n", "detected"),
    ("a refusal on the last line with no newline is detected",
     "boot\nfatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: floor 1", "detected"),
    ("a refusal without the colon after the knob is not counted",
     "fatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK floor 1\n", "not-detected"),
    ("an empty log is not detected", "", "not-detected"),
)


def _matcher_calls():
    """The sorted call names and the open() mode literals inside probe_verdict, read from this file's own source."""
    import ast
    with open(os.path.realpath(__file__), "rb") as fh:
        tree = ast.parse(fh.read())
    calls, modes = set(), []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "probe_verdict":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    func = sub.func
                    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else "?"
                    calls.add(name)
                    if name == "open":
                        modes.extend(a.value for a in sub.args[1:] if isinstance(a, ast.Constant))
                        modes.extend("kw" for _ in sub.keywords)
    return sorted(calls), modes


def selftest_matcher(T, base):
    """Matcher and report legs, and the bar (b) potency leg."""
    for i, (label, text, want) in enumerate(MATCHER_LOGS):
        path = os.path.join(base, "matcher-%d.log" % i)
        _write(path, text)
        T.leg("probe matcher: " + label, probe_verdict(path), want)
    big = os.path.join(base, "matcher-big.log")
    with open(big, "w", encoding="ascii") as fh:
        fh.write("filler line\n" * 200000)
        fh.write("fatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: floor 1\n")
    T.leg("probe matcher: detection in a large log (200000 lines before the refusal)", probe_verdict(big), "detected")
    T.leg("probe matcher: a missing log is refused, never not-detected",
          probe_verdict(os.path.join(base, "no-such.log")).startswith("refused: the probe log could not be read"), True)
    T.leg("probe matcher: a directory in place of the log is refused, never not-detected",
          probe_verdict(base).startswith("refused: "), True)
    T.leg("probe report: detected is ok with the boot exit and the knob named", probe_report("detected", 1),
          (True, "probe mutation detected: the boot refused (exit 1) and the refusal names AI_MEMORY_REQUIRE_ROLLBACK_CHECK"))
    T.leg("probe report: not-detected is no, inconclusive", probe_report("not-detected", 1)[0], False)
    good, line = probe_report("refused: the probe log could not be read (OSError)", 1)
    T.leg("probe report: a refused verdict is no and names the reason, never ok", (good, "could not be read" in line), (False, True))
    T.leg("probe report: an empty verdict is no", probe_report("", 1)[0], False)
    T.leg("probe matcher: probe_verdict starts no child and writes nothing (it calls only open in rb mode, read, type "
          "and split)", _matcher_calls(), (["open", "read", "split", "type"], ["rb"]))
    clean = os.path.join(base, "matcher-1.log")
    builtins_mod = sys.modules["builtins"]
    real_open = builtins_mod.open

    def forged_open(_path, *args, **kwargs):
        return real_open(os.path.join(base, "matcher-0.log"), *args, **kwargs)

    builtins_mod.open = forged_open
    try:
        forged = probe_verdict(clean)
    finally:
        builtins_mod.open = real_open
    T.leg("bar-b potency: a replaced open turns a not-detected log into detected (why stage 0 refuses it)",
          (forged, probe_verdict(clean)), ("detected", "not-detected"))


def _free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _fake_lab(base, name, mutation, script):
    """A Lab whose binary is a fake serve that prints SCRIPT[0] and exits with SCRIPT[1]."""
    rdir = os.path.join(base, name)
    os.makedirs(os.path.join(rdir, "evidence"))
    fake = os.path.join(rdir, "fake-ai-memory")
    _write(fake, "#!%s -IS\nimport sys\nsys.stdout.write(%r)\nsys.exit(%d)\n" % (sys.executable, script[0], script[1]), 0o755)
    port = _free_port()
    opts = {"port_b": port - 1, "probe_mutation": mutation, "no_caveat_probe": False, "keep": False, "corpus_ns": "x"}
    lab = Lab(opts, Ledger(Sink(), False), {"PATH": "/usr/bin:/bin"}, run_dir=rdir)
    lab.bin = fake
    return lab, port


def _selftest_signal_exit(T, base, signum, want):
    """main under a real signal: the handler is installed, the daemons stop, run/ is removed and the exit is 128+n."""
    sig_dir = os.path.join(base, "signal-%d" % signum)
    started = []

    class _SignalLab(Lab):
        def __init__(self, opts, ledger, environ):
            super().__init__(opts, ledger, environ, run_dir=sig_dir)

        def run(self):
            os.makedirs(self.rdir)
            self.owned = True
            proc = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time\ntime.sleep(60)\n"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    env={"PATH": "/usr/bin:/bin"})
            self.daemons.append(proc)
            started.append(proc)
            if signal.getsignal(signum) is not _interrupt:
                return 99
            os.kill(os.getpid(), signum)
            for _ in range(500):
                time.sleep(0.01)
            return 98

    saved = (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM), globals()["Lab"])
    globals()["Lab"] = _SignalLab
    gone = []
    try:
        rc = main([], {"PATH": "/usr/bin:/bin"})
        for proc in started:
            gone.append(_pid_gone(proc))
    finally:
        globals()["Lab"] = saved[2]
        signal.signal(signal.SIGINT, saved[0])
        signal.signal(signal.SIGTERM, saved[1])
        for proc in started:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    T.leg("signal: %s stops the daemons (the daemon pid is gone when main returns), removes run/ and exits %d"
          % (signal.Signals(signum).name, want), (rc, gone, os.path.exists(sig_dir)), (want, [True], False))


def _selftest_signal_window(T, base, window, signum):
    """5527 r8 F2: main with SIGINT or SIGTERM delivered inside one window; cleanup runs and the exit is 128+n.

    The signal is delivered by os.kill from a wrapper at the exact point named by WINDOW, so the handler runs at
    the next bytecode, inside the window.
    """
    want = 128 + signum
    sig_dir = os.path.join(base, "window-%s-%d" % (window, signum))
    started = []
    real_popen = subprocess.Popen
    real_signal = signal.signal
    real_no = Ledger.no
    state = {"fired": False}

    def fire():
        if not state["fired"]:
            state["fired"] = True
            os.kill(os.getpid(), signum)

    class _WindowLab(Lab):
        def __init__(self, opts, ledger, environ):
            super().__init__(opts, ledger, environ, run_dir=sig_dir)

        def run(self):
            os.makedirs(sig_dir)
            self.owned = True
            self.bin = os.path.join(sig_dir, "fake-daemon")
            _write(self.bin, "#!%s -IS\nimport time\ntime.sleep(60)\n" % sys.executable, 0o755)
            self.rust_log = "info"
            if window == "spawn":
                self.launch("n", 1, "db", sig_dir, "fed", sig_dir, 2, "c", "k", "a", os.path.join(sig_dir, "log"), "peer")
                return 98
            proc = real_popen([sys.executable, "-I", "-S", "-c", "import time\ntime.sleep(60)\n"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              env={"PATH": "/usr/bin:/bin"})
            started.append(proc)
            self.daemons.append(proc)
            if window == "handler":
                raise RuntimeError("forced")
            return 0

    def late_popen(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        started.append(proc)
        fire()
        return proc

    def window_signal(num, handler):
        if window == "install" and num == signal.SIGTERM and handler is _interrupt:
            old = real_signal(num, handler)
            fire()
            return old
        if window == "ignore-1" and num == signal.SIGINT and handler == signal.SIG_IGN:
            fire()
        old = real_signal(num, handler)
        if window == "ignore-2" and num == signal.SIGINT and handler == signal.SIG_IGN:
            fire()
        return old

    def window_no(self, text):
        fire()

    saved = (real_signal(signal.SIGINT, signal.SIG_DFL), real_signal(signal.SIGTERM, signal.SIG_DFL), Lab)
    real_signal(signal.SIGINT, saved[0])
    real_signal(signal.SIGTERM, saved[1])
    globals()["Lab"] = _WindowLab
    if window == "spawn":
        subprocess.Popen = late_popen
    if window in ("install", "ignore-1", "ignore-2"):
        signal.signal = window_signal
    if window == "handler":
        Ledger.no = window_no
    gone = []
    err = ""
    rc = None
    try:
        try:
            rc = main([], {"PATH": "/usr/bin:/bin"})
        except BaseException as exc:  # noqa: BLE001 - an escape is the defect this leg detects
            err = exc.__class__.__name__
        for proc in started:
            gone.append(_pid_gone(proc))
    finally:
        subprocess.Popen = real_popen
        signal.signal = real_signal
        Ledger.no = real_no
        globals()["Lab"] = saved[2]
        real_signal(signal.SIGINT, saved[0])
        real_signal(signal.SIGTERM, saved[1])
        for proc in started:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    T.leg("signal window %s: %s stops every started daemon, removes run/ and exits %d with no escaping exception"
          % (window, signal.Signals(signum).name, want),
          (rc, all(gone) and (bool(gone) or window == "install"), os.path.exists(sig_dir), err), (want, True, False, ""))


def _pid_gone(proc):
    """True only when the child was already reaped (returncode set, no poll here) and its pid no longer answers."""
    if proc.returncode is None:
        return False
    try:
        os.kill(proc.pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


def selftest_probe_block(T, base):
    """Bar (a): the probe block records exactly one verdict or the run fails; the real block over a fake serve."""
    cases = (
        ("probe block: mutation and a refusal naming the knob records ok",
         True, ("fatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: floor 1\n", 1), (None, 1, 0)),
        ("probe block: mutation and a refusal for another knob records no",
         True, ("fatal: refuses to disable AI_MEMORY_CID_ENFORCE: floor 1\n", 1), (None, 0, 1)),
        ("probe block: mutation and a node that listened records no (mutation not detected)",
         True, ("listening on https://127.0.0.1\n", 0), (None, 0, 1)),
        ("probe block: no mutation and a node that listened records ok", False, ("listening on https://127.0.0.1\n", 0), (None, 1, 0)),
        ("probe block: no mutation and a refusal records no", False, ("fatal: refused\n", 1), (None, 0, 1)),
    )
    for i, (label, mutation, script, want) in enumerate(cases):
        lab, _port = _fake_lab(base, "probe-%d" % i, mutation, script)
        rc = lab.probe_guarded()
        T.leg(label, (rc, lab.led.passes, lab.led.fails), want, lab.led.out.value())
    lab, port = _fake_lab(base, "probe-busy", False, ("listening on\n", 0))
    busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        busy.bind(("127.0.0.1", port))
        busy.listen(1)
        rc = lab.probe_guarded()
    finally:
        busy.close()
    T.leg("probe block: an occupied probe port records one no and the count passes", (rc, lab.led.passes, lab.led.fails),
          (None, 0, 1), lab.led.out.value())

    def raising():
        raise ValueError("boom")

    def silent():
        return None

    for i, (label, block) in enumerate((
            ("bar-a: a probe block that raises before its verdict fails the run (#5739)", raising),
            ("bar-a: a probe block that records no verdict fails the run (#5739)", silent),
            ("bar-a: a probe block that records two verdicts fails the run (#5739)", "twice"))):
        lab, _port = _fake_lab(base, "probe-bar-%d" % i, False, ("", 0))
        if block == "twice":
            led = lab.led

            def block():
                led.ok("one")
                led.no("two")
        lab.probe_block = block
        rc = lab.probe_guarded()
        T.leg(label, (rc, "did not record exactly one verdict" in lab.led.out.value()), (1, True), lab.led.out.value())
    def interrupted():
        raise LabInterrupted(signal.SIGTERM)

    lab, _port = _fake_lab(base, "probe-interrupt", False, ("", 0))
    lab.probe_block = interrupted
    try:
        lab.probe_guarded()
        got = "returned"
    except LabInterrupted as exc:
        got = exc.signum
    T.leg("signal: an interrupt inside the probe block propagates out of the probe guard", got,
          signal.SIGTERM, lab.led.out.value())
    for signum, want in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
        _selftest_signal_exit(T, base, signum, want)
        for window in ("install", "spawn", "handler", "ignore-1", "ignore-2"):
            if window != "ignore-2" or signum == signal.SIGTERM:  # SIGINT is already ignored in the second window
                _selftest_signal_window(T, base, window, signum)
    live = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time\ntime.sleep(60)\n"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"})
    try:
        before = _pid_gone(live)
    finally:
        live.kill()
        live.wait()
    T.leg("signal: the pid check reports a live daemon as not gone and a reaped one as gone (control)",
          (before, _pid_gone(live)), (False, True))
    try:
        try:
            raise LabInterrupted(signal.SIGINT)
        except Exception:  # noqa: BLE001 - the leg proves an ordinary handler cannot catch the interrupt
            got = "swallowed"
    except LabInterrupted:
        got = "propagated"
    T.leg("signal: an ordinary error handler cannot swallow an interrupt", got, "propagated")
    lab, _port = _fake_lab(base, "probe-skip", False, ("", 0))
    lab.o["no_caveat_probe"] = True
    rc = lab.step_posture()
    T.leg("probe block: a skipped probe records nothing and the count does not apply", (rc, lab.led.passes, lab.led.fails),
          (None, 0, 0))
    led = Ledger(Sink(), False)
    T.leg("bar-a: a run that recorded no PASS exits non-zero", final_rc(led, True, []), 1)
    led.ok("x")
    T.leg("bar-a: control: one PASS, no FAIL, summary printed and streams flushed exits 0", final_rc(led, True, [Sink()]), 0)
    T.leg("bar-a: a summary that was not printed exits non-zero", final_rc(led, False, [Sink()]), 1)
    T.leg("bar-a: a stream that cannot be flushed exits non-zero", final_rc(led, True, [Sink(fail=True)]), 1)
    led.no("y")
    T.leg("bar-a: a FAIL exits non-zero", final_rc(led, True, [Sink()]), 1)
    led = Ledger(Sink(fail=True), False)
    led.ok("a verdict that could not be written")
    T.leg("bar-a: a PASS line that could not be written exits non-zero", (led.broken, final_rc(led, True, [])), (True, 1))
    led = Ledger(Sink(), False)
    led.ok("x")
    T.leg("summary: a ledger with no FAIL reports green", led.summary(), True)
    led.no("y")
    T.leg("summary: a ledger with a FAIL reports red and prints the counts",
          (led.summary(), "\n   1 PASS / 1 FAIL\n" in led.out.value()), (False, True))


JQ_CASES = (
    ("seed_rows", '{"count":7,"memories":[1]}', "7"), ("seed_rows", '{"count":false,"memories":[1,2]}', "2"),
    ("seed_rows", '{"count":"7"}', "7"), ("seed_rows", '{"memories":[1,2,3]}', "3"), ("seed_rows", "[1,2]", "0"),
    ("seed_rows", '"x"', "0"), ("seed_rows", "not json", "0"), ("seed_rows", "{}", "0"),
    ("seed_rows", '{"count":3.0}', "3"), ("seed_rows", '{"memories":{"a":1}}', "1"), ("seed_rows", '{"count":null}', "0"),
    ("recall_hits", '{"memories":[{"title":"t"},{"title":"u"}]}', 1), ("recall_hits", '{"results":[{"title":"t"}]}', 1),
    ("recall_hits", '[{"title":"t"},{"title":"t"}]', 0), ("recall_hits", '{"memories":null,"results":[{"title":"t"}]}', 1),
    ("recall_hits", '{"memories":[null,{"title":"t"}]}', 1), ("recall_hits", '{"memories":[1,{"title":"t"}]}', 0),
    ("recall_hits", '{"title":"t"}', 0), ("recall_hits", "", 0), ("recall_hits", '{"memories":{"a":{"title":"t"}}}', 1),
    ("recall_count", '{"memories":[1,2,3]}', 3), ("recall_count", "[1,2]", 0), ("recall_count", '{"memories":5}', 0),
    ("recall_count", '{"a":1,"b":2}', 2), ("recall_count", "null", 0),
    ("recall_top_title", '{"memories":[{"title":"t"}]}', "t"), ("recall_top_title", '{"memories":[]}', "?"),
    ("recall_top_title", '{"memories":[{"title":null}]}', "?"), ("recall_top_title", '{"memories":["s"]}', ""),
    ("recall_top_title", '{"a":1}', ""), ("recall_top_title", "[1]", ""), ("recall_top_title", "null", "?"),
    ("recall_top_title", '{"memories":[{"title":3.0}]}', "3"),
    ("json_field_id", '{"id":"abc"}', "abc"), ("json_field_id", '{"id":3.0}', "3"), ("json_field_id", '{"id":false}', ""),
    ("json_field_id", "[1]", ""), ("json_field_id", "", ""),
)


def selftest_jq(T):
    """The jq 1.6 readers the lab replaced, against measured jq 1.6 output."""
    fns = {"seed_rows": seed_rows, "recall_hits": lambda t: recall_hits(t, "t"), "recall_count": recall_count,
           "recall_top_title": recall_top_title, "json_field_id": lambda t: json_field(t, "id")}
    for name, text, want in JQ_CASES:
        T.leg("jq parity: %s %s" % (name, text or "<empty>"), fns[name](text), want)
    T.leg("derived query: the first four ASCII-alphanumeric words, each followed by a space",
          derive_query("Ballast-scheduling: harbour (rotation) plan B"), "Ballast scheduling harbour rotation ")
    T.leg("derived query: a title with no ASCII alphanumerics derives nothing", derive_query("— ✓ —"), "")
    T.leg("derived query: no title derives nothing", derive_query(None), "")


def selftest_inputs(T, base):
    """Ports, arguments, scratch directory, environments and program resolution."""
    for text, want in (("19482", 19482), ("65533", 65533), ("1", 1)):
        T.leg("port check: PORT_B=[%s] is accepted" % text, parse_port(text), want)
    for text in ("1/0", "PORT_A+1", "a[0]", "x[$(:)]", "abc", "-1", "0", "01", "019482", "65534", "99999", "123456", " 1",
                 "1 ", " 19482", "19482 ", "1\n", "\u0661", "+1", "1_000", "0x10", "1e3", ""):
        T.leg("port check: PORT_B=[%s] is refused" % text.replace("\n", "\\n"), parse_port(text), None)
    for text, want in (("2000", 2000), ("0", None), ("-5", None), ("2k", None), ("1000000000", None), ("\u0662", None)):
        T.leg("rows check: CORPUS_ROWS=[%s]" % text, parse_rows(text), want)
    for text, want in (("lab-corpus", True), ("a/b:c.d@e_f", True), ("", False), ("a b", False), ("a;b", False),
                       ("a\nb", False), ("$(x)", False)):
        T.leg("namespace check: --corpus-ns [%s]" % text.replace("\n", "\\n"), safe_namespace(text), want)
    env = {"PATH": "/usr/bin"}
    for label, argv, want in (
            ("args: --help exits 0 with the usage", ["--help"], 0), ("args: -h exits 0", ["-h"], 0),
            ("args: an unknown argument exits 2", ["--nope"], 2), ("args: a missing value exits 1", ["--bin"], 1),
            ("args: --help after an unknown argument still exits 2", ["--nope", "--help"], 2),
            ("args: a bad port exits 2", ["--port-a", "0"], 2),
            ("args: --probe-mutation with --no-caveat-probe exits 2", ["--probe-mutation", "--no-caveat-probe"], 2),
            ("args: an unsafe --corpus-ns exits 2", ["--corpus-ns", "a b"], 2),
            ("args: a bad --corpus-rows exits 2", ["--corpus-rows", "0"], 2)):
        _opts, early = parse_args(argv, env)
        T.leg(label, early[0] if early else "parsed", want, early)
    opts, early = parse_args(["--port-b", "65533", "--keep"], {"PORT_A": "19481"})
    T.leg("args: valid options parse (control)", (early, opts and opts["port_b"], opts and opts["keep"]), (None, 65533, True))
    _opts, early = parse_args([], {"PORT_B": "abc"})
    T.leg("args: a bad PORT_B from the environment exits 2", early and early[0], 2)
    _opts, early = parse_args([], {"CORPUS_ROWS": "1e3"})
    T.leg("args: a bad CORPUS_ROWS from the environment exits 2", early and early[0], 2)
    T.leg("probe scratch: scratch_base with TMPDIR unset is the absolute current directory",
          scratch_base({}, base), os.path.realpath(base))
    T.leg("probe scratch: scratch_base with TMPDIR empty is the absolute current directory",
          scratch_base({"TMPDIR": ""}, base), os.path.realpath(base))
    T.leg("probe scratch: scratch_base with TMPDIR relative is absolute under the current directory",
          scratch_base({"TMPDIR": "rel"}, base), os.path.realpath(os.path.join(base, "rel")))
    T.leg("probe scratch: scratch_base with TMPDIR absolute is that directory", scratch_base({"TMPDIR": base}, "/"),
          os.path.realpath(base))
    os.makedirs(os.path.join(base, "rel"))
    made = scratch_dir("leg", {"TMPDIR": "rel"}, base)
    T.leg("probe scratch: scratch_dir with TMPDIR relative makes an absolute directory under it",
          (os.path.isabs(made), made.startswith(os.path.realpath(os.path.join(base, "rel")) + os.sep)), (True, True))
    with open(os.path.realpath(__file__), encoding="utf-8") as fh:
        source = fh.read()
    T.leg("probe scratch: scratch_dir is the only scratch-directory maker in run.py",
          (source.count("mk" + "dtemp("), source.count("mk" + "stemp("), source.count("Temporary" + "Directory(")), (1, 0, 0))
    stray = ("LAB_STRAY_CANARY", "PYTHONPATH", "LD_PRELOAD", "BASH_ENV", "SSLKEYLOGFILE")
    builds = (tool_env("/usr/bin", "/h"), tool_env("/usr/bin", "/h", AI_MEMORY_KEY_DIR="/k"),
              daemon_env("/usr/bin", "/h", "/k", "id", "{}", "/w", "info"), probe_env("/usr/bin", "/h", "/k", False),
              probe_env("/usr/bin", "/h", "/k", True), n4_env("/usr/bin", "/h"))
    T.leg("environment: no caller variable reaches any child environment builder",
          [k for e in builds for k in e if k in stray], [])
    T.leg("environment: the tool environment is PATH, HOME and AI_MEMORY_NO_CONFIG",
          sorted(tool_env("/p", "/h")), ["AI_MEMORY_NO_CONFIG", "HOME", "PATH"])
    T.leg("environment: the daemon environment is the posture plus seven named variables",
          sorted(set(daemon_env("/p", "/h", "/k", "id", "{}", "/w", "info")) - set(posture_env())),
          ["AI_MEMORY_FED_IDENTITY", "AI_MEMORY_FED_PEER_ATTESTATION", "AI_MEMORY_KEY_DIR", "AI_MEMORY_WITNESS_KEY_DIR",
           "HOME", "PATH", "RUST_LOG"])
    T.leg("environment: the probe lowers the rollback-check knob only under mutation",
          (PROBE_KNOB in probe_env("/p", "/h", "/k", False), probe_env("/p", "/h", "/k", True).get(PROBE_KNOB)), (False, "0"))
    T.leg("environment: N4 loosens only the secret-screen knob under the profile", n4_env("/p", "/h"),
          {"PATH": "/p", "HOME": "/h", "AI_MEMORY_SECURITY_PROFILE": "asi-hard", "AI_MEMORY_SECRET_SCREEN_MODE": "off"})
    T.leg("environment: PATH keeps only absolute existing directories, once each",
          search_path({"PATH": "rel:/usr/bin::.:/no/such/dir:/bin:/usr/bin"}), "/usr/bin:/bin")
    for value, want in (("ai_memory=debug,federation=trace", ("ai_memory=debug,federation=trace", False)),
                        ("x;rm", (DEFAULT_RUST_LOG, True)), ("$(id)", (DEFAULT_RUST_LOG, True)),
                        ("a b", (DEFAULT_RUST_LOG, True)), ("x" * 257, (DEFAULT_RUST_LOG, True)),
                        ("", (DEFAULT_RUST_LOG, False))):
        T.leg("environment: RUST_LOG [%s]" % value[:40], rust_log_value({"RUST_LOG": value}), want)
    T.leg("environment: RUST_LOG unset uses the lab default", rust_log_value({}), (DEFAULT_RUST_LOG, False))
    progdir = os.path.join(base, "progs")
    exe = os.path.join(progdir, "prog")
    _write(exe, "#!/bin/sh\n", 0o755)
    plain = os.path.join(progdir, "plain")
    _write(plain, "x\n", 0o644)
    T.leg("program: an executable file resolves to its real path", resolve_program(exe, "/usr/bin"), os.path.realpath(exe))
    T.leg("program: a bare name resolves on PATH", resolve_program("prog", progdir), os.path.realpath(exe))
    T.leg("program: a non-executable file is refused", resolve_program(plain, "/usr/bin"), None)
    T.leg("program: a directory is refused", resolve_program(progdir, "/usr/bin"), None)
    T.leg("program: an empty value is refused", resolve_program("", "/usr/bin"), None)
    T.leg("program: a missing bare name is refused", resolve_program("no-such-program-x", progdir), None)
    T.leg("doc: the self-test is documented by its docstring", bool((selftest.__doc__ or "").strip()), True)
    with open(os.path.realpath(__file__), "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    above = []
    for i, line in enumerate(lines):
        if re.match(r"\s*(def|class) ", line):
            j = i - 1
            while j >= 0 and re.match(r"\s*@", lines[j]):
                j -= 1
            if j >= 0 and lines[j].strip().startswith("#") and not lines[j].strip().startswith("# ---"):
                above.append(i + 1)
    T.leg("doc: no comment sits directly above a def or class in run.py (a description is the function's own docstring)",
          above, [])
    empty = os.path.join(base, "empty-path")
    os.makedirs(empty)
    for label, corpus, want in (
            ("preflight: openssl is the one tool a run needs from PATH (no curl, jq or sqlite3 without --corpus-db)", None,
             "missing required tool(s): openssl\n"),
            ("preflight: --corpus-db also needs sqlite3 and jq", "x.db", "missing required tool(s): openssl sqlite3 jq\n")):
        opts = {"corpus_db": corpus, "bin": "", "signer": "", "keep": False}
        lab = Lab(opts, Ledger(Sink(), False), {"PATH": empty}, run_dir=os.path.join(base, "preflight-run"))
        ok = lab.preflight()
        T.leg(label, (ok, want in lab.led.out.value()), (False, True), lab.led.out.value()[-200:])
    with open(os.path.realpath(__file__), "r", encoding="utf-8") as fh:
        src = fh.read()
    steps = [(int(m.group(1)), m.start()) for m in re.finditer(r'L\.step\("(\d+) · ', src)]
    n1 = src.find('"N1 ')
    holder = [num for num, at in steps if at < n1]
    pointer = re.findall(r"which is exactly what step (\d+) asserts", src)
    T.leg("doc: the crypto step names the step that asserts N1, the same-CA unpinned refusal (#5817)",
          (pointer, holder[-1:] if n1 >= 0 else []), ([str(holder[-1])] if holder and n1 >= 0 else ["?"], [7]))


SHADOW_MODULES = ("re", "json", "ssl", "subprocess", "socket", "sqlite3", "os", "shutil", "tempfile", "signal", "errno",
                  "sitecustomize", "usercustomize")


def _child(T, base, label, argv, want_rc, want_text, env_extra=None, cwd=None, stdin_path=None, marker_ok=False):
    """Run ARGV with a minimal environment; the leg passes on the wanted exit, the wanted text and no shadow marker."""
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": base}
    env.update(env_extra or {})
    marker = os.path.join(base, "marker")
    if os.path.exists(marker):
        os.remove(marker)
    stdin = open(stdin_path, "rb") if stdin_path else subprocess.DEVNULL
    try:
        proc = subprocess.run(argv, env=env, cwd=cwd or base, stdin=stdin, capture_output=True, timeout=120)
    except subprocess.TimeoutExpired:
        T.leg(label, "timeout", want_rc)
        return
    finally:
        if stdin_path:
            stdin.close()
    out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
    marked = os.path.exists(marker) and not marker_ok
    T.leg(label, (proc.returncode, want_text in out, marked), (want_rc, True, False), out[-300:])


def selftest_start_state(T, base):
    """Start-state legs: each hazard and its neighbouring spellings, run as a child on a scratch copy of this file."""
    py = sys.executable
    with open(os.path.realpath(__file__), "rb") as fh:
        source = fh.read()
    copy_dir = os.path.join(base, "copy")
    os.makedirs(copy_dir)
    copy = os.path.join(copy_dir, "run.py")
    with open(copy, "wb") as fh:
        fh.write(source)
    os.chmod(copy, 0o755)
    plain_dir = os.path.join(base, "plain")
    os.makedirs(plain_dir)
    with open(os.path.join(plain_dir, "run.py"), "wb") as fh:
        fh.write(source)
    marker = os.path.join(base, "marker")
    shadow_body = ("import builtins as _b\n_f = _b.open(%r, 'a')\n_f.write(__name__ + '\\n')\n_f.close()\n"
                   "_real = _b.open\n" % marker)
    patch_open = shadow_body + "def _forged(*a, **k):\n    return _real(*a, **k)\n_b.open = _forged\n"
    for name in SHADOW_MODULES:
        _write(os.path.join(copy_dir, name + ".py"), patch_open if name.endswith("customize") else shadow_body)
    cwd_dir = os.path.join(base, "cwd")
    for name in SHADOW_MODULES:
        _write(os.path.join(cwd_dir, name + ".py"), shadow_body)
    site_dir = os.path.join(base, "sitedir")
    _write(os.path.join(site_dir, "sitecustomize.py"), patch_open)
    user_base = os.path.join(base, "userbase")
    vi = sys.version_info
    _write(os.path.join(user_base, "lib", "python%d.%d" % (vi[0], vi[1]), "site-packages", "usercustomize.py"), patch_open)
    usage = "usage: run.py [options]"
    help_ = [copy, "--help"]
    controls = [
        ("start state: -I -S runs (control)", [py, "-I", "-S"] + help_, None, None),
        ("start state: -I alone re-executes with -I -S and runs (control; refused where the installation's site replaced a sys hook)", [py, "-I"] + help_, None, None),
        ("start state: the cluster -IS runs (control)", [py, "-IS"] + help_, None, None),
        ("start state: the cluster -SI runs (control)", [py, "-SI"] + help_, None, None),
        ("start state: -I -S -X frozen_modules=off runs (control)", [py, "-I", "-S", "-X", "frozen_modules=off"] + help_, None, None),
        ("start state: -I -S -Xfrozen_modules=on runs (control)", [py, "-I", "-S", "-Xfrozen_modules=on"] + help_, None, None),
        ("start state: -I -X frozen_modules=off re-executes and runs (control; refused where the installation's site replaced a sys hook)", [py, "-I", "-X", "frozen_modules=off"] + help_,
         None, None),
        ("start state: -I -s -E -B -q -S runs (control)", [py, "-I", "-s", "-E", "-B", "-q", "-S"] + help_, None, None),
        ("start state: PYTHONPATH with a sitecustomize under -I -S never runs it (control)", [py, "-I", "-S"] + help_,
         {"PYTHONPATH": site_dir}, None),
        ("start state: PYTHONPATH with a sitecustomize under -I never runs it (control; refused where the installation's site replaced a sys hook)", [py, "-I"] + help_,
         {"PYTHONPATH": site_dir}, None),
        ("start state: PYTHONWARNINGS=error under -I is ignored (control; refused where the installation's site replaced a sys hook)", [py, "-I"] + help_, {"PYTHONWARNINGS": "error"}, None),
        ("start state: PYTHONINSPECT=1 under -I is ignored (control; refused where the installation's site replaced a sys hook)", [py, "-I"] + help_, {"PYTHONINSPECT": "1"}, None),
        ("start state: shadow modules in the current directory never load under -I -S (control)", [py, "-I", "-S"] + help_,
         None, cwd_dir),
        ("start state: shadow modules in the script directory never load under -I (control; refused where the installation's site replaced a sys hook)", [py, "-I"] + help_, None, copy_dir),
        ("start state: the shebang start runs (control)", help_, {"PATH": os.path.dirname(py) + ":/usr/bin:/bin"}, None),
        ("start state: an inherited ignored SIGHUP (nohup) runs (control)",
         [py, "-I", "-S", "-c", "import os, signal; signal.signal(signal.SIGHUP, signal.SIG_IGN); "
          "os.execv(%r, [%r, '-I', '-S', %r, '--help'])" % (py, py, copy)], None, None),
    ]
    if vi >= (3, 11):
        controls.append(("start state: -I -P -S runs (control, Python 3.11+)", [py, "-I", "-P", "-S"] + help_, None, None))
    probe = subprocess.run([py, "-I", "-c", "import sys\nfor h in ('excepthook', 'displayhook', 'unraisablehook', "
                            "'breakpointhook'):\n    if getattr(sys, h) is not getattr(sys, '__' + h + '__'):\n"
                            "        print(h)\n"], stdin=subprocess.DEVNULL, capture_output=True,
                           env={"PATH": "/usr/bin:/bin", "HOME": base}, timeout=120)
    site_hooks = probe.stdout.decode("ascii", "replace").split()
    T.leg("start state: the probe of the installation's site under -I ran (control)", probe.returncode, 0,
          probe.stderr[-200:])
    if site_hooks:
        T.emit("  info: this installation's site replaces sys.%s under -I, so a start with -I but without -S is "
               "refused here (exit 78) instead of re-executing\n" % site_hooks[0])
    for label, argv, extra, cwd in controls:
        if argv[0] == py and "-S" not in argv and "-IS" not in argv and "-SI" not in argv and site_hooks:
            _child(T, base, label, argv, _LAB_REFUSED_RC, "sys.%s is replaced" % site_hooks[0], extra, cwd)
        else:
            _child(T, base, label, argv, 0, usage, extra, cwd)
    refusals = (
        ("start state: a plain start is refused", [py] + help_, None, None, "not started isolated"),
        ("start state: -E -s without -I is refused", [py, "-E", "-s"] + help_, None, None, "not started isolated"),
        ("start state: -S without -I is refused", [py, "-S"] + help_, None, None, "not started isolated"),
        ("bar-b: a sitecustomize on PYTHONPATH that replaces open at interpreter start is refused",
         [py] + help_, {"PYTHONPATH": site_dir}, None, "builtin open replaced"),
        ("bar-b: a usercustomize under PYTHONUSERBASE that replaces open at interpreter start is refused",
         [py] + help_, {"PYTHONUSERBASE": user_base}, None, "builtin open replaced"),
        ("start state: PYTHONINSPECT=1 without -I is refused", [py] + help_, {"PYTHONINSPECT": "1"}, None, "inspect"),
        ("start state: -I -i is refused", [py, "-I", "-S", "-i"] + help_, None, None, "interpreter option -i "),
        ("start state: the cluster -Ii is refused", [py, "-Ii", "-S"] + help_, None, None, "interpreter option -Ii "),
        ("start state: PYTHONSTARTUP with -i is refused", [py, "-i"] + help_,
         {"PYTHONSTARTUP": os.path.join(site_dir, "sitecustomize.py")}, None, "interpreter option -i "),
        ("start state: -O is refused", [py, "-I", "-S", "-O"] + help_, None, None, "interpreter option -O "),
        ("start state: -OO is refused", [py, "-I", "-S", "-OO"] + help_, None, None, "interpreter option -OO "),
        ("start state: the cluster -ISO is refused", [py, "-ISO"] + help_, None, None, "interpreter option -ISO "),
        ("start state: -v is refused", [py, "-I", "-S", "-v"] + help_, None, None, "interpreter option -v "),
        ("start state: -b is refused", [py, "-I", "-S", "-b"] + help_, None, None, "interpreter option -b "),
        ("start state: -d is refused", [py, "-I", "-S", "-d"] + help_, None, None, "interpreter option -d "),
        ("start state: -u is refused", [py, "-I", "-S", "-u"] + help_, None, None, "interpreter option -u "),
        ("start state: -R is refused", [py, "-I", "-S", "-R"] + help_, None, None, "interpreter option -R "),
        ("start state: -x is refused", [py, "-I", "-S", "-x"] + help_, None, None, "interpreter option -x "),
        ("start state: -W error is refused", [py, "-I", "-S", "-W", "error"] + help_, None, None, "warning options"),
        ("start state: -Werror is refused", [py, "-I", "-S", "-Werror"] + help_, None, None, "warning options"),
        ("start state: -X dev is refused", [py, "-I", "-S", "-X", "dev"] + help_, None, None, "-X dev"),
        ("start state: -Xdev is refused", [py, "-I", "-S", "-Xdev"] + help_, None, None, "-Xdev"),
        ("start state: -X importtime is refused", [py, "-I", "-S", "-X", "importtime"] + help_, None, None, "-X importtime"),
        ("start state: -X utf8 is refused", [py, "-I", "-S", "-X", "utf8"] + help_, None, None, "-X utf8"),
        ("start state: -- before the script is refused", [py, "-I", "-S", "--"] + help_, None, None, "interpreter option -- "),
        ("start state: -c running the source is refused",
         [py, "-I", "-S", "-c", "exec(compile(open(%r).read(), %r, 'exec'))" % (copy, copy), "--help"], None, None,
         "entry by -c or -m"),
        ("start state: -c that sets __file__ first is refused",
         [py, "-I", "-S", "-c", "__file__ = %r\nexec(compile(open(%r).read(), %r, 'exec'))" % (copy, copy, copy), "--help"],
         None, None, "entry by -c or -m"),
        ("start state: -m from the script directory is refused", [py, "-m", "run", "--help"], None, plain_dir, "REFUSED"),
        ("start state: run as a module through runpy.run_module is refused",
         [py, "-I", "-S", "-c", "import sys, runpy; sys.path.insert(0, %r); sys.argv = [%r, '--help']; "
          "runpy.run_module('run', run_name='__main__', alter_sys=True)" % (copy_dir, copy)], None, None,
         "entry by -m or an import"),
        ("start state: LD_PRELOAD set to empty is refused", [py, "-I", "-S"] + help_, {"LD_PRELOAD": ""}, None, "LD_PRELOAD"),
        ("start state: LD_LIBRARY_PATH is refused", [py, "-I", "-S"] + help_, {"LD_LIBRARY_PATH": "/no/such"}, None,
         "LD_LIBRARY_PATH"),
        ("start state: LD_AUDIT set to empty is refused", [py, "-I", "-S"] + help_, {"LD_AUDIT": ""}, None, "LD_AUDIT"),
        ("start state: DYLD_INSERT_LIBRARIES is refused", [py, "-I"] + help_, {"DYLD_INSERT_LIBRARIES": "/x"}, None,
         "DYLD_INSERT_LIBRARIES"),
    )
    for label, argv, extra, cwd, why in refusals:
        _child(T, base, label, argv, _LAB_REFUSED_RC, why, extra, cwd, marker_ok=True)
    if vi >= (3, 11):
        _child(T, base, "start state: -X frozen_modules=maybe is refused by the interpreter before the program runs",
               [py, "-I", "-S", "-X", "frozen_modules=maybe"] + help_, 1, "bad value for option -X frozen_modules", marker_ok=True)
    _child(T, base, "start state: -I -S -m run with the script directory on PYTHONPATH never finds the program",
           [py, "-I", "-S", "-m", "run", "--help"], 1, "No module named run", {"PYTHONPATH": copy_dir}, marker_ok=True)
    _child(T, base, "start state: entry from stdin is refused", [py, "-I", "-S", "-", "--help"], _LAB_REFUSED_RC,
           "run.py: REFUSED: entry from stdin is not allowed",
           stdin_path=copy, marker_ok=True)
    orig_now = getattr(sys, "orig_argv", None)
    ctypes_now = _lab_ctypes_argv()
    T.leg("5908: the ctypes command-line reader (Python 3.9 path) agrees with sys.orig_argv",
          ctypes_now == list(orig_now) if orig_now is not None else ctypes_now is not None and len(ctypes_now) >= 1, True,
          "%r vs %r" % (ctypes_now, orig_now))
    with open(os.path.join(LAB, "README.md"), "rb") as fh:
        readme = fh.read().decode("utf-8", "replace")
    first = source.decode("utf-8").split("\n", 1)[0]
    T.leg("5940: the README quotes the real first line of run.py, the env -S requirement and the plain-python3 refusal",
          (("`%s`" % first) in readme, "env -S" in readme or "`env` that supports `-S`" in readme,
           "plain `python3 run.py`" in readme and "`78`" in readme), (True, True, True))
    import ast
    tree = ast.parse(source.decode("utf-8"))
    named = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and hasattr(__import__("builtins"), n.id)}
    local = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    local |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    local |= {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
    checked = set(_LAB_BUILTIN_NAMES) | set(_LAB_CORE_TYPE_NAMES)
    listed = checked | set(_LAB_UNCHECKED_BUILTINS) | {"__name__"}
    T.leg("5941: every builtin name run.py uses is identity-checked or named in the unchecked list",
          (sorted(named - local - listed), sorted(checked & set(_LAB_UNCHECKED_BUILTINS))), ([], []))
    drivers = (
        ("bar-b: a driver that replaces open before running the file is refused",
         "import builtins, runpy, sys\nreal = builtins.open\nbuiltins.open = lambda *a, **k: real(*a, **k)\n"
         "sys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n", "builtin open replaced"),
        ("bar-b: a built-in function of another module that is also named open (os.open) in place of open is refused",
         "import builtins, os, runpy, sys\nbuiltins.open = os.open\n"
         "sys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n", "builtin open replaced"),
        ("bar-c: a name that replaces the matcher's open (an injected global) is refused",
         "import runpy, sys\nsys.argv = [%r, '--help']\nrunpy.run_path(%r, init_globals={'open': open}, run_name='__main__')\n",
         "unexpected global open"),
        ("bar-c: a module that replaces one the matcher uses (re in sys.modules) is refused",
         "import runpy, sys, types\nrunpy.run_path('/dev/null')\nsys.modules['re'] = types.ModuleType('re')\n"
         "sys.argv = [%r, '--help']\n"
         "runpy.run_path(%r, run_name='__main__')\n", "module re loaded from outside"),
        ("bar-c: a module posing as built-in under another name (re in sys.modules) is refused before any import",
         "import importlib.machinery, runpy, sys, types\nrunpy.run_path('/dev/null')\nm = types.ModuleType('re')\n"
         "m.__spec__ = importlib.machinery.ModuleSpec('not_re', None, origin='built-in')\nsys.modules['re'] = m\n"
         "sys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n", "module re loaded from outside"),
        ("bar-c: an import hook added before the file runs is refused",
         "import runpy, sys\nclass F:\n    @staticmethod\n    def find_spec(*a):\n        return None\nsys.meta_path.insert(0, F)\n"
         "sys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n", "sys.meta_path"),
        ("bar-c: an object that is not a module standing in for one the matcher uses (re in sys.modules) is refused",
         "import re, runpy, sys\nrunpy.run_path('/dev/null')\nclass R:\n    pass\nr = R()\nr.__dict__.update(vars(re))\n"
         "sys.modules['re'] = r\nsys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n",
         "module re is not a module object"),
        ("start state: an object that is not the builtin posix module in sys.modules is refused",
         "import runpy, sys, types\nrunpy.run_path('/dev/null')\nsys.modules['posix'] = types.SimpleNamespace(environ={})\n"
         "sys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n", "the posix module is not the builtin one"),
        ("start state: a driver that runs the file through exec is refused",
         "import sys\nsys.argv = [%r, '--help']\nsrc = %r\nexec(compile(open(src).read(), src, 'exec'), {'__name__': '__main__', "
         "'__file__': src})\n", "__builtins__ is not the builtins module"),
        ("5908: a command line that cannot be read (no sys.orig_argv, ctypes unusable) is refused",
         "import runpy, sys\nif hasattr(sys, 'orig_argv'):\n    del sys.orig_argv\nsys.modules['ctypes'] = None\n"
         "sys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n", "command line cannot be read"),
        ("5941: a driver that replaces the builtin all is refused",
         "import builtins, runpy, sys\nbuiltins.all = lambda *a: True\nsys.argv = [%r, '--help']\n"
         "runpy.run_path(%r, run_name='__main__')\n", "builtin all replaced"),
        ("5941: a driver that replaces the builtin float is refused",
         "import builtins, runpy, sys\nreal = builtins.float\nbuiltins.float = lambda *a: real(*a)\nsys.argv = [%r, '--help']\n"
         "runpy.run_path(%r, run_name='__main__')\n", "builtin float replaced"),
        ("start state: a trace hook set before the file runs is refused",
         "import runpy, sys\nsys.settrace(lambda *a: None)\nsys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n",
         "trace or profile hook"),
        ("start state: a replaced sys.excepthook is refused",
         "import runpy, sys\nsys.excepthook = lambda *a: None\nsys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n",
         "sys.excepthook is replaced"),
        ("start state: a replaced sys.displayhook is refused",
         "import runpy, sys\nsys.displayhook = lambda *a: None\nsys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n",
         "sys.displayhook is replaced"),
        ("start state: a replaced sys.unraisablehook is refused",
         "import runpy, sys\nsys.unraisablehook = lambda *a: None\nsys.argv = [%r, '--help']\n"
         "runpy.run_path(%r, run_name='__main__')\n", "sys.unraisablehook is replaced"),
        ("start state: a replaced sys.breakpointhook is refused",
         "import runpy, sys\nsys.breakpointhook = lambda *a: None\nsys.argv = [%r, '--help']\n"
         "runpy.run_path(%r, run_name='__main__')\n", "sys.breakpointhook is replaced"),
        ("start state: a profile hook set before the file runs is refused",
         "import runpy, sys\nsys.setprofile(lambda *a: None)\nsys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n",
         "trace or profile hook"),
    )
    if vi >= (3, 12):
        drivers += (
            ("start state: a sys.monitoring tool registered before the file runs is refused (Python 3.12+)",
             "import runpy, sys\nsys.monitoring.use_tool_id(3, 'x')\nsys.argv = [%r, '--help']\n"
             "runpy.run_path(%r, run_name='__main__')\n", "sys.monitoring tool is registered"),)
    names = "[" + ", ".join(repr(n) for n in _LAB_BUILTIN_NAMES) + "]"
    drivers += (
        ("start state: each of the 23 checked builtin functions (open, __import__ and 21 more) is refused when "
         "replaced",
         "import builtins, runpy, sys\nreal_dir = builtins.dir\nfor n in " + names + ":\n    f = getattr(builtins, n)\n"
         "    setattr(builtins, n, (lambda g: lambda *a, **k: g(*a, **k))(f))\n"
         "builtins.globals = lambda: sys._getframe(1).f_globals\n"
         "builtins.dir = lambda *a: real_dir(*a) if a else sorted(sys._getframe(1).f_locals)\n"
         "sys.argv = [%r, '--help']\nrunpy.run_path(%r, run_name='__main__')\n",
         "; ".join("builtin %s replaced" % n for n in _LAB_BUILTIN_NAMES) if len(_LAB_BUILTIN_NAMES) == 23
         else "23 names, not %d" % len(_LAB_BUILTIN_NAMES)),)
    for i, (label, body, why) in enumerate(drivers):
        driver = os.path.join(base, "driver-%d.py" % i)
        _write(driver, body % (copy, copy))
        _child(T, base, label, [py, "-I", "-S", driver], _LAB_REFUSED_RC, why, marker_ok=True)
    for label, argv, extra, rc, text in (
            ("port check: a valid PORT_B reaches the next check (control)", [copy, "--probe-mutation", "--no-caveat-probe"],
             {"PORT_B": "19482"}, 2, "--probe-mutation needs the cold-boot probe"),
            ("port check: PORT_B=[0] in the environment is refused", [copy], {"PORT_B": "0"}, 2, "PORT_B must be a decimal port"),
            ("port check: --port-a abc is refused", [copy, "--port-a", "abc"], None, 2, "PORT_A must be a decimal port"),
            ("args: an unknown argument exits 2 with the usage", [copy, "--nope"], None, 2, "unknown argument: --nope\nusage:"),
            ("args: a missing value exits 1", [copy, "--bin"], None, 1, "run.py: --bin needs a value"),
            ("args: an unsafe --corpus-ns exits 2", [copy, "--corpus-ns", "a;b"], None, 2, "refusing unsafe --corpus-ns: a;b")):
        _child(T, base, label, [py, "-I", "-S"] + argv, rc, text, extra)
    if os.path.exists("/dev/full"):
        with open("/dev/full", "wb") as full:
            proc = subprocess.run([py, "-I", "-S", copy, "--help"], stdin=subprocess.DEVNULL, stdout=full,
                                  stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "HOME": base}, timeout=120)
        T.leg("bar-a: a usage text that cannot be written exits non-zero", proc.returncode, 1, proc.stderr[-200:])
    else:
        T.emit("  info: no /dev/full on this host, so the unwritable-stdout leg does not run here\n")


def selftest(out):
    """--posture-selftest: the drift guard, posture lists, probe matcher and probe block, jq parity, inputs, start
    state and exit paths. Writes only under one scratch directory below $TMPDIR (or the current directory) and
    removes it. Exit 0 only when at least one leg ran, every leg passed and the output was written."""
    T = Legs(out)
    T.emit("posture drift-guard legs (#5078):\n")
    base = scratch_dir("lab-selftest")
    try:
        selftest_drift(T, base)
        selftest_render(T)
        selftest_matcher(T, base)
        selftest_probe_block(T, base)
        selftest_jq(T)
        selftest_inputs(T, base)
        selftest_start_state(T, base)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    T.emit("\n  %d PASS / %d FAIL\n" % (T.passes, T.fails))
    flushed = flush_streams([out])
    return 0 if (T.passes >= 1 and T.fails == 0 and flushed and not T.broken) else 1


# ---------------------------------------------------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------------------------------------------------
_FINISH_ATTEMPTS = 8


def _interrupt(signum, _frame):
    raise LabInterrupted(signum)


def main(argv, environ):
    """Parse, then run the self-test or the lab; returns the exit code (the caller leaves through os._exit)."""
    opts, early = parse_args(argv, environ)
    if early is not None:
        rc, out_text, err_text = early
        try:
            sys.stdout.write(out_text)
            sys.stderr.write(err_text)
        except (OSError, ValueError):
            rc = rc or 1
        if not flush_streams([sys.stdout, sys.stderr]):
            rc = rc or 1
        return rc
    if opts["posture_selftest"]:
        rc = selftest(sys.stdout)
        return rc if flush_streams([sys.stdout, sys.stderr]) else 1
    ledger = Ledger(sys.stdout, sys.stdout.isatty() and not environ.get("NO_COLOR"))
    lab = Lab(opts, ledger, environ)
    rc = 1
    try:
        try:
            signal.signal(signal.SIGINT, _interrupt)
            signal.signal(signal.SIGTERM, _interrupt)
            rc = lab.run()
        except LabInterrupted as exc:
            rc = 128 + exc.signum
        except Exception as exc:  # noqa: BLE001 - an unexpected error is a FAIL, never a pass
            ledger.no("the lab stopped on an unexpected %s: %s" % (exc.__class__.__name__, exc))
            rc = 1
    except LabInterrupted as exc:  # a signal in the handler-install or error-report window
        rc = 128 + exc.signum
    rc = _finish(lab, ledger, rc)
    if rc == 0:
        return final_rc(ledger, lab.summarized, [sys.stdout, sys.stderr])
    flush_streams([sys.stdout, sys.stderr])
    return rc


def _finish(lab, ledger, rc):
    """Ignore SIGINT and SIGTERM, then clean up. A signal that lands first only restarts that step (cleanup is
    idempotent); if the bound is exhausted the exit is non-zero with a named line (#5527 r8, F2)."""
    for _ in range(_FINISH_ATTEMPTS):
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            lab.cleanup()
            return rc
        except LabInterrupted as exc:
            rc = rc or 128 + exc.signum
    try:
        ledger.no("cleanup did not complete: interrupted %d times; daemons or run/ may remain" % _FINISH_ATTEMPTS)
    except Exception:  # noqa: BLE001 - the exit code still carries the failure
        pass
    return rc or 1


if __name__ == "__main__":
    os._exit(main(sys.argv[1:], os.environ))
